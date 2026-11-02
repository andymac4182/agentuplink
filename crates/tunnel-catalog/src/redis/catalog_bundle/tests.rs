use super::*;
use crate::redis::recovery_schema::tests::base_catalog;

const PREFIX: &str = "tunnel-catalog:test-schema:";
const TENANT: &str = "00000000-0000-4000-8000-000000000001";
const USER: &str = "00000000-0000-4000-8000-000000000011";
const DEVICE: &str = "00000000-0000-4000-8000-000000000021";
const CREDENTIAL: &str = "00000000-0000-4000-8000-000000000031";
const SERVICE: &str = "00000000-0000-4000-8000-000000000041";

fn identity() -> CatalogBundleIdentity {
    CatalogBundleIdentity::new("deployment-a", "test-schema").expect("identity")
}

fn key(kind: &str) -> String {
    match kind {
        "device" => format!("{PREFIX}device:{TENANT}:{DEVICE}"),
        "credential" => format!("{PREFIX}credential:{TENANT}:{DEVICE}:{CREDENTIAL}"),
        "service" => format!("{PREFIX}service:{TENANT}:{DEVICE}:{SERVICE}"),
        "grant" => format!("{PREFIX}grant:{TENANT}:{USER}:{DEVICE}:{SERVICE}"),
        "epoch" => format!("{PREFIX}coord:epoch:{TENANT}:{DEVICE}"),
        "tenant" => format!("{PREFIX}tenant:{TENANT}"),
        "membership" => format!("{PREFIX}membership:{TENANT}:{USER}"),
        _ => panic!("unknown fixture kind"),
    }
}

fn complete_catalog() -> Vec<ObservedRedisKey> {
    let mut observed = base_catalog();
    let fingerprint = "a".repeat(64);
    let hash = |kind: &str, fields: &[(&str, &str)]| {
        ObservedRedisKey::hash(
            key(kind),
            -1,
            fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    };
    observed.push(hash(
        "credential",
        &[
            ("tenant_id", TENANT),
            ("device_id", DEVICE),
            ("credential_id", CREDENTIAL),
            ("spki_fingerprint", &fingerprint),
            ("serial", "1"),
            ("not_before_us", "100"),
            ("expires_at_us", "1000"),
            ("revoked_at_us", ""),
            ("active", "1"),
        ],
    ));
    observed.push(hash(
        "service",
        &[
            ("tenant_id", TENANT),
            ("device_id", DEVICE),
            ("service_id", SERVICE),
            ("service_type", "echo"),
            ("display_name", "synthetic echo"),
            ("capabilities", "{}"),
            ("version", "1"),
            ("active", "1"),
        ],
    ));
    observed.push(hash(
        "grant",
        &[
            ("tenant_id", TENANT),
            ("principal_id", USER),
            ("device_id", DEVICE),
            ("service_id", SERVICE),
            ("revision", "1"),
            ("permissions", "[\"echo:invoke\"]"),
            ("constraints", "{}"),
            ("expires_at_us", ""),
            ("active", "1"),
            ("revoked_at_us", ""),
        ],
    ));
    for (suffix, member) in [
        (
            format!("idx:credentials:{TENANT}:{DEVICE}"),
            CREDENTIAL.to_owned(),
        ),
        (
            format!("idx:services:{TENANT}:{DEVICE}"),
            SERVICE.to_owned(),
        ),
        (format!("idx:grants_device:{TENANT}:{DEVICE}"), key("grant")),
    ] {
        observed.push(ObservedRedisKey::set(
            format!("{PREFIX}{suffix}"),
            -1,
            vec![member],
        ));
    }
    observed.push(ObservedRedisKey::string(
        format!("{PREFIX}idx:fingerprint:{fingerprint}"),
        -1,
        key("credential"),
    ));
    observed
}

fn set_field(observed: &mut [ObservedRedisKey], kind: &str, field: &str, value: &str) {
    let entry = observed
        .iter_mut()
        .find(|entry| entry.key == key(kind))
        .expect("key");
    let ObservedRedisValue::Hash(fields) = &mut entry.value else {
        panic!("hash expected");
    };
    fields
        .iter_mut()
        .find(|(k, _)| k == field)
        .expect("field")
        .1 = value.to_owned();
}

fn document(observed: &[ObservedRedisKey]) -> BundleDocument {
    let snapshot = validate_observed_catalog(PREFIX, observed).expect("complete source graph");
    BundleDocument {
        schema_version: BUNDLE_SCHEMA_VERSION,
        snapshot_schema_version: RECOVERY_SNAPSHOT_SCHEMA_VERSION,
        deployment_id: "deployment-a".to_owned(),
        redis_namespace: "test-schema".to_owned(),
        source: SourceObservation {
            incarnation: "incarnation-a".to_owned(),
            redis_run_id: "1".repeat(40),
            catalog_generation: 7,
            captured_at: "2026-11-02T00:00:00Z".to_owned(),
        },
        catalog_digest: durable_catalog_digest(snapshot.canonical_bytes()),
        entries: projected_entries(&snapshot),
    }
}

fn parse_document(document: &BundleDocument) -> Result<CatalogBundle, CatalogBundleError> {
    let bytes = serde_json::to_vec(document).expect("encode");
    CatalogBundle::parse(&bytes, &durable_catalog_digest(&bytes), &identity())
}

fn bundle(observed: &[ObservedRedisKey]) -> CatalogBundle {
    parse_document(&document(observed)).expect("valid bundle")
}

fn plan_error(before: &[ObservedRedisKey], after: &[ObservedRedisKey]) -> CatalogBundleError {
    plan_catalog_reconciliation(&bundle(before), &bundle(after))
        .err()
        .expect("refusal")
}

#[test]
fn complete_bundle_reuses_recovery_digest_and_remains_untrusted() {
    let observed = complete_catalog();
    let snapshot = validate_observed_catalog(PREFIX, &observed).expect("schema");
    let bundle = bundle(&observed);
    assert_eq!(bundle.snapshot.canonical_bytes(), snapshot.canonical_bytes());
    let summary = serde_json::to_value(bundle.summary()).expect("summary");
    assert_eq!(summary["status"], "schema_valid_only");
    assert_eq!(summary["historical_completeness"], "unproven");
    assert_eq!(summary["custody"], "unproven");
    assert_eq!(summary["quiescence"], "unproven");
    assert_eq!(summary["apply_authorized"], false);
    assert!(summary.get("entries").is_none());
    assert_eq!(summary["key_count"], 26);
}

#[test]
fn hashes_encoding_identity_and_bounds_fail_closed() {
    let document = document(&complete_catalog());
    let bytes = serde_json::to_vec(&document).expect("encode");
    assert!(matches!(
        CatalogBundle::parse(&bytes, &"0".repeat(64), &identity()),
        Err(CatalogBundleError::Hash)
    ));
    let foreign = CatalogBundleIdentity::new("other", "test-schema").expect("identity");
    assert!(matches!(
        CatalogBundle::parse(&bytes, &durable_catalog_digest(&bytes), &foreign),
        Err(CatalogBundleError::Identity)
    ));
    let original = String::from_utf8(bytes).expect("UTF-8");
    for malformed in [
        format!("{original}\n"),
        original.replacen("\"schema_version\":1", "\"schema_version\":true", 1),
        original.replacen("\"schema_version\":1", "\"schema_version\":1.0", 1),
        original.replacen("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1", 1),
        original.replacen("\"schema_version\":1", "\"unknown\":0,\"schema_version\":1", 1),
    ] {
        assert!(matches!(
            CatalogBundle::parse(
                malformed.as_bytes(),
                &durable_catalog_digest(malformed.as_bytes()),
                &identity(),
            ),
            Err(CatalogBundleError::Encoding)
        ));
    }
    assert!(matches!(
        CatalogBundle::parse(
            &vec![0; MAX_CATALOG_BUNDLE_BYTES + 1],
            &"0".repeat(64),
            &identity(),
        ),
        Err(CatalogBundleError::Bound)
    ));
}

#[test]
fn supplied_indexes_duplicates_unknown_and_foreign_keys_are_not_repaired() {
    for mutate in 0..5 {
        let mut document = document(&complete_catalog());
        match mutate {
            0 => document
                .entries
                .retain(|entry| !entry.key.contains("idx:credentials:")),
            1 => document.entries.push(document.entries[0].clone()),
            2 => document.entries[0].key = format!("{PREFIX}unknown:record"),
            3 => {
                document.entries[0].key = document.entries[0].key.replace("test-schema", "foreign");
            }
            4 => {
                let entry = document
                    .entries
                    .iter_mut()
                    .find(|entry| entry.key == key("device"))
                    .expect("device");
                let BundleValue::Hash(fields) = &mut entry.value else {
                    panic!("hash");
                };
                fields
                    .iter_mut()
                    .find(|(k, _)| k == "tenant_id")
                    .expect("tenant")
                    .1 = USER.to_owned();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            parse_document(&document),
            Err(CatalogBundleError::Graph)
        ));
    }
}

#[test]
fn generation_metadata_is_not_an_importable_durable_record() {
    let mut document = document(&complete_catalog());
    document.entries.push(BundleEntry {
        key: format!("{PREFIX}meta:catalog_generation"),
        value: BundleValue::String("7".to_owned()),
    });
    assert!(matches!(
        parse_document(&document),
        Err(CatalogBundleError::NonDurable)
    ));
}

#[test]
fn known_complete_records_cannot_disappear_with_their_indexes() {
    let before = complete_catalog();
    let after = base_catalog();
    assert_eq!(plan_error(&before, &after), CatalogBundleError::MissingRecord);
}

#[test]
fn unversioned_tenant_membership_and_credential_revocations_are_preserved() {
    for kind in ["tenant", "membership", "credential"] {
        let mut before = complete_catalog();
        set_field(&mut before, kind, "active", "0");
        let after = complete_catalog();
        assert_eq!(plan_error(&before, &after), CatalogBundleError::RevocationRollback);
    }
    let mut before = complete_catalog();
    set_field(&mut before, "credential", "active", "0");
    set_field(&mut before, "credential", "revoked_at_us", "500");
    for replacement in ["", "501"] {
        let mut after = before.clone();
        set_field(&mut after, "credential", "revoked_at_us", replacement);
        assert_eq!(plan_error(&before, &after), CatalogBundleError::RevocationRollback);
    }
}

#[test]
fn increasing_version_cannot_resurrect_a_revoked_grant() {
    let mut before = complete_catalog();
    set_field(&mut before, "grant", "revision", "2");
    set_field(&mut before, "grant", "active", "0");
    set_field(&mut before, "grant", "revoked_at_us", "500");
    let mut after = complete_catalog();
    set_field(&mut after, "grant", "revision", "3");
    assert_eq!(plan_error(&before, &after), CatalogBundleError::RevocationRollback);
}

#[test]
fn all_monotonic_counters_compare_exactly_above_floating_point_precision() {
    for (kind, field) in [
        ("device", "device_version"),
        ("service", "version"),
        ("grant", "revision"),
    ] {
        let mut before = complete_catalog();
        set_field(&mut before, kind, field, "9007199254740993");
        let mut after = before.clone();
        set_field(&mut after, kind, field, "9007199254740992");
        assert_eq!(plan_error(&before, &after), CatalogBundleError::CounterRollback);
        set_field(&mut after, kind, field, &u64::MAX.to_string());
        assert_eq!(plan_error(&before, &after), CatalogBundleError::CounterExhausted);
    }
    let mut before = complete_catalog();
    let epoch = before
        .iter_mut()
        .find(|entry| entry.key == key("epoch"))
        .expect("epoch");
    epoch.value = ObservedRedisValue::String("9007199254740993".to_owned());
    let mut after = before.clone();
    let epoch = after
        .iter_mut()
        .find(|entry| entry.key == key("epoch"))
        .expect("epoch");
    epoch.value = ObservedRedisValue::String("9007199254740992".to_owned());
    assert_eq!(plan_error(&before, &after), CatalogBundleError::CounterRollback);
}

#[test]
fn equal_numeric_version_cannot_hide_content_conflicts_with_leading_zeroes() {
    for (kind, version, field, value) in [
        ("device", "device_version", "display_name", "changed"),
        ("service", "version", "capabilities", "{\"new\":true}"),
        ("grant", "revision", "permissions", "[]"),
    ] {
        for version_text in ["1", "01"] {
            let before = complete_catalog();
            let mut after = before.clone();
            set_field(&mut after, kind, version, version_text);
            set_field(&mut after, kind, field, value);
            assert_eq!(
                plan_error(&before, &after),
                CatalogBundleError::EqualVersionConflict
            );
        }
    }
}

#[test]
fn last_seen_change_is_informational_without_rewriting_target_bytes_or_digest() {
    let before = complete_catalog();
    let mut after = before.clone();
    set_field(&mut after, "device", "last_seen_at_us", "123");
    let baseline = bundle(&before);
    let target = bundle(&after);
    let original = target.snapshot.canonical_bytes().to_vec();
    let plan = plan_catalog_reconciliation(&baseline, &target).expect("informational");
    assert_eq!(plan.difference_count(), 1);
    assert_eq!(
        plan.differences[0].classification,
        "operational_last_seen_only"
    );
    assert_ne!(plan.baseline_catalog_digest, plan.target_catalog_digest);
    assert_eq!(target.snapshot.canonical_bytes(), original);
    assert_eq!(plan.target_catalog_digest, durable_catalog_digest(&original));
}

#[test]
fn deterministic_draft_does_not_treat_time_generation_or_hashes_as_custody() {
    let baseline = bundle(&complete_catalog());
    let mut next = document(&complete_catalog());
    next.source.catalog_generation = u64::MAX;
    next.source.captured_at = "2099-01-01T00:00:00Z".to_owned();
    let target = parse_document(&next).expect("observed metadata only");
    let first = plan_catalog_reconciliation(&baseline, &target).expect("draft");
    let second = plan_catalog_reconciliation(&baseline, &target).expect("draft");
    assert_eq!(
        first.canonical_bytes().expect("bytes"),
        second.canonical_bytes().expect("bytes")
    );
    assert_eq!(first.difference_count(), 0);
    let value = serde_json::to_value(first).expect("JSON");
    assert_eq!(value["status"], "offline_draft");
    assert_eq!(value["apply_authorized"], false);
    assert_eq!(value["external_anchors_verified"], false);
    for field in ["historical_completeness", "custody", "quiescence"] {
        assert_eq!(value[field], "unproven");
    }
}

#[test]
fn valid_additions_and_higher_version_changes_remain_unauthorized_drafts() {
    let baseline = bundle(&base_catalog());
    let mut observed = complete_catalog();
    set_field(&mut observed, "service", "version", "2");
    set_field(&mut observed, "service", "display_name", "updated service");
    let target = bundle(&observed);
    let plan = plan_catalog_reconciliation(&baseline, &target).expect("new valid records");
    assert_eq!(plan.difference_count(), 7);
    assert!(!plan.apply_authorized);
    assert!(!plan.external_anchors_verified);
    set_field(&mut observed, "grant", "revision", &u64::MAX.to_string());
    assert!(matches!(
        plan_catalog_reconciliation(&baseline, &bundle(&observed)),
        Err(CatalogBundleError::CounterExhausted)
    ));
}

#[test]
fn canonical_order_and_durable_digest_are_required_independently_of_file_hash() {
    let mut document = document(&complete_catalog());
    document.entries.reverse();
    assert!(matches!(
        parse_document(&document),
        Err(CatalogBundleError::Encoding)
    ));
    document.entries.reverse();
    document.catalog_digest = "0".repeat(64);
    assert!(matches!(
        parse_document(&document),
        Err(CatalogBundleError::Hash)
    ));
}

#[test]
fn credential_identity_and_existing_membership_role_changes_are_refused() {
    let before = complete_catalog();
    for (kind, field, value) in [
        ("credential", "serial", "2"),
        ("credential", "expires_at_us", "2000"),
        ("membership", "role", "admin"),
    ] {
        let mut after = before.clone();
        set_field(&mut after, kind, field, value);
        assert_eq!(plan_error(&before, &after), CatalogBundleError::IdentityChanged);
    }
}
