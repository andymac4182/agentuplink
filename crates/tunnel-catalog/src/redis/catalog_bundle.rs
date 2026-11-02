//! Offline, untrusted catalog bundles. No Redis connection or mutation API.
//!
//! The existing recovery schema remains the sole graph/key-class authority.
//! A hash-valid bundle and a compatible draft do not establish completeness,
//! custody, quiescence, a current Redis run, or permission to activate.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::recovery_schema::{
    CanonicalKind, MAX_RECOVERY_SNAPSHOT_KEYS, ObservedRedisKey, ObservedRedisType,
    ObservedRedisValue, RECOVERY_SNAPSHOT_SCHEMA_VERSION, ValidatedCatalogSnapshot,
    validate_observed_catalog,
};
use crate::recovery::durable_catalog_digest;

/// Encoded JSON limit; the existing stricter four-MiB graph limit also applies.
pub const MAX_CATALOG_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const BUNDLE_SCHEMA_VERSION: u16 = 1;

/// Closed, payload-free failures. No record/key/path is interpolated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogBundleError {
    Identity,
    Bound,
    Hash,
    Encoding,
    Schema,
    Graph,
    NonDurable,
    MissingRecord,
    CounterRollback,
    CounterExhausted,
    EqualVersionConflict,
    RevocationRollback,
    IdentityChanged,
    IndexChanged,
}

impl fmt::Display for CatalogBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Identity => "catalog bundle trust-domain identity refused",
            Self::Bound => "catalog bundle size bound exceeded",
            Self::Hash => "catalog bundle expected hash does not match",
            Self::Encoding => "catalog bundle is not canonical JSON",
            Self::Schema => "catalog bundle schema refused",
            Self::Graph => "catalog bundle complete graph refused",
            Self::NonDurable => "catalog bundle contains non-durable keys",
            Self::MissingRecord => "catalog target omits a known durable record",
            Self::CounterRollback => "catalog target counter rollback refused",
            Self::CounterExhausted => "catalog target counter is exhausted",
            Self::EqualVersionConflict => "catalog equal-version content conflict",
            Self::RevocationRollback => "catalog known revocation rollback refused",
            Self::IdentityChanged => "catalog known identity changed",
            Self::IndexChanged => "catalog target removes a known index member",
        })
    }
}

impl std::error::Error for CatalogBundleError {}

/// Selected from local checked configuration, never from bundle claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogBundleIdentity {
    deployment_id: String,
    redis_namespace: String,
}

impl CatalogBundleIdentity {
    pub fn new(deployment_id: &str, redis_namespace: &str) -> Result<Self, CatalogBundleError> {
        if deployment_id.is_empty()
            || deployment_id.len() > 128
            || !deployment_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || super::validate_redis_namespace(redis_namespace).is_err()
        {
            return Err(CatalogBundleError::Identity);
        }
        Ok(Self {
            deployment_id: deployment_id.to_owned(),
            redis_namespace: redis_namespace.to_owned(),
        })
    }

    fn prefix(&self) -> String {
        format!("tunnel-catalog:{}:", self.redis_namespace)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceObservation {
    incarnation: String,
    redis_run_id: String,
    catalog_generation: u64,
    captured_at: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum BundleValue {
    Hash(Vec<(String, String)>),
    Set(Vec<String>),
    String(String),
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BundleEntry {
    key: String,
    value: BundleValue,
}

impl BundleEntry {
    fn observed(&self) -> ObservedRedisKey {
        let (redis_type, value) = match &self.value {
            BundleValue::Hash(fields) => (
                ObservedRedisType::Hash,
                ObservedRedisValue::Hash(fields.clone()),
            ),
            BundleValue::Set(members) => (
                ObservedRedisType::Set,
                ObservedRedisValue::Set(members.clone()),
            ),
            BundleValue::String(value) => (
                ObservedRedisType::String,
                ObservedRedisValue::String(value.clone()),
            ),
        };
        ObservedRedisKey {
            key: self.key.clone(),
            redis_type,
            ttl_ms: -1,
            value,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleDocument {
    schema_version: u16,
    snapshot_schema_version: u16,
    deployment_id: String,
    redis_namespace: String,
    source: SourceObservation,
    catalog_digest: String,
    entries: Vec<BundleEntry>,
}

/// A schema-valid, hash-bound input; deliberately neither approved nor trusted.
pub struct CatalogBundle {
    identity: CatalogBundleIdentity,
    document: BundleDocument,
    snapshot: ValidatedCatalogSnapshot,
    file_sha256: String,
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn projected_entries(snapshot: &ValidatedCatalogSnapshot) -> Vec<BundleEntry> {
    snapshot
        .canonical_entries()
        .iter()
        .map(|entry| BundleEntry {
            key: entry.key.clone(),
            value: match entry.kind {
                CanonicalKind::Hash => BundleValue::Hash(entry.fields.clone()),
                CanonicalKind::Set => BundleValue::Set(
                    entry.fields.iter().map(|(_, value)| value.clone()).collect(),
                ),
                CanonicalKind::String => BundleValue::String(entry.fields[0].1.clone()),
            },
        })
        .collect()
}

impl CatalogBundle {
    pub fn parse(
        bytes: &[u8],
        expected_sha256: &str,
        identity: &CatalogBundleIdentity,
    ) -> Result<Self, CatalogBundleError> {
        if bytes.len() > MAX_CATALOG_BUNDLE_BYTES {
            return Err(CatalogBundleError::Bound);
        }
        if !lower_hex(expected_sha256, 64) || durable_catalog_digest(bytes) != expected_sha256 {
            return Err(CatalogBundleError::Hash);
        }
        let document: BundleDocument =
            serde_json::from_slice(bytes).map_err(|_| CatalogBundleError::Encoding)?;
        if serde_json::to_vec(&document).map_err(|_| CatalogBundleError::Encoding)? != bytes {
            return Err(CatalogBundleError::Encoding);
        }
        if document.schema_version != BUNDLE_SCHEMA_VERSION
            || document.snapshot_schema_version != RECOVERY_SNAPSHOT_SCHEMA_VERSION
            || document.entries.is_empty()
            || document.entries.len() > MAX_RECOVERY_SNAPSHOT_KEYS
            || !lower_hex(&document.catalog_digest, 64)
            || !lower_hex(&document.source.redis_run_id, 40)
            || document.source.captured_at.len() > 64
            || chrono::DateTime::parse_from_rfc3339(&document.source.captured_at).is_err()
            || document.source.incarnation.is_empty()
            || document.source.incarnation.len() > 128
            || !document
                .source
                .incarnation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(CatalogBundleError::Schema);
        }
        if document.deployment_id != identity.deployment_id
            || document.redis_namespace != identity.redis_namespace
        {
            return Err(CatalogBundleError::Identity);
        }
        let observed = document
            .entries
            .iter()
            .map(BundleEntry::observed)
            .collect::<Vec<_>>();
        let snapshot = validate_observed_catalog(&identity.prefix(), &observed)
            .map_err(|_| CatalogBundleError::Graph)?;
        if snapshot.durable_key_count() != observed.len() {
            return Err(CatalogBundleError::NonDurable);
        }
        // The schema derives relationships and checks the supplied indexes.
        // Projection checks ordering; it never repairs or rewrites the input.
        if projected_entries(&snapshot) != document.entries {
            return Err(CatalogBundleError::Encoding);
        }
        if durable_catalog_digest(snapshot.canonical_bytes()) != document.catalog_digest {
            return Err(CatalogBundleError::Hash);
        }
        Ok(Self {
            identity: identity.clone(),
            document,
            snapshot,
            file_sha256: expected_sha256.to_owned(),
        })
    }

    pub fn summary(&self) -> CatalogBundleSummary {
        CatalogBundleSummary {
            schema_version: BUNDLE_SCHEMA_VERSION,
            status: "schema_valid_only",
            file_sha256: self.file_sha256.clone(),
            catalog_digest: self.document.catalog_digest.clone(),
            key_count: self.snapshot.durable_key_count(),
            canonical_byte_count: self.snapshot.canonical_byte_count(),
            historical_completeness: "unproven",
            custody: "unproven",
            quiescence: "unproven",
            apply_authorized: false,
        }
    }
}

/// Redacted stdout summary. Successful validation grants no write authority.
#[derive(Serialize)]
pub struct CatalogBundleSummary {
    schema_version: u16,
    status: &'static str,
    file_sha256: String,
    catalog_digest: String,
    key_count: usize,
    canonical_byte_count: usize,
    historical_completeness: &'static str,
    custody: &'static str,
    quiescence: &'static str,
    apply_authorized: bool,
}

#[derive(Serialize)]
struct PlannedDifference {
    key: String,
    classification: &'static str,
}

/// A private offline draft. There is intentionally no apply method.
#[derive(Serialize)]
pub struct CatalogReconciliationPlan {
    schema_version: u16,
    status: &'static str,
    deployment_id: String,
    redis_namespace: String,
    baseline_sha256: String,
    target_sha256: String,
    baseline_catalog_digest: String,
    target_catalog_digest: String,
    baseline_source: SourceObservation,
    target_source: SourceObservation,
    historical_completeness: &'static str,
    custody: &'static str,
    quiescence: &'static str,
    external_anchors_verified: bool,
    apply_authorized: bool,
    differences: Vec<PlannedDifference>,
}

impl CatalogReconciliationPlan {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CatalogBundleError> {
        let bytes = serde_json::to_vec(self).map_err(|_| CatalogBundleError::Encoding)?;
        if bytes.len() > MAX_CATALOG_BUNDLE_BYTES {
            return Err(CatalogBundleError::Bound);
        }
        Ok(bytes)
    }

    pub fn difference_count(&self) -> usize {
        self.differences.len()
    }
}

fn counter(before: &str, after: &str) -> Result<bool, CatalogBundleError> {
    let before = before.parse::<u64>().map_err(|_| CatalogBundleError::Graph)?;
    let after = after.parse::<u64>().map_err(|_| CatalogBundleError::Graph)?;
    if after < before {
        return Err(CatalogBundleError::CounterRollback);
    }
    if after == u64::MAX {
        return Err(CatalogBundleError::CounterExhausted);
    }
    Ok(before == after)
}

fn compare_entry(
    before: &BundleEntry,
    after: &BundleEntry,
    prefix: &str,
) -> Result<&'static str, CatalogBundleError> {
    let key = before
        .key
        .strip_prefix(prefix)
        .ok_or(CatalogBundleError::Identity)?;
    match (&before.value, &after.value) {
        (BundleValue::String(a), BundleValue::String(b)) if key.starts_with("coord:epoch:") => {
            counter(a, b)?;
        }
        (BundleValue::String(a), BundleValue::String(b)) => {
            if a != b {
                return Err(CatalogBundleError::IdentityChanged);
            }
        }
        (BundleValue::Set(a), BundleValue::Set(b)) => {
            if a.iter().any(|member| b.binary_search(member).is_err()) {
                return Err(CatalogBundleError::IndexChanged);
            }
        }
        (BundleValue::Hash(a), BundleValue::Hash(b)) => {
            let a = a
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<BTreeMap<_, _>>();
            let b = b
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<BTreeMap<_, _>>();
            if (a.get("active") == Some(&"0") && b.get("active") != Some(&"0"))
                || a.get("revoked_at_us").is_some_and(|v| !v.is_empty())
                    && (b.get("active") != Some(&"0")
                        || b.get("revoked_at_us") != a.get("revoked_at_us"))
            {
                return Err(CatalogBundleError::RevocationRollback);
            }
            let immutable = if key.starts_with("credential:") {
                &["spki_fingerprint", "serial", "not_before_us", "expires_at_us"][..]
            } else if key.starts_with("device:") {
                &["owner_user_id"][..]
            } else if key.starts_with("identity:") {
                &["issuer", "subject", "user_id"][..]
            } else if key.starts_with("membership:") {
                &["role"][..]
            } else {
                &[][..]
            };
            if immutable.iter().any(|field| a.get(field) != b.get(field)) {
                return Err(CatalogBundleError::IdentityChanged);
            }
            let version = if key.starts_with("device:") {
                Some("device_version")
            } else if key.starts_with("service:") {
                Some("version")
            } else if key.starts_with("grant:") {
                Some("revision")
            } else {
                None
            };
            if let Some(version) = version {
                let old = a.get(version).ok_or(CatalogBundleError::Graph)?;
                let new = b.get(version).ok_or(CatalogBundleError::Graph)?;
                if counter(old, new)? {
                    let mut policy_a = a.clone();
                    let mut policy_b = b.clone();
                    if key.starts_with("device:") {
                        policy_a.remove("last_seen_at_us");
                        policy_b.remove("last_seen_at_us");
                    }
                    if policy_a != policy_b {
                        return Err(CatalogBundleError::EqualVersionConflict);
                    }
                    if a != b {
                        return Ok("operational_last_seen_only");
                    }
                }
            }
        }
        _ => return Err(CatalogBundleError::Graph),
    }
    Ok(if before == after { "unchanged" } else { "changed" })
}

/// Compare two complete schema-valid inputs. No network, writes, merge or repair.
pub fn plan_catalog_reconciliation(
    baseline: &CatalogBundle,
    target: &CatalogBundle,
) -> Result<CatalogReconciliationPlan, CatalogBundleError> {
    if baseline.identity != target.identity {
        return Err(CatalogBundleError::Identity);
    }
    let target_keys = target
        .document
        .entries
        .iter()
        .map(|entry| (entry.key.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let baseline_keys = baseline
        .document
        .entries
        .iter()
        .map(|entry| (entry.key.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut differences = Vec::new();
    for (key, before) in &baseline_keys {
        let after = target_keys.get(key).ok_or(CatalogBundleError::MissingRecord)?;
        let classification = compare_entry(before, after, &baseline.identity.prefix())?;
        if classification != "unchanged" {
            differences.push(PlannedDifference {
                key: (*key).to_owned(),
                classification,
            });
        }
    }
    for (key, entry) in &target_keys {
        // Check exhaustion even for newly introduced identities.
        compare_entry(entry, entry, &target.identity.prefix())?;
        if !baseline_keys.contains_key(key) {
            differences.push(PlannedDifference {
                key: (*key).to_owned(),
                classification: "new",
            });
        }
    }
    differences.sort_by(|a, b| a.key.cmp(&b.key));
    // Source generation is retained as an observation, never used to infer
    // freshness or overwrite/activate a target generation.
    let plan = CatalogReconciliationPlan {
        schema_version: BUNDLE_SCHEMA_VERSION,
        status: "offline_draft",
        deployment_id: baseline.identity.deployment_id.clone(),
        redis_namespace: baseline.identity.redis_namespace.clone(),
        baseline_sha256: baseline.file_sha256.clone(),
        target_sha256: target.file_sha256.clone(),
        baseline_catalog_digest: baseline.document.catalog_digest.clone(),
        target_catalog_digest: target.document.catalog_digest.clone(),
        baseline_source: baseline.document.source.clone(),
        target_source: target.document.source.clone(),
        historical_completeness: "unproven",
        custody: "unproven",
        quiescence: "unproven",
        external_anchors_verified: false,
        apply_authorized: false,
        differences,
    };
    plan.canonical_bytes()?;
    Ok(plan)
}

#[cfg(test)]
mod tests;
