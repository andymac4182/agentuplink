//! The actual offline CLI feeding the production Redis recovery workflow.
//!
//! Run only against a dedicated test Redis, with TEST_REDIS_URL set. No Redis
//! configuration, restart or global flush is performed; every key belongs to a
//! fresh fixture namespace. The plaintext loopback fixture is intentional;
//! production relay CLI TLS/configuration is covered by its separate gates.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{Duration as WallDuration, Utc};
use tokio::process::Command;
use tokio::time::timeout;
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, PermissionSet, PrincipalIdentity, RecoveryApproval, RedisCatalog, ServiceSpec,
    TenantRecord, UserRecord,
};
use tunnel_relay::recovery::{
    QuiescenceAcknowledgement, RecoverRequest, RecoveryApprovalVersionStore, RecoveryFenceIdentity,
    RecoveryObservation, RecoveryWorkflowConfig, RecoveryWorkflowError, recover, recovery_observe,
};
use tunnel_relay::redis_connection::RedisTlsMaterialPaths;
use uuid::Uuid;

const DEPLOYMENT: &str = "authority-recovery-integration";
const INITIAL: &str = "initial-incarnation";
const CANDIDATE: &str = "recovered-incarnation";
const NONCE: &str = "independent-recovery-test-nonce-123456";
const SPKI: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ISSUER: &str = "https://authority-recovery.invalid";
const SUBJECT: &str = "test-principal";

fn records() -> CatalogFixture {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "authority recovery test".into(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "authority recovery principal".into(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.into(),
            subject: SUBJECT.into(),
            user_id: user,
        }],
        memberships: vec![MembershipRecord {
            tenant_id: tenant,
            user_id: user,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant,
            device_id: device,
            owner_user_id: user,
            display_name: "authority recovery device".into(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant,
            device_id: device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: SPKI.into(),
            serial: Some("authority-recovery-test".into()),
            not_before: now - WallDuration::seconds(1),
            expires_at: now + WallDuration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant,
            device_id: device,
            service_id: service,
            service_type: "echo".into(),
            display_name: "authority recovery echo".into(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant,
            principal_id: user,
            device_id: device,
            service_id: service,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".into()]),
            },
            constraints: serde_json::json!({"max_bytes": 4096}),
            expires_at: Some(now + WallDuration::hours(1)),
            active: true,
        }],
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

async fn run_authority(args: &[&str]) {
    let output = timeout(
        Duration::from_secs(5),
        Command::new(env!("CARGO_BIN_EXE_tunnel-authority"))
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("authority CLI deadline")
    .expect("spawn authority CLI");
    assert!(
        output.status.success(),
        "authority CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() < 128);
}

fn utf8(path: &Path) -> &str {
    path.to_str().unwrap()
}

async fn sign(
    directory: &Path,
    label: &str,
    observation: &RecoveryObservation,
    version: u64,
) -> PathBuf {
    let observed = directory.join(format!("{label}-observation.json"));
    let unsigned = directory.join(format!("{label}-unsigned.json"));
    let signed = directory.join(format!("{label}-signed.json"));
    let now = Utc::now();
    let approval = RecoveryApproval {
        schema_version: 1,
        deployment_id: observation.deployment_id.clone(),
        redis_namespace: observation.redis_namespace.clone(),
        redis_run_id: observation.redis_run_id.clone(),
        deployment_incarnation: observation.deployment_incarnation.clone(),
        approval_version: version,
        nonce: NONCE.into(),
        catalog_digest: observation.catalog_digest.clone(),
        issued_at: now,
        not_before: now,
        expires_at: now + WallDuration::seconds(60),
    };
    write_private(&observed, &serde_json::to_vec(observation).unwrap());
    write_private(&unsigned, &serde_json::to_vec(&approval).unwrap());
    run_authority(&[
        "sign-recovery-approval",
        "--key",
        utf8(&directory.join("key.der")),
        "--key-id",
        "recovery-test",
        "--observation",
        utf8(&observed),
        "--approval",
        utf8(&unsigned),
        "--expected-nonce",
        NONCE,
        "--output",
        utf8(&signed),
    ])
    .await;
    signed
}

fn request(path: PathBuf) -> RecoverRequest {
    RecoverRequest {
        expected_nonce: NONCE.into(),
        approval_path: path,
        quiescence: QuiescenceAcknowledgement::new("synthetic-test-fencing", true, true).unwrap(),
    }
}

fn highest_version(config: &RecoveryWorkflowConfig) -> Option<u64> {
    RecoveryApprovalVersionStore::open(
        &config.fence_path,
        RecoveryFenceIdentity::new(DEPLOYMENT, &config.redis_namespace).unwrap(),
    )
    .unwrap()
    .load()
    .unwrap()
    .highest_approval_version
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated TEST_REDIS_URL Redis fixture"]
async fn cli_signed_recovery_preserves_revocations_and_rejects_stale_authority() {
    timeout(Duration::from_secs(45), real_recovery())
        .await
        .expect("recovery test deadline");
}

async fn real_recovery() {
    let url = std::env::var("TEST_REDIS_URL").expect("dedicated TEST_REDIS_URL is required");
    let namespace = format!("test-authority-recovery-{}", Uuid::new_v4().simple());
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    run_authority(&[
        "generate-key",
        "--key-id",
        "recovery-test",
        "--private-key",
        utf8(&directory.join("key.der")),
        "--public-keys",
        utf8(&directory.join("trust.json")),
    ])
    .await;

    let records = records();
    let grant = &records.grants[0];
    let credential = &records.credentials[0];
    let active = RedisCatalog::connect_for_recovery(&url, &namespace, INITIAL)
        .await
        .unwrap();
    active.activate_deployment_incarnation().await.unwrap();
    active.seed_fixture(&records).await.unwrap();
    let principal = active
        .resolve_consumer(ISSUER, SUBJECT, Some(grant.tenant_id))
        .await
        .unwrap()
        .expect("positive principal control");
    assert!(
        active
            .authorize(
                &principal,
                grant.device_id,
                grant.service_id,
                Utc::now(),
                Utc::now()
            )
            .await
            .unwrap()
            .is_some(),
        "grant must work before revocation"
    );
    assert!(
        active
            .resolve_device(SPKI, Utc::now())
            .await
            .unwrap()
            .is_some(),
        "credential must work before revocation"
    );

    let config = RecoveryWorkflowConfig::new(
        &url,
        DEPLOYMENT,
        &namespace,
        CANDIDATE,
        directory.join("fence.json"),
        directory.join("trust.json"),
        RedisTlsMaterialPaths::default(),
    )
    .unwrap();
    drop(
        RecoveryApprovalVersionStore::bootstrap(
            &config.fence_path,
            RecoveryFenceIdentity::new(DEPLOYMENT, &namespace).unwrap(),
        )
        .unwrap(),
    );

    let before_revocation = recovery_observe(&config).await.unwrap();
    let stale = request(sign(&directory, "before-revocation", &before_revocation, 1).await);
    active
        .revoke_grant(
            grant.tenant_id,
            grant.principal_id,
            grant.device_id,
            grant.service_id,
            Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(
        recover(&config, &stale).await.unwrap_err(),
        RecoveryWorkflowError::CatalogDigestMismatch
    );
    assert_eq!(
        highest_version(&config),
        None,
        "digest refusal must not consume version"
    );
    assert!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, INITIAL)
            .await
            .is_ok()
    );
    assert!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, CANDIDATE)
            .await
            .is_err()
    );

    active
        .revoke_credential(
            credential.tenant_id,
            credential.device_id,
            credential.credential_id,
            Utc::now(),
        )
        .await
        .unwrap();
    let observed = recovery_observe(&config).await.unwrap();
    assert_ne!(observed.catalog_digest, before_revocation.catalog_digest);
    let valid = request(sign(&directory, "current", &observed, 1).await);
    let mut wrong_nonce = valid.clone();
    wrong_nonce.expected_nonce = "another-independent-nonce-123456".into();
    assert_eq!(
        recover(&config, &wrong_nonce).await.unwrap_err(),
        RecoveryWorkflowError::ApprovalRejected
    );
    assert_eq!(highest_version(&config), None);

    // Do not restart a shared test Redis. A separately signed approval for a
    // different run must be refused against the actual server's observed run.
    let mut another_run = observed.clone();
    another_run.redis_run_id = "another-redis-run".into();
    let wrong_run = request(sign(&directory, "wrong-run", &another_run, 1).await);
    assert_eq!(
        recover(&config, &wrong_run).await.unwrap_err(),
        RecoveryWorkflowError::ApprovalRejected
    );
    assert_eq!(highest_version(&config), None);

    let outcome = recover(&config, &valid)
        .await
        .expect("CLI approval must activate candidate");
    assert_eq!(outcome.approval_version, 1);
    assert_eq!(outcome.redis_run_id, observed.redis_run_id);
    assert_eq!(highest_version(&config), Some(1));
    assert!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, INITIAL)
            .await
            .is_err()
    );
    let recovered = RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, CANDIDATE)
        .await
        .unwrap();
    let principal = recovered
        .resolve_consumer(ISSUER, SUBJECT, Some(grant.tenant_id))
        .await
        .unwrap()
        .expect("principal identity survives; its grant stays revoked");
    assert!(
        recovered
            .authorize(
                &principal,
                grant.device_id,
                grant.service_id,
                Utc::now(),
                Utc::now()
            )
            .await
            .unwrap()
            .is_none(),
        "recovery must not restore revoked principal access"
    );
    assert!(
        recovered
            .resolve_device(SPKI, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "recovery must not restore revoked credential access"
    );
    assert_eq!(
        recover(&config, &valid).await.unwrap_err(),
        RecoveryWorkflowError::ApprovalRejected
    );

    // Fresh scope and signature still cannot bypass the persisted version
    // fence by selecting a new incarnation. Each workflow opens it from disk.
    let mut later_config = config.clone();
    later_config.deployment_incarnation = "later-incarnation".into();
    let later_observed = recovery_observe(&later_config).await.unwrap();
    let reused_version = request(sign(&directory, "reused-version", &later_observed, 1).await);
    assert_eq!(
        recover(&later_config, &reused_version).await.unwrap_err(),
        RecoveryWorkflowError::ApprovalRejected
    );
    assert_eq!(highest_version(&config), Some(1));
    assert!(
        RedisCatalog::connect_with_deployment_incarnation(&url, &namespace, CANDIDATE)
            .await
            .is_ok()
    );
    recovered.cleanup_fixture_namespace().await.unwrap();
}
