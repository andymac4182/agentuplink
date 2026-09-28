//! The real path (task row M6-C22): `tunnel-relay recover` accepts an
//! approval `tunnel-authority sign-recovery-approval` wrote, and refuses one
//! from the wrong key and one signed against a stale catalog digest.
//!
//! Both binaries run as processes. `tunnel-relay` is found beside this
//! crate's binary in the same Cargo target directory, so build it first
//! (`cargo build -p tunnel-relay --bin tunnel-relay --locked`); a workspace
//! build or test run already has. Like `tunnel-relay`'s
//! `recovery_workflow.rs`, whose fixture and configuration this follows, the
//! test needs `TUNNEL_CATALOG_REDIS_URL` set to a plaintext database-0 Redis
//! and puts the same bounded TLS forwarder in front of it, because the relay
//! accepts only `rediss://`. Every key lives under a fresh
//! `test-authority-recovery-<uuid>` namespace, deleted at the end.

#![cfg(unix)]

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::Value;
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, PrincipalIdentity, RedisCatalog, ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

#[path = "../../tunnel-relay/tests/common/recovery_redis.rs"]
mod recovery_redis;

const DEPLOYMENT_ID: &str = "m6-c22-authority-deployment";
const INITIAL_INCARNATION: &str = "m6-c22-authority-initial";
const CANDIDATE_INCARNATION: &str = "m6-c22-authority-candidate";
const KEY_ID: &str = "m6-c22-recovery-operator";
const ACKNOWLEDGEMENT: &str = "m6-c22-change-record";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "agent-tunnel-{label}-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create test directory");
        // The relay refuses a control path under a symbolic link, and the
        // temporary directory is one on macOS.
        let path = fs::canonicalize(path).expect("canonicalize test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private directory");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    upstream_url: String,
    namespace: String,
    tenant: Uuid,
    device: Uuid,
}

async fn seed(upstream_url: &str) -> Fixture {
    let namespace = format!("test-authority-recovery-{}", Uuid::new_v4().simple());
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    let records = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "authority recovery tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "authority recovery user".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.authority-recovery.invalid".to_owned(),
            subject: format!("authority-recovery-subject-{user}"),
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
            display_name: "authority recovery device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant,
            device_id: device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            serial: Some("authority-recovery-credential".to_owned()),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant,
            device_id: device,
            service_id: service,
            service_type: "echo".to_owned(),
            display_name: "authority recovery echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant,
            principal_id: user,
            device_id: device,
            service_id: service,
            permissions: tunnel_catalog::PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({"max_bytes": 4096}),
            expires_at: Some(now + ChronoDuration::hours(1)),
            active: true,
        }],
    };
    let catalog = RedisCatalog::connect_for_recovery(upstream_url, &namespace, INITIAL_INCARNATION)
        .await
        .expect("connect authority recovery catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate the initial incarnation");
    catalog
        .seed_fixture(&records)
        .await
        .expect("seed the authority recovery fixture");
    Fixture {
        upstream_url: upstream_url.to_owned(),
        namespace,
        tenant,
        device,
    }
}

async fn cleanup(fixture: &Fixture) {
    RedisCatalog::connect_for_recovery(&fixture.upstream_url, &fixture.namespace, "cleanup")
        .await
        .expect("connect cleanup catalog")
        .cleanup_fixture_namespace()
        .await
        .expect("delete the test namespace");
}

async fn active_is(fixture: &Fixture, incarnation: &str) -> bool {
    RedisCatalog::connect_with_deployment_incarnation(
        &fixture.upstream_url,
        &fixture.namespace,
        incarnation,
    )
    .await
    .is_ok()
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("quote TOML string")
}

fn toml_path(path: &Path) -> String {
    toml_string(path.to_str().expect("UTF-8 path"))
}

/// A cluster relay configuration whose `[recovery]` section is real and whose
/// serving paths are never read by the recovery commands (the same shape as
/// `recovery_workflow.rs`'s `write_cli_config`).
fn write_relay_config(
    relay: &TestDirectory,
    fixture: &Fixture,
    redis_url: &str,
    redis_root_ca: &Path,
) -> PathBuf {
    let unused = |name: &str| toml_path(&relay.path(name));
    let text = format!(
        "oidc_issuer = \"https://issuer.authority-recovery.invalid\"\n\
         oidc_audience = [\"authority-recovery-test\"]\n\
         oidc_jwks_path = {}\n\
         redis_url = {}\n\
         redis_tls_root_ca_path = {}\n\
         redis_namespace = {}\n\
         device_tls_cert_chain = {}\n\
         device_tls_private_key = {}\n\
         device_tls_client_ca = {}\n\
         consumer_tls_cert_chain = {}\n\
         consumer_tls_private_key = {}\n\
         node_id = \"authority-recovery-node\"\n\
         deployment_incarnation = {}\n\n\
         [cluster]\n\
         deployment_id = {}\n\
         peer_bind = \"127.0.0.1:1\"\n\
         peer_tls_cert_chain = {}\n\
         peer_tls_private_key = {}\n\
         peer_tls_client_ca = {}\n\
         membership_signer_trust_path = {}\n\
         checkpoint_authority_endpoint = \"https://checkpoint.authority-recovery.invalid\"\n\
         checkpoint_authority_trust_path = {}\n\
         membership_version_state_path = {}\n\n\
         [recovery]\n\
         fence_path = {}\n\
         trusted_keys_path = {}\n\
         deployment_incarnation = {}\n",
        unused("jwks.json"),
        toml_string(redis_url),
        toml_path(redis_root_ca),
        toml_string(&fixture.namespace),
        unused("device-cert.pem"),
        unused("device-key.pem"),
        unused("device-ca.pem"),
        unused("consumer-cert.pem"),
        unused("consumer-key.pem"),
        toml_string(INITIAL_INCARNATION),
        toml_string(DEPLOYMENT_ID),
        unused("peer-cert.pem"),
        unused("peer-key.pem"),
        unused("peer-ca.pem"),
        unused("membership-trust.json"),
        unused("checkpoint-ca.pem"),
        unused("membership-state.json"),
        toml_path(&relay.path("recovery-fence.json")),
        toml_path(&relay.path("trusted-keys.json")),
        toml_string(CANDIDATE_INCARNATION),
    );
    let path = relay.path("relay.toml");
    fs::write(&path, text).expect("write relay configuration");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("config mode");
    path
}

fn tunnel_relay() -> PathBuf {
    let relay = Path::new(env!("CARGO_BIN_EXE_tunnel-authority")).with_file_name("tunnel-relay");
    assert!(
        relay.is_file(),
        "tunnel-relay is not built beside tunnel-authority at {}; run \
         `cargo build -p tunnel-relay --bin tunnel-relay --locked` first",
        relay.display()
    );
    relay
}

/// Run a binary with a bounded deadline, off the async runtime's threads.
async fn run(program: PathBuf, args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(&program)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().expect("poll").is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("{} exceeded its test deadline", program.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().expect("join")
    })
    .await
    .expect("join blocking runner")
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

async fn relay_cli(args: &[&str]) -> Output {
    run(tunnel_relay(), strings(args)).await
}

async fn authority_cli(args: &[&str]) -> Output {
    run(
        PathBuf::from(env!("CARGO_BIN_EXE_tunnel-authority")),
        strings(args),
    )
    .await
}

fn success_json(what: &str, output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{what} failed ({:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|_| panic!("{what} printed {stdout}"))
}

fn arg(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

/// Observe the candidate with the relay and save the result for the authority.
async fn observe(config: &Path, into: &Path) -> Value {
    let output = relay_cli(&["recovery-observe", "--config", arg(config)]).await;
    let observation = success_json("recovery-observe", &output);
    fs::write(into, &output.stdout).expect("save observation");
    observation
}

/// Sign on the authority side and move the approval into the relay's `0700`
/// recovery directory, as an operator would carry it.
async fn sign(key: &Path, observation: &Path, version: u64, out: &Path) -> String {
    let version = version.to_string();
    let output = authority_cli(&[
        "sign-recovery-approval",
        "--key",
        arg(key),
        "--key-id",
        KEY_ID,
        "--observation",
        arg(observation),
        "--deployment-id",
        DEPLOYMENT_ID,
        "--deployment-incarnation",
        CANDIDATE_INCARNATION,
        "--approval-version",
        &version,
        "--out",
        arg(out),
    ])
    .await;
    let signed = success_json("sign-recovery-approval", &output);
    signed["result"]["nonce"]
        .as_str()
        .expect("printed nonce")
        .to_owned()
}

async fn recover(config: &Path, approval: &Path, nonce: &str) -> Output {
    relay_cli(&[
        "recover",
        "--config",
        arg(config),
        "--approval",
        arg(approval),
        "--expected-nonce",
        nonce,
        "--acknowledgement-id",
        ACKNOWLEDGEMENT,
        "--old-primary-fenced",
        "--old-relays-fenced",
    ])
    .await
}

fn assert_recover_refused(output: &Output, message: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "recover must refuse: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "expected {message:?} in {stderr}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture and a built tunnel-relay"]
async fn relay_recover_accepts_an_authority_approval_and_refuses_wrong_key_and_stale_digest() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("TUNNEL_CATALOG_REDIS_URL");
    let _ = tunnel_relay();
    let fixture = seed(&upstream_url).await;
    // Two hosts' worth of state: the relay's recovery directory and the
    // authority's key directory.
    let relay = TestDirectory::new("m6-c22-relay");
    let authority = TestDirectory::new("m6-c22-authority");
    let forwarder =
        recovery_redis::RedisTlsForwarder::start(&upstream_url, relay.path("redis-ca.pem")).await;
    let config = write_relay_config(&relay, &fixture, &forwarder.url, &forwarder.root_ca);

    // The authority generates its key; the trusted-key document goes to the
    // relay's `[recovery] trusted_keys_path`.
    let key = authority.path("recovery.pk8");
    success_json(
        "generate-recovery-key",
        &authority_cli(&[
            "generate-recovery-key",
            "--key-id",
            KEY_ID,
            "--key-out",
            arg(&key),
            "--trusted-keys-out",
            arg(&relay.path("trusted-keys.json")),
        ])
        .await,
    );
    // A second key under the same key id, which no relay trusts.
    let wrong = TestDirectory::new("m6-c22-wrong-authority");
    let wrong_key = wrong.path("recovery.pk8");
    success_json(
        "generate-recovery-key (untrusted)",
        &authority_cli(&[
            "generate-recovery-key",
            "--key-id",
            KEY_ID,
            "--key-out",
            arg(&wrong_key),
            "--trusted-keys-out",
            arg(&wrong.path("trusted-keys.json")),
        ])
        .await,
    );

    let initialized = relay_cli(&["recovery-initialize", "--config", arg(&config)]).await;
    assert!(
        initialized.status.success(),
        "recovery-initialize: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    // 1. Wrong key: the relay's trusted-key document does not hold it.
    let observation = authority.path("observation-1.json");
    observe(&config, &observation).await;
    let approval = relay.path("approval-wrong-key.json");
    let nonce = sign(&wrong_key, &observation, 1, &approval).await;
    assert_recover_refused(
        &recover(&config, &approval, &nonce).await,
        "recovery approval was rejected",
    );
    assert!(active_is(&fixture, INITIAL_INCARNATION).await);

    // 2. Stale digest: the durable catalog moves after the observation the
    // authority signed (a revocation, here).
    let approval = relay.path("approval-stale.json");
    let nonce = sign(&key, &observation, 1, &approval).await;
    RedisCatalog::connect_with_deployment_incarnation(
        &fixture.upstream_url,
        &fixture.namespace,
        INITIAL_INCARNATION,
    )
    .await
    .expect("connect the active catalog")
    .revoke_device(fixture.tenant, fixture.device, Utc::now())
    .await
    .expect("move the durable catalog");
    assert_recover_refused(
        &recover(&config, &approval, &nonce).await,
        "recovery approval does not match the live catalog observation",
    );
    assert!(active_is(&fixture, INITIAL_INCARNATION).await);

    // 3. The real path: a fresh observation, signed by the trusted key. The
    // two refusals consumed no version (both precede the fence write), so
    // version 1 is still free.
    let observation = authority.path("observation-2.json");
    let observed = observe(&config, &observation).await;
    let approval = relay.path("approval.json");
    let nonce = sign(&key, &observation, 1, &approval).await;
    let recovered = success_json("recover", &recover(&config, &approval, &nonce).await);
    assert_eq!(recovered["approval_version"], 1);
    assert_eq!(recovered["deployment_incarnation"], CANDIDATE_INCARNATION);
    assert_eq!(recovered["catalog_digest"], observed["catalog_digest"]);
    assert_eq!(recovered["quiescence_declared"], true);
    assert!(active_is(&fixture, CANDIDATE_INCARNATION).await);
    assert!(!active_is(&fixture, INITIAL_INCARNATION).await);

    // 4. The consumed approval is not accepted twice.
    assert_recover_refused(
        &recover(&config, &approval, &nonce).await,
        "recovery approval was rejected",
    );

    // 5. The fence itself: a *fresh* approval (new observation, new nonce)
    // at the consumed version is refused, and the same observation signed one
    // version higher is accepted -- the version was the only difference.
    // (Re-activating the already-active candidate commits again.)
    let observation = authority.path("observation-3.json");
    observe(&config, &observation).await;
    let approval = relay.path("approval-fence.json");
    let nonce = sign(&key, &observation, 1, &approval).await;
    assert_recover_refused(
        &recover(&config, &approval, &nonce).await,
        "recovery approval was rejected",
    );
    let approval = relay.path("approval-above-fence.json");
    let nonce = sign(&key, &observation, 2, &approval).await;
    let above = success_json(
        "recover above the fence",
        &recover(&config, &approval, &nonce).await,
    );
    assert_eq!(above["approval_version"], 2);

    cleanup(&fixture).await;
    forwarder.shutdown().await;
}
