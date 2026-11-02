#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::{Duration, Utc};
use serde_json::{Value, json};
use tunnel_catalog::recovery::{
    MAX_RECOVERY_RECORD_BYTES, RecoveryApproval, RecoveryApprovalIssuer, RecoveryApprovalVerifier,
    RecoveryPolicy, SignedRecoveryApproval,
};
use tunnel_relay::recovery::{
    QuiescenceStatus, RECOVERY_FENCE_SCHEMA_VERSION, RecoveryObservation,
    load_trusted_recovery_keys,
};

const KEY_ID: &str = "authority-test-key";
const NONCE: &str = "independent-test-nonce-123456";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn empty() -> Self {
        let directory = tempfile::tempdir().unwrap();
        // /tmp and /var can be symlinks on Darwin. The tool deliberately does
        // not follow ancestor symlinks; give it the real private directory.
        let root = directory.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _directory: directory,
            root,
        }
    }

    fn new() -> Self {
        let fixture = Self::empty();
        success(&fixture.generate("key.der", "public.json"));
        fixture.write("approval.json", &serde_json::to_vec(&approval()).unwrap());
        fixture.write(
            "observation.json",
            &serde_json::to_vec(&observation()).unwrap(),
        );
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.path(name), bytes).unwrap();
        fs::set_permissions(self.path(name), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn generate(&self, key: &str, public: &str) -> Output {
        command()
            .args(["generate-key", "--key-id", KEY_ID, "--private-key"])
            .arg(self.path(key))
            .arg("--public-keys")
            .arg(self.path(public))
            .output()
            .unwrap()
    }

    fn sign(&self, output: &str) -> Output {
        self.sign_command(output).output().unwrap()
    }

    fn sign_command(&self, output: &str) -> Command {
        let mut command = command();
        command
            .arg("sign-recovery-approval")
            .arg("--key")
            .arg(self.path("key.der"))
            .args(["--key-id", KEY_ID, "--observation"])
            .arg(self.path("observation.json"))
            .arg("--approval")
            .arg(self.path("approval.json"))
            .args(["--expected-nonce", NONCE, "--output"])
            .arg(self.path(output));
        command
    }

    fn verifier(&self, deployment: &str) -> RecoveryApprovalVerifier {
        let trust: Value =
            serde_json::from_slice(&fs::read(self.path("public.json")).unwrap()).unwrap();
        assert_eq!(trust["schema_version"], 1);
        assert_eq!(trust["keys"][0]["key_id"], KEY_ID);
        // Exercise the actual relay trust-file boundary, not a test-only
        // decoder that could drift together with the authority's encoder.
        let trusted = load_trusted_recovery_keys(&self.path("public.json")).unwrap();
        RecoveryApprovalVerifier::new(
            RecoveryPolicy::new(
                deployment,
                "catalog-test",
                "redis-run-test",
                "incarnation-test",
            )
            .unwrap(),
            trusted,
        )
        .unwrap()
    }
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tunnel-authority"))
}

fn approval() -> RecoveryApproval {
    let now = Utc::now();
    RecoveryApproval {
        schema_version: 1,
        deployment_id: "deployment-test".into(),
        redis_namespace: "catalog-test".into(),
        redis_run_id: "redis-run-test".into(),
        deployment_incarnation: "incarnation-test".into(),
        approval_version: 7,
        nonce: NONCE.into(),
        catalog_digest: "a".repeat(64),
        issued_at: now,
        not_before: now,
        expires_at: now + Duration::seconds(60),
    }
}

fn observation() -> Value {
    // Serialize the production observation type to make a schema change in
    // the relay fail these process tests until the authority accepts it.
    serde_json::to_value(RecoveryObservation {
        schema_version: RECOVERY_FENCE_SCHEMA_VERSION,
        deployment_id: "deployment-test".into(),
        redis_namespace: "catalog-test".into(),
        deployment_incarnation: "incarnation-test".into(),
        redis_run_id: "redis-run-test".into(),
        catalog_digest: "a".repeat(64),
        catalog_generation: "42".into(),
        key_count: 9,
        byte_count: 1024,
        quiescence: QuiescenceStatus::Unproven,
    })
    .unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
}

fn failure(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("tunnel-authority: "));
    assert!(output.stderr.len() < 256);
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn generated_key_and_exact_emitted_approval_work_with_the_existing_verifier() {
    let fixture = Fixture::new();
    let output = fixture.sign("signed.json");
    success(&output);
    let bytes = fs::read(fixture.path("signed.json")).unwrap();
    assert!(!bytes.ends_with(b"\n"));
    let signed: SignedRecoveryApproval = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(signed.encode().unwrap(), bytes);
    assert_eq!(mode(&fixture.path("key.der")), 0o600);
    assert_eq!(mode(&fixture.path("public.json")), 0o600);
    assert_eq!(mode(&fixture.path("signed.json")), 0o600);

    let key_bytes = fs::read(fixture.path("key.der")).unwrap();
    RecoveryApprovalIssuer::from_pkcs8(KEY_ID, &key_bytes).expect("strict PKCS#8 v2 parser");
    let verifier = fixture.verifier("deployment-test");
    let verified = verifier.verify(&bytes, NONCE, Utc::now(), Some(6)).unwrap();
    assert_eq!(verified.approval(), &signed.approval());
    assert_eq!(verified.signed_bytes(), bytes);
    assert!(
        !output
            .stdout
            .windows(16)
            .any(|part| part == &key_bytes[..16])
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&signed.signature));

    assert!(verifier.verify(&bytes, NONCE, Utc::now(), Some(7)).is_err());
    assert!(verifier.verify(&bytes, NONCE, Utc::now(), Some(8)).is_err());
    assert!(
        fixture
            .verifier("another-deployment")
            .verify(&bytes, NONCE, Utc::now(), None)
            .is_err()
    );
    assert!(
        verifier
            .verify(&bytes, "different-valid-nonce", Utc::now(), None)
            .is_err()
    );
    let mut with_newline = bytes;
    with_newline.push(b'\n');
    assert!(
        verifier
            .verify(&with_newline, NONCE, Utc::now(), None)
            .is_err()
    );
    let mut tampered = signed;
    tampered.catalog_digest = "b".repeat(64);
    assert!(
        verifier
            .verify(&tampered.encode().unwrap(), NONCE, Utc::now(), None)
            .is_err()
    );
}

#[test]
fn command_rejects_every_approval_scope_or_nonce_mismatch_before_creating_output() {
    let fixture = Fixture::new();
    for field in [
        "deployment_id",
        "redis_namespace",
        "redis_run_id",
        "deployment_incarnation",
        "catalog_digest",
        "nonce",
    ] {
        let mut document = serde_json::to_value(approval()).unwrap();
        document[field] = if field == "catalog_digest" {
            json!("b".repeat(64))
        } else {
            json!("different-operator-value")
        };
        fixture.write("approval.json", &serde_json::to_vec(&document).unwrap());
        failure(&fixture.sign("signed.json"));
        assert!(!fixture.path("signed.json").exists(), "{field}");
    }
}

#[test]
fn malformed_expired_future_or_excess_lifetime_approvals_are_not_signed() {
    let fixture = Fixture::new();
    let now = Utc::now();
    let mut expired = approval();
    expired.issued_at = now - Duration::seconds(120);
    expired.not_before = expired.issued_at;
    expired.expires_at = now - Duration::seconds(60);
    let mut future = approval();
    future.issued_at = now + Duration::seconds(20);
    future.not_before = future.issued_at;
    future.expires_at = future.issued_at + Duration::seconds(60);
    let mut long = approval();
    long.expires_at = long.issued_at + Duration::seconds(61);
    let mut zero_version = approval();
    zero_version.approval_version = 0;
    let mut wrong_schema = approval();
    wrong_schema.schema_version = 2;
    for rejected in [expired, future, long, zero_version, wrong_schema] {
        fixture.write("approval.json", &serde_json::to_vec(&rejected).unwrap());
        failure(&fixture.sign("signed.json"));
        assert!(!fixture.path("signed.json").exists());
    }
    for malformed in [
        b"not-json".as_slice(),
        b"{}",
        b"{\"nonce\":\"x\",\"nonce\":\"y\"}",
    ] {
        fixture.write("approval.json", malformed);
        failure(&fixture.sign("signed.json"));
        assert!(!fixture.path("signed.json").exists());
    }
    let mut unknown = serde_json::to_value(approval()).unwrap();
    unknown["unexpected"] = json!("must not be silently ignored");
    fixture.write("approval.json", &serde_json::to_vec(&unknown).unwrap());
    failure(&fixture.sign("signed.json"));
    fixture.write("approval.json", &vec![b' '; MAX_RECOVERY_RECORD_BYTES + 1]);
    failure(&fixture.sign("signed.json"));
    assert!(!fixture.path("signed.json").exists());
}

#[test]
fn observation_schema_and_quiescence_cannot_be_promoted_to_fencing_proof() {
    let fixture = Fixture::new();
    for (field, value) in [
        ("schema_version", json!(2)),
        ("quiescence", json!("proven")),
        ("unexpected", json!("ignored")),
    ] {
        let mut observed = observation();
        observed[field] = value;
        fixture.write("observation.json", &serde_json::to_vec(&observed).unwrap());
        failure(&fixture.sign("signed.json"));
        assert!(!fixture.path("signed.json").exists());
    }
}

#[test]
fn insecure_keys_inputs_and_parents_are_refused() {
    let fixture = Fixture::new();
    for name in ["key.der", "approval.json", "observation.json"] {
        fs::set_permissions(fixture.path(name), fs::Permissions::from_mode(0o644)).unwrap();
        failure(&fixture.sign("signed.json"));
        assert!(!fixture.path("signed.json").exists());
        fs::set_permissions(fixture.path(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
    failure(&fixture.sign("signed.json"));
    failure(&fixture.generate("other-key.der", "other-public.json"));
    assert!(!fixture.path("signed.json").exists());
    assert!(!fixture.path("other-key.der").exists());
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn symlink_and_hard_link_keys_and_symlink_ancestors_are_refused() {
    let fixture = Fixture::new();
    fs::rename(fixture.path("key.der"), fixture.path("real-key.der")).unwrap();
    symlink(fixture.path("real-key.der"), fixture.path("key.der")).unwrap();
    failure(&fixture.sign("signed.json"));
    fs::remove_file(fixture.path("key.der")).unwrap();
    fs::hard_link(fixture.path("real-key.der"), fixture.path("key.der")).unwrap();
    failure(&fixture.sign("signed.json"));
    fs::remove_file(fixture.path("key.der")).unwrap();
    fs::rename(fixture.path("real-key.der"), fixture.path("key.der")).unwrap();
    symlink(&fixture.root, fixture.path("linked-directory")).unwrap();
    failure(&fixture.generate("linked-directory/new-key.der", "new-public.json"));
    assert!(!fixture.path("new-key.der").exists());
    assert!(!fixture.path("new-public.json").exists());
    assert!(!fixture.path("signed.json").exists());
}

#[test]
fn malformed_oversized_or_nonregular_keys_are_refused() {
    let fixture = Fixture::new();
    for invalid in [b"not-a-private-key".to_vec(), vec![0; 4097]] {
        fixture.write("key.der", &invalid);
        failure(&fixture.sign("signed.json"));
        assert!(!fixture.path("signed.json").exists());
    }
    fs::remove_file(fixture.path("key.der")).unwrap();
    fs::create_dir(fixture.path("key.der")).unwrap();
    failure(&fixture.sign("signed.json"));
    assert!(!fixture.path("signed.json").exists());
}

#[test]
fn signing_never_overwrites_an_existing_file_or_symlink() {
    let fixture = Fixture::new();
    fixture.write("signed.json", b"existing approval");
    failure(&fixture.sign("signed.json"));
    assert_eq!(
        fs::read(fixture.path("signed.json")).unwrap(),
        b"existing approval"
    );
    symlink(fixture.path("signed.json"), fixture.path("linked.json")).unwrap();
    failure(&fixture.sign("linked.json"));
    assert_eq!(
        fs::read(fixture.path("signed.json")).unwrap(),
        b"existing approval"
    );
}

#[test]
fn generation_never_replaces_a_key_or_trust_file_and_cleans_reserved_paths() {
    let fixture = Fixture::new();
    let old_key = fs::read(fixture.path("key.der")).unwrap();
    let old_public = fs::read(fixture.path("public.json")).unwrap();
    failure(&fixture.generate("key.der", "new-public.json"));
    failure(&fixture.generate("new-key.der", "public.json"));
    failure(&fixture.generate("same-path", "same-path"));
    assert_eq!(fs::read(fixture.path("key.der")).unwrap(), old_key);
    assert_eq!(fs::read(fixture.path("public.json")).unwrap(), old_public);
    assert!(!fixture.path("new-key.der").exists());
    assert!(!fixture.path("new-public.json").exists());
    assert!(!fixture.path("same-path").exists());
}

#[test]
fn strict_cli_parsing_and_parent_traversal_fail_without_writing() {
    let fixture = Fixture::new();
    success(&command().arg("--help").output().unwrap());
    for args in [
        vec!["sign-recovery-approval"],
        vec!["generate-key", "--key-id", KEY_ID, "--key-id", KEY_ID],
        vec!["--help", "unexpected"],
        vec!["publish-membership"],
    ] {
        let output = command().args(args).output().unwrap();
        failure(&output);
        assert_eq!(output.status.code(), Some(2));
    }
    fs::create_dir(fixture.path("child")).unwrap();
    fs::set_permissions(fixture.path("child"), fs::Permissions::from_mode(0o700)).unwrap();
    failure(&fixture.sign("child/../outside-signed.json"));
    assert!(!fixture.path("outside-signed.json").exists());
}
