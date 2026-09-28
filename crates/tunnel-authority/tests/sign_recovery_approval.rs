//! `tunnel-authority` run as a process, without Redis (task row M6-C22).
//!
//! Each test drives the real binary. The approval it writes is checked with
//! the library verifier `tunnel-relay recover` uses, against the trusted-key
//! document the binary itself wrote, so the file format, the key format and
//! the trusted-key format are all the shipped ones. The Redis-backed test in
//! `recover_accepts_authority_approval.rs` then proves the relay's `recover`
//! accepts it.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use chrono::Utc;
use serde_json::Value;
use tunnel_catalog::{
    RecoveryApprovalIssuer, RecoveryApprovalVerifier, RecoveryError, RecoveryPolicy,
    TrustedRecoveryKey,
};

const DEPLOYMENT: &str = "authority-test-deployment";
const NAMESPACE: &str = "authority-test-namespace";
const RUN_ID: &str = "0123456789abcdef0123456789abcdef01234567";
const INCARNATION: &str = "authority-test-incarnation-2";
const DIGEST: &str = "5f3c2d8b6e1a4f7c9b0d2e4f6a8c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c";
const KEY_ID: &str = "authority-test-operator";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tunnel-authority-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).expect("create scratch directory");
        let path = fs::canonicalize(path).expect("canonicalize scratch directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("scratch mode");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// A `0700` subdirectory.
    fn private_dir(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        fs::create_dir(&path).expect("create private directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private mode");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tunnel-authority"))
        .args(args)
        .output()
        .expect("run tunnel-authority")
}

fn arg(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

fn json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().count(),
        1,
        "one JSON object on stdout: {stdout}"
    );
    serde_json::from_str(stdout.trim()).expect("stdout is JSON")
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o7777
}

fn observation_text(deployment: &str, incarnation: &str, digest: &str) -> String {
    serde_json::json!({
        "schema_version": 1,
        "deployment_id": deployment,
        "redis_namespace": NAMESPACE,
        "deployment_incarnation": incarnation,
        "redis_run_id": RUN_ID,
        "catalog_digest": digest,
        "catalog_generation": "42",
        "key_count": 17,
        "byte_count": 4096,
        "quiescence": "unproven",
    })
    .to_string()
}

struct Keys {
    key: PathBuf,
    trusted: PathBuf,
}

fn generate(scratch: &Scratch, directory: &str, key_id: &str) -> Keys {
    let keys = scratch.private_dir(directory);
    let key = keys.join("recovery.pk8");
    let trusted = keys.join("trusted-keys.json");
    let output = authority(&[
        "generate-recovery-key",
        "--key-id",
        key_id,
        "--key-out",
        arg(&key),
        "--trusted-keys-out",
        arg(&trusted),
    ]);
    assert!(
        output.status.success(),
        "generate-recovery-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = json(&output);
    assert_eq!(result["ok"], true);
    assert_eq!(result["result"]["key_id"], key_id);
    Keys { key, trusted }
}

fn write_observation(scratch: &Scratch, name: &str, text: &str) -> PathBuf {
    let path = scratch.path(name);
    fs::write(&path, text).expect("write observation");
    path
}

fn sign(key: &Path, key_id: &str, observation: &Path, out: &Path, version: &str) -> Output {
    authority(&[
        "sign-recovery-approval",
        "--key",
        arg(key),
        "--key-id",
        key_id,
        "--observation",
        arg(observation),
        "--deployment-id",
        DEPLOYMENT,
        "--deployment-incarnation",
        INCARNATION,
        "--approval-version",
        version,
        "--out",
        arg(out),
    ])
}

/// The trusted keys a relay would load from the document the binary wrote.
fn trusted_keys(path: &Path) -> Vec<TrustedRecoveryKey> {
    let document: Value =
        serde_json::from_slice(&fs::read(path).expect("read trusted keys")).expect("JSON");
    assert_eq!(document["schema_version"], 1);
    document["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|entry| {
            let hex = entry["public_key"].as_str().expect("public_key");
            assert_eq!(hex.len(), 64, "the public key is 64 hex digits");
            let mut key = [0_u8; 32];
            for (index, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
            }
            TrustedRecoveryKey::new(entry["key_id"].as_str().expect("key_id"), key)
                .expect("trusted key")
        })
        .collect()
}

fn verify(
    trusted: Vec<TrustedRecoveryKey>,
    approval: &Path,
    nonce: &str,
) -> Result<tunnel_catalog::VerifiedRecoveryApproval, RecoveryError> {
    let policy = RecoveryPolicy::new(DEPLOYMENT, NAMESPACE, RUN_ID, INCARNATION).expect("policy");
    RecoveryApprovalVerifier::new(policy, trusted)
        .expect("verifier")
        .verify(
            &fs::read(approval).expect("read approval"),
            nonce,
            Utc::now(),
            None,
        )
}

fn assert_refused(output: &Output, status: i32, code: &str) {
    assert_eq!(
        output.status.code(),
        Some(status),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = json(output);
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], code, "{result}");
    assert_eq!(result["error"]["retryable"], false);
}

#[test]
fn a_signed_approval_verifies_against_the_generated_trusted_key_document() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    assert_eq!(mode(&keys.key), 0o600, "the private key is 0600");
    assert_eq!(
        mode(&keys.trusted),
        0o600,
        "the trusted-key document is 0600"
    );
    // The key is the PKCS#8 v2 DER the library signer loads.
    RecoveryApprovalIssuer::from_pkcs8(KEY_ID, &fs::read(&keys.key).expect("key"))
        .expect("PKCS#8 v2 Ed25519");

    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.private_dir("out").join("approval.json");
    let output = sign(&keys.key, KEY_ID, &observation, &out, "7");
    assert!(
        output.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "a success writes nothing to stderr"
    );
    let result = json(&output);
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "sign-recovery-approval");
    assert_eq!(result["ok"], true);
    let summary = &result["result"];
    let nonce = summary["nonce"].as_str().expect("nonce").to_owned();
    assert_eq!(nonce.len(), 32, "a 128-bit hex nonce");

    assert_eq!(
        mode(&out),
        0o600,
        "the approval is written 0600, as recover requires"
    );
    let verified =
        verify(trusted_keys(&keys.trusted), &out, &nonce).expect("the approval verifies");
    assert_eq!(verified.approval_version(), 7);
    assert_eq!(verified.catalog_digest(), DIGEST);
    assert_eq!(verified.publisher_key_id(), KEY_ID);
    assert_eq!(summary["approval_version"], 7);
    assert_eq!(summary["catalog_digest"], DIGEST);
    assert_eq!(summary["redis_run_id"], RUN_ID);
    assert_eq!(summary["deployment_incarnation"], INCARNATION);
    let issued_at =
        chrono::DateTime::parse_from_rfc3339(summary["issued_at"].as_str().expect("issued_at"))
            .expect("RFC 3339");
    assert_eq!(
        (verified.expires_at() - issued_at.with_timezone(&Utc)).num_seconds(),
        60,
        "the default lifetime is the 60 s maximum"
    );
    assert_eq!(
        (verified.expires_at() - verified.not_before()).num_seconds(),
        65,
        "the window opens one 5 s skew bound before signing"
    );

    // Redacted: no signature, no key bytes, no path.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let approval: Value = serde_json::from_slice(&fs::read(&out).expect("approval")).expect("JSON");
    let signature = approval["signature"].as_str().expect("signature");
    assert!(!stdout.contains(signature), "stdout carries no signature");
    assert!(
        !stdout.contains(scratch.0.to_str().expect("path")),
        "stdout carries no path"
    );

    // A different nonce is refused by the verifier: the nonce is bound.
    assert_eq!(
        verify(
            trusted_keys(&keys.trusted),
            &out,
            "another-nonce-0000000000"
        )
        .expect_err("nonce"),
        RecoveryError::NonceMismatch
    );
}

#[test]
fn an_approval_from_another_key_is_refused_by_the_trusted_key_document() {
    let scratch = Scratch::new();
    let trusted = generate(&scratch, "trusted", KEY_ID);
    // Same key id, different key: the "wrong key" an operator could pick up.
    let other = generate(&scratch, "other", KEY_ID);
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.private_dir("out").join("approval.json");
    let output = sign(&other.key, KEY_ID, &observation, &out, "1");
    assert!(output.status.success(), "the authority itself cannot tell");
    let nonce = json(&output)["result"]["nonce"]
        .as_str()
        .expect("nonce")
        .to_owned();
    assert_eq!(
        verify(trusted_keys(&trusted.trusted), &out, &nonce).expect_err("wrong key"),
        RecoveryError::SignatureInvalid
    );
}

#[test]
fn a_private_key_with_a_wider_mode_is_refused_and_nothing_is_written() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.private_dir("out").join("approval.json");
    for wider in [0o640, 0o644, 0o604, 0o400, 0o700] {
        fs::set_permissions(&keys.key, fs::Permissions::from_mode(wider)).expect("chmod key");
        let output = sign(&keys.key, KEY_ID, &observation, &out, "1");
        assert_refused(&output, 3, "CREDENTIAL_PERMISSIONS");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("must be 0600"),
            "mode {wider:o}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!out.exists(), "mode {wider:o}: nothing is written");
    }
}

#[test]
fn a_private_key_directory_open_to_others_is_refused() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.private_dir("out").join("approval.json");
    let directory = keys.key.parent().expect("key directory").to_owned();
    for wider in [0o750, 0o755, 0o711] {
        fs::set_permissions(&directory, fs::Permissions::from_mode(wider)).expect("chmod dir");
        let output = sign(&keys.key, KEY_ID, &observation, &out, "1");
        assert_refused(&output, 3, "CREDENTIAL_PERMISSIONS");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("must be 0700"),
            "mode {wider:o}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!out.exists());
    }
    // generate-recovery-key refuses the same directory.
    let output = authority(&[
        "generate-recovery-key",
        "--key-id",
        KEY_ID,
        "--key-out",
        arg(&directory.join("second.pk8")),
        "--trusted-keys-out",
        arg(&scratch.path("second-trusted.json")),
    ]);
    assert_refused(&output, 3, "CREDENTIAL_PERMISSIONS");
    assert!(!directory.join("second.pk8").exists());
}

#[test]
fn a_symbolic_link_to_the_private_key_is_refused() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    let link = keys.key.with_file_name("link.pk8");
    symlink(&keys.key, &link).expect("symlink");
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.private_dir("out").join("approval.json");
    assert_refused(
        &sign(&link, KEY_ID, &observation, &out, "1"),
        3,
        "CREDENTIAL_PERMISSIONS",
    );
    assert!(!out.exists());
}

#[test]
fn a_key_file_that_is_not_a_pkcs8_ed25519_key_is_refused() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    fs::write(&keys.key, b"not a PKCS#8 key").expect("overwrite test key");
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.private_dir("out").join("approval.json");
    assert_refused(
        &sign(&keys.key, KEY_ID, &observation, &out, "1"),
        3,
        "CREDENTIAL_ERROR",
    );
    assert!(!out.exists());
}

#[test]
fn an_existing_output_is_never_overwritten() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out_dir = scratch.private_dir("out");
    let out = out_dir.join("approval.json");
    fs::write(&out, b"an earlier approval").expect("existing output");
    assert_refused(
        &sign(&keys.key, KEY_ID, &observation, &out, "1"),
        2,
        "OUTPUT_EXISTS",
    );
    assert_eq!(fs::read(&out).expect("read"), b"an earlier approval");

    // A dangling symbolic link is an existing path too: nothing is created
    // at its target.
    let dangling = out_dir.join("dangling.json");
    let target = out_dir.join("target.json");
    symlink(&target, &dangling).expect("symlink");
    assert_refused(
        &sign(&keys.key, KEY_ID, &observation, &dangling, "1"),
        2,
        "OUTPUT_EXISTS",
    );
    assert!(!target.exists(), "no file is created through the link");

    // generate-recovery-key refuses an existing key or trusted-key path, and
    // writes neither file.
    let existing_key = generate(&scratch, "again", KEY_ID);
    let fresh_trusted = scratch.path("fresh-trusted.json");
    let output = authority(&[
        "generate-recovery-key",
        "--key-id",
        KEY_ID,
        "--key-out",
        arg(&existing_key.key),
        "--trusted-keys-out",
        arg(&fresh_trusted),
    ]);
    assert_refused(&output, 2, "OUTPUT_EXISTS");
    assert!(!fresh_trusted.exists());
    let fresh_key = existing_key.key.with_file_name("fresh.pk8");
    let output = authority(&[
        "generate-recovery-key",
        "--key-id",
        KEY_ID,
        "--key-out",
        arg(&fresh_key),
        "--trusted-keys-out",
        arg(&existing_key.trusted),
    ]);
    assert_refused(&output, 2, "OUTPUT_EXISTS");
    assert!(!fresh_key.exists());
}

#[test]
fn an_observation_that_disagrees_with_the_operator_is_refused() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    let out = scratch.private_dir("out").join("approval.json");
    for (name, text, fragment) in [
        (
            "other-deployment.json",
            observation_text("another-deployment", INCARNATION, DIGEST),
            "deployment_id",
        ),
        (
            "other-incarnation.json",
            observation_text(DEPLOYMENT, "another-incarnation", DIGEST),
            "deployment_incarnation",
        ),
        (
            "bad-digest.json",
            observation_text(DEPLOYMENT, INCARNATION, &DIGEST.to_uppercase()),
            "does not verify",
        ),
        (
            "extra-field.json",
            observation_text(DEPLOYMENT, INCARNATION, DIGEST).replace('}', ",\"extra\":1}"),
            "recovery-observe",
        ),
        (
            "proven.json",
            observation_text(DEPLOYMENT, INCARNATION, DIGEST).replace("unproven", "proven"),
            "quiescence",
        ),
    ] {
        let observation = write_observation(&scratch, name, &text);
        let output = sign(&keys.key, KEY_ID, &observation, &out, "1");
        assert_refused(&output, 2, "INVALID_OBSERVATION");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(fragment),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!out.exists(), "{name}: nothing is written");
    }
}

#[test]
fn invalid_invocations_exit_two() {
    let scratch = Scratch::new();
    let keys = generate(&scratch, "keys", KEY_ID);
    let observation = write_observation(
        &scratch,
        "observation.json",
        &observation_text(DEPLOYMENT, INCARNATION, DIGEST),
    );
    let out = scratch.path("approval.json");
    for version in ["0", "-1", "one"] {
        assert_refused(
            &sign(&keys.key, KEY_ID, &observation, &out, version),
            2,
            "INVALID_INVOCATION",
        );
    }
    assert_refused(
        &authority(&["sign-recovery-approval"]),
        2,
        "INVALID_INVOCATION",
    );
    assert_refused(&authority(&["no-such-command"]), 2, "INVALID_INVOCATION");
    let output = authority(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage: tunnel-authority"));
    assert!(!out.exists());
}

#[test]
fn help_and_version_answer_without_touching_anything() {
    for args in [
        vec!["--help"],
        vec!["sign-recovery-approval", "--help"],
        vec!["generate-recovery-key", "--help"],
    ] {
        let output = authority(&args);
        assert!(output.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Usage: tunnel-authority"),
            "{args:?}"
        );
    }
    let output = authority(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("tunnel-authority {}", env!("CARGO_PKG_VERSION"))
    );
}
