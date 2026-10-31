//! An offline operator tool. No Redis access, activation or local version fence.
mod private_files;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use chrono::Utc;
use serde::Deserialize;
use tunnel_catalog::recovery::{
    MAX_RECOVERY_RECORD_BYTES, RecoveryApproval, RecoveryApprovalIssuer, RecoveryApprovalVerifier,
    RecoveryPolicy, TrustedRecoveryKey,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const MAX_PRIVATE_KEY_BYTES: usize = 4096;

const HELP: &str = "tunnel-authority: offline recovery approval signing

Usage:
  tunnel-authority generate-key --key-id ID --private-key PATH --public-keys PATH
  tunnel-authority sign-recovery-approval --key PATH --key-id ID --observation PATH --approval PATH --expected-nonce NONCE --output PATH

generate-key creates a PKCS#8 v2 Ed25519 private key and a recovery trusted-keys
JSON document. Both output paths must be absent. Keep the private key on the
separate authority host; install only the public-keys file on relay hosts.

sign-recovery-approval reads an unsigned RecoveryApproval JSON document, the
reviewed recovery-observe JSON output and an independently supplied nonce.
It requires matching deployment, namespace, incarnation, Redis run and digest,
validates the current 60-second approval window and writes exact canonical
signed bytes, without a newline. Its output path must be absent. Transfer
those bytes without reformatting. An observation is not proof of reconciliation.

All input and output files require an owner-only (0700) parent directory;
input files must be owner-only (0600), regular files. Symlinks are refused.
Paths containing '..' are refused. These file protections require Unix.

Signing approves the operator's reviewed catalog digest. It does not inspect
Redis, reconcile revocations, prove quiescence, or activate a deployment.
Recover independently verifies the actual catalog, nonce and durable version
fence. Never reset that fence or reuse a consumed approval. Failed commands
must not be treated as successful; after a crash inspect incomplete outputs
and use fresh output paths. No private key or signed approval is printed.
";

enum Command {
    Help,
    Generate {
        key_id: String,
        private_key: OsString,
        public_keys: OsString,
    },
    Sign {
        key: OsString,
        key_id: String,
        observation: OsString,
        approval: OsString,
        expected_nonce: String,
        output: OsString,
    },
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut args = args.into_iter();
    let command = args.next().ok_or("a command is required; use --help")?;
    if command == "--help" || command == "-h" {
        return if args.next().is_none() {
            Ok(Command::Help)
        } else {
            Err("unexpected arguments after help")
        };
    }
    let allowed: &[&str] = if command == "generate-key" {
        &["--key-id", "--private-key", "--public-keys"]
    } else if command == "sign-recovery-approval" {
        &[
            "--key",
            "--key-id",
            "--observation",
            "--approval",
            "--expected-nonce",
            "--output",
        ]
    } else {
        return Err("unknown command; use --help");
    };
    let mut options = BTreeMap::new();
    while let Some(flag) = args.next() {
        let name = allowed
            .iter()
            .copied()
            .find(|name| flag == *name)
            .ok_or("unknown option; use --help")?;
        let value = args.next().ok_or("option requires a value")?;
        if value.is_empty() || options.insert(name, value).is_some() {
            return Err("empty or duplicate option");
        }
    }
    let mut take = |name| options.remove(name).ok_or("missing required option");
    if command == "generate-key" {
        Ok(Command::Generate {
            key_id: text(take("--key-id")?)?,
            private_key: take("--private-key")?,
            public_keys: take("--public-keys")?,
        })
    } else {
        Ok(Command::Sign {
            key: take("--key")?,
            key_id: text(take("--key-id")?)?,
            observation: take("--observation")?,
            approval: take("--approval")?,
            expected_nonce: text(take("--expected-nonce")?)?,
            output: take("--output")?,
        })
    }
}

fn text(value: OsString) -> Result<String> {
    value
        .into_string()
        .map_err(|_| "option requires UTF-8 text")
}

// Wire compatibility with tunnel-relay::recovery::RecoveryObservation. Keep
// the counters untrusted and quiescence explicitly unproven; the offline
// authority does not turn this read-only observation into a reconciliation or
// fencing claim. Real recover reads the catalog again before activation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema_version: u16,
    deployment_id: String,
    redis_namespace: String,
    deployment_incarnation: String,
    redis_run_id: String,
    catalog_digest: String,
    #[serde(rename = "catalog_generation")]
    _catalog_generation: String,
    #[serde(rename = "key_count")]
    _key_count: usize,
    #[serde(rename = "byte_count")]
    _byte_count: usize,
    #[serde(rename = "quiescence")]
    _quiescence: Unproven,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Unproven {
    Unproven,
}

fn generate_key(key_id: String, private_key: &Path, public_keys: &Path) -> Result<()> {
    let (issuer, bytes) = RecoveryApprovalIssuer::generate(&key_id)
        .map_err(|_| "key generation failed; check key identifier")?;
    let bytes = Zeroizing::new(bytes);
    let public_key = issuer.public_key().map_err(|_| "invalid issuer key")?;
    let public_key: String = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let trust = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "keys": [{ "key_id": key_id, "public_key": public_key }],
    }))
    .map_err(|_| "cannot encode public trust document")?;

    // Reserve both paths before writing either. Errors drop only files created
    // by this invocation; an existing key/trust document is never replaced.
    let mut private_output = private_files::NewFile::create(private_key)?;
    let mut public_output = private_files::NewFile::create(public_keys)?;
    public_output.write_and_sync(&trust)?;
    private_output.write_and_sync(&bytes)?;
    public_output.commit();
    private_output.commit();
    println!("Created private signing key and public recovery trust document.");
    Ok(())
}

fn sign_approval(
    key: &Path,
    key_id: String,
    observation_path: &Path,
    approval_path: &Path,
    expected_nonce: String,
    output: &Path,
) -> Result<()> {
    let input = private_files::read(approval_path, MAX_RECOVERY_RECORD_BYTES)?;
    let approval: RecoveryApproval =
        serde_json::from_slice(&input).map_err(|_| "malformed unsigned recovery approval")?;
    let observed = private_files::read(observation_path, MAX_RECOVERY_RECORD_BYTES)?;
    let observation: Observation =
        serde_json::from_slice(&observed).map_err(|_| "malformed recovery observation")?;
    if observation.schema_version != 1 {
        return Err("unsupported recovery observation schema");
    }
    if observation.catalog_digest != approval.catalog_digest {
        return Err("approval catalog digest does not match reviewed observation");
    }
    let policy = RecoveryPolicy::new(
        observation.deployment_id,
        observation.redis_namespace,
        observation.redis_run_id,
        observation.deployment_incarnation,
    )
    .map_err(|_| "invalid recovery approval scope")?;
    let key_bytes = Zeroizing::new(private_files::read(key, MAX_PRIVATE_KEY_BYTES)?);
    let issuer = RecoveryApprovalIssuer::from_pkcs8(&key_id, &key_bytes)
        .map_err(|_| "invalid key identifier or PKCS#8 v2 Ed25519 private key")?;
    let trusted = TrustedRecoveryKey::new(
        key_id,
        issuer.public_key().map_err(|_| "invalid issuer key")?,
    )
    .map_err(|_| "invalid issuer key")?;
    let verifier = RecoveryApprovalVerifier::new(policy, [trusted])
        .map_err(|_| "invalid recovery verification policy")?;
    let signed = issuer
        .sign_approval_bytes(approval)
        .map_err(|_| "cannot encode signed recovery approval")?;
    // The library signer intentionally performs no validation. The exact bytes
    // we emit must pass the same verifier used by recover. The offline signer
    // does not know the relay's persisted version anchor; recover checks it.
    verifier
        .verify(&signed, &expected_nonce, Utc::now(), None)
        .map_err(|_| "approval rejected by recovery policy (scope, nonce, shape or time window)")?;
    let mut file = private_files::NewFile::create(output)?;
    file.write_and_sync(&signed)?;
    file.commit();
    println!("Created canonical signed recovery approval.");
    Ok(())
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Help => {
            print!("{HELP}");
            Ok(())
        }
        Command::Generate {
            key_id,
            private_key,
            public_keys,
        } => generate_key(key_id, Path::new(&private_key), Path::new(&public_keys)),
        Command::Sign {
            key,
            key_id,
            observation,
            approval,
            expected_nonce,
            output,
        } => sign_approval(
            Path::new(&key),
            key_id,
            Path::new(&observation),
            Path::new(&approval),
            expected_nonce,
            Path::new(&output),
        ),
    }
}

fn main() -> ExitCode {
    let command = match parse_args(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("tunnel-authority: {error}");
            return ExitCode::from(2);
        }
    };
    match run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tunnel-authority: {error}");
            ExitCode::FAILURE
        }
    }
}
