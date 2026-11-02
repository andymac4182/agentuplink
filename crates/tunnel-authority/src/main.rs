//! Separate operator authority. Recovery signing remains an offline command.
mod online;
mod online_config;
mod online_state;
mod private_files;
mod state_store;

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

const HELP: &str = "tunnel-authority: membership and offline recovery authority

Usage:
  tunnel-authority generate-key --key-id ID --private-key PATH --public-keys PATH [--purpose recovery|membership]
  tunnel-authority sign-recovery-approval --key PATH --key-id ID --observation PATH --approval PATH --expected-nonce NONCE --output PATH
  tunnel-authority initialize-membership --config PATH --inventory PATH --expected-redis-run-id RUN
  tunnel-authority approve-membership --config PATH --inventory PATH --expected-revision N --expected-redis-run-id RUN
  tunnel-authority check-config --config PATH
  tunnel-authority serve --config PATH

generate-key creates a PKCS#8 v2 Ed25519 private key and a recovery trusted-keys
JSON document by default; --purpose membership emits membership trust instead.
Both output paths must be absent. Keep the private key on the
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

Offline recovery signing approves the operator's reviewed catalog digest. It does not inspect
Redis, reconcile revocations, prove quiescence, or activate a deployment.
Recover independently verifies the actual catalog, nonce and durable version
fence. Never reset that fence or reuse a consumed approval. Failed commands
must not be treated as successful; after a crash inspect incomplete outputs
and use fresh output paths. No private key or signed approval is printed.

serve owns one durable authority state, continuously publishes signed membership
over Redis TLS and serves nonce-bound checkpoints over mandatory mTLS. It never
initializes or repairs state. initialize-membership explicitly approves the
independently supplied Redis run; approve-membership requires the service stopped
and a higher inventory revision. Both version allocators survive approvals and
incarnation changes. Recovery and CA private keys must not be given to serve.
Use separate keys for membership and recovery. Never roll back the state volume;
a valid whole-volume rollback cannot be detected from that same volume alone.
";

enum Command {
    Help,
    Generate {
        key_id: String,
        private_key: OsString,
        public_keys: OsString,
        membership: bool,
    },
    Check {
        config: OsString,
    },
    Initialize {
        config: OsString,
        inventory: OsString,
        expected_run: String,
    },
    Approve {
        config: OsString,
        inventory: OsString,
        expected_run: String,
        expected_revision: u64,
    },
    Serve {
        config: OsString,
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
    if matches!(
        command.to_str(),
        Some("initialize-membership" | "approve-membership" | "check-config" | "serve")
    ) {
        return parse_online(command.to_str().ok_or("invalid command")?, args);
    }
    let allowed: &[&str] = if command == "generate-key" {
        &["--key-id", "--private-key", "--public-keys", "--purpose"]
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
    let membership = match options.remove("--purpose") {
        None => false,
        Some(value) if value == "recovery" => false,
        Some(value) if value == "membership" => true,
        Some(_) => return Err("key purpose must be recovery or membership"),
    };
    let mut take = |name| options.remove(name).ok_or("missing required option");
    if command == "generate-key" {
        Ok(Command::Generate {
            key_id: text(take("--key-id")?)?,
            private_key: take("--private-key")?,
            public_keys: take("--public-keys")?,
            membership,
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

fn parse_online(command: &str, args: impl Iterator<Item = OsString>) -> Result<Command> {
    let allowed = match command {
        "serve" | "check-config" => &["--config"][..],
        "initialize-membership" => &["--config", "--inventory", "--expected-redis-run-id"][..],
        "approve-membership" => &[
            "--config",
            "--inventory",
            "--expected-redis-run-id",
            "--expected-revision",
        ][..],
        _ => return Err("unknown authority command"),
    };
    let mut args = args;
    let mut options = BTreeMap::new();
    while let Some(flag) = args.next() {
        let name = allowed
            .iter()
            .copied()
            .find(|name| flag == *name)
            .ok_or("unknown option")?;
        let value = args.next().ok_or("option requires a value")?;
        if value.is_empty() || options.insert(name, value).is_some() {
            return Err("empty or duplicate option");
        }
    }
    let mut take = |name| options.remove(name).ok_or("missing required option");
    let config = take("--config")?;
    match command {
        "serve" => Ok(Command::Serve { config }),
        "check-config" => Ok(Command::Check { config }),
        "initialize-membership" => Ok(Command::Initialize {
            config,
            inventory: take("--inventory")?,
            expected_run: text(take("--expected-redis-run-id")?)?,
        }),
        "approve-membership" => Ok(Command::Approve {
            config,
            inventory: take("--inventory")?,
            expected_run: text(take("--expected-redis-run-id")?)?,
            expected_revision: text(take("--expected-revision")?)?
                .parse()
                .map_err(|_| "expected revision must be an unsigned integer")?,
        }),
        _ => Err("unknown authority command"),
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

fn generate_key(
    key_id: String,
    private_key: &Path,
    public_keys: &Path,
    membership: bool,
) -> Result<()> {
    let (issuer, bytes) = RecoveryApprovalIssuer::generate(&key_id)
        .map_err(|_| "key generation failed; check key identifier")?;
    let bytes = Zeroizing::new(bytes);
    let public_key = issuer.public_key().map_err(|_| "invalid issuer key")?;
    let public_key: String = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut document =
        serde_json::json!({ "keys": [{ "key_id": key_id, "public_key": public_key }] });
    if !membership {
        document["schema_version"] = serde_json::json!(1);
    }
    let trust = serde_json::to_vec(&document).map_err(|_| "cannot encode public trust document")?;

    // Reserve both paths before writing either. Errors drop only files created
    // by this invocation; an existing key/trust document is never replaced.
    let mut private_output = private_files::NewFile::create(private_key)?;
    let mut public_output = private_files::NewFile::create(public_keys)?;
    public_output.write_and_sync(&trust)?;
    private_output.write_and_sync(&bytes)?;
    public_output.commit();
    private_output.commit();
    if membership {
        println!("Created private signing key and public membership trust document.");
    } else {
        println!("Created private signing key and public recovery trust document.");
    }
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
            membership,
        } => generate_key(
            key_id,
            Path::new(&private_key),
            Path::new(&public_keys),
            membership,
        ),
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
        Command::Check { config } => {
            online::check(online_config::Config::load(Path::new(&config))?)?;
            println!(
                "Authority configuration and independent state are valid; Redis was not contacted."
            );
            Ok(())
        }
        Command::Initialize {
            config,
            inventory,
            expected_run,
        } => {
            online_state::initialize(
                &online_config::Config::load(Path::new(&config))?,
                Path::new(&inventory),
                &expected_run,
            )?;
            println!(
                "Initialized independent membership authority state; Redis was not contacted."
            );
            Ok(())
        }
        Command::Approve {
            config,
            inventory,
            expected_run,
            expected_revision,
        } => {
            online_state::approve(
                &online_config::Config::load(Path::new(&config))?,
                Path::new(&inventory),
                expected_revision,
                &expected_run,
            )?;
            println!(
                "Approved membership inventory; both version allocators preserved; publication required."
            );
            Ok(())
        }
        Command::Serve { config } => online::run(online_config::Config::load(Path::new(&config))?),
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
