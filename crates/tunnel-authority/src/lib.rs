//! `tunnel-authority`: the operator's signing tools, kept off every relay host.
//!
//! cluster.md requires that "the publisher's signing key, issuing CA keys, and
//! root verification bundle remain outside Redis and normal relay
//! configuration". This crate is the separate binary that holds that
//! capability (task row M6-C22, option (b), coordinator decision under the
//! owner's delegation, 2026-09-28). Slice 1 ships the recovery-approval
//! signer:
//!
//! * `generate-recovery-key` writes a fresh PKCS#8 v2 Ed25519 private key
//!   (`0600`, in a `0700` directory, never overwriting) and the public
//!   trusted-key document a relay's `[recovery] trusted_keys_path` reads.
//! * `sign-recovery-approval` reads that key and one `tunnel-relay
//!   recovery-observe` result, draws a fresh nonce, signs the approval with
//!   [`tunnel_catalog::RecoveryApprovalIssuer::sign_approval_bytes`], checks
//!   the bytes with the same [`tunnel_catalog::RecoveryApprovalVerifier`] that
//!   `tunnel-relay recover` runs, and writes the approval exclusively.
//!
//! Both are thin wrappers over the library signer; nothing here defines a
//! second encoding. Slice 2 (membership publishing and the checkpoint
//! responder) is not in this crate yet.
//!
//! Output is one JSON object on stdout, `{"schema_version":1,"command":...,
//! "ok":...}`, following docs/runtime.md's `--json` convention, and never
//! carries a private key, a signature or a path. Exit statuses follow the
//! client's table: `0` success, `1` an unexpected internal or I/O failure,
//! `2` an invalid invocation or input (including an output path that already
//! exists), `3` a refused credential (the private key file's mode, its
//! directory's mode, or its contents).

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

use chrono::{DateTime, Duration, SubsecRound, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tunnel_catalog::{
    RecoveryApproval, RecoveryApprovalIssuer, RecoveryApprovalVerifier, RecoveryPolicy,
    TrustedRecoveryKey,
};
use zeroize::Zeroizing;

/// The schema of every JSON object this binary prints.
pub const OUTPUT_SCHEMA_VERSION: u16 = 1;
/// The recovery approval schema signed here (`tunnel_catalog::recovery`).
pub const APPROVAL_SCHEMA_VERSION: u16 = tunnel_catalog::recovery::RECOVERY_SCHEMA_VERSION;
/// The `recovery-observe` result schema this binary accepts
/// (`RECOVERY_FENCE_SCHEMA_VERSION` in `tunnel-relay`'s `recovery.rs`).
pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;
/// The trusted-key document schema `tunnel-relay` accepts
/// (`load_trusted_recovery_keys`).
pub const TRUSTED_KEYS_SCHEMA_VERSION: u16 = 1;
/// The longest approval lifetime the verifier accepts (`MAX_RECOVERY_LIFETIME`).
pub const MAX_LIFETIME_SECONDS: i64 = 60;
/// The private key file's required mode.
pub const PRIVATE_KEY_FILE_MODE: u32 = 0o600;
/// The private key directory's required mode.
pub const PRIVATE_KEY_DIRECTORY_MODE: u32 = 0o700;
/// The highest approval version accepted at all: the largest integer every
/// JSON reader represents exactly (2^53 - 1).
pub const MAX_APPROVAL_VERSION: u64 = (1 << 53) - 1;
/// The highest approval version accepted without `--allow-version-jump`. The
/// authority keeps no issuing state, so it cannot see the relay's fence; a
/// relay's fence never goes down, so a mistyped large version permanently
/// blocks every smaller approval on that relay. Versions are expected to be
/// issued one at a time, so anything above this is refused as a likely typo.
pub const MAX_UNFLAGGED_APPROVAL_VERSION: u64 = 1_000;
/// An approval file is written with the mode `tunnel-relay recover` requires
/// of it (`RECOVERY_CONTROL_FILE_MODE`).
pub const APPROVAL_FILE_MODE: u32 = 0o600;

const MAX_KEY_FILE_BYTES: u64 = 4 * 1024;
const MAX_OBSERVATION_BYTES: u64 = 16 * 1024;
const NONCE_RANDOM_BYTES: usize = 16;

const USAGE: &str = "Usage: tunnel-authority <COMMAND>

The operator's signing tools. Run them on the authority host, never on a relay
host: the private key they read must not be in any relay's configuration.

Commands:
  generate-recovery-key   Write a new recovery-approval signing key and the
                          public trusted-key document for the relays
  sign-recovery-approval  Sign a recovery approval for one recovery-observe
                          result

Options:
  -h, --help     Print help
  -V, --version  Print version

Output is one JSON object on stdout. Exit status: 0 success, 1 internal or I/O
failure, 2 invalid invocation or input, 3 refused credential.
";

const GENERATE_USAGE: &str = "Usage: tunnel-authority generate-recovery-key --key-id ID --key-out PATH --trusted-keys-out PATH

Write a fresh PKCS#8 v2 Ed25519 private key to --key-out (mode 0600; its
directory must already exist with mode 0700) and the public trusted-key
document {\"schema_version\":1,\"keys\":[{\"key_id\":ID,\"public_key\":HEX}]} to
--trusted-keys-out (mode 0600), which becomes a relay's
[recovery] trusted_keys_path. Neither file may exist; nothing is overwritten.
";

const SIGN_USAGE: &str = "Usage: tunnel-authority sign-recovery-approval --key PATH --key-id ID --observation PATH --deployment-id ID --deployment-incarnation INC --approval-version N --out PATH [--lifetime-seconds S] [--allow-version-jump]

Sign one recovery approval for the `tunnel-relay recovery-observe` result in
--observation. --deployment-id and --deployment-incarnation are your statement
of what you approve and must equal the observation's. --approval-version must
be higher than every version the relay has consumed, and at most 1000 unless
--allow-version-jump is given (never above 2^53-1): the relay's fence never
goes down, so a mistyped large version blocks recovery on it for good. The key file must be mode
0600 in a directory with mode 0700. The approval is written to --out (mode
0600), which must not exist. The approval expires --lifetime-seconds after it
is signed (1..=60, default 60): run `tunnel-relay recover` with the printed
nonce as --expected-nonce before then.
";

/// Run one command line (without the program name) and return its status.
pub fn run(args: Vec<OsString>) -> ExitCode {
    let args = match args
        .into_iter()
        .map(OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(_) => {
            return report::<()>(
                "tunnel-authority",
                Err(Failure::invocation("arguments must be valid UTF-8")),
            );
        }
    };
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    match command.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        "-V" | "--version" => {
            println!("tunnel-authority {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "generate-recovery-key" => {
            if wants_help(rest) {
                print!("{GENERATE_USAGE}");
                return ExitCode::SUCCESS;
            }
            let outcome = GenerateArgs::parse(rest).and_then(|args| generate_recovery_key(&args));
            report("generate-recovery-key", outcome)
        }
        "sign-recovery-approval" => {
            if wants_help(rest) {
                print!("{SIGN_USAGE}");
                return ExitCode::SUCCESS;
            }
            let outcome = SignArgs::parse(rest).and_then(|args| sign_recovery_approval(&args));
            report("sign-recovery-approval", outcome)
        }
        other => report::<()>(
            "tunnel-authority",
            Err(Failure::invocation(format!(
                "unknown command {other:?}; run tunnel-authority --help"
            ))),
        ),
    }
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

/// The failure classes, each with its exit status and diagnostic code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// `2`: a bad command line.
    Invocation,
    /// `2`: the observation file is unreadable, malformed or disagrees with
    /// what the operator said they approve.
    InvalidObservation,
    /// `2`: an output path already exists; nothing was written.
    OutputExists,
    /// `3`: the key file or its directory has the wrong mode or type.
    CredentialPermissions,
    /// `3`: the key file is not a usable PKCS#8 v2 Ed25519 key.
    Credential,
    /// `1`: signing or self-verification failed.
    Internal,
    /// `1`: a filesystem operation failed.
    Io,
}

impl FailureKind {
    fn exit_code(self) -> u8 {
        match self {
            Self::Invocation | Self::InvalidObservation | Self::OutputExists => 2,
            Self::CredentialPermissions | Self::Credential => 3,
            Self::Internal | Self::Io => 1,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Invocation => "INVALID_INVOCATION",
            Self::InvalidObservation => "INVALID_OBSERVATION",
            Self::OutputExists => "OUTPUT_EXISTS",
            Self::CredentialPermissions => "CREDENTIAL_PERMISSIONS",
            Self::Credential => "CREDENTIAL_ERROR",
            Self::Internal => "INTERNAL_ERROR",
            Self::Io => "IO_ERROR",
        }
    }
}

/// A refusal. The message is fixed text written here: it names no path, key
/// material or signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
}

impl Failure {
    fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn invocation(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Invocation, message)
    }

    fn observation(message: impl Into<String>) -> Self {
        Self::new(FailureKind::InvalidObservation, message)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    schema_version: u16,
    command: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody<'a>>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    retryable: bool,
}

fn report<T: Serialize>(command: &str, outcome: Result<T, Failure>) -> ExitCode {
    match outcome {
        Ok(result) => {
            let envelope = Envelope {
                schema_version: OUTPUT_SCHEMA_VERSION,
                command,
                ok: true,
                result: Some(result),
                error: None,
            };
            match serde_json::to_string(&envelope) {
                Ok(line) => {
                    println!("{line}");
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    eprintln!("tunnel-authority: the result could not be encoded");
                    ExitCode::FAILURE
                }
            }
        }
        Err(failure) => {
            let envelope = Envelope::<()> {
                schema_version: OUTPUT_SCHEMA_VERSION,
                command,
                ok: false,
                result: None,
                error: Some(ErrorBody {
                    code: failure.kind.code(),
                    message: &failure.message,
                    retryable: false,
                }),
            };
            if let Ok(line) = serde_json::to_string(&envelope) {
                println!("{line}");
            }
            eprintln!("tunnel-authority: {command}: {}", failure.message);
            ExitCode::from(failure.kind.exit_code())
        }
    }
}

// ------------------------------------------------------------ arguments

fn take_value<'a>(
    args: &'a [String],
    index: &mut usize,
    flag: &str,
    slot: &mut Option<&'a str>,
) -> Result<(), Failure> {
    if slot.is_some() {
        return Err(Failure::invocation(format!("{flag} was given twice")));
    }
    let value = args
        .get(*index + 1)
        .ok_or_else(|| Failure::invocation(format!("{flag} needs a value")))?;
    if value.is_empty() || value.starts_with("--") {
        return Err(Failure::invocation(format!("{flag} needs a value")));
    }
    *slot = Some(value);
    *index += 2;
    Ok(())
}

fn required<'a>(slot: Option<&'a str>, flag: &str) -> Result<&'a str, Failure> {
    slot.ok_or_else(|| Failure::invocation(format!("{flag} is required")))
}

/// `generate-recovery-key` arguments.
#[derive(Debug)]
pub struct GenerateArgs {
    pub key_id: String,
    pub key_out: PathBuf,
    pub trusted_keys_out: PathBuf,
}

impl GenerateArgs {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        let (mut key_id, mut key_out, mut trusted) = (None, None, None);
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--key-id" => take_value(args, &mut index, "--key-id", &mut key_id)?,
                "--key-out" => take_value(args, &mut index, "--key-out", &mut key_out)?,
                "--trusted-keys-out" => {
                    take_value(args, &mut index, "--trusted-keys-out", &mut trusted)?
                }
                other => {
                    return Err(Failure::invocation(format!(
                        "unknown generate-recovery-key argument {other:?}"
                    )));
                }
            }
        }
        Ok(Self {
            key_id: required(key_id, "--key-id")?.to_owned(),
            key_out: PathBuf::from(required(key_out, "--key-out")?),
            trusted_keys_out: PathBuf::from(required(trusted, "--trusted-keys-out")?),
        })
    }
}

/// `sign-recovery-approval` arguments.
#[derive(Debug)]
pub struct SignArgs {
    pub key: PathBuf,
    pub key_id: String,
    pub observation: PathBuf,
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub approval_version: u64,
    pub out: PathBuf,
    pub lifetime_seconds: i64,
    pub allow_version_jump: bool,
}

impl SignArgs {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        let mut key = None;
        let mut key_id = None;
        let mut observation = None;
        let mut deployment_id = None;
        let mut incarnation = None;
        let mut version = None;
        let mut out = None;
        let mut lifetime = None;
        let mut allow_version_jump = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--key" => take_value(args, &mut index, "--key", &mut key)?,
                "--key-id" => take_value(args, &mut index, "--key-id", &mut key_id)?,
                "--observation" => take_value(args, &mut index, "--observation", &mut observation)?,
                "--deployment-id" => {
                    take_value(args, &mut index, "--deployment-id", &mut deployment_id)?
                }
                "--deployment-incarnation" => take_value(
                    args,
                    &mut index,
                    "--deployment-incarnation",
                    &mut incarnation,
                )?,
                "--approval-version" => {
                    take_value(args, &mut index, "--approval-version", &mut version)?
                }
                "--out" => take_value(args, &mut index, "--out", &mut out)?,
                "--lifetime-seconds" => {
                    take_value(args, &mut index, "--lifetime-seconds", &mut lifetime)?
                }
                "--allow-version-jump" => {
                    if allow_version_jump {
                        return Err(Failure::invocation("--allow-version-jump was given twice"));
                    }
                    allow_version_jump = true;
                    index += 1;
                }
                other => {
                    return Err(Failure::invocation(format!(
                        "unknown sign-recovery-approval argument {other:?}"
                    )));
                }
            }
        }
        let approval_version = required(version, "--approval-version")?
            .parse::<u64>()
            .ok()
            .filter(|version| (1..=MAX_APPROVAL_VERSION).contains(version))
            .ok_or_else(|| {
                Failure::invocation(
                    "--approval-version must be a whole number from 1 to 9007199254740991 (2^53-1)",
                )
            })?;
        if approval_version > MAX_UNFLAGGED_APPROVAL_VERSION && !allow_version_jump {
            return Err(Failure::invocation(format!(
                "--approval-version {approval_version} is above {MAX_UNFLAGGED_APPROVAL_VERSION}; a relay's fence never goes down, so a mistyped version blocks every smaller one for good. Pass --allow-version-jump if it is intended"
            )));
        }
        let lifetime_seconds = match lifetime {
            None => MAX_LIFETIME_SECONDS,
            Some(value) => value
                .parse::<i64>()
                .ok()
                .filter(|seconds| (1..=MAX_LIFETIME_SECONDS).contains(seconds))
                .ok_or_else(|| {
                    Failure::invocation("--lifetime-seconds must be a whole number from 1 to 60")
                })?,
        };
        Ok(Self {
            key: PathBuf::from(required(key, "--key")?),
            key_id: required(key_id, "--key-id")?.to_owned(),
            observation: PathBuf::from(required(observation, "--observation")?),
            deployment_id: required(deployment_id, "--deployment-id")?.to_owned(),
            deployment_incarnation: required(incarnation, "--deployment-incarnation")?.to_owned(),
            approval_version,
            out: PathBuf::from(required(out, "--out")?),
            lifetime_seconds,
            allow_version_jump,
        })
    }
}

// ------------------------------------------------------------ key files

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// The key's directory must be a real directory (not a symbolic link) with
/// mode exactly `0700`.
fn check_key_directory(path: &Path) -> Result<(), Failure> {
    let directory = parent_of(path);
    let metadata = fs::symlink_metadata(directory).map_err(|_| {
        Failure::new(
            FailureKind::CredentialPermissions,
            "the private key's directory cannot be inspected",
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Failure::new(
            FailureKind::CredentialPermissions,
            "the private key's directory is not a directory (a symbolic link is refused)",
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != PRIVATE_KEY_DIRECTORY_MODE {
        return Err(Failure::new(
            FailureKind::CredentialPermissions,
            format!("the private key's directory has mode {mode:04o}; it must be 0700"),
        ));
    }
    Ok(())
}

fn check_key_file_metadata(metadata: &Metadata) -> Result<(), Failure> {
    if !metadata.file_type().is_file() {
        return Err(Failure::new(
            FailureKind::CredentialPermissions,
            "the private key is not a regular file (a symbolic link is refused)",
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != PRIVATE_KEY_FILE_MODE {
        return Err(Failure::new(
            FailureKind::CredentialPermissions,
            format!("the private key file has mode {mode:04o}; it must be 0600"),
        ));
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(Failure::new(
            FailureKind::Credential,
            "the private key file is too large to be a PKCS#8 Ed25519 key",
        ));
    }
    Ok(())
}

/// Read an externally provisioned private key file, refusing it unless it is
/// a regular file with mode `0600` in a directory with mode `0700`. The file
/// is opened without following a symbolic link and re-checked on the open
/// handle, so a file swapped after the path check is refused too.
pub fn read_private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, Failure> {
    check_key_directory(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Failure::new(
                FailureKind::Credential,
                "the private key file does not exist",
            )
        } else {
            Failure::new(
                FailureKind::Credential,
                "the private key file cannot be read",
            )
        }
    })?;
    check_key_file_metadata(&metadata)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| {
            Failure::new(
                FailureKind::Credential,
                "the private key file cannot be read",
            )
        })?;
    let opened = file.metadata().map_err(|_| {
        Failure::new(
            FailureKind::Credential,
            "the private key file cannot be read",
        )
    })?;
    check_key_file_metadata(&opened)?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(Failure::new(
            FailureKind::CredentialPermissions,
            "the private key file changed while it was opened",
        ));
    }
    // Sized up front so `read_to_end` never reallocates and leaves a copy of
    // key bytes behind in freed memory.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES as usize + 1));
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            Failure::new(
                FailureKind::Credential,
                "the private key file cannot be read",
            )
        })?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(Failure::new(
            FailureKind::Credential,
            "the private key file is too large to be a PKCS#8 Ed25519 key",
        ));
    }
    Ok(bytes)
}

fn refuse_existing(path: &Path, what: &str) -> Result<(), Failure> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Failure::new(
            FailureKind::OutputExists,
            format!("the {what} path already exists; nothing was written or overwritten"),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Failure::new(
            FailureKind::Io,
            format!("the {what} path cannot be inspected"),
        )),
    }
}

/// Create `path` exclusively with `mode` and write `bytes`, synced. A path
/// that exists (as anything, including a dangling symbolic link) is refused
/// and left untouched; a failed write removes the file this call created.
pub fn write_exclusive(path: &Path, bytes: &[u8], mode: u32, what: &str) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                Failure::new(
                    FailureKind::OutputExists,
                    format!("the {what} path already exists; nothing was written or overwritten"),
                )
            } else {
                Failure::new(
                    FailureKind::Io,
                    format!("the {what} file cannot be created"),
                )
            }
        })?;
    let written = (|| {
        // The process umask can only clear bits; set the mode exactly.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if written.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(Failure::new(
            FailureKind::Io,
            format!("the {what} file could not be written; it was removed"),
        ));
    }
    drop(file);
    // Make the new directory entry durable; a failure here is reported but
    // the complete file stays.
    File::open(parent_of(path))
        .and_then(|directory| directory.sync_all())
        .map_err(|_| {
            Failure::new(
                FailureKind::Io,
                format!("the {what} file was written but its directory could not be synced"),
            )
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ------------------------------------------------------------ generate

#[derive(Serialize)]
struct TrustedKeysDocument<'a> {
    schema_version: u16,
    keys: [TrustedKeyEntry<'a>; 1],
}

#[derive(Serialize)]
struct TrustedKeyEntry<'a> {
    key_id: &'a str,
    public_key: &'a str,
}

/// `generate-recovery-key`'s redacted result.
#[derive(Debug, Serialize)]
pub struct GeneratedKey {
    pub key_id: String,
    /// The Ed25519 public key, 64 lower-case hex digits (public data).
    pub public_key: String,
    pub key_format: &'static str,
}

/// Write a new signing key and its trusted-key document.
pub fn generate_recovery_key(args: &GenerateArgs) -> Result<GeneratedKey, Failure> {
    check_key_directory(&args.key_out)?;
    refuse_existing(&args.key_out, "--key-out")?;
    refuse_existing(&args.trusted_keys_out, "--trusted-keys-out")?;
    if args.key_out == args.trusted_keys_out {
        return Err(Failure::invocation(
            "--key-out and --trusted-keys-out must be different files",
        ));
    }
    let (issuer, pkcs8) = RecoveryApprovalIssuer::generate(args.key_id.as_str())
        .map_err(|_| Failure::invocation("--key-id must be 1..=128 bytes with no spaces"))?;
    let pkcs8 = Zeroizing::new(pkcs8);
    let public_key = hex(&issuer
        .public_key()
        .map_err(|_| Failure::new(FailureKind::Internal, "the generated key is unusable"))?);
    let document = serde_json::to_vec(&TrustedKeysDocument {
        schema_version: TRUSTED_KEYS_SCHEMA_VERSION,
        keys: [TrustedKeyEntry {
            key_id: &args.key_id,
            public_key: &public_key,
        }],
    })
    .map_err(|_| {
        Failure::new(
            FailureKind::Internal,
            "the trusted-key document could not be encoded",
        )
    })?;
    write_exclusive(&args.key_out, &pkcs8, PRIVATE_KEY_FILE_MODE, "--key-out")?;
    if let Err(failure) = write_exclusive(
        &args.trusted_keys_out,
        &document,
        APPROVAL_FILE_MODE,
        "--trusted-keys-out",
    ) {
        // Leave no private key whose public half was never written.
        let _ = fs::remove_file(&args.key_out);
        return Err(failure);
    }
    Ok(GeneratedKey {
        key_id: args.key_id.clone(),
        public_key,
        key_format: "pkcs8-v2-der-ed25519",
    })
}

// ------------------------------------------------------------ sign

/// A `tunnel-relay recovery-observe` result, field for field
/// (`RecoveryObservation` in `crates/tunnel-relay/src/recovery.rs`). Unknown
/// fields are refused, so a changed observation schema fails here rather than
/// being signed half-read.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u16,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub deployment_incarnation: String,
    pub redis_run_id: String,
    pub catalog_digest: String,
    pub catalog_generation: String,
    pub key_count: u64,
    pub byte_count: u64,
    pub quiescence: String,
}

/// Read and check one observation file.
pub fn read_observation(path: &Path) -> Result<Observation, Failure> {
    let metadata = fs::metadata(path)
        .map_err(|_| Failure::observation("the observation file cannot be read"))?;
    if !metadata.is_file() || metadata.len() > MAX_OBSERVATION_BYTES {
        return Err(Failure::observation(
            "the observation must be a regular file of at most 16 KiB",
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_OBSERVATION_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| Failure::observation("the observation file cannot be read"))?;
    let observation: Observation = serde_json::from_slice(&bytes).map_err(|_| {
        Failure::observation(
            "the observation is not one `tunnel-relay recovery-observe` JSON result",
        )
    })?;
    if observation.schema_version != OBSERVATION_SCHEMA_VERSION {
        return Err(Failure::observation(format!(
            "the observation has schema_version {}; this build reads {OBSERVATION_SCHEMA_VERSION}",
            observation.schema_version
        )));
    }
    if observation.quiescence != "unproven" {
        return Err(Failure::observation(
            "the observation's quiescence is not \"unproven\"; it is not a recovery-observe result",
        ));
    }
    Ok(observation)
}

/// `sign-recovery-approval`'s redacted result: identifiers, the nonce to pass
/// to `tunnel-relay recover --expected-nonce`, the window, and the digest of
/// the written file. No key, signature or path.
#[derive(Debug, Serialize)]
pub struct SignedApprovalSummary {
    pub approval_version: u64,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub deployment_incarnation: String,
    pub redis_run_id: String,
    pub catalog_digest: String,
    pub nonce: String,
    pub publisher_key_id: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approval_sha256: String,
}

fn fresh_nonce() -> Result<String, Failure> {
    let mut random = [0_u8; NONCE_RANDOM_BYTES];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| Failure::new(FailureKind::Internal, "no system randomness for the nonce"))?;
    Ok(hex(&random))
}

/// Sign one approval and write it exclusively.
pub fn sign_recovery_approval(args: &SignArgs) -> Result<SignedApprovalSummary, Failure> {
    refuse_existing(&args.out, "--out")?;
    let observation = read_observation(&args.observation)?;
    if observation.deployment_id != args.deployment_id {
        return Err(Failure::observation(
            "the observation's deployment_id is not --deployment-id; nothing was signed",
        ));
    }
    if observation.deployment_incarnation != args.deployment_incarnation {
        return Err(Failure::observation(
            "the observation's deployment_incarnation is not --deployment-incarnation; nothing was signed",
        ));
    }
    let pkcs8 = read_private_key(&args.key)?;
    let issuer = RecoveryApprovalIssuer::from_pkcs8(args.key_id.as_str(), &pkcs8).map_err(|_| {
        Failure::new(
            FailureKind::Credential,
            "the private key is not a PKCS#8 v2 Ed25519 key, or --key-id is not 1..=128 bytes with no spaces",
        )
    })?;
    drop(pkcs8);
    let public_key = issuer
        .public_key()
        .map_err(|_| Failure::new(FailureKind::Credential, "the private key is unusable"))?;

    let nonce = fresh_nonce()?;
    // Whole seconds: the approval's JSON then carries plain RFC 3339 instants.
    let now = Utc::now().trunc_subsecs(0);
    // `recover` enforces `not_before` strictly at activation, against the
    // relay's clock and Redis `TIME` (`check_approval_window` and the
    // activation script in `tunnel-catalog/src/redis/recovery.rs`). Starting
    // the window one cluster skew bound before signing keeps an authority
    // clock up to 5 s ahead of those from refusing its own fresh approval. It
    // cannot be used earlier than it exists, and it ends no later.
    let not_before = now - tunnel_catalog::clock::MAX_CLUSTER_CLOCK_SKEW_WALL;
    let approval = RecoveryApproval {
        schema_version: APPROVAL_SCHEMA_VERSION,
        deployment_id: observation.deployment_id.clone(),
        redis_namespace: observation.redis_namespace.clone(),
        redis_run_id: observation.redis_run_id.clone(),
        deployment_incarnation: observation.deployment_incarnation.clone(),
        approval_version: args.approval_version,
        nonce: nonce.clone(),
        catalog_digest: observation.catalog_digest.clone(),
        issued_at: now,
        not_before,
        expires_at: now + Duration::seconds(args.lifetime_seconds),
    };
    let bytes = issuer
        .sign_approval_bytes(approval.clone())
        .map_err(|_| Failure::new(FailureKind::Internal, "the approval could not be signed"))?;

    // The same verifier `tunnel-relay recover` runs, with the observation as
    // its policy and this key as the only trusted key: an approval this binary
    // writes is one a relay trusting this key accepts for this observation,
    // unless the catalog, the Redis run or the relay's fence moved since.
    let policy = RecoveryPolicy::new(
        &observation.deployment_id,
        &observation.redis_namespace,
        &observation.redis_run_id,
        &observation.deployment_incarnation,
    )
    .map_err(|_| {
        Failure::observation("the observation's identifiers are not valid recovery identifiers")
    })?;
    let trusted = TrustedRecoveryKey::new(args.key_id.as_str(), public_key)
        .map_err(|_| Failure::invocation("--key-id must be 1..=128 bytes with no spaces"))?;
    let verifier = RecoveryApprovalVerifier::new(policy, [trusted])
        .map_err(|_| Failure::new(FailureKind::Internal, "the self-check could not be built"))?;
    verifier
        .verify(&bytes, &nonce, now, None)
        .map_err(|error| {
            Failure::observation(format!(
                "the signed approval does not verify against the observation ({error}); nothing was written"
            ))
        })?;

    write_exclusive(&args.out, &bytes, APPROVAL_FILE_MODE, "--out")?;
    Ok(SignedApprovalSummary {
        approval_version: approval.approval_version,
        deployment_id: approval.deployment_id,
        redis_namespace: approval.redis_namespace,
        deployment_incarnation: approval.deployment_incarnation,
        redis_run_id: approval.redis_run_id,
        catalog_digest: approval.catalog_digest,
        nonce,
        publisher_key_id: args.key_id.clone(),
        issued_at: approval.issued_at,
        not_before: approval.not_before,
        expires_at: approval.expires_at,
        approval_sha256: hex(&Sha256::digest(&bytes)),
    })
}
