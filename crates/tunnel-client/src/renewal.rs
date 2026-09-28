//! `tunnel-client credentials renew` (task row M0-07; M0-03 decision (3)(a)).
//!
//! A renewal is two local steps with the external issuer between them, and
//! neither step touches the current pair until the new one has been checked:
//!
//! 1. [`begin`] writes a new private key beside the current one (the
//!    *pending key*, `<key>.renew-pending`, mode `0600`, in the key's
//!    directory, made `0700`) and a CSR for it. The current key and
//!    certificate are not opened for writing.
//! 2. The operator carries the CSR to the issuer.
//! 3. [`complete`] checks the issued certificate exactly as
//!    `credentials import` checks one -- its public key is the pending key's,
//!    it is X.509 v3 with this profile's device role SAN, it is not already
//!    expired -- plus one check import cannot make: it must come from the
//!    issuer of the current certificate (the same issuer name and authority
//!    key identifier, and, when the current certificate file carries its
//!    issuer, a chain that verifies to it). The profile's configured server
//!    trust must still load. Only then does the swap below run.
//!
//! **The swap.** Two files cannot be replaced atomically together, so the
//! sequence is ordered so that every state a crash can leave is either a
//! valid pair or one that [`recover`] resolves to a valid pair without any
//! input:
//!
//! | step | file operation | pair at rest if killed here |
//! |---|---|---|
//! | `certificate_staged` | the issued chain is written to `<cert>.renew-staged` and synced | old, valid |
//! | `previous_key_cleared` / `previous_certificate_cleared` | an older `<file>.renew-previous` is removed | old, valid |
//! | `previous_key_kept` / `previous_certificate_kept` | the current key and certificate are hard-linked to `<file>.renew-previous` | old, valid |
//! | `certificate_installed` | `rename(<cert>.renew-staged, <cert>)` | **new certificate, old key**: recovery renames the pending key into place |
//! | `key_installed` | `rename(<key>.renew-pending, <key>)` | new, valid |
//!
//! Each rename is followed by a sync of its directory. Recovery runs under
//! the same lock at the start of every `credentials renew` and of `connect`,
//! and `doctor` reports the interrupted state without changing it. A
//! failure (not a crash) of the last rename puts the previous certificate
//! back at once, so a refusal also leaves the old pair.
//!
//! **A running supervisor keeps its pair.** `connect` pins the bytes of its
//! credentials when it starts ([`crate::credentials::PinnedCredentials`]),
//! so the new pair is used only after a stop and a start -- `disconnect` or
//! the service manager -- never by a reconnect or a rotation mid-life.
//!
//! **Only Unix.** Like `credentials create` and `import`, renewal needs an
//! owner-only file mode; elsewhere it is refused. [`inspect`] is portable.

use crate::config::{CredentialConfig, RuntimeConfig};
use crate::credentials::{CredentialError, load_certificates, load_private_key};
#[cfg(unix)]
use crate::credentials::{
    certificates_from_pem, check_import_validity, ensure_parent, generate_request, sync_parent,
    verify_certificate_key, verify_device_role, write_new,
};
#[cfg(unix)]
use rustls::pki_types::CertificateDer;
use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

/// How long a renewal, or a starting `connect` recovering one, waits for the
/// profile's renewal lock. Every holder keeps it only for a few file
/// operations, never while waiting on an operator or a network.
pub const RENEWAL_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A debug-build-only environment variable naming a [`SwapStep`] after which
/// the process aborts, as a kill would stop it. Absent from release builds:
/// the read is compiled only with `debug_assertions`.
pub const RENEW_ABORT_AFTER_ENV: &str = "TUNNEL_CLIENT_TEST_RENEW_ABORT_AFTER";

/// The files a renewal uses beside the profile's current pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalFiles {
    pub key: PathBuf,
    pub certificate: PathBuf,
    /// The new key, written by [`begin`], renamed over `key` last.
    pub pending_key: PathBuf,
    /// The issued chain, written by [`complete`], renamed over `certificate`.
    pub staged_certificate: PathBuf,
    /// The pair the last renewal replaced, kept for a manual rollback.
    pub previous_key: PathBuf,
    pub previous_certificate: PathBuf,
    /// The profile's renewal lock, beside the key; never removed.
    pub lock: PathBuf,
}

impl RenewalFiles {
    #[must_use]
    pub fn new(credentials: &CredentialConfig) -> Self {
        let key = credentials.client_key.clone();
        let certificate = credentials.client_certificate.clone();
        Self {
            pending_key: beside(&key, "renew-pending"),
            staged_certificate: beside(&certificate, "renew-staged"),
            previous_key: beside(&key, "renew-previous"),
            previous_certificate: beside(&certificate, "renew-previous"),
            lock: beside(&key, "renew-lock"),
            key,
            certificate,
        }
    }

    /// Whether anything a renewal leaves behind is present.
    #[must_use]
    pub fn has_renewal_artifacts(&self) -> bool {
        present(&self.pending_key) || present(&self.previous_certificate)
    }

    /// Refuse a layout the rename sequence cannot handle safely.
    #[cfg(unix)]
    fn check_layout(&self) -> Result<(), RenewalError> {
        if self.key == self.certificate {
            return Err(RenewalError::Unsupported(
                "the profile keeps its key and certificate in one file; renewal replaces \
                 them separately, so give them separate paths",
            ));
        }
        for path in [&self.key, &self.certificate] {
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
                return Err(RenewalError::Unsupported(
                    "the profile's key or certificate is a symbolic link; renewal replaces \
                     files by rename, which would replace the link rather than its target",
                ));
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn managed(&self) -> [&Path; 7] {
        [
            &self.key,
            &self.certificate,
            &self.pending_key,
            &self.staged_certificate,
            &self.previous_key,
            &self.previous_certificate,
            &self.lock,
        ]
    }
}

/// `<name>.<suffix>` in the same directory as `path`.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.{suffix}"))
}

fn present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// One file operation of the swap, in order (see the module table).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwapStep {
    CertificateStaged,
    PreviousKeyCleared,
    PreviousCertificateCleared,
    PreviousKeyKept,
    PreviousCertificateKept,
    CertificateInstalled,
    KeyInstalled,
}

impl SwapStep {
    /// Every step, in the order the swap takes them.
    pub const ALL: [Self; 7] = [
        Self::CertificateStaged,
        Self::PreviousKeyCleared,
        Self::PreviousCertificateCleared,
        Self::PreviousKeyKept,
        Self::PreviousCertificateKept,
        Self::CertificateInstalled,
        Self::KeyInstalled,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::CertificateStaged => "certificate_staged",
            Self::PreviousKeyCleared => "previous_key_cleared",
            Self::PreviousCertificateCleared => "previous_certificate_cleared",
            Self::PreviousKeyKept => "previous_key_kept",
            Self::PreviousCertificateKept => "previous_certificate_kept",
            Self::CertificateInstalled => "certificate_installed",
            Self::KeyInstalled => "key_installed",
        }
    }
}

/// What recovery did to an interrupted swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// The new certificate was in place; the pending key was renamed in.
    RolledForward,
    /// The key did not match either certificate but the kept previous
    /// certificate did; it was put back.
    RolledBack,
}

impl Recovery {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RolledForward => "rolled_forward",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// The result of [`begin`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalRequest {
    /// A pending renewal was discarded first (`--discard-pending`).
    pub discarded_pending: bool,
    /// An interrupted earlier swap was resolved first.
    pub recovered: Option<Recovery>,
}

/// The result of [`complete`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Renewed {
    pub certificate_count: usize,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    /// `notBefore` when it is still ahead of this host's clock (M6-C54):
    /// installed, and reported, exactly as `credentials import` does.
    pub not_yet_valid_until: Option<i64>,
    /// The swap had already completed with this certificate; nothing changed.
    pub already_installed: bool,
    pub recovered: Option<Recovery>,
}

/// Whether a renewal is pending or interrupted, for `doctor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalStatus {
    None,
    Pending,
    Interrupted,
}

/// What [`inspect`] found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewalState {
    pub status: RenewalStatus,
    /// When the pending key was written, as unix seconds.
    pub pending_since_unix: Option<i64>,
}

/// Why a renewal step refused or failed. Every message is fixed text or a
/// library's parse detail: no path, key or certificate body is carried.
#[derive(Debug)]
pub enum RenewalError {
    /// `begin` found a pending renewal (M0-07's stale-pending rule): it is
    /// never replaced silently, because the issuer may already hold its CSR.
    Pending { since_unix: Option<i64> },
    /// `complete` found no pending renewal to complete.
    NotPending,
    /// Another renewal holds the profile's renewal lock.
    Locked,
    /// The profile's layout cannot be renewed by rename.
    Unsupported(&'static str),
    /// Renewal is refused on this platform (no owner-only file mode yet).
    UnsupportedPlatform,
    /// There is no valid current pair to renew.
    NoCurrentCredential(CredentialError),
    /// The pending key cannot be read.
    PendingKeyUnusable(CredentialError),
    /// The CSR output already exists; renewal never overwrites a file.
    CsrExists,
    /// The CSR output names one of the profile's own credential files.
    CsrOutputIsCredential,
    /// The issued certificate cannot be read.
    IssuedUnreadable(io::Error),
    /// The issued certificate was refused by an import check.
    Refused(CredentialError),
    /// The issued certificate is not from the current certificate's issuer.
    IssuerChanged(&'static str),
    /// The issued chain does not verify to the current certificate's issuer.
    UntrustedChain(String),
    /// The profile's configured server trust does not load.
    ServerTrust(CredentialError),
    /// A file operation failed; `step` names it. The pair is still valid.
    Io {
        step: &'static str,
        error: io::Error,
    },
    /// Unit tests only: the swap was stopped after this step, as a kill
    /// would stop it. Production code never asks for this.
    #[doc(hidden)]
    Interrupted(SwapStep),
}

impl fmt::Display for RenewalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { since_unix } => {
                formatter.write_str("a renewal is already pending")?;
                if let Some(since) = since_unix {
                    write!(formatter, " (its key was written at unix time {since})")?;
                }
                formatter.write_str(
                    "; complete it with `credentials renew --certificate PATH`, or start over \
                     with `--discard-pending`, which makes a certificate issued for the pending \
                     request unusable",
                )
            }
            Self::NotPending => formatter.write_str(
                "no renewal is pending for this profile; run `credentials renew --csr-out PATH` \
                 first (the current credential is unchanged)",
            ),
            Self::Locked => formatter.write_str(
                "another renewal holds this profile's renewal lock; retry once it has finished",
            ),
            Self::Unsupported(reason) => formatter.write_str(reason),
            Self::UnsupportedPlatform => formatter.write_str(
                "credential renewal requires an owner-only filesystem ACL on this platform",
            ),
            Self::NoCurrentCredential(error) => write!(
                formatter,
                "there is no valid current credential to renew ({}); use `credentials create` \
                 and `credentials import` for a first credential",
                describe(error, "the current credential")
            ),
            Self::PendingKeyUnusable(error) => write!(
                formatter,
                "the pending renewal key cannot be used ({}); start over with \
                 `credentials renew --csr-out PATH --discard-pending`",
                describe(error, "the pending key")
            ),
            Self::CsrExists => formatter.write_str(
                "the CSR output already exists; renewal never overwrites a file, and no key \
                 was written",
            ),
            Self::CsrOutputIsCredential => formatter
                .write_str("the CSR output names one of the profile's own credential files"),
            Self::IssuedUnreadable(error) => {
                write!(formatter, "the issued certificate cannot be read: {error}")
            }
            Self::Refused(error) => write!(
                formatter,
                "the issued certificate was refused and the current credential is unchanged: {}",
                describe(error, "the issued certificate file")
            ),
            Self::IssuerChanged(reason) => write!(
                formatter,
                "the issued certificate was refused and the current credential is unchanged: \
                 {reason}; the relay trusts the issuer of the current certificate"
            ),
            Self::UntrustedChain(detail) => write!(
                formatter,
                "the issued certificate was refused and the current credential is unchanged: \
                 it does not verify to the issuer of the current certificate: {detail}"
            ),
            Self::ServerTrust(error) => write!(
                formatter,
                "the profile's configured server trust does not load ({}); the current \
                 credential is unchanged",
                describe(error, "the server CA file")
            ),
            Self::Io { step, error } => write!(
                formatter,
                "credential renewal failed at {step}: {error}; the current credential is still \
                 a valid pair"
            ),
            Self::Interrupted(step) => write!(formatter, "interrupted after {}", step.name()),
        }
    }
}

impl Error for RenewalError {}

/// A credential error's text with any path replaced by `role`.
fn describe(error: &CredentialError, role: &str) -> String {
    match error {
        CredentialError::NoCertificates(_) => format!("{role} holds no certificate"),
        CredentialError::NoPrivateKey(_) => format!("{role} holds no private key"),
        CredentialError::AlreadyExists(_) => format!("{role} already exists"),
        CredentialError::InsecurePermissions(_) => {
            format!("{role} is in a directory that is not owner-only")
        }
        CredentialError::Io(io) => format!("{role} cannot be read: {io}"),
        other => other.to_string(),
    }
}

#[cfg(unix)]
fn io_error(step: &'static str) -> impl FnOnce(io::Error) -> RenewalError {
    move |error| RenewalError::Io { step, error }
}

/// Whether the key at `key` is the certificate chain's at `certificate`.
fn pair_matches(key: &Path, certificate: &Path) -> bool {
    let (Ok(key), Ok(chain)) = (load_private_key(key), load_certificates(certificate)) else {
        return false;
    };
    !chain.is_empty() && crate::credentials::verify_certificate_key(&chain, key).is_ok()
}

fn modified_unix(path: &Path) -> Option<i64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let seconds = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    i64::try_from(seconds).ok()
}

/// Report a pending or interrupted renewal without changing anything.
#[must_use]
pub fn inspect(credentials: &CredentialConfig) -> RenewalState {
    let files = RenewalFiles::new(credentials);
    let pending = present(&files.pending_key);
    let pending_since_unix = pending.then(|| modified_unix(&files.pending_key)).flatten();
    let interrupted = !pair_matches(&files.key, &files.certificate)
        && ((pending && pair_matches(&files.pending_key, &files.certificate))
            || pair_matches(&files.key, &files.previous_certificate));
    let status = if interrupted {
        RenewalStatus::Interrupted
    } else if pending {
        RenewalStatus::Pending
    } else {
        RenewalStatus::None
    };
    RenewalState {
        status,
        pending_since_unix,
    }
}

/// The profile's renewal lock: an exclusive `flock` on `<key>.renew-lock`,
/// held while this value lives and released however the process ends.
#[cfg(unix)]
#[derive(Debug)]
struct RenewalLock {
    _file: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl RenewalLock {
    fn acquire(path: &Path, wait: std::time::Duration) -> Result<Self, RenewalError> {
        use rustix::fs::{FlockOperation, Mode, OFlags};
        let file = rustix::fs::open(
            path,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| io_error("the renewal lock")(io::Error::from(error)))?;
        let stat = rustix::fs::fstat(&file)
            .map_err(|error| io_error("the renewal lock")(io::Error::from(error)))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(RenewalError::Unsupported(
                "the renewal lock is not a regular file owned by this user",
            ));
        }
        let deadline = std::time::Instant::now() + wait;
        loop {
            match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Self { _file: file }),
                Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(rustix::io::Errno::WOULDBLOCK) => return Err(RenewalError::Locked),
                Err(error) => return Err(io_error("the renewal lock")(io::Error::from(error))),
            }
        }
    }
}

#[cfg(unix)]
fn lock(files: &RenewalFiles) -> Result<RenewalLock, RenewalError> {
    if !files.key.parent().is_none_or(|parent| {
        parent.as_os_str().is_empty() || fs::metadata(parent).is_ok_and(|m| m.is_dir())
    }) {
        return Err(RenewalError::NoCurrentCredential(CredentialError::Io(
            io::Error::from(io::ErrorKind::NotFound),
        )));
    }
    RenewalLock::acquire(&files.lock, RENEWAL_LOCK_WAIT)
}

/// Resolve an interrupted swap to one valid pair. The caller holds the lock.
#[cfg(unix)]
fn recover_locked(files: &RenewalFiles) -> Result<Option<Recovery>, RenewalError> {
    if pair_matches(&files.key, &files.certificate) {
        return Ok(None);
    }
    if present(&files.pending_key) && pair_matches(&files.pending_key, &files.certificate) {
        fs::rename(&files.pending_key, &files.key).map_err(io_error("recovery"))?;
        sync_parent(&files.key).map_err(|error| sync_error("recovery", error))?;
        return Ok(Some(Recovery::RolledForward));
    }
    if present(&files.previous_certificate) && pair_matches(&files.key, &files.previous_certificate)
    {
        fs::rename(&files.previous_certificate, &files.certificate)
            .map_err(io_error("recovery"))?;
        sync_parent(&files.certificate).map_err(|error| sync_error("recovery", error))?;
        return Ok(Some(Recovery::RolledBack));
    }
    Ok(None)
}

#[cfg(unix)]
fn sync_error(step: &'static str, error: CredentialError) -> RenewalError {
    match error {
        CredentialError::Io(error) => RenewalError::Io { step, error },
        other => RenewalError::Io {
            step,
            error: io::Error::other(other.to_string()),
        },
    }
}

/// Resolve an interrupted swap, under the renewal lock, for `connect`.
///
/// Does nothing -- and takes no lock, so creates no file -- unless a
/// renewal has left something behind, so a profile that has never been
/// renewed, or whose directory is read-only, starts exactly as before.
#[cfg(unix)]
pub fn recover(credentials: &CredentialConfig) -> Result<Option<Recovery>, RenewalError> {
    let files = RenewalFiles::new(credentials);
    if !files.has_renewal_artifacts() || files.check_layout().is_err() {
        return Ok(None);
    }
    let _lock = lock(&files)?;
    recover_locked(&files)
}

/// Renewal is Unix-only; elsewhere there is nothing to recover.
#[cfg(not(unix))]
pub fn recover(_credentials: &CredentialConfig) -> Result<Option<Recovery>, RenewalError> {
    Ok(None)
}

/// The current pair's chain, or why there is no valid current pair.
#[cfg(unix)]
fn current_chain(files: &RenewalFiles) -> Result<Vec<CertificateDer<'static>>, RenewalError> {
    let key = load_private_key(&files.key).map_err(RenewalError::NoCurrentCredential)?;
    let chain = load_certificates(&files.certificate).map_err(RenewalError::NoCurrentCredential)?;
    if chain.is_empty() {
        return Err(RenewalError::NoCurrentCredential(
            CredentialError::NoCertificates(files.certificate.clone()),
        ));
    }
    verify_certificate_key(&chain, key).map_err(RenewalError::NoCurrentCredential)?;
    Ok(chain)
}

/// Step one: write a pending key and its CSR beside the current pair.
#[cfg(unix)]
pub fn begin(
    config: &RuntimeConfig,
    csr_out: &Path,
    discard_pending: bool,
) -> Result<RenewalRequest, RenewalError> {
    let files = RenewalFiles::new(&config.credentials);
    files.check_layout()?;
    if files.managed().contains(&csr_out)
        || csr_out == config.credentials.server_ca
        || csr_out == files.lock
    {
        return Err(RenewalError::CsrOutputIsCredential);
    }
    let _lock = lock(&files)?;
    let recovered = recover_locked(&files)?;
    current_chain(&files)?;
    if present(csr_out) {
        return Err(RenewalError::CsrExists);
    }
    let pending = present(&files.pending_key);
    if pending && !discard_pending {
        return Err(RenewalError::Pending {
            since_unix: modified_unix(&files.pending_key),
        });
    }
    if pending {
        fs::remove_file(&files.pending_key).map_err(io_error("discarding the pending key"))?;
    }
    // A staged certificate without a pending key belongs to no renewal.
    remove_if_present(&files.staged_certificate, "clearing a staged certificate")?;

    ensure_parent(&files.key, true).map_err(|error| sync_error("the key directory", error))?;
    ensure_parent(csr_out, false).map_err(|error| sync_error("the CSR directory", error))?;
    let (key_pem, csr_pem) = generate_request(&config.device_id)
        .map_err(|error| sync_error("generating the key", error))?;
    write_new(&files.pending_key, key_pem.as_bytes(), true)
        .map_err(|error| sync_error("writing the pending key", error))?;
    if let Err(error) = write_new(csr_out, csr_pem.as_bytes(), false) {
        // Leave nothing behind: a retry must not be refused as pending.
        let _ = fs::remove_file(&files.pending_key);
        return Err(match error {
            CredentialError::AlreadyExists(_) => RenewalError::CsrExists,
            other => sync_error("writing the CSR", other),
        });
    }
    sync_parent(&files.pending_key)
        .map_err(|error| sync_error("writing the pending key", error))?;
    Ok(RenewalRequest {
        discarded_pending: pending,
        recovered,
    })
}

/// Renewal is refused where there is no owner-only file mode.
#[cfg(not(unix))]
pub fn begin(
    _config: &RuntimeConfig,
    _csr_out: &Path,
    _discard_pending: bool,
) -> Result<RenewalRequest, RenewalError> {
    Err(RenewalError::UnsupportedPlatform)
}

#[cfg(unix)]
fn remove_if_present(path: &Path, step: &'static str) -> Result<(), RenewalError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RenewalError::Io { step, error }),
    }
}

/// Step three: check the issued certificate and swap the pair in.
#[cfg(unix)]
pub fn complete(config: &RuntimeConfig, issued: &Path) -> Result<Renewed, RenewalError> {
    complete_with(
        config,
        issued,
        crate::credentials::unix_now(),
        &mut abort_after_if_asked,
    )
}

/// Renewal is refused where there is no owner-only file mode.
#[cfg(not(unix))]
pub fn complete(_config: &RuntimeConfig, _issued: &Path) -> Result<Renewed, RenewalError> {
    Err(RenewalError::UnsupportedPlatform)
}

/// The process-level interruption hook: in a debug build, abort -- no
/// destructor, no cleanup, as a kill -- right after the step named by
/// [`RENEW_ABORT_AFTER_ENV`]. Release builds compile none of it.
#[cfg(unix)]
fn abort_after_if_asked(step: SwapStep) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os(RENEW_ABORT_AFTER_ENV).is_some_and(|value| value == step.name()) {
        eprintln!("tunnel-client: test hook aborting after {}", step.name());
        std::process::abort();
    }
    let _ = step;
    false
}

/// [`complete`] against an explicit clock, with `interrupt` asked after each
/// swap step; `true` stops the swap there as a kill would.
#[cfg(unix)]
fn complete_with(
    config: &RuntimeConfig,
    issued_path: &Path,
    now_unix: i64,
    interrupt: &mut dyn FnMut(SwapStep) -> bool,
) -> Result<Renewed, RenewalError> {
    let files = RenewalFiles::new(&config.credentials);
    files.check_layout()?;
    let _lock = lock(&files)?;
    let recovered = recover_locked(&files)?;
    let pending_present = present(&files.pending_key);
    // Read once: every check and the installed file see the same bytes.
    let issued = match fs::read(issued_path) {
        Ok(issued) => issued,
        Err(_) if !pending_present => return Err(RenewalError::NotPending),
        Err(error) => return Err(RenewalError::IssuedUnreadable(error)),
    };
    let current = current_chain(&files)?;
    // A re-run after the swap completed is answered, not refused.
    let already_installed =
        !pending_present && fs::read(&files.certificate).is_ok_and(|installed| installed == issued);
    if !pending_present && !already_installed {
        return Err(RenewalError::NotPending);
    }
    let chain = certificates_from_pem(&issued).map_err(RenewalError::Refused)?;
    let Some(leaf) = chain.first() else {
        return Err(RenewalError::Refused(CredentialError::NoCertificates(
            issued_path.to_owned(),
        )));
    };
    if already_installed {
        let (not_before_unix, not_after_unix) = validity(leaf)?;
        return Ok(Renewed {
            certificate_count: chain.len(),
            not_before_unix,
            not_after_unix,
            not_yet_valid_until: (not_before_unix > now_unix).then_some(not_before_unix),
            already_installed: true,
            recovered,
        });
    }
    let pending = load_private_key(&files.pending_key).map_err(RenewalError::PendingKeyUnusable)?;
    // The checks `credentials import` makes, in its order.
    verify_certificate_key(&chain, pending).map_err(RenewalError::Refused)?;
    verify_device_role(leaf, &config.device_id).map_err(RenewalError::Refused)?;
    let not_yet_valid_until =
        check_import_validity(leaf, now_unix).map_err(RenewalError::Refused)?;
    verify_issuer_continuity(&current, &chain, now_unix)?;
    let trust =
        load_certificates(&config.credentials.server_ca).map_err(RenewalError::ServerTrust)?;
    if trust.is_empty() {
        return Err(RenewalError::ServerTrust(CredentialError::NoCertificates(
            config.credentials.server_ca.clone(),
        )));
    }
    let (not_before_unix, not_after_unix) = validity(leaf)?;
    swap(&files, &issued, interrupt)?;
    Ok(Renewed {
        certificate_count: chain.len(),
        not_before_unix,
        not_after_unix,
        not_yet_valid_until,
        already_installed: false,
        recovered,
    })
}

#[cfg(unix)]
fn validity(leaf: &CertificateDer<'_>) -> Result<(i64, i64), RenewalError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|error| {
        RenewalError::Refused(CredentialError::CertificateUnparseable(error.to_string()))
    })?;
    let validity = parsed.validity();
    Ok((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

/// The issued certificate must come from the issuer of the current one,
/// which is the issuer the relay has been accepting for this device.
///
/// Always: the same issuer name, and the same authority key identifier when
/// the current certificate carries one. When the current certificate file
/// also carries its issuer (a chain of two or more), the issued chain must
/// verify to those certificates with the TLS stack's own client-certificate
/// verifier -- the check the relay makes, anchored on what this profile
/// already trusts rather than on anything the issued file supplies.
#[cfg(unix)]
fn verify_issuer_continuity(
    current: &[CertificateDer<'static>],
    issued: &[CertificateDer<'static>],
    now_unix: i64,
) -> Result<(), RenewalError> {
    use x509_parser::extensions::ParsedExtension;
    fn parse<'a>(
        der: &'a CertificateDer<'_>,
    ) -> Result<x509_parser::certificate::X509Certificate<'a>, RenewalError> {
        x509_parser::parse_x509_certificate(der.as_ref())
            .map(|(_, parsed)| parsed)
            .map_err(|error| {
                RenewalError::Refused(CredentialError::CertificateUnparseable(error.to_string()))
            })
    }
    let (old, new) = (parse(&current[0])?, parse(&issued[0])?);
    if old.issuer().as_raw() != new.issuer().as_raw() {
        return Err(RenewalError::IssuerChanged(
            "it names a different issuer than the current certificate",
        ));
    }
    let authority_key = |certificate: &x509_parser::certificate::X509Certificate<'_>| {
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(identifier) => identifier
                    .key_identifier
                    .as_ref()
                    .map(|identifier| identifier.0.to_vec()),
                _ => None,
            })
    };
    if let Some(expected) = authority_key(&old)
        && authority_key(&new).as_ref() != Some(&expected)
    {
        return Err(RenewalError::IssuerChanged(
            "it was signed by a different issuer key than the current certificate",
        ));
    }
    let anchors = &current[1..];
    if anchors.is_empty() {
        return Ok(());
    }
    let mut roots = rustls::RootCertStore::empty();
    for anchor in anchors {
        roots
            .add(anchor.clone())
            .map_err(|error| RenewalError::UntrustedChain(error.to_string()))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        std::sync::Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|error| RenewalError::UntrustedChain(error.to_string()))?;
    // Judged inside the certificate's own window: a certificate not yet
    // valid on this clock is accepted here exactly as import accepts it.
    let (not_before, _) = validity(&issued[0])?;
    let at = u64::try_from(now_unix.max(not_before)).unwrap_or(0);
    rustls::server::danger::ClientCertVerifier::verify_client_cert(
        verifier.as_ref(),
        &issued[0],
        &issued[1..],
        rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(at)),
    )
    .map(|_| ())
    .map_err(|error| RenewalError::UntrustedChain(error.to_string()))
}

/// The rename sequence in the module table. `interrupt` is asked after each
/// step; `true` stops there with every file as that step left it.
#[cfg(unix)]
fn swap(
    files: &RenewalFiles,
    issued: &[u8],
    interrupt: &mut dyn FnMut(SwapStep) -> bool,
) -> Result<(), RenewalError> {
    let mut after = |step: SwapStep| {
        if interrupt(step) {
            Err(RenewalError::Interrupted(step))
        } else {
            Ok(())
        }
    };
    remove_if_present(&files.staged_certificate, "staging the certificate")?;
    write_new(&files.staged_certificate, issued, false)
        .map_err(|error| sync_error("staging the certificate", error))?;
    sync_parent(&files.staged_certificate)
        .map_err(|error| sync_error("staging the certificate", error))?;
    after(SwapStep::CertificateStaged)?;

    remove_if_present(&files.previous_key, "clearing the previous key")?;
    after(SwapStep::PreviousKeyCleared)?;
    remove_if_present(
        &files.previous_certificate,
        "clearing the previous certificate",
    )?;
    after(SwapStep::PreviousCertificateCleared)?;
    keep(
        &files.key,
        &files.previous_key,
        true,
        "keeping the previous key",
    )?;
    after(SwapStep::PreviousKeyKept)?;
    keep(
        &files.certificate,
        &files.previous_certificate,
        false,
        "keeping the previous certificate",
    )?;
    after(SwapStep::PreviousCertificateKept)?;

    fs::rename(&files.staged_certificate, &files.certificate)
        .map_err(io_error("installing the certificate"))?;
    sync_parent(&files.certificate)
        .map_err(|error| sync_error("installing the certificate", error))?;
    after(SwapStep::CertificateInstalled)?;

    if let Err(error) = fs::rename(&files.pending_key, &files.key) {
        // Not a crash: put the previous certificate back now, so the
        // refusal leaves the old pair. The pending key stays for a retry.
        let _ = fs::rename(&files.previous_certificate, &files.certificate);
        let _ = sync_parent(&files.certificate);
        return Err(RenewalError::Io {
            step: "installing the key",
            error,
        });
    }
    sync_parent(&files.key).map_err(|error| sync_error("installing the key", error))?;
    after(SwapStep::KeyInstalled)?;
    Ok(())
}

/// Keep `from` at `to`: a hard link, or a private copy where the filesystem
/// has none.
#[cfg(unix)]
fn keep(from: &Path, to: &Path, private: bool, step: &'static str) -> Result<(), RenewalError> {
    match fs::hard_link(from, to) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(RenewalError::Io { step, error });
        }
        Err(_) => {
            let bytes = fs::read(from).map_err(io_error(step))?;
            write_new(to, &bytes, private).map_err(|error| sync_error(step, error))?;
        }
    }
    sync_parent(to).map_err(|error| sync_error(step, error))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyPair, SanType};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const DEVICE: &str = "44444444-4444-4444-8444-444444444444";

    /// A synthetic issuer, generated per test.
    struct Issuer {
        key: KeyPair,
        certificate: rcgen::Certificate,
    }

    impl Issuer {
        fn new(name: &str) -> Self {
            let key = KeyPair::generate().expect("issuer key");
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_identifier_method = KeyIdMethod::Sha256;
            let certificate = params.self_signed(&key).expect("issuer certificate");
            Self { key, certificate }
        }

        /// A device certificate for the public key in `key_pem`.
        fn issue(&self, key_pem: &str, device: &str) -> String {
            let subject = KeyPair::from_pem(key_pem).expect("subject key");
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, format!("device/{device}"));
            params.subject_alt_names = vec![SanType::URI(
                format!("urn:agent-tunnel:device:{device}")
                    .try_into()
                    .expect("URI SAN"),
            )];
            params.use_authority_key_identifier_extension = true;
            params.not_before = rcgen::date_time_ymd(2024, 1, 1);
            params.not_after = rcgen::date_time_ymd(2099, 1, 1);
            params
                .signed_by(&subject, &self.certificate, &self.key)
                .expect("device certificate")
                .pem()
        }
    }

    struct Profile {
        _dir: TempDir,
        config: RuntimeConfig,
        files: RenewalFiles,
        csr: PathBuf,
        issued: PathBuf,
    }

    impl Profile {
        /// A profile with a current pair from `issuer`; `with_issuer` also
        /// puts the issuer's certificate in the current chain file.
        fn new(issuer: &Issuer, with_issuer: bool) -> Self {
            let dir = tempfile::tempdir().expect("profile directory");
            let credentials = dir.path().join("credentials");
            fs::create_dir(&credentials).expect("credential directory");
            let mut config = RuntimeConfig {
                device_id: DEVICE.to_owned(),
                ..RuntimeConfig::default()
            };
            config.credentials.client_key = credentials.join("device-key.pem");
            config.credentials.client_certificate = credentials.join("device-cert.pem");
            config.credentials.server_ca = credentials.join("server-ca.pem");
            let key = KeyPair::generate().expect("current key");
            let mut chain = issuer.issue(&key.serialize_pem(), DEVICE);
            if with_issuer {
                chain.push_str(&issuer.certificate.pem());
            }
            fs::write(&config.credentials.client_key, key.serialize_pem()).expect("key");
            fs::set_permissions(
                &config.credentials.client_key,
                fs::Permissions::from_mode(0o600),
            )
            .expect("key mode");
            fs::write(&config.credentials.client_certificate, chain).expect("certificate");
            fs::write(&config.credentials.server_ca, issuer.certificate.pem()).expect("trust");
            let files = RenewalFiles::new(&config.credentials);
            Self {
                csr: dir.path().join("renew.csr"),
                issued: dir.path().join("issued.pem"),
                _dir: dir,
                config,
                files,
            }
        }

        fn begin(&self) -> String {
            begin(&self.config, &self.csr, false).expect("begin renewal");
            fs::read_to_string(&self.files.pending_key).expect("pending key")
        }

        fn pair(&self) -> (Vec<u8>, Vec<u8>) {
            (
                fs::read(&self.files.key).expect("key"),
                fs::read(&self.files.certificate).expect("certificate"),
            )
        }

        fn complete(&self) -> Result<Renewed, RenewalError> {
            complete_with(&self.config, &self.issued, 1_800_000_000, &mut |_| false)
        }

        fn assert_one_valid_pair(&self) {
            assert!(
                pair_matches(&self.files.key, &self.files.certificate),
                "the profile's key and certificate must be a pair"
            );
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn begin_writes_an_owner_only_pending_key_and_leaves_the_pair_untouched() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        let before = profile.pair();
        let pending = profile.begin();
        assert_eq!(profile.pair(), before, "the current pair was touched");
        assert_eq!(mode(&profile.files.pending_key), 0o600);
        assert_eq!(mode(profile.files.key.parent().expect("dir")), 0o700);
        let csr = fs::read_to_string(&profile.csr).expect("CSR");
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(!csr.contains("PRIVATE KEY"), "the CSR carries no key");
        assert_ne!(pending.as_bytes(), before.0.as_slice(), "a new key");
        assert_eq!(
            inspect(&profile.config.credentials).status,
            RenewalStatus::Pending
        );
    }

    #[test]
    fn a_pending_renewal_is_never_replaced_without_discard() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        let first = profile.begin();
        fs::remove_file(&profile.csr).expect("carry the CSR away");
        let refused = begin(&profile.config, &profile.csr, false).expect_err("stale pending");
        assert!(matches!(
            refused,
            RenewalError::Pending {
                since_unix: Some(_)
            }
        ));
        assert_eq!(
            fs::read_to_string(&profile.files.pending_key).expect("pending"),
            first,
            "the pending key was replaced"
        );
        assert!(!profile.csr.exists(), "a refusal wrote a CSR");
        let request = begin(&profile.config, &profile.csr, true).expect("discard and restart");
        assert!(request.discarded_pending);
        assert_ne!(
            fs::read_to_string(&profile.files.pending_key).expect("pending"),
            first
        );
    }

    #[test]
    fn an_existing_csr_output_is_refused_before_anything_is_written_or_discarded() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        let first = profile.begin();
        let refused = begin(&profile.config, &profile.csr, true).expect_err("CSR exists");
        assert!(matches!(refused, RenewalError::CsrExists), "{refused}");
        assert_eq!(
            fs::read_to_string(&profile.files.pending_key).expect("pending"),
            first,
            "the pending key was discarded by a refused request"
        );
    }

    #[test]
    fn begin_without_a_current_pair_is_refused() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        fs::write(
            &profile.files.key,
            KeyPair::generate().expect("k").serialize_pem(),
        )
        .expect("mismatched key");
        let refused = begin(&profile.config, &profile.csr, false).expect_err("no pair");
        assert!(
            matches!(refused, RenewalError::NoCurrentCredential(_)),
            "{refused}"
        );
        assert!(!profile.files.pending_key.exists());
    }

    #[test]
    fn a_matching_certificate_from_the_same_issuer_is_swapped_in() {
        for with_issuer in [false, true] {
            let issuer = Issuer::new("synthetic renewal issuer");
            let profile = Profile::new(&issuer, with_issuer);
            let before = profile.pair();
            let pending = profile.begin();
            fs::write(&profile.issued, issuer.issue(&pending, DEVICE)).expect("issued");
            let renewed = profile.complete().expect("renewal completes");
            assert!(!renewed.already_installed);
            assert_eq!(
                fs::read_to_string(&profile.files.key).expect("key"),
                pending,
                "the pending key is the key"
            );
            assert_eq!(mode(&profile.files.key), 0o600);
            profile.assert_one_valid_pair();
            assert!(!profile.files.pending_key.exists());
            assert!(!profile.files.staged_certificate.exists());
            assert_eq!(
                fs::read(&profile.files.previous_key).expect("kept"),
                before.0
            );
            assert_eq!(
                fs::read(&profile.files.previous_certificate).expect("kept"),
                before.1
            );
            assert_eq!(
                inspect(&profile.config.credentials).status,
                RenewalStatus::None
            );
            // Re-running the same import answers rather than refuses.
            assert!(profile.complete().expect("re-run").already_installed);
        }
    }

    /// The refusals: every one leaves the old pair byte-for-byte, and the
    /// pending key in place for a retry with the right certificate.
    #[test]
    fn a_refused_certificate_leaves_the_old_pair_untouched() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let impostor_same_name = Issuer::new("synthetic renewal issuer");
        let other = Issuer::new("another synthetic issuer");
        type Issue<'a> = Box<dyn Fn(&str) -> String + 'a>;
        let cases: Vec<(&str, bool, Issue<'_>)> = vec![
            (
                "certificate for another key",
                false,
                Box::new(|_| {
                    issuer.issue(&KeyPair::generate().expect("k").serialize_pem(), DEVICE)
                }),
            ),
            (
                "certificate for another device",
                false,
                Box::new(|pending| issuer.issue(pending, "55555555-5555-4555-8555-555555555555")),
            ),
            (
                "certificate from an issuer with another name",
                false,
                Box::new(|pending| other.issue(pending, DEVICE)),
            ),
            (
                "certificate from another issuer key, same name, leaf-only profile",
                false,
                Box::new(|pending| impostor_same_name.issue(pending, DEVICE)),
            ),
            (
                "certificate from another issuer key, same name, chained profile",
                true,
                Box::new(|pending| impostor_same_name.issue(pending, DEVICE)),
            ),
        ];
        for (label, with_issuer, issue) in cases {
            let profile = Profile::new(&issuer, with_issuer);
            let before = profile.pair();
            let pending = profile.begin();
            fs::write(&profile.issued, issue(&pending)).expect("issued");
            let refused = profile.complete().expect_err(label);
            match label {
                "certificate for another key" => assert!(
                    matches!(
                        refused,
                        RenewalError::Refused(CredentialError::KeyMismatch(_))
                    ),
                    "{label}: {refused}"
                ),
                "certificate for another device" => assert!(
                    matches!(
                        refused,
                        RenewalError::Refused(CredentialError::DeviceIdMismatch { .. })
                    ),
                    "{label}: {refused}"
                ),
                "certificate from an issuer with another name" => assert!(
                    matches!(refused, RenewalError::IssuerChanged(_)),
                    "{label}: {refused}"
                ),
                _ => assert!(
                    matches!(
                        refused,
                        RenewalError::IssuerChanged(_) | RenewalError::UntrustedChain(_)
                    ),
                    "{label}: {refused}"
                ),
            }
            assert_eq!(profile.pair(), before, "{label}: the old pair changed");
            assert_eq!(
                fs::read_to_string(&profile.files.pending_key).expect("pending"),
                pending,
                "{label}: the pending key was lost"
            );
            assert!(!profile.files.staged_certificate.exists(), "{label}");
            assert!(!profile.files.previous_key.exists(), "{label}");
            let message = refused.to_string();
            assert!(
                !message.contains(&*profile.files.key.to_string_lossy()),
                "{message}"
            );
        }
    }

    /// The cryptographic check alone: an impostor issuer copying the real
    /// issuer's name *and* its key identifier is refused only because the
    /// chain does not verify to the issuer the current file carries.
    #[test]
    fn an_impostor_copying_the_issuer_name_and_key_id_is_refused_by_the_chain() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, true);
        let before = profile.pair();
        let pending = profile.begin();
        // Forge: an impostor key whose certificate claims the real issuer's
        // subject key identifier, so the name and AKI checks both pass.
        let real_ski = {
            let (_, parsed) =
                x509_parser::parse_x509_certificate(issuer.certificate.der()).expect("issuer");
            parsed
                .extensions()
                .iter()
                .find_map(|extension| match extension.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) => {
                        Some(id.0.to_vec())
                    }
                    _ => None,
                })
                .expect("issuer SKI")
        };
        let impostor_key = KeyPair::generate().expect("impostor key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "synthetic renewal issuer");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_identifier_method = KeyIdMethod::PreSpecified(real_ski);
        let impostor = Issuer {
            certificate: params.self_signed(&impostor_key).expect("impostor"),
            key: impostor_key,
        };
        fs::write(&profile.issued, impostor.issue(&pending, DEVICE)).expect("issued");
        let refused = profile.complete().expect_err("forged issuer");
        assert!(
            matches!(refused, RenewalError::UntrustedChain(_)),
            "{refused}"
        );
        assert_eq!(profile.pair(), before);
    }

    #[test]
    fn completing_without_a_pending_renewal_is_refused() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        let before = profile.pair();
        let key = KeyPair::generate().expect("k").serialize_pem();
        fs::write(&profile.issued, issuer.issue(&key, DEVICE)).expect("issued");
        let refused = profile.complete().expect_err("nothing pending");
        assert!(matches!(refused, RenewalError::NotPending), "{refused}");
        assert_eq!(profile.pair(), before);
    }

    /// The crash-safety property, step by step: stop the swap after each
    /// file operation, exactly as a kill leaves the files, then recover.
    /// Every stop recovers to one valid pair -- the old one before the
    /// certificate rename, the new one from it on -- and only the stop after
    /// the certificate rename leaves a mismatched pair at rest at all.
    #[test]
    fn an_interrupted_swap_recovers_to_one_valid_pair_at_every_step() {
        for (index, stop) in SwapStep::ALL.into_iter().enumerate() {
            let issuer = Issuer::new("synthetic renewal issuer");
            let profile = Profile::new(&issuer, true);
            let old = profile.pair();
            let pending = profile.begin();
            let issued = issuer.issue(&pending, DEVICE);
            fs::write(&profile.issued, &issued).expect("issued");
            let mut seen = Vec::new();
            let interrupted = complete_with(
                &profile.config,
                &profile.issued,
                1_800_000_000,
                &mut |step| {
                    seen.push(step);
                    step == stop
                },
            )
            .expect_err("stopped");
            assert!(matches!(interrupted, RenewalError::Interrupted(step) if step == stop));
            assert_eq!(seen, SwapStep::ALL[..=index], "steps run in order");

            let at_rest_valid = pair_matches(&profile.files.key, &profile.files.certificate);
            assert_eq!(
                at_rest_valid,
                stop != SwapStep::CertificateInstalled,
                "{stop:?}: only the stop between the two renames leaves a mismatch"
            );
            let expected_status = if at_rest_valid {
                if stop == SwapStep::KeyInstalled {
                    RenewalStatus::None
                } else {
                    RenewalStatus::Pending
                }
            } else {
                RenewalStatus::Interrupted
            };
            assert_eq!(
                inspect(&profile.config.credentials).status,
                expected_status,
                "{stop:?}"
            );

            let recovered = recover(&profile.config.credentials).expect("recover");
            profile.assert_one_valid_pair();
            let new_pair = index >= 5;
            if new_pair {
                assert_eq!(
                    fs::read_to_string(&profile.files.key).expect("key"),
                    pending
                );
                assert_eq!(
                    fs::read_to_string(&profile.files.certificate).expect("cert"),
                    issued
                );
            } else {
                assert_eq!(profile.pair(), old, "{stop:?}: the old pair changed");
            }
            assert_eq!(
                recovered,
                (stop == SwapStep::CertificateInstalled).then_some(Recovery::RolledForward),
                "{stop:?}"
            );
            // And the same import, re-run, completes or answers.
            let rerun = profile.complete().expect("re-run completes");
            assert_eq!(rerun.already_installed, new_pair, "{stop:?}");
            profile.assert_one_valid_pair();
            assert_eq!(
                fs::read_to_string(&profile.files.key).expect("key"),
                pending
            );
        }
    }

    #[test]
    fn a_kept_previous_certificate_rolls_a_foreign_mismatch_back() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        let old = profile.pair();
        fs::copy(
            &profile.files.certificate,
            &profile.files.previous_certificate,
        )
        .expect("keep");
        let stray = KeyPair::generate().expect("k").serialize_pem();
        fs::write(&profile.files.certificate, issuer.issue(&stray, DEVICE)).expect("stray");
        assert_eq!(
            inspect(&profile.config.credentials).status,
            RenewalStatus::Interrupted
        );
        assert_eq!(
            recover(&profile.config.credentials).expect("recover"),
            Some(Recovery::RolledBack)
        );
        assert_eq!(profile.pair(), old);
    }

    #[test]
    fn recovery_without_renewal_artifacts_creates_nothing() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        assert_eq!(recover(&profile.config.credentials).expect("recover"), None);
        assert!(!profile.files.lock.exists(), "a lock file was created");
    }

    #[test]
    fn a_held_renewal_lock_refuses_a_second_renewal() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let profile = Profile::new(&issuer, false);
        let _held = RenewalLock::acquire(&profile.files.lock, std::time::Duration::ZERO)
            .expect("first lock");
        let refused =
            RenewalLock::acquire(&profile.files.lock, std::time::Duration::from_millis(60))
                .expect_err("second lock");
        assert!(matches!(refused, RenewalError::Locked), "{refused}");
    }

    #[test]
    fn a_layout_that_rename_cannot_renew_is_refused() {
        let issuer = Issuer::new("synthetic renewal issuer");
        let mut profile = Profile::new(&issuer, false);
        profile.config.credentials.client_certificate =
            profile.config.credentials.client_key.clone();
        assert!(matches!(
            begin(&profile.config, &profile.csr, false),
            Err(RenewalError::Unsupported(_))
        ));
        let profile = Profile::new(&issuer, false);
        let target = profile.files.key.with_file_name("real-key.pem");
        fs::rename(&profile.files.key, &target).expect("move");
        std::os::unix::fs::symlink(&target, &profile.files.key).expect("link");
        assert!(matches!(
            begin(&profile.config, &profile.csr, false),
            Err(RenewalError::Unsupported(_))
        ));
        let profile = Profile::new(&issuer, false);
        for into in [
            profile.files.pending_key.clone(),
            profile.files.key.clone(),
            profile.config.credentials.server_ca.clone(),
        ] {
            assert!(
                matches!(
                    begin(&profile.config, &into, false),
                    Err(RenewalError::CsrOutputIsCredential)
                ),
                "{}",
                into.display()
            );
        }
        assert!(!profile.files.pending_key.exists());
    }
}
