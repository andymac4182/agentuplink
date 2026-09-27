//! Runtime ownership of the signed M7 membership directory.
//!
//! The cluster crate contains the pure signature and version verifier.  This
//! module supplies the missing process boundary around it: a fresh checkpoint
//! is obtained from an operator-provisioned HTTPS authority, the opaque Redis
//! record is read through the catalog, and only then is a peer admitted.  The
//! runtime deliberately keeps no private signing material and never treats a
//! Redis value as a trust anchor.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
#[cfg(test)]
use chrono::Duration as ChronoDuration;
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, Uri, body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    sync::{Mutex as AsyncMutex, Notify, RwLock},
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{SharedCatalog, SignedMembershipRecord as CatalogMembershipRecord};
use tunnel_cluster::membership::{
    MAX_AUTHORIZED_NODES, MAX_RECORD_BYTES, MembershipError, MembershipPolicy, MembershipVerifier,
    MembershipVersionState, PrivateEndpointPolicy, TrustedPublisherKey, VerifiedMembership,
    VerifiedPeerBinding,
};

use crate::{
    config::ClusterConfig,
    membership_version_state::{MembershipVersionStateStore, MembershipVersionStateStoreError},
    peer_runtime::peer_readiness::PeerRouteTarget,
};

/// The largest checkpoint request/response body accepted by this runtime.
pub const MAX_CHECKPOINT_BYTES: usize = MAX_RECORD_BYTES;
/// The largest operator authority endpoint accepted by the HTTP adapter.
pub const MAX_AUTHORITY_ENDPOINT_BYTES: usize = 2_048;
/// A checkpoint authority request never waits longer than this value unless a
/// stricter deployment value is configured.
pub const MAX_CHECKPOINT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// A local membership-fence write is small and bounded.  If the filesystem
/// does not complete within this deadline the runtime remains unready while it
/// joins the still-running blocking task before another reconcile can start.
pub const MAX_MEMBERSHIP_PERSISTENCE_TIMEOUT: Duration = Duration::from_secs(2);
/// A reconciliation pass may never retain more than this many records.
pub const MAX_MEMBERSHIP_RECORDS: usize = MAX_AUTHORIZED_NODES;
/// Consecutive reconcile passes that must each conclude
/// [`MembershipUnreadyReason::MissingLocalKey`] before this relay surrenders
/// the device ownership it holds (task row M7-C181). The same count confirms
/// a checkpoint that omits this node entirely (M7-C182, case (a)).
///
/// **Coordinator decision under the owner's delegation (2026-09-27).** Two:
/// the pass that first observes the condition, and one independent
/// confirming pass. One pass is never enough, so a single bad read of a
/// record cannot close a fleet of device sessions. The confirming pass is
/// the next completed pass, so the surrender starts **no later than** about
/// one reconcile interval (1 to 5 s by configuration) after the first
/// observation -- an upper bound, not a guaranteed gap: a pass woken early
/// by a membership notification can confirm sooner, and a slow or failing
/// authority can delay it (a failure resets the count). No minimum elapsed
/// time is added: the two passes each fetch a fresh nonce-bound checkpoint
/// and re-read the catalog, so the confirmation is independent evidence
/// whatever the gap, and the publish race that *does* need time to settle is
/// handled separately ([`SurrenderBounds::local_record_below_minimum`]). Any
/// pass that concludes anything else -- `Ready`, a transient read or
/// checkpoint failure, an expiry -- resets the count, so the surrender can
/// only ever be later than this bound, never earlier.
pub const OWN_KEY_SURRENDER_CONFIRMATIONS: u32 = 2;

/// Why this relay must give up the device ownership it holds while its
/// membership is unready (M7-C181, M7-C182, M7-C184).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipSurrenderCause {
    /// This relay's own verified record no longer approves the key it
    /// serves, confirmed by [`OWN_KEY_SURRENDER_CONFIRMATIONS`] passes
    /// (M7-C181).
    OwnKeyRetired,
    /// A fresh signed checkpoint does not name this node at all: a signed
    /// removal, confirmed by [`OWN_KEY_SURRENDER_CONFIRMATIONS`] passes
    /// (M7-C182, case (a)).
    NodeRemoved,
    /// The checkpoint names this node, but no verified record for it reaches
    /// the checkpoint's minimum version, and that has persisted for
    /// [`SurrenderBounds::local_record_below_minimum`] (M7-C182, case (b)).
    LocalRecordBelowMinimum,
    /// Membership has been unready for a reason other than an unreachable
    /// catalog for [`SurrenderBounds::prolonged_unready`] (M7-C184).
    ProlongedUnready,
}

impl OwnershipSurrenderCause {
    /// A bounded, payload-free diagnostic label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OwnKeyRetired => "own_key_retired",
            Self::NodeRemoved => "node_removed",
            Self::LocalRecordBelowMinimum => "local_record_below_minimum",
            Self::ProlongedUnready => "prolonged_unready",
        }
    }
}

/// The time-based ownership surrender bounds (M7-C182, M7-C184).
///
/// Both are derived from configuration by [`SurrenderBounds::derive`]; the
/// field-level documents give the reasoning. Tests may shorten them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurrenderBounds {
    /// How long a local record below the checkpoint's minimum version must
    /// persist before it is treated as a removal (M7-C182, case (b)).
    ///
    /// **Coordinator decision under the owner's delegation (2026-09-27).**
    /// One membership record lifetime plus the accepted clock skew (60 s +
    /// 5 s = 65 s at the configured maximum). No record at the minimum is
    /// what a publish race produces: the authority's checkpoint names the
    /// node at a version whose record has not reached Redis yet. A
    /// publisher that is alive re-signs within one record lifetime, so a
    /// gap still present after a whole lifetime plus skew is not a race in
    /// flight but a publisher that is not going to publish this node. (A
    /// record that is in Redis but below the minimum fails verification and
    /// is `MembershipRejected`, bounded by `prolonged_unready` instead.)
    pub local_record_below_minimum: Duration,
    /// How long membership may stay unready, for any reason except an
    /// unreachable catalog, before ownership is surrendered (M7-C184).
    ///
    /// **Coordinator decision under the owner's delegation (2026-09-27).**
    /// The longest owner lease (30 s) plus a margin of one record lifetime
    /// plus skew (65 s): 95 s at the configured maxima. The lease term is
    /// the point of the rule -- a relay that stopped renewing would have lost
    /// every device within one lease, so an unready relay that keeps
    /// renewing should not hold them much longer than that. The margin keeps
    /// the rule clear of every routine signed-evidence window: a missed
    /// re-sign or a publish race heals within one record lifetime plus skew,
    /// the default rekey convergence hold is the same 65 s and never makes
    /// the relay unready, and every more specific rule (M7-C181, M7-C182)
    /// fires first. Time while the catalog is unreachable does not count:
    /// the relay cannot renew leases then, so they lapse on their own. Nor
    /// does time inside a shared control-plane outage -- the checkpoint
    /// authority unreachable, or the publisher no longer re-signing any
    /// record -- which leaves every relay equally unready, so a surrender
    /// would only move devices between relays that cannot serve them
    /// (M7-C186).
    pub prolonged_unready: Duration,
}

impl SurrenderBounds {
    /// Derive both bounds from the membership record lifetime, the accepted
    /// clock skew, and the longest owner lease.
    #[must_use]
    pub fn derive(membership_record_lifetime: Duration, max_clock_skew: Duration) -> Self {
        let local_record_below_minimum = membership_record_lifetime.saturating_add(max_clock_skew);
        Self {
            local_record_below_minimum,
            prolonged_unready: crate::config::MAX_OWNER_LEASE
                .saturating_add(local_record_below_minimum),
        }
    }
}

/// Which local-membership gap a reconcile pass concluded (M7-C182).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalMembershipGap {
    /// The fresh checkpoint does not name this node.
    NodeOmitted,
    /// The checkpoint names this node, but no verified record for it reaches
    /// the checkpoint's minimum version.
    BelowMinimum,
}

/// Boxed async boundary used by the injectable authority and catalog source.
pub type MembershipFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A fresh nonce and deployment identity sent to the external checkpoint
/// authority.  The nonce is generated by the relay process and is never read
/// from Redis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckpointRequest {
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub nonce: String,
}

impl CheckpointRequest {
    fn validate(&self) -> Result<(), CheckpointAuthorityError> {
        if self.deployment_id.trim().is_empty()
            || self.deployment_id.len() > 128
            || self.deployment_incarnation.trim().is_empty()
            || self.deployment_incarnation.len() > 128
            || self
                .deployment_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self
                .deployment_incarnation
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self.nonce.len() < 16
            || self.nonce.len() > 128
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CheckpointAuthorityError::InvalidRequest);
        }
        Ok(())
    }
}

/// Opaque bounded response bytes returned by a checkpoint authority.
#[derive(Clone, Eq, PartialEq)]
pub struct CheckpointResponse {
    bytes: Vec<u8>,
}

impl fmt::Debug for CheckpointResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointResponse")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl CheckpointResponse {
    /// Build a response after applying the wire-size bound.  Signature and
    /// nonce validation remain the responsibility of [`MembershipVerifier`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, CheckpointAuthorityError> {
        if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointAuthorityError::BodyTooLarge);
        }
        Ok(Self { bytes })
    }

    /// Return the signed checkpoint bytes for the pure verifier.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the bounded response.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Errors at the external checkpoint authority boundary.  The display form
/// intentionally excludes URLs, response bodies and transport details that
/// could contain credentials or operator payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointAuthorityError {
    InvalidEndpoint,
    InvalidRequest,
    InvalidTrustBundle,
    Transport,
    DeadlineExceeded,
    HttpStatus(u16),
    InvalidResponse,
    BodyTooLarge,
    Cancelled,
}

impl CheckpointAuthorityError {
    /// Whether this failure is a shared control-plane outage that every
    /// relay sees alike, rather than something about this relay (M7-C186).
    ///
    /// **Coordinator decision under the owner's delegation (2026-09-27).**
    /// Shared: the authority unreachable or failing -- a transport failure,
    /// a deadline, a 5xx, `408 Request Timeout`, `429 Too Many Requests`, or
    /// an unusable answer. Specific to this relay, so it counts toward the
    /// prolonged-unready surrender: any other 4xx (for example `401`/`403`
    /// refusing a decommissioned relay's client certificate -- exempting it
    /// would recreate M7-C181 through the authority) and this relay's own
    /// invalid endpoint, request or trust bundle. A TLS-level refusal of the
    /// client certificate surfaces as `Transport` and cannot be told apart
    /// from an unreachable authority, so it stays shared.
    #[must_use]
    pub const fn is_shared_outage(&self) -> bool {
        match self {
            Self::HttpStatus(status) => {
                !(*status >= 400 && *status < 500) || *status == 408 || *status == 429
            }
            Self::InvalidEndpoint | Self::InvalidRequest | Self::InvalidTrustBundle => false,
            Self::Transport
            | Self::DeadlineExceeded
            | Self::InvalidResponse
            | Self::BodyTooLarge
            | Self::Cancelled => true,
        }
    }
}

impl fmt::Display for CheckpointAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => formatter.write_str("invalid checkpoint authority endpoint"),
            Self::InvalidRequest => formatter.write_str("invalid checkpoint authority request"),
            Self::InvalidTrustBundle => {
                formatter.write_str("invalid checkpoint authority trust bundle")
            }
            Self::Transport => formatter.write_str("checkpoint authority transport failed"),
            Self::DeadlineExceeded => formatter.write_str("checkpoint authority deadline exceeded"),
            Self::HttpStatus(status) => {
                write!(formatter, "checkpoint authority returned HTTP {status}")
            }
            Self::InvalidResponse => {
                formatter.write_str("checkpoint authority response was invalid")
            }
            Self::BodyTooLarge => {
                formatter.write_str("checkpoint authority response exceeded the size bound")
            }
            Self::Cancelled => formatter.write_str("checkpoint authority request was cancelled"),
        }
    }
}

impl Error for CheckpointAuthorityError {}

/// Injectable checkpoint authority boundary.  Implementations must return the
/// signed checkpoint bytes without verifying them; the runtime always applies
/// the operator-installed [`TrustedPublisherKey`] set afterwards.
pub trait CheckpointAuthority: Send + Sync {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>>;
}

/// A typed membership-record source.  Redis-backed implementations should
/// return the signed opaque values from the catalog and must not deserialize or
/// trust them before this runtime verifies them.
pub trait MembershipRecordSource: Send + Sync {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<CatalogMembershipRecord>, MembershipSourceError>>;
}

/// Catalog read failures are kept separate from signature failures so readiness
/// and diagnostics can distinguish an unavailable authority from a rejected
/// record without exposing backend text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipSourceError {
    Catalog,
    TooManyRecords,
    InvalidRecordEnvelope,
    Cancelled,
}

impl fmt::Display for MembershipSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog => formatter.write_str("membership catalog unavailable"),
            Self::TooManyRecords => {
                formatter.write_str("membership record count exceeded the bound")
            }
            Self::InvalidRecordEnvelope => {
                formatter.write_str("membership record envelope was invalid")
            }
            Self::Cancelled => formatter.write_str("membership catalog read was cancelled"),
        }
    }
}

impl Error for MembershipSourceError {}

/// Adapter for the authoritative catalog directory.  Each value is one
/// independently signed opaque membership record; the source does not merge,
/// deserialize, or verify records before the runtime's external checkpoint
/// and signed verifier gates run.
#[derive(Clone)]
pub struct CatalogMembershipSource {
    catalog: SharedCatalog,
}

impl CatalogMembershipSource {
    #[must_use]
    pub fn new(catalog: SharedCatalog) -> Self {
        Self { catalog }
    }
}

impl MembershipRecordSource for CatalogMembershipSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<CatalogMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move {
            self.catalog
                .read_signed_memberships()
                .await
                .map_err(|error| {
                    // Name the typed catalog cause once: `Source(Catalog)`
                    // alone could not be attributed (found while diagnosing
                    // the M8-C46 process gate).  Catalog errors carry static
                    // detail strings, never record bytes or credentials.
                    tracing::warn!(?error, "signed membership directory read failed");
                    MembershipSourceError::Catalog
                })
        })
    }
}

/// A bounded source useful for an operator-owned directory adapter and focused
/// runtime tests.  It is intentionally explicit: it does not manufacture or
/// sign membership records.
#[derive(Clone, Default)]
pub struct StaticMembershipSource {
    records: Arc<RwLock<Vec<CatalogMembershipRecord>>>,
}

impl StaticMembershipSource {
    pub fn new(records: Vec<CatalogMembershipRecord>) -> Result<Self, MembershipSourceError> {
        if records.len() > MAX_MEMBERSHIP_RECORDS {
            return Err(MembershipSourceError::TooManyRecords);
        }
        Ok(Self {
            records: Arc::new(RwLock::new(records)),
        })
    }

    pub async fn replace(
        &self,
        records: Vec<CatalogMembershipRecord>,
    ) -> Result<(), MembershipSourceError> {
        if records.len() > MAX_MEMBERSHIP_RECORDS {
            return Err(MembershipSourceError::TooManyRecords);
        }
        *self.records.write().await = records;
        Ok(())
    }
}

impl MembershipRecordSource for StaticMembershipSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<CatalogMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move { Ok(self.records.read().await.clone()) })
    }
}

/// Runtime timing and identity policy.  It is separate from `ClusterConfig`
/// so tests and embedding callers can inject an already constructed verifier
/// policy while the production constructor can derive one from configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRuntimeConfig {
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub node_id: String,
    pub boot_id: String,
    /// SPKI digest observed from this relay's completed peer certificate.
    /// Production startup should provide it before bootstrap so a fresh boot
    /// cannot become ready merely because Redis contains a matching node ID.
    pub local_spki_sha256: Option<String>,
    pub membership_record_lifetime: Duration,
    pub membership_refresh: Duration,
    pub membership_reconcile: Duration,
    pub checkpoint_timeout: Duration,
    pub max_clock_skew: Duration,
    pub endpoint_policy: PrivateEndpointPolicy,
}

impl MembershipRuntimeConfig {
    /// Derive bounded runtime settings from the operator-provisioned cluster
    /// configuration.  The deployment incarnation remains an explicit input
    /// because it is persisted outside Redis and is not a cluster TOML secret.
    pub fn from_cluster_config(
        cluster: &ClusterConfig,
        node_id: impl Into<String>,
        boot_id: impl Into<String>,
        deployment_incarnation: impl Into<String>,
    ) -> Result<Self, MembershipRuntimeError> {
        cluster
            .validate()
            .map_err(|_| MembershipRuntimeError::InvalidConfiguration)?;
        let endpoint_policy = if cluster.endpoint_policy.allowed_hosts.is_empty() {
            if !cluster.endpoint_policy.allowed_server_names.is_empty() {
                return Err(MembershipRuntimeError::InvalidConfiguration);
            }
            PrivateEndpointPolicy {
                allowed_hosts: BTreeSet::new(),
                allowed_server_names: BTreeSet::new(),
                allowed_ports: cluster
                    .endpoint_policy
                    .allowed_ports
                    .iter()
                    .copied()
                    .collect(),
                require_private_ip: true,
            }
        } else {
            PrivateEndpointPolicy::allowlisted(
                cluster.endpoint_policy.allowed_hosts.clone(),
                cluster.endpoint_policy.allowed_server_names.clone(),
                cluster.endpoint_policy.allowed_ports.clone(),
            )
            .map_err(MembershipRuntimeError::Membership)?
        };
        Self::new(
            cluster.deployment_id.clone(),
            deployment_incarnation,
            node_id,
            boot_id,
            endpoint_policy,
            Duration::from_secs(cluster.membership_record_lifetime_seconds),
            Duration::from_secs(cluster.membership_refresh_seconds),
            Duration::from_secs(cluster.membership_reconcile_seconds),
            Duration::from_secs(cluster.checkpoint_timeout_seconds),
            Duration::from_secs(cluster.max_clock_skew_seconds),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment_id: impl Into<String>,
        deployment_incarnation: impl Into<String>,
        node_id: impl Into<String>,
        boot_id: impl Into<String>,
        endpoint_policy: PrivateEndpointPolicy,
        membership_record_lifetime: Duration,
        membership_refresh: Duration,
        membership_reconcile: Duration,
        checkpoint_timeout: Duration,
        max_clock_skew: Duration,
    ) -> Result<Self, MembershipRuntimeError> {
        let config = Self {
            deployment_id: deployment_id.into(),
            deployment_incarnation: deployment_incarnation.into(),
            node_id: node_id.into(),
            boot_id: boot_id.into(),
            local_spki_sha256: None,
            membership_record_lifetime,
            membership_refresh,
            membership_reconcile,
            checkpoint_timeout,
            max_clock_skew,
            endpoint_policy,
        };
        config.validate()?;
        Ok(config)
    }

    /// Bind readiness to the SPKI digest observed from the local peer TLS
    /// certificate.  The digest is a public pin, not a private key or a
    /// certificate payload.
    pub fn with_local_spki_sha256(
        mut self,
        spki_sha256: impl Into<String>,
    ) -> Result<Self, MembershipRuntimeError> {
        let spki_sha256 = spki_sha256.into();
        if !is_spki_digest(&spki_sha256) {
            return Err(MembershipRuntimeError::InvalidConfiguration);
        }
        self.local_spki_sha256 = Some(spki_sha256);
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), MembershipRuntimeError> {
        if self.deployment_id.trim().is_empty()
            || self.deployment_id.len() > 128
            || self.deployment_incarnation.trim().is_empty()
            || self.deployment_incarnation.len() > 128
            || self.node_id.trim().is_empty()
            || self.node_id.len() > 128
            || self.boot_id.trim().is_empty()
            || self.boot_id.len() > 128
            || self
                .deployment_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self
                .local_spki_sha256
                .as_deref()
                .is_some_and(|spki| !is_spki_digest(spki))
            || self
                .deployment_incarnation
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self
                .node_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self
                .boot_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(MembershipRuntimeError::InvalidConfiguration);
        }
        if self.membership_record_lifetime.is_zero()
            || self.membership_record_lifetime > Duration::from_secs(60)
            || self.membership_refresh.is_zero()
            || self.membership_refresh > Duration::from_secs(20)
            || self.membership_refresh > self.membership_record_lifetime
            || self.membership_reconcile.is_zero()
            || self.membership_reconcile > Duration::from_secs(5)
            || self.checkpoint_timeout.is_zero()
            || self.checkpoint_timeout > MAX_CHECKPOINT_REQUEST_TIMEOUT
            || self.max_clock_skew > tunnel_catalog::clock::MAX_CLUSTER_CLOCK_SKEW
        {
            return Err(MembershipRuntimeError::InvalidConfiguration);
        }
        Ok(())
    }

    fn verifier_policy(&self) -> Result<MembershipPolicy, MembershipRuntimeError> {
        let mut policy = MembershipPolicy::new(
            self.deployment_id.clone(),
            self.deployment_incarnation.clone(),
            self.endpoint_policy.clone(),
        )
        .map_err(MembershipRuntimeError::Membership)?;
        policy.max_record_lifetime = chrono::Duration::from_std(self.membership_record_lifetime)
            .map_err(|_| MembershipRuntimeError::InvalidConfiguration)?;
        policy.max_clock_skew = chrono::Duration::from_std(self.max_clock_skew)
            .map_err(|_| MembershipRuntimeError::InvalidConfiguration)?;
        policy
            .validate()
            .map_err(MembershipRuntimeError::Membership)
    }
}

/// Readiness is deliberately smaller than the internal error surface and safe
/// to expose from a health/readiness endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MembershipReadiness {
    Starting,
    Ready,
    Unready(MembershipUnreadyReason),
}

/// Redacted readiness causes.  These contain no backend messages, URLs or
/// signed membership payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MembershipUnreadyReason {
    UnknownAuthority,
    CheckpointExpired,
    CatalogUnavailable,
    MembershipRejected,
    MissingLocalMembership,
    MissingLocalKey,
    PersistenceUnavailable,
    Cancelled,
}

impl MembershipReadiness {
    /// Every code [`Self::code`] can return, in a fixed order: the closed
    /// label set of the private metrics listener's
    /// `tunnel_relay_membership_readiness` series (task row M0-03).
    pub const CODES: [&'static str; 10] = [
        "starting",
        "ready",
        "unknown_authority",
        "checkpoint_expired",
        "catalog_unavailable",
        "membership_rejected",
        "missing_local_membership",
        "missing_local_key",
        "persistence_unavailable",
        "cancelled",
    ];

    /// The stable, payload-free code for this readiness: `starting`,
    /// `ready`, or the unready reason's [`MembershipUnreadyReason::code`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Unready(reason) => reason.code(),
        }
    }
}

impl MembershipUnreadyReason {
    /// The stable, payload-free code for this reason, as `serve` prints it
    /// on a failed bootstrap and the metrics listener labels it after one.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownAuthority => "unknown_authority",
            Self::CheckpointExpired => "checkpoint_expired",
            Self::CatalogUnavailable => "catalog_unavailable",
            Self::MembershipRejected => "membership_rejected",
            Self::MissingLocalMembership => "missing_local_membership",
            Self::MissingLocalKey => "missing_local_key",
            Self::PersistenceUnavailable => "persistence_unavailable",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether becoming unready for this reason must also withdraw this
    /// relay's approved peer SPKI pins (M7-C86).
    ///
    /// **Recorded owner decision (2026-09-16).** Withdrawing the pin set is
    /// the fail-closed answer when the *trust evidence itself* was rejected:
    /// an authority this relay cannot verify, a signed record that failed
    /// verification, or an expired checkpoint or key window. In those states
    /// the relay can no longer say which peer keys are approved, so it must
    /// approve none -- that is what makes a rogue-signed record fail closed
    /// in both directions (`m7_deployment_spki_replacement` phase 6).
    ///
    /// The remaining reasons are *local or transient*: this relay's own
    /// prerequisites are unmet, or an infrastructure read failed, while the
    /// signed peer keys it already verified are untouched. Withdrawing trust
    /// there turned one relay's transient local failure into a cluster-wide
    /// trust blackout (M7-C81, M7-C83). The decision is that those should
    /// retain the verified set and withdraw *readiness* instead.
    ///
    /// **Held: today every reason returns `true`.** Retaining regresses
    /// `verify-m7-trust-expiry` (M7-C86, M7-C131), so nothing is retained
    /// until that is understood. The reasons are split out now so that the
    /// labels are accurate and the retention is a one-line change here.
    #[must_use]
    pub const fn withdraws_peer_trust(self) -> bool {
        match self {
            // M7-C86 (the retention split) is held: until its trust-expiry
            // regression is understood, every unready reason withdraws the
            // pin set, exactly as before the split. The classification stays
            // named per reason so the split is a one-line decision to revisit.
            Self::UnknownAuthority
            | Self::MembershipRejected
            | Self::CheckpointExpired
            | Self::MissingLocalMembership
            | Self::MissingLocalKey
            | Self::CatalogUnavailable
            | Self::PersistenceUnavailable
            | Self::Cancelled => true,
        }
    }

    /// Whether time unready for this reason counts toward the
    /// prolonged-unready ownership surrender (M7-C184).
    ///
    /// Every reason counts except two. `CatalogUnavailable` is Redis being
    /// unreachable: the relay cannot renew owner leases then either, so they
    /// lapse on their own and a surrender would add nothing but a reason to
    /// close sessions on a transient. `Cancelled` is shutdown, which closes
    /// every session anyway.
    ///
    /// A pass is also excluded, whatever its reason, when it shows a shared
    /// control-plane outage (M7-C186): the checkpoint authority unreachable
    /// (`UnknownAuthority` from an authority error, not from a record signed
    /// by an unknown key), or a fresh checkpoint with no record for any node
    /// it names still inside its lifetime (the publisher has stopped). That
    /// is decided per pass in `count_surrender_evidence`, not here.
    #[must_use]
    pub const fn counts_toward_prolonged_unready(self) -> bool {
        !matches!(self, Self::CatalogUnavailable | Self::Cancelled)
    }
}

impl fmt::Display for MembershipUnreadyReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownAuthority => "unknown membership authority",
            Self::CheckpointExpired => "membership checkpoint expired",
            Self::CatalogUnavailable => "membership catalog unavailable",
            Self::MembershipRejected => "membership record rejected",
            Self::MissingLocalMembership => "local relay membership is unavailable",
            Self::MissingLocalKey => "local relay key is not approved",
            Self::PersistenceUnavailable => "membership version state persistence unavailable",
            Self::Cancelled => "membership runtime cancelled",
        })
    }
}

/// Runtime errors retain typed verifier failures for callers that need to
/// classify an admission rejection, while authority/catalog strings remain
/// intentionally redacted.
#[derive(Debug)]
pub enum MembershipRuntimeError {
    InvalidConfiguration,
    Authority(CheckpointAuthorityError),
    Source(MembershipSourceError),
    Membership(MembershipError),
    Persistence(MembershipVersionStateStoreError),
    PersistenceTimeout,
    NotReady,
    PeerRejected,
    CheckpointExpired,
    Cancelled,
    Join,
}

impl fmt::Display for MembershipRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("invalid membership runtime configuration")
            }
            Self::Authority(error) => error.fmt(formatter),
            Self::Source(error) => error.fmt(formatter),
            Self::Membership(error) => error.fmt(formatter),
            Self::Persistence(error) => error.fmt(formatter),
            Self::PersistenceTimeout => {
                formatter.write_str("membership version state persistence timed out")
            }
            Self::NotReady => formatter.write_str("membership runtime is not ready"),
            Self::PeerRejected => formatter.write_str("peer membership is not currently trusted"),
            Self::CheckpointExpired => formatter.write_str("membership checkpoint expired"),
            Self::Cancelled => formatter.write_str("membership runtime cancelled"),
            Self::Join => formatter.write_str("membership task did not join cleanly"),
        }
    }
}

impl Error for MembershipRuntimeError {}

impl From<CheckpointAuthorityError> for MembershipRuntimeError {
    fn from(error: CheckpointAuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<MembershipSourceError> for MembershipRuntimeError {
    fn from(error: MembershipSourceError) -> Self {
        Self::Source(error)
    }
}

/// A redacted directory entry suitable for diagnostics.  Endpoints and signed
/// bytes are intentionally absent; routing callers use the opaque verifier
/// binding returned by [`MembershipRuntime::admit_peer`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedMembershipSnapshot {
    pub node_id: String,
    pub record_version: u64,
    pub publisher_key_id: String,
    pub key_ids: Vec<String>,
    pub spki_sha256: Vec<String>,
    pub valid_until: DateTime<Utc>,
}

/// A bounded, redacted status snapshot.  It contains identifiers and timing
/// facts only; no signed payload, endpoint, token, certificate or key material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub readiness: MembershipReadiness,
    pub generation: u64,
    pub checkpoint_version: Option<u64>,
    pub checkpoint_expires_at: Option<DateTime<Utc>>,
    pub trust_expires_at: Option<DateTime<Utc>>,
    /// Relay-process monotonic trust deadline. It is comparable with actor
    /// terminal events from the same process and avoids wall-clock mapping.
    pub trust_deadline_ms: Option<u64>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub membership_count: usize,
    pub active_peer_count: usize,
    pub memberships: Vec<RedactedMembershipSnapshot>,
}

/// Peer identity extracted from the completed mTLS handshake.  The runtime
/// never accepts this as authority by itself; it must match a verified record.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerIdentity {
    pub node_id: String,
    pub boot_id: String,
    pub spki_sha256: String,
}

impl PeerIdentity {
    pub fn new(
        node_id: impl Into<String>,
        boot_id: impl Into<String>,
        spki_sha256: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            boot_id: boot_id.into(),
            spki_sha256: spki_sha256.into(),
        }
    }
}

/// Why an already admitted peer was invalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerInvalidationReason {
    TrustExpired,
    MembershipRevoked,
    MembershipChanged,
    AuthorityUnknown,
    PersistenceUnavailable,
    RuntimeCancelled,
}

impl PeerInvalidationReason {
    const fn code(self) -> u8 {
        match self {
            Self::TrustExpired => 1,
            Self::MembershipRevoked => 2,
            Self::MembershipChanged => 3,
            Self::AuthorityUnknown => 4,
            Self::PersistenceUnavailable => 5,
            Self::RuntimeCancelled => 6,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TrustExpired),
            2 => Some(Self::MembershipRevoked),
            3 => Some(Self::MembershipChanged),
            4 => Some(Self::AuthorityUnknown),
            5 => Some(Self::PersistenceUnavailable),
            6 => Some(Self::RuntimeCancelled),
            _ => None,
        }
    }
}

/// Cancellation state for one authenticated peer admission.  The token
/// remains compatible with transport cancellation while the bounded reason
/// lets a caller distinguish signed trust expiry from an unrelated close.
/// The optional monotonic deadline is the admission's own signed trust
/// boundary; it lets a stream observer attribute a failure that arrives after
/// that boundary to expiry even when this process's invalidation dispatcher
/// has not run yet.
#[derive(Clone)]
pub struct PeerAdmissionCancellation {
    token: CancellationToken,
    reason: Arc<AtomicU8>,
    expires_at: Option<SharedAdmissionExpiry>,
}

/// The monotonic trust deadline of one admission, shared between the
/// runtime's active-admission table and every stream riding the admission.
///
/// It only ever moves when a successful reconcile re-binds an unchanged
/// admission to freshly verified signed evidence (M7-C80); it is never moved
/// earlier than a boundary already observed and never extended by a cache hit,
/// a late response or a clock correction.
#[derive(Clone, Debug)]
struct SharedAdmissionExpiry(Arc<Mutex<(Instant, Option<DateTime<Utc>>)>>);

impl SharedAdmissionExpiry {
    fn new(expires_at: Instant, trust_expires_at: Option<DateTime<Utc>>) -> Self {
        Self(Arc::new(Mutex::new((expires_at, trust_expires_at))))
    }

    fn load(&self) -> (Instant, Option<DateTime<Utc>>) {
        match self.0.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    fn get(&self) -> Instant {
        self.load().0
    }

    fn set(&self, expires_at: Instant, trust_expires_at: DateTime<Utc>) {
        let value = (expires_at, Some(trust_expires_at));
        match self.0.lock() {
            Ok(mut guard) => *guard = value,
            Err(poisoned) => *poisoned.into_inner() = value,
        }
    }
}

impl PeerAdmissionCancellation {
    /// Construct an unclassified cancellation edge for providers that only
    /// expose the legacy token. MembershipRuntime uses the private reason
    /// cell populated by its invalidation dispatcher.  No deadline is known,
    /// so only an explicit trust-expiry invalidation counts as expiry.
    #[must_use]
    pub fn from_token(token: CancellationToken) -> Self {
        Self {
            token,
            reason: Arc::new(AtomicU8::new(0)),
            expires_at: None,
        }
    }

    /// Construct an unclassified cancellation edge bound to one monotonic
    /// trust deadline.  Providers without an invalidation dispatcher can use
    /// this so a failure observed after the deadline is still attributed to
    /// trust expiry.
    #[must_use]
    pub fn from_token_with_deadline(token: CancellationToken, expires_at: Instant) -> Self {
        Self {
            token,
            reason: Arc::new(AtomicU8::new(0)),
            expires_at: Some(SharedAdmissionExpiry::new(expires_at, None)),
        }
    }

    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    pub fn cancelled(&self) -> impl Future<Output = ()> + '_ {
        self.token.cancelled()
    }

    #[must_use]
    pub fn reason(&self) -> Option<PeerInvalidationReason> {
        PeerInvalidationReason::from_code(self.reason.load(Ordering::Acquire))
    }

    /// Return the admission's monotonic trust deadline when the provider
    /// exposed one.  It is shared with the runtime's active-admission table,
    /// so it reads the current value: a successful reconcile that re-binds an
    /// unchanged admission to fresh signed evidence moves it later (M7-C80),
    /// and nothing else ever moves it.
    #[must_use]
    pub fn expires_at(&self) -> Option<Instant> {
        self.expires_at.as_ref().map(SharedAdmissionExpiry::get)
    }

    /// Return whether signed trust for this admission has ended.
    ///
    /// This is positive evidence, not absence: either the invalidation
    /// dispatcher recorded `TrustExpired` for this edge, or the admission's
    /// own monotonic deadline has passed before the dispatcher ran.  The peer
    /// relay enforces the same signed boundary and may reset or end a pooled
    /// stream first; the observer of that failure must still attribute it to
    /// the earlier trust deadline rather than to a generic transport close.
    /// An explicit different invalidation reason is never reinterpreted as
    /// expiry.
    #[must_use]
    pub fn trust_expired(&self) -> bool {
        match self.reason() {
            Some(PeerInvalidationReason::TrustExpired) => true,
            Some(_) => false,
            None => self
                .expires_at()
                .is_some_and(|deadline| Instant::now() >= deadline),
        }
    }
}

/// Callback invoked after the peer token has been cancelled.  Callback input
/// is limited to the handshake identity and a bounded reason.
pub type PeerInvalidationCallback = Arc<dyn Fn(PeerIdentity, PeerInvalidationReason) + Send + Sync>;

/// A monotonic deadline attached to one admission.  It is never extended by a
/// Redis cache hit, a late HTTP response or a wall-clock correction; only a
/// successful reconcile re-binding the admission to freshly verified signed
/// evidence for the same key moves it, and never earlier (M7-C80).
#[derive(Clone, Copy, Debug)]
pub struct AdmissionDeadline {
    started_at: Instant,
    expires_at: Instant,
    trust_expires_at: DateTime<Utc>,
}

impl AdmissionDeadline {
    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    #[must_use]
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    #[must_use]
    pub fn trust_expires_at(&self) -> DateTime<Utc> {
        self.trust_expires_at
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// Evidence returned after an mTLS peer identity is matched to the current
/// signed directory.  The cancellation token is cancelled on expiry,
/// revocation, record replacement or runtime shutdown.
#[derive(Clone)]
pub struct PeerAdmission {
    identity: PeerIdentity,
    binding: VerifiedPeerBinding,
    deadline: AdmissionDeadline,
    invalidation: CancellationToken,
    invalidation_reason: Arc<AtomicU8>,
    expiry: SharedAdmissionExpiry,
}

impl fmt::Debug for PeerAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAdmission")
            .field("identity", &self.identity)
            .field("deadline", &self.deadline)
            .field("cancelled", &self.invalidation.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl PeerAdmission {
    #[must_use]
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Opaque verified binding for the peer transport policy.
    #[must_use]
    pub fn binding(&self) -> &VerifiedPeerBinding {
        &self.binding
    }

    /// The admission's current deadline, read through the same shared cell
    /// its streams read, so a clone never reports a boundary the runtime has
    /// since re-bound (M7-C80).
    #[must_use]
    pub fn deadline(&self) -> AdmissionDeadline {
        let (expires_at, trust_expires_at) = self.expiry.load();
        AdmissionDeadline {
            started_at: self.deadline.started_at,
            expires_at,
            trust_expires_at: trust_expires_at.unwrap_or(self.deadline.trust_expires_at),
        }
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.invalidation.clone()
    }

    /// Return the token, its live invalidation cause, and the admission's
    /// monotonic trust deadline as one bounded value.
    #[must_use]
    pub fn cancellation(&self) -> PeerAdmissionCancellation {
        PeerAdmissionCancellation {
            token: self.invalidation.clone(),
            reason: self.invalidation_reason.clone(),
            expires_at: Some(self.expiry.clone()),
        }
    }

    #[must_use]
    pub fn is_invalidated(&self) -> bool {
        self.invalidation.is_cancelled()
    }
}

struct ActivePeer {
    admission: PeerAdmission,
    record_version: u64,
}

struct RuntimeState {
    verifier: MembershipVerifier,
    readiness: MembershipReadiness,
    generation: u64,
    checkpoint_version: Option<u64>,
    checkpoint_expires_at: Option<DateTime<Utc>>,
    trust_expires_at: Option<DateTime<Utc>>,
    trust_deadline: Option<Instant>,
    last_verified_at: Option<DateTime<Utc>>,
    active_peers: BTreeMap<PeerIdentity, ActivePeer>,
    callback: Option<PeerInvalidationCallback>,
    last_persisted_version_state: Option<MembershipVersionState>,
    /// Consecutive completed reconcile passes that each concluded this
    /// relay's served key is not approved by its own verified record
    /// (`MissingLocalKey`). Reset by any pass that concludes otherwise
    /// (M7-C181).
    own_key_missing_passes: u32,
    /// Consecutive completed passes whose fresh checkpoint did not name this
    /// node (M7-C182, case (a)). Reset by any pass that concludes otherwise.
    node_omitted_passes: u32,
    /// When the current run of consecutive passes that each found this
    /// node's record below the checkpoint's minimum began, and how long that
    /// run has been confirmed for: from its first pass to its latest pass
    /// (M7-C182, case (b)). Measured between completed passes, so it grows
    /// only on evidence, never on the absence of a pass.
    below_minimum_since: Option<Instant>,
    below_minimum_persisted: Duration,
    /// Unready time confirmed by consecutive passes that each concluded an
    /// unready reason other than an unreachable catalog (M7-C184). Reset by
    /// a `Ready` pass. An interval with an unreachable-catalog pass at either
    /// end adds nothing.
    prolonged_unready: Duration,
    /// When the most recent completed pass concluded, if it concluded an
    /// unready reason that counts toward [`Self::prolonged_unready`].
    last_counted_unready_pass: Option<Instant>,
    /// The local-membership gap the pass in progress concluded, if any. Set
    /// by the pass, consumed when it is counted (M7-C182).
    pass_local_gap: Option<LocalMembershipGap>,
    /// Whether the pass in progress saw the signature of a shared publisher
    /// outage: a fresh checkpoint, but no record for any node it names still
    /// inside its signed lifetime (M7-C186). Set by the pass, consumed when
    /// it is counted.
    pass_publisher_outage: bool,
    /// The time-based surrender bounds (M7-C182, M7-C184).
    surrender_bounds: SurrenderBounds,
}

/// A cancellable, joined membership reconciliation task.
pub struct MembershipRuntimeHandle {
    cancellation: CancellationToken,
    task: JoinHandle<Result<(), MembershipRuntimeError>>,
}

impl fmt::Debug for MembershipRuntimeHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MembershipRuntimeHandle")
            .field("cancelled", &self.cancellation.is_cancelled())
            .field("finished", &self.task.is_finished())
            .finish()
    }
}

impl MembershipRuntimeHandle {
    /// Request cancellation and await the supervisor task to completion.
    ///
    /// This is intentionally an unbounded, joined final shutdown.  A
    /// reconciliation pass can be awaiting the local version-fence
    /// `spawn_blocking` write; Tokio cannot cancel that blocking task, and
    /// dropping this handle would detach the supervisor while the write still
    /// owns the store.  Callers that have a wall-clock cleanup deadline must
    /// retain this handle and report a deadline overrun after this join rather
    /// than wrapping this consuming method in an abortable timeout.
    pub async fn shutdown(self) -> Result<(), MembershipRuntimeError> {
        self.cancellation.cancel();
        self.task.await.map_err(|_| MembershipRuntimeError::Join)?
    }

    /// Request cancellation without waiting.  Call [`Self::shutdown`] when a
    /// joined task is required by the embedding supervisor.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Process-local M7 membership state and reconciliation supervisor.
pub struct MembershipRuntime {
    config: MembershipRuntimeConfig,
    catalog: Arc<dyn MembershipRecordSource>,
    authority: Arc<dyn CheckpointAuthority>,
    cancellation: CancellationToken,
    wake: Notify,
    reconcile_gate: AsyncMutex<()>,
    state: Mutex<RuntimeState>,
    version_store: Option<Arc<MembershipVersionStateStore>>,
    started: AtomicBool,
    /// The SPKI digest this process currently presents on new peer
    /// handshakes, and therefore the one its readiness is bound to.  Starts
    /// at `config.local_spki_sha256`; only
    /// [`MembershipRuntime::switch_local_serving_spki`] changes it, under the
    /// reconcile gate and only to a key the verified record approves now
    /// (task rows M8-C28, M8-C45).
    local_serving_spki: Mutex<Option<String>>,
}

/// How the current verified record for this relay treats one of its own
/// candidate SPKI digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalKeyApproval {
    /// The runtime is not Ready, so no local key is approved.
    NotReady,
    /// No current record for this node lists the key.
    Absent,
    /// The record lists the key as revoked.
    Revoked,
    /// The record lists the key, but not for this instant.
    OutsideWindow,
    /// The record approves the key now.
    Approved {
        /// The verified record version that approves it.
        record_version: u64,
    },
}

impl LocalKeyApproval {
    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved { .. })
    }

    /// A bounded label for diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::Absent => "absent",
            Self::Revoked => "revoked",
            Self::OutsideWindow => "outside_window",
            Self::Approved { .. } => "approved",
        }
    }
}

/// Why a switch of the locally served peer identity was refused.
#[derive(Debug)]
pub enum LocalServingSwitchError<E> {
    /// The digest is not a lower-case SHA-256 hex SPKI pin.
    InvalidDigest,
    /// The verified record does not approve the key now.
    NotApproved(LocalKeyApproval),
    /// The transport refused to install the identity.
    Install(E),
}

impl fmt::Debug for MembershipRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MembershipRuntime")
            .field("node_id", &self.config.node_id)
            .field("boot_id", &"<redacted>")
            .field("started", &self.started.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl MembershipRuntime {
    /// Construct a runtime using the authoritative bounded catalog directory.
    /// Catalog implementations retain a compatibility fallback for the
    /// legacy single-record namespace, but production Redis reads all nodes.
    pub fn new(
        catalog: SharedCatalog,
        authority: Arc<dyn CheckpointAuthority>,
        config: MembershipRuntimeConfig,
        trusted_publishers: impl IntoIterator<Item = TrustedPublisherKey>,
    ) -> Result<Arc<Self>, MembershipRuntimeError> {
        Self::with_source(
            Arc::new(CatalogMembershipSource::new(catalog)),
            authority,
            config,
            trusted_publishers,
        )
    }

    /// Construct a runtime with the required durable high-water fence.
    ///
    /// The store is opened by the caller in a bounded blocking context.  This
    /// constructor performs the already-open store read and restores only its
    /// version fences before any checkpoint or catalog operation is allowed.
    pub fn new_with_store(
        catalog: SharedCatalog,
        authority: Arc<dyn CheckpointAuthority>,
        config: MembershipRuntimeConfig,
        trusted_publishers: impl IntoIterator<Item = TrustedPublisherKey>,
        store: Arc<MembershipVersionStateStore>,
    ) -> Result<Arc<Self>, MembershipRuntimeError> {
        Self::with_source_and_store(
            Arc::new(CatalogMembershipSource::new(catalog)),
            authority,
            config,
            trusted_publishers,
            store,
        )
    }

    /// Construct a runtime around an injected bounded membership source.
    pub fn with_source(
        catalog: Arc<dyn MembershipRecordSource>,
        authority: Arc<dyn CheckpointAuthority>,
        config: MembershipRuntimeConfig,
        trusted_publishers: impl IntoIterator<Item = TrustedPublisherKey>,
    ) -> Result<Arc<Self>, MembershipRuntimeError> {
        Self::with_source_and_optional_store(catalog, authority, config, trusted_publishers, None)
    }

    /// Construct a runtime around an injected source and an already-open,
    /// identity-bound durable version store.
    pub fn with_source_and_store(
        catalog: Arc<dyn MembershipRecordSource>,
        authority: Arc<dyn CheckpointAuthority>,
        config: MembershipRuntimeConfig,
        trusted_publishers: impl IntoIterator<Item = TrustedPublisherKey>,
        store: Arc<MembershipVersionStateStore>,
    ) -> Result<Arc<Self>, MembershipRuntimeError> {
        Self::with_source_and_optional_store(
            catalog,
            authority,
            config,
            trusted_publishers,
            Some(store),
        )
    }

    fn with_source_and_optional_store(
        catalog: Arc<dyn MembershipRecordSource>,
        authority: Arc<dyn CheckpointAuthority>,
        config: MembershipRuntimeConfig,
        trusted_publishers: impl IntoIterator<Item = TrustedPublisherKey>,
        version_store: Option<Arc<MembershipVersionStateStore>>,
    ) -> Result<Arc<Self>, MembershipRuntimeError> {
        config.validate()?;
        let policy = config.verifier_policy()?;
        let mut verifier = MembershipVerifier::new(policy, trusted_publishers)
            .map_err(MembershipRuntimeError::Membership)?;
        let persisted_version_state = version_store
            .as_ref()
            .map(|store| store.load().map_err(MembershipRuntimeError::Persistence))
            .transpose()?;
        if let Some(version_state) = persisted_version_state.as_ref() {
            verifier
                .restore_version_state(version_state.clone())
                .map_err(MembershipRuntimeError::Membership)?;
        }
        Ok(Arc::new(Self {
            catalog,
            authority,
            cancellation: CancellationToken::new(),
            wake: Notify::new(),
            reconcile_gate: AsyncMutex::new(()),
            state: Mutex::new(RuntimeState {
                verifier,
                readiness: MembershipReadiness::Starting,
                generation: 0,
                checkpoint_version: None,
                checkpoint_expires_at: None,
                trust_expires_at: None,
                trust_deadline: None,
                last_verified_at: None,
                active_peers: BTreeMap::new(),
                callback: None,
                last_persisted_version_state: persisted_version_state,
                own_key_missing_passes: 0,
                node_omitted_passes: 0,
                below_minimum_since: None,
                below_minimum_persisted: Duration::ZERO,
                prolonged_unready: Duration::ZERO,
                last_counted_unready_pass: None,
                pass_local_gap: None,
                pass_publisher_outage: false,
                surrender_bounds: SurrenderBounds::derive(
                    config.membership_record_lifetime,
                    config.max_clock_skew,
                ),
            }),
            local_serving_spki: Mutex::new(config.local_spki_sha256.clone()),
            config,
            version_store,
            started: AtomicBool::new(false),
        }))
    }

    /// The SPKI digest this process's readiness is currently bound to.
    #[must_use]
    pub fn local_serving_spki(&self) -> Option<String> {
        self.local_serving_spki
            .lock()
            .expect("local serving SPKI mutex poisoned")
            .clone()
    }

    /// How the current verified record for this node treats `spki` now.
    ///
    /// Reads retained verified state only; it never fetches or verifies
    /// anything and grants nothing.
    #[must_use]
    pub fn local_key_approval(&self, spki: &str) -> LocalKeyApproval {
        let now = Utc::now();
        let state = self.state.lock().expect("membership state mutex poisoned");
        Self::local_key_approval_locked(&state, &self.config.node_id, spki, now)
    }

    fn local_key_approval_locked(
        state: &RuntimeState,
        node_id: &str,
        spki: &str,
        now: DateTime<Utc>,
    ) -> LocalKeyApproval {
        // `MissingLocalKey` is the one unready state whose retained evidence
        // is fully verified and current: the pass verified a fresh checkpoint
        // and every record, and concluded only that the *served* key is not
        // approved by this node's record. Answering from that evidence lets
        // a staged successor the same record approves be switched to, which
        // is the only way out of that state during a rotation whose
        // predecessor was withdrawn early (M8-C65). Every other unready
        // reason means the evidence itself is missing, failed or expired.
        if !matches!(
            state.readiness,
            MembershipReadiness::Ready
                | MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalKey)
        ) {
            return LocalKeyApproval::NotReady;
        }
        let Ok(checkpoint) = state.verifier.fresh_checkpoint(now) else {
            return LocalKeyApproval::NotReady;
        };
        let Some(minimum) = checkpoint
            .checkpoint()
            .minimum_versions
            .get(node_id)
            .copied()
        else {
            return LocalKeyApproval::Absent;
        };
        let Some(membership) =
            state
                .verifier
                .retained_memberships()
                .into_iter()
                .find(|membership| {
                    membership.node_id() == node_id && membership.record().record_version >= minimum
                })
        else {
            return LocalKeyApproval::Absent;
        };
        let mut listed = LocalKeyApproval::Absent;
        for key in membership
            .keys()
            .iter()
            .filter(|key| key.spki_sha256 == spki)
        {
            if key.revoked {
                return LocalKeyApproval::Revoked;
            }
            // M7-C171, option (a): activation within the skew, expiry strict.
            if membership.key_window_open(key, now) && membership.record().expires_at >= now {
                return LocalKeyApproval::Approved {
                    record_version: membership.record().record_version,
                };
            }
            listed = LocalKeyApproval::OutsideWindow;
        }
        listed
    }

    /// Bind readiness to `spki` and run `install` -- which makes the transport
    /// present that identity on new handshakes -- as one step.
    ///
    /// Holds the reconcile gate, so no reconciliation pass reads the local
    /// digest half-way through, and refuses unless the current verified
    /// record approves `spki` at this instant.  `install` runs only after
    /// that check; if it fails, readiness stays bound to the previous digest.
    /// Readiness is never satisfied by a *staged* key: only by the one being
    /// served (task row M8-C45).
    pub async fn switch_local_serving_spki<E>(
        &self,
        spki: &str,
        install: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), LocalServingSwitchError<E>> {
        if !is_spki_digest(spki) {
            return Err(LocalServingSwitchError::InvalidDigest);
        }
        let _reconcile_guard = self.reconcile_gate.lock().await;
        let approval = self.local_key_approval(spki);
        if !approval.is_approved() {
            return Err(LocalServingSwitchError::NotApproved(approval));
        }
        install().map_err(LocalServingSwitchError::Install)?;
        *self
            .local_serving_spki
            .lock()
            .expect("local serving SPKI mutex poisoned") = Some(spki.to_owned());
        // The own-key passes counted so far judged the key served until now;
        // they are no evidence about the one served from here on (M8-C65).
        // Held under the reconcile gate, so no pass is counted half-way
        // through. A fresh pass is requested so readiness follows the switch
        // without waiting for the periodic interval.
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .own_key_missing_passes = 0;
        self.wake.notify_one();
        Ok(())
    }

    /// Install or replace the process-local invalidation callback.
    pub fn set_invalidation_callback(&self, callback: Option<PeerInvalidationCallback>) {
        if let Ok(mut state) = self.state.lock() {
            state.callback = callback;
        }
    }

    /// Trigger a best-effort immediate reconcile.  Periodic reconciliation
    /// remains enabled, so lost pub/sub notifications cannot preserve stale
    /// trust indefinitely.
    pub fn notify_membership_changed(&self) {
        self.wake.notify_one();
    }

    /// Run one startup/reconciliation pass synchronously.  A caller that
    /// needs a long-lived supervisor should call [`Self::start`] afterwards.
    pub async fn bootstrap(&self) -> Result<MembershipSnapshot, MembershipRuntimeError> {
        self.reconcile_once().await
    }

    /// Start the bounded five-second-or-faster reconciliation supervisor.
    /// Initial authority/catalog failure leaves the runtime unready but does
    /// not detach the supervisor; it will retry on the configured interval.
    pub async fn start(
        self: &Arc<Self>,
    ) -> Result<MembershipRuntimeHandle, MembershipRuntimeError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(MembershipRuntimeError::InvalidConfiguration);
        }
        let _ = self.bootstrap().await;
        let runtime = Arc::clone(self);
        let cancellation = self.cancellation.clone();
        let task = tokio::spawn(async move { runtime.run_loop().await });
        Ok(MembershipRuntimeHandle { cancellation, task })
    }

    /// Run the supervisor until the runtime cancellation token is set.
    async fn run_loop(self: Arc<Self>) -> Result<(), MembershipRuntimeError> {
        let mut interval = tokio::time::interval(self.config.membership_reconcile);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = self.cancellation.cancelled() => {
                    let invalidations = self.mark_cancelled();
                    self.dispatch_invalidations(invalidations);
                    return Ok(());
                }
                _ = interval.tick() => {
                    Self::observe_reconcile(self.reconcile_once().await);
                }
                _ = self.wake.notified() => {
                    Self::observe_reconcile(self.reconcile_once().await);
                }
            }
        }
    }

    /// Name a failed periodic reconcile once, at warning level.
    ///
    /// A reconcile that fails takes this runtime out of `Ready` and
    /// invalidates every peer admission, which withdraws the transport pin
    /// set with it. Discarding the result left that transition with no
    /// operator-visible cause at all, so a peer path that failed closed for a
    /// few seconds could not be attributed (M7-C83). The typed error names
    /// signed-membership evidence only: no consumer request, body or
    /// credential passes through it.
    fn observe_reconcile(result: Result<MembershipSnapshot, MembershipRuntimeError>) {
        if let Err(error) = result {
            tracing::warn!(
                ?error,
                "membership reconcile failed; peer admissions and pins fail closed until it recovers"
            );
        }
    }

    /// Readiness and status are calculated from retained signed evidence.  A
    /// monotonic expiry check runs even when no timer task has fired yet.
    #[must_use]
    pub fn snapshot(&self) -> MembershipSnapshot {
        let (snapshot, invalidations) = {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            let invalidations = state.expire_if_needed(Utc::now(), Instant::now());
            (state.snapshot(), invalidations)
        };
        self.dispatch_invalidations(invalidations);
        snapshot
    }

    #[must_use]
    pub fn readiness(&self) -> MembershipReadiness {
        self.snapshot().readiness
    }

    /// Return bounded peer route targets from the current verified signed
    /// directory.  The target contains only the private endpoint, TLS name,
    /// and currently valid public SPKI pins needed for an authenticated
    /// readiness probe; it is never included in the public health snapshot.
    ///
    /// A signed membership record does not carry a boot ID.  The probe uses
    /// the authenticated certificate's node/SPKI identity, while owner
    /// routing continues to bind the catalog-selected boot ID before any
    /// request body is admitted.
    #[must_use]
    pub fn verified_peer_route_targets(&self) -> Vec<PeerRouteTarget> {
        let now = Utc::now();
        let state = self.state.lock().expect("membership state mutex poisoned");
        if !matches!(state.readiness, MembershipReadiness::Ready) {
            return Vec::new();
        }
        Self::route_targets_at(&state, now)
    }

    fn route_targets_at(state: &RuntimeState, now: DateTime<Utc>) -> Vec<PeerRouteTarget> {
        let Ok(checkpoint) = state.verifier.fresh_checkpoint(now) else {
            return Vec::new();
        };
        let minimum_versions = checkpoint.checkpoint().minimum_versions.clone();
        state
            .verifier
            .retained_memberships()
            .into_iter()
            .filter(|membership| {
                minimum_versions
                    .get(membership.node_id())
                    .is_some_and(|minimum| membership.record().record_version >= *minimum)
            })
            .filter_map(|membership| PeerRouteTarget::from_verified_membership(&membership, now))
            .take(MAX_MEMBERSHIP_RECORDS)
            .collect()
    }

    /// Return the process's fresh node/boot/SPKI tuple when the caller has
    /// supplied the observed local peer certificate pin.  This tuple is useful
    /// to the peer transport policy and does not itself grant admission.
    #[must_use]
    pub fn local_peer_identity(&self) -> Option<PeerIdentity> {
        self.local_serving_spki().map(|spki_sha256| {
            PeerIdentity::new(&self.config.node_id, &self.config.boot_id, spki_sha256)
        })
    }

    /// Return the highest accepted version fences for restricted local
    /// persistence.  Restoring these fences never accepts record bytes.
    #[must_use]
    pub fn version_state(&self) -> MembershipVersionState {
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .verifier
            .version_state()
    }

    pub fn restore_version_state(
        &self,
        version_state: MembershipVersionState,
    ) -> Result<(), MembershipRuntimeError> {
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .verifier
            .restore_version_state(version_state)
            .map_err(MembershipRuntimeError::Membership)
    }

    /// Admit an mTLS-authenticated peer and return a cancellation-bound,
    /// monotonic trust deadline.  The caller must still check the deadline
    /// immediately before each request/dispatch.
    pub fn admit_peer(
        &self,
        identity: PeerIdentity,
    ) -> Result<PeerAdmission, MembershipRuntimeError> {
        let now_wall = Utc::now();
        let now_mono = Instant::now();
        let (result, invalidations) = {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            let mut invalidations = state.expire_if_needed(now_wall, now_mono);
            let result = (|| {
                if !matches!(state.readiness, MembershipReadiness::Ready) {
                    return Err(MembershipRuntimeError::NotReady);
                }
                let binding = state
                    .verifier
                    .bind_peer(
                        &identity.node_id,
                        &identity.boot_id,
                        &identity.spki_sha256,
                        now_wall,
                    )
                    .map_err(|_| MembershipRuntimeError::PeerRejected)?;
                let trust_deadline = state
                    .trust_deadline
                    .ok_or(MembershipRuntimeError::CheckpointExpired)?;
                if trust_deadline <= now_mono {
                    state.readiness =
                        MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired);
                    invalidations.extend(
                        state.invalidate_active(now_wall, PeerInvalidationReason::TrustExpired),
                    );
                    return Err(MembershipRuntimeError::CheckpointExpired);
                }
                let record_version = state
                    .verifier
                    .retained_memberships()
                    .into_iter()
                    .find(|membership| membership.node_id() == identity.node_id.as_str())
                    .map(|membership| membership.record().record_version)
                    .ok_or(MembershipRuntimeError::PeerRejected)?;
                let peer_deadline = monotonic_deadline(now_wall, now_mono, binding.valid_until());
                if peer_deadline <= now_mono {
                    return Err(MembershipRuntimeError::PeerRejected);
                }
                // The wall-clock expiry is the signed trust boundary. Keep
                // the original monotonic admission deadline on a refresh:
                // independently converting the same signed expiry from a
                // later receipt instant can move the resulting Instant
                // backwards by transport/clock-conversion drift.
                let admission_trust_expires_at = state
                    .trust_expires_at
                    .ok_or(MembershipRuntimeError::CheckpointExpired)?
                    .min(binding.valid_until());
                // Forwarded streams on one authenticated peer share one
                // process-local admission edge. Reusing the active admission
                // is essential: replacing it for every pooled H3 stream
                // would cancel the previous stream as a false membership
                // change. Never reuse after invalidation, expiry, a binding
                // revision, or a genuinely shortened signed trust boundary.
                if let Some(previous) = state.active_peers.get(&identity)
                    && previous.record_version == record_version
                    && previous.admission.binding() == &binding
                    && !previous.admission.is_invalidated()
                    && !previous.admission.deadline.is_expired()
                    && admission_trust_expires_at >= previous.admission.deadline.trust_expires_at()
                {
                    return Ok(previous.admission.clone());
                }
                if !state.active_peers.contains_key(&identity)
                    && state.active_peers.len() >= MAX_MEMBERSHIP_RECORDS
                {
                    return Err(MembershipRuntimeError::PeerRejected);
                }
                let deadline = AdmissionDeadline {
                    started_at: now_mono,
                    expires_at: trust_deadline.min(peer_deadline),
                    // Retain the wall-clock signed boundary used for reuse
                    // and revalidation. The monotonic deadline above remains
                    // anchored to this admission and is never extended by a
                    // later checkpoint receipt.
                    trust_expires_at: admission_trust_expires_at,
                };
                let admission = PeerAdmission {
                    identity: identity.clone(),
                    binding,
                    deadline,
                    invalidation: CancellationToken::new(),
                    invalidation_reason: Arc::new(AtomicU8::new(0)),
                    expiry: SharedAdmissionExpiry::new(
                        deadline.expires_at,
                        Some(deadline.trust_expires_at),
                    ),
                };
                if let Some(previous) = state.active_peers.insert(
                    identity.clone(),
                    ActivePeer {
                        admission: admission.clone(),
                        record_version,
                    },
                ) {
                    invalidations.push(Invalidation {
                        identity: identity.clone(),
                        token: previous.admission.invalidation,
                        reason_cell: previous.admission.invalidation_reason,
                        callback: state.callback.clone(),
                        reason: PeerInvalidationReason::MembershipChanged,
                    });
                }
                Ok(admission)
            })();
            (result, invalidations)
        };
        self.dispatch_invalidations(invalidations);
        result
    }

    /// Remove an active peer after its transport has closed.
    pub fn remove_peer(&self, identity: &PeerIdentity) {
        if let Ok(mut state) = self.state.lock()
            && let Some(peer) = state.active_peers.remove(identity)
        {
            peer.admission.invalidation.cancel();
        }
    }

    /// Match a peer identity against current verifier state without retaining
    /// an active connection token.  Transport policy adapters can use this for
    /// route selection before opening a stream.
    pub fn verified_peer_binding(
        &self,
        identity: &PeerIdentity,
    ) -> Result<VerifiedPeerBinding, MembershipRuntimeError> {
        let now_wall = Utc::now();
        let now_mono = Instant::now();
        let (result, invalidations) = {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            let invalidations = state.expire_if_needed(now_wall, now_mono);
            let result = if !matches!(state.readiness, MembershipReadiness::Ready) {
                Err(MembershipRuntimeError::NotReady)
            } else {
                state
                    .verifier
                    .bind_peer(
                        &identity.node_id,
                        &identity.boot_id,
                        &identity.spki_sha256,
                        now_wall,
                    )
                    .map_err(|_| MembershipRuntimeError::PeerRejected)
            };
            (result, invalidations)
        };
        self.dispatch_invalidations(invalidations);
        result
    }

    /// Perform one full nonce/checkpoint/catalog reconciliation pass.
    pub async fn reconcile_once(&self) -> Result<MembershipSnapshot, MembershipRuntimeError> {
        // Pub/sub wakeups, the periodic timer, and an operator-triggered
        // bootstrap may all race.  Keep one complete pass in flight so a
        // slower persistence result cannot be overtaken by a later pass.
        let _reconcile_guard = self.reconcile_gate.lock().await;
        {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            state.pass_local_gap = None;
            state.pass_publisher_outage = false;
        }
        let result = self.reconcile_once_inner().await;
        if let Err(error) = &result {
            self.mark_error(error);
        }
        self.count_own_key_missing_pass(&result);
        self.count_surrender_evidence(&result, Instant::now());
        result
    }

    /// Record the local-membership gap the pass in progress concluded.
    fn note_local_gap(&self, gap: LocalMembershipGap) {
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .pass_local_gap = Some(gap);
    }

    /// Count this completed pass toward the local-membership (M7-C182) and
    /// prolonged-unready (M7-C184) surrenders. Runs under the reconcile gate
    /// after the pass has installed its readiness, so passes are counted in
    /// the order they completed.
    fn count_surrender_evidence(
        &self,
        result: &Result<MembershipSnapshot, MembershipRuntimeError>,
        now: Instant,
    ) {
        let mut state = self.state.lock().expect("membership state mutex poisoned");
        let gap = state.pass_local_gap.take();
        // M7-C186: a shared control-plane outage -- the checkpoint authority
        // unreachable, or the publisher no longer re-signing any record --
        // makes every relay unready alike. Surrendering devices then only
        // moves them to relays that are just as unready, so such a pass
        // neither advances the publish-race run nor accrues unready time.
        let shared_outage = std::mem::take(&mut state.pass_publisher_outage)
            || matches!(
                result,
                Err(MembershipRuntimeError::Authority(error)) if error.is_shared_outage()
            );
        let missing_local_membership = state.readiness
            == MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalMembership);

        // Case (a): a checkpoint that omits this node, pass-confirmed.
        state.node_omitted_passes =
            if missing_local_membership && gap == Some(LocalMembershipGap::NodeOmitted) {
                state.node_omitted_passes.saturating_add(1)
            } else {
                0
            };

        // Case (b): a record below the checkpoint's minimum, time-confirmed
        // between the first and the latest pass that each observed it.
        if missing_local_membership
            && gap == Some(LocalMembershipGap::BelowMinimum)
            && !shared_outage
        {
            let since = *state.below_minimum_since.get_or_insert(now);
            state.below_minimum_persisted = now.saturating_duration_since(since);
        } else {
            state.below_minimum_since = None;
            state.below_minimum_persisted = Duration::ZERO;
        }

        // M7-C184: unready while the catalog is reachable.
        match state.readiness {
            MembershipReadiness::Ready | MembershipReadiness::Starting => {
                state.prolonged_unready = Duration::ZERO;
                state.last_counted_unready_pass = None;
            }
            MembershipReadiness::Unready(reason) => {
                let counted = reason.counts_toward_prolonged_unready() && !shared_outage;
                if counted && let Some(previous) = state.last_counted_unready_pass {
                    state.prolonged_unready = state
                        .prolonged_unready
                        .saturating_add(now.saturating_duration_since(previous));
                }
                state.last_counted_unready_pass = counted.then_some(now);
            }
        }
    }

    /// Why this relay must surrender the device ownership it holds now, if
    /// it must (M7-C181, M7-C182, M7-C184). Reads retained in-process state
    /// only; it never fetches anything.
    ///
    /// The more specific causes are checked first. Deliberately narrower
    /// than "not ready": a single failed pass, an unreachable catalog, or
    /// clock-offset health (which is not membership state at all) never
    /// answers `Some` here.
    #[must_use]
    pub fn ownership_surrender_cause(&self) -> Option<OwnershipSurrenderCause> {
        let state = self.state.lock().expect("membership state mutex poisoned");
        let MembershipReadiness::Unready(reason) = state.readiness else {
            return None;
        };
        let bounds = state.surrender_bounds;
        match reason {
            MembershipUnreadyReason::MissingLocalKey
                if state.own_key_missing_passes >= OWN_KEY_SURRENDER_CONFIRMATIONS =>
            {
                Some(OwnershipSurrenderCause::OwnKeyRetired)
            }
            MembershipUnreadyReason::MissingLocalMembership
                if state.node_omitted_passes >= OWN_KEY_SURRENDER_CONFIRMATIONS =>
            {
                Some(OwnershipSurrenderCause::NodeRemoved)
            }
            MembershipUnreadyReason::MissingLocalMembership
                if state.below_minimum_since.is_some()
                    && state.below_minimum_persisted >= bounds.local_record_below_minimum =>
            {
                Some(OwnershipSurrenderCause::LocalRecordBelowMinimum)
            }
            // Only while the latest pass itself counted: a relay whose
            // catalog is unreachable now, or that is inside a shared outage
            // now, keeps what it accrued but does not surrender on it.
            _ if state.last_counted_unready_pass.is_some()
                && state.prolonged_unready >= bounds.prolonged_unready =>
            {
                Some(OwnershipSurrenderCause::ProlongedUnready)
            }
            _ => None,
        }
    }

    /// The time-based surrender bounds in effect.
    #[must_use]
    pub fn surrender_bounds(&self) -> SurrenderBounds {
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .surrender_bounds
    }

    /// Replace the time-based surrender bounds. A test seam: the relay
    /// itself always runs with [`SurrenderBounds::derive`].
    #[doc(hidden)]
    pub fn set_surrender_bounds(&self, bounds: SurrenderBounds) {
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .surrender_bounds = bounds;
    }

    /// Count this completed pass toward the own-key surrender (M7-C181).
    ///
    /// Only a pass that itself reached the `MissingLocalKey` conclusion counts:
    /// that branch is the one that installs `Unready(MissingLocalKey)` and
    /// returns `PeerRejected`, and `mark_error` leaves readiness alone for
    /// `PeerRejected`. Every other outcome -- `Ready`, a checkpoint fetch or
    /// catalog read failure, a rejected or expired record, a missing local
    /// record -- resets the count. Runs under the reconcile gate, so passes
    /// are counted in the order they completed.
    fn count_own_key_missing_pass(
        &self,
        result: &Result<MembershipSnapshot, MembershipRuntimeError>,
    ) {
        let mut state = self.state.lock().expect("membership state mutex poisoned");
        let concluded_missing_key = matches!(result, Err(MembershipRuntimeError::PeerRejected))
            && state.readiness
                == MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalKey);
        state.own_key_missing_passes = if concluded_missing_key {
            state.own_key_missing_passes.saturating_add(1)
        } else {
            0
        };
    }

    /// Consecutive completed reconcile passes that concluded this relay's
    /// served key is not approved by its own verified record.
    #[must_use]
    pub fn own_key_missing_passes(&self) -> u32 {
        self.state
            .lock()
            .expect("membership state mutex poisoned")
            .own_key_missing_passes
    }

    /// Whether this relay must surrender the device ownership it holds
    /// because its own served key is missing or revoked in its own verified
    /// membership record, confirmed by [`OWN_KEY_SURRENDER_CONFIRMATIONS`]
    /// consecutive reconcile passes (task row M7-C181).
    ///
    /// Deliberately narrower than "not ready": a checkpoint authority or
    /// catalog read failure, a rejected record, an expired checkpoint or key
    /// window, or clock-offset health never answers `true` here. Those only
    /// withdraw readiness and admission (M7-C86, M7-C90, M7-C91); the owner
    /// lease rules still bound what an unready owner may dispatch.
    #[must_use]
    pub fn own_key_surrender_required(&self) -> bool {
        self.ownership_surrender_cause() == Some(OwnershipSurrenderCause::OwnKeyRetired)
    }

    async fn reconcile_once_inner(&self) -> Result<MembershipSnapshot, MembershipRuntimeError> {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let request = CheckpointRequest {
            deployment_id: self.config.deployment_id.clone(),
            deployment_incarnation: self.config.deployment_incarnation.clone(),
            nonce: nonce.clone(),
        };
        let request_started_wall = Utc::now();
        let request_started_mono = Instant::now();
        let response = self.fetch_checkpoint(request).await?;
        let checkpoint_received_wall = Utc::now();

        // Stage all verification against a clone. Existing verified bindings
        // remain usable while a candidate is being persisted; only the
        // successful, durable candidate is swapped into live state.
        let mut candidate_verifier = self
            .state
            .lock()
            .expect("membership state mutex poisoned")
            .verifier
            .clone();
        let checkpoint = candidate_verifier
            .verify_checkpoint(response.as_bytes(), &nonce, checkpoint_received_wall)
            .map_err(map_checkpoint_error)?;

        // A valid checkpoint advances the high-water fence even if the
        // subsequent catalog snapshot is malformed.  Persist it before the
        // untrusted record bytes are read so a restart cannot replay an
        // already accepted checkpoint.
        let checkpoint_version_state = candidate_verifier.version_state();
        self.persist_if_changed(checkpoint_version_state, checkpoint_received_wall)
            .await?;

        let records = self.read_memberships().await?;
        // Record and key windows are evaluated at the instant the records
        // were read, not at checkpoint receipt. A same-key re-sign published
        // between the two carries a signing instant later than checkpoint
        // receipt; the verifier accepts it (it is inside the clock-skew
        // allowance) and retains it as the node's highest version, so judging
        // its key window at the earlier instant found no active local key,
        // reported `PeerRejected`, and revoked every admission (M7-C170).
        // Nothing is widened: the read instant is the moment this relay
        // actually holds the evidence, and every check stays strict at it.
        let records_received_wall = Utc::now();
        let records_received_mono = Instant::now();
        let checkpoint_minimums = &checkpoint.checkpoint().minimum_versions;
        let freshness_floor = records_received_wall
            - chrono::Duration::from_std(self.config.max_clock_skew)
                .unwrap_or(chrono::Duration::zero());
        // Whether any record for a node the checkpoint names, at or above its
        // minimum, is still inside its signed lifetime (M7-C186). Computed
        // over every record, before and independently of verification (which
        // stops at the first failure), from each record's *claimed* node,
        // version and expiry: it only decides whether this pass counts
        // toward a surrender, never what is trusted.
        let fresh_named_record = records.iter().any(|catalog_record| {
            serde_json::from_slice::<tunnel_cluster::membership::SignedMembershipRecord>(
                &catalog_record.bytes,
            )
            .is_ok_and(|signed| {
                checkpoint_minimums
                    .get(&signed.node_id)
                    .is_some_and(|&minimum| signed.record_version >= minimum)
                    && signed.expires_at >= freshness_floor
            })
        });
        let record_result = (|| {
            if records.len() > MAX_MEMBERSHIP_RECORDS {
                return Err(MembershipRuntimeError::Source(
                    MembershipSourceError::TooManyRecords,
                ));
            }
            let mut seen_nodes = BTreeSet::new();
            for catalog_record in records {
                if catalog_record.bytes.is_empty()
                    || catalog_record.bytes.len() > MAX_CHECKPOINT_BYTES
                    || catalog_record.version == 0
                {
                    return Err(MembershipRuntimeError::Source(
                        MembershipSourceError::InvalidRecordEnvelope,
                    ));
                }
                let signed: tunnel_cluster::membership::SignedMembershipRecord =
                    serde_json::from_slice(&catalog_record.bytes).map_err(|_| {
                        MembershipRuntimeError::Source(MembershipSourceError::InvalidRecordEnvelope)
                    })?;
                if signed.record_version != catalog_record.version
                    || !seen_nodes.insert(signed.node_id.clone())
                {
                    return Err(MembershipRuntimeError::Source(
                        MembershipSourceError::InvalidRecordEnvelope,
                    ));
                }
                // M7-C185: the catalog never deletes a removed node's record,
                // so a record the checkpoint does not ask for must not fail
                // every relay's pass. Selected by the record's claimed node
                // and version *before* verification -- the shape check runs
                // first inside `verify_membership`, so a removed record that
                // has also expired would otherwise fail as a window error.
                // A record for a node the checkpoint omits is skipped; a
                // record below its node's minimum is absent for that node
                // only (for this relay's own node that is M7-C182 case (b)).
                // Skipped records are never signature-checked. That grants
                // nothing: a skipped record is never retained, bound or
                // routed to. Everything else stays fatal: a bad signature,
                // non-canonical encoding, a rollback, an equal-version
                // conflict, and any unexpired record at or above its minimum
                // that fails any check (expired peer records: M7-C187 below).
                let Some(&minimum) = checkpoint_minimums.get(&signed.node_id) else {
                    continue;
                };
                if signed.record_version < minimum {
                    continue;
                }
                // M7-C187: another node's record past its signed lifetime
                // plus the accepted skew -- exactly the instant verification
                // would report `Expired` -- is absent for that node only, so
                // one lapsed record costs that node its route instead of
                // failing every relay's pass. Selected from the claimed
                // expiry before verification, like M7-C185, and never
                // signature-checked: it grants nothing, because routing and
                // peer binding re-check the retained record's own window
                // and an unverified record is never retained. This relay's
                // own expired record is still verified and stays fatal, and
                // every unexpired record still fails the pass on any check.
                //
                // One carve-out keeps "absent" from granting anything: a
                // lapsed record at a version above one this relay retains
                // verified and still inside its window (plus skew) is not
                // skipped. Skipping it would leave that older record
                // routable, although the publisher has superseded it -- an
                // already-expired revision is how a publisher withdraws a
                // node's live record -- so it stays fatal as before. A
                // stuck publisher never reaches this: its node's last record
                // is the one retained, and any older one lapsed first.
                if signed.node_id != self.config.node_id
                    && signed.expires_at < freshness_floor
                    && !candidate_verifier
                        .retained_memberships()
                        .iter()
                        .any(|retained| {
                            retained.node_id() == signed.node_id.as_str()
                                && retained.record().record_version < signed.record_version
                                && retained.record().expires_at >= freshness_floor
                        })
                {
                    continue;
                }
                candidate_verifier
                    .verify_membership(&catalog_record.bytes, records_received_wall)
                    .map_err(MembershipRuntimeError::Membership)?;
            }
            Ok::<_, MembershipRuntimeError>(())
        })();
        // A publisher outage signature: the checkpoint is fresh but no node
        // it names has a record still inside its lifetime (M7-C186).
        if !fresh_named_record {
            self.state
                .lock()
                .expect("membership state mutex poisoned")
                .pass_publisher_outage = true;
        }
        if let Err(error) = record_result {
            // Persist partially accepted record fences before installing the
            // failed candidate as unready. This also covers a valid
            // checkpoint followed by malformed catalog input.
            let version_state = candidate_verifier.version_state();
            self.persist_if_changed(version_state, checkpoint_received_wall)
                .await?;
            self.install_unready_candidate(
                candidate_verifier,
                MembershipUnreadyReason::MembershipRejected,
                checkpoint.checkpoint().checkpoint_version,
                checkpoint.checkpoint().expires_at,
                checkpoint_received_wall,
                PeerInvalidationReason::MembershipRevoked,
            );
            return Err(error);
        }

        let checkpoint_expiry = checkpoint.checkpoint().expires_at;
        let Some(local_minimum_version) = checkpoint
            .checkpoint()
            .minimum_versions
            .get(&self.config.node_id)
            .copied()
        else {
            let version_state = candidate_verifier.version_state();
            self.persist_if_changed(version_state, checkpoint_received_wall)
                .await?;
            // A fresh signed checkpoint that does not name this node, and no
            // record for it in the catalog (one would have failed
            // verification as `NodeNotInCheckpoint`): a signed removal
            // (M7-C182, case (a)).
            self.note_local_gap(LocalMembershipGap::NodeOmitted);
            self.install_unready_candidate(
                candidate_verifier,
                MembershipUnreadyReason::MissingLocalMembership,
                checkpoint.checkpoint().checkpoint_version,
                checkpoint_expiry,
                checkpoint_received_wall,
                PeerInvalidationReason::MembershipRevoked,
            );
            return Err(MembershipRuntimeError::NotReady);
        };
        let local_membership =
            candidate_verifier
                .retained_memberships()
                .into_iter()
                .find(|membership| {
                    membership.node_id() == self.config.node_id.as_str()
                        && membership.record().record_version >= local_minimum_version
                });
        let Some(local_membership) = local_membership else {
            // Every record in the candidate verified; what is missing is a
            // usable record for *this* node at or above the checkpoint's
            // minimum version. That is `MissingLocalMembership`, the same
            // condition as a checkpoint that does not name this node, and
            // deliberately not `MembershipRejected`, which means a record
            // failed verification. (M7-C86 would retain peer pins for this
            // local condition; that retention is held, so it withdraws them
            // like every other unready reason today.)
            let version_state = candidate_verifier.version_state();
            self.persist_if_changed(version_state, checkpoint_received_wall)
                .await?;
            // The node is named, but the catalog holds no record for it and
            // any record retained from an earlier pass is below the minimum:
            // what a publish race produces, or a publisher that stopped
            // writing this node (M7-C182, case (b)). A record that *is* in
            // the catalog below the minimum fails verification above and is
            // `MembershipRejected`, which only M7-C184 bounds.
            self.note_local_gap(LocalMembershipGap::BelowMinimum);
            self.install_unready_candidate(
                candidate_verifier,
                MembershipUnreadyReason::MissingLocalMembership,
                checkpoint.checkpoint().checkpoint_version,
                checkpoint_expiry,
                checkpoint_received_wall,
                PeerInvalidationReason::MembershipRevoked,
            );
            return Err(MembershipRuntimeError::PeerRejected);
        };

        // Select the key for this relay's observed certificate before applying
        // the signed time window.  `active_key` intentionally returns the
        // latest valid key for peer callers, but that selection is unsafe for
        // local readiness during an overlap: an unrelated newer key must not
        // replace the identity proof for this process.  A known, non-revoked
        // local key that has expired is an expiry boundary; a missing,
        // revoked, or not-yet-active local pin remains a membership rejection.
        // The digest currently served, read under the reconcile gate this
        // pass holds, so a concurrent identity switch is either wholly before
        // or wholly after this pass.
        let local_serving_spki = self.local_serving_spki();
        let local_spki = local_serving_spki.as_deref();
        let local_key = local_spki.and_then(|spki| {
            local_membership.keys().iter().find(|key| {
                // M7-C171, option (a): a `not_before` up to the accepted
                // clock skew ahead of this relay's clock is active, as the
                // verifier already accepted the record itself; expiry stays
                // strict.
                !key.revoked
                    && key.spki_sha256 == spki
                    && local_membership.key_window_open(key, records_received_wall)
            })
        });
        let Some(local_key) = local_key else {
            let local_key_has_expired_pin = local_spki.is_some_and(|spki| {
                local_membership.keys().iter().any(|key| {
                    !key.revoked
                        && key.spki_sha256 == spki
                        && key.expires_at < records_received_wall
                })
            });
            let (reason, error, invalidation_reason) = if local_key_has_expired_pin {
                (
                    MembershipUnreadyReason::CheckpointExpired,
                    MembershipRuntimeError::CheckpointExpired,
                    PeerInvalidationReason::TrustExpired,
                )
            } else {
                // This relay's own certificate is not an approved key of its
                // own record: a statement about this relay's right to serve,
                // not about the peer keys it verified. Readiness, ownership
                // and admission still fail closed. (M7-C86 would retain the
                // peer pin set here; that retention is held, so the set is
                // withdrawn today.) The *expired* local pin above stays
                // `CheckpointExpired`.
                (
                    MembershipUnreadyReason::MissingLocalKey,
                    MembershipRuntimeError::PeerRejected,
                    PeerInvalidationReason::MembershipRevoked,
                )
            };
            let version_state = candidate_verifier.version_state();
            self.persist_if_changed(version_state, checkpoint_received_wall)
                .await?;
            self.install_unready_candidate(
                candidate_verifier,
                reason,
                checkpoint.checkpoint().checkpoint_version,
                checkpoint_expiry,
                checkpoint_received_wall,
                invalidation_reason,
            );
            return Err(error);
        };

        let mut trust_wall_expiry = checkpoint_expiry.min(local_membership.record().expires_at);
        if local_key.expires_at < trust_wall_expiry {
            trust_wall_expiry = local_key.expires_at;
        }
        let trust_deadline = monotonic_deadline(
            request_started_wall,
            request_started_mono,
            trust_wall_expiry,
        );
        if trust_deadline <= records_received_mono || local_key.expires_at <= records_received_wall
        {
            let version_state = candidate_verifier.version_state();
            self.persist_if_changed(version_state, checkpoint_received_wall)
                .await?;
            self.install_unready_candidate(
                candidate_verifier,
                MembershipUnreadyReason::CheckpointExpired,
                checkpoint.checkpoint().checkpoint_version,
                checkpoint_expiry,
                checkpoint_received_wall,
                PeerInvalidationReason::TrustExpired,
            );
            return Err(MembershipRuntimeError::CheckpointExpired);
        }

        let version_state = candidate_verifier.version_state();

        // Verification advances the candidate fences before readiness is
        // exposed. Persist that exact high-water state first, without holding
        // the synchronous runtime mutex across filesystem I/O. Existing
        // bindings remain usable until this durable candidate is swapped.
        self.persist_if_changed(version_state, checkpoint_received_wall)
            .await?;
        let mut state = self.state.lock().expect("membership state mutex poisoned");

        state.verifier = candidate_verifier;
        state.readiness = MembershipReadiness::Ready;
        state.generation = state.generation.saturating_add(1);
        state.checkpoint_version = Some(checkpoint.checkpoint().checkpoint_version);
        state.checkpoint_expires_at = Some(checkpoint_expiry);
        state.trust_expires_at = Some(trust_wall_expiry);
        state.trust_deadline = Some(trust_deadline);
        state.last_verified_at = Some(checkpoint_received_wall);
        let invalidations = state.revalidate_active(
            records_received_wall,
            records_received_mono,
            PeerInvalidationReason::MembershipChanged,
        );
        let snapshot = state.snapshot();
        drop(state);
        self.dispatch_invalidations(invalidations);
        Ok(snapshot)
    }

    async fn fetch_checkpoint(
        &self,
        request: CheckpointRequest,
    ) -> Result<CheckpointResponse, MembershipRuntimeError> {
        request
            .validate()
            .map_err(MembershipRuntimeError::Authority)?;
        tokio::select! {
            _ = self.cancellation.cancelled() => Err(MembershipRuntimeError::Cancelled),
            response = tokio::time::timeout(
                self.config.checkpoint_timeout,
                self.authority.fetch_checkpoint(request),
            ) => match response {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(error)) => Err(MembershipRuntimeError::Authority(error)),
                Err(_) => Err(MembershipRuntimeError::Authority(
                    CheckpointAuthorityError::DeadlineExceeded,
                )),
            },
        }
    }

    async fn read_memberships(
        &self,
    ) -> Result<Vec<CatalogMembershipRecord>, MembershipRuntimeError> {
        tokio::select! {
            _ = self.cancellation.cancelled() => Err(MembershipRuntimeError::Cancelled),
            records = tokio::time::timeout(
                self.config.checkpoint_timeout,
                self.catalog.read_signed_memberships(),
            ) => match records {
                Ok(Ok(records)) => Ok(records),
                Ok(Err(error)) => Err(MembershipRuntimeError::Source(error)),
                Err(_) => Err(MembershipRuntimeError::Source(MembershipSourceError::Catalog)),
            },
        }
    }

    async fn persist_version_state(
        &self,
        version_state: MembershipVersionState,
    ) -> Result<(), MembershipRuntimeError> {
        let Some(store) = self.version_store.as_ref().cloned() else {
            return Ok(());
        };
        let mut task = tokio::task::spawn_blocking(move || store.save(&version_state));
        match tokio::time::timeout(MAX_MEMBERSHIP_PERSISTENCE_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(MembershipRuntimeError::Persistence(error)),
            Ok(Err(_)) => Err(MembershipRuntimeError::Persistence(
                MembershipVersionStateStoreError::Io,
            )),
            Err(_) => {
                // Dropping a JoinHandle does not cancel a blocking task.  Join
                // it before releasing the reconcile gate so a late write can
                // never race a subsequent pass that might publish Ready.
                let _ = task.await;
                Err(MembershipRuntimeError::PersistenceTimeout)
            }
        }
    }

    async fn persist_if_changed(
        &self,
        version_state: MembershipVersionState,
        now: DateTime<Utc>,
    ) -> Result<(), MembershipRuntimeError> {
        if self.version_store.is_none() {
            return Ok(());
        }
        {
            let state = self.state.lock().expect("membership state mutex poisoned");
            if state.last_persisted_version_state.as_ref() == Some(&version_state) {
                return Ok(());
            }
        }
        if let Err(error) = self.persist_version_state(version_state.clone()).await {
            self.mark_persistence_failure(now);
            return Err(error);
        }
        let mut state = self.state.lock().expect("membership state mutex poisoned");
        state.last_persisted_version_state = Some(version_state);
        Ok(())
    }

    fn mark_persistence_failure(&self, now: DateTime<Utc>) {
        let invalidations = {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            state.readiness =
                MembershipReadiness::Unready(MembershipUnreadyReason::PersistenceUnavailable);
            state.invalidate_active(now, PeerInvalidationReason::PersistenceUnavailable)
        };
        self.dispatch_invalidations(invalidations);
    }

    fn install_unready_candidate(
        &self,
        verifier: MembershipVerifier,
        reason: MembershipUnreadyReason,
        checkpoint_version: u64,
        checkpoint_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        invalidation_reason: PeerInvalidationReason,
    ) {
        let invalidations = {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            state.verifier = verifier;
            state.readiness = MembershipReadiness::Unready(reason);
            state.checkpoint_version = Some(checkpoint_version);
            state.checkpoint_expires_at = Some(checkpoint_expires_at);
            state.last_verified_at = Some(now);
            state.invalidate_active(now, invalidation_reason)
        };
        self.dispatch_invalidations(invalidations);
    }

    fn mark_error(&self, error: &MembershipRuntimeError) {
        if matches!(
            error,
            MembershipRuntimeError::NotReady | MembershipRuntimeError::PeerRejected
        ) {
            return;
        }
        let reason = match error {
            MembershipRuntimeError::Authority(_) => MembershipUnreadyReason::UnknownAuthority,
            MembershipRuntimeError::Source(MembershipSourceError::Catalog) => {
                MembershipUnreadyReason::CatalogUnavailable
            }
            MembershipRuntimeError::Source(MembershipSourceError::Cancelled) => {
                MembershipUnreadyReason::Cancelled
            }
            MembershipRuntimeError::Source(
                MembershipSourceError::TooManyRecords
                | MembershipSourceError::InvalidRecordEnvelope,
            ) => MembershipUnreadyReason::MembershipRejected,
            MembershipRuntimeError::Membership(MembershipError::UnknownPublisherKey(_)) => {
                MembershipUnreadyReason::UnknownAuthority
            }
            MembershipRuntimeError::Membership(_) => MembershipUnreadyReason::MembershipRejected,
            MembershipRuntimeError::Persistence(_) | MembershipRuntimeError::PersistenceTimeout => {
                MembershipUnreadyReason::PersistenceUnavailable
            }
            MembershipRuntimeError::CheckpointExpired => MembershipUnreadyReason::CheckpointExpired,
            MembershipRuntimeError::Cancelled => MembershipUnreadyReason::Cancelled,
            MembershipRuntimeError::NotReady | MembershipRuntimeError::PeerRejected => {
                unreachable!("handled before readiness mapping")
            }
            MembershipRuntimeError::InvalidConfiguration | MembershipRuntimeError::Join => {
                MembershipUnreadyReason::UnknownAuthority
            }
        };
        let invalidations = {
            let mut state = self.state.lock().expect("membership state mutex poisoned");
            state.readiness = MembershipReadiness::Unready(reason);
            match reason {
                MembershipUnreadyReason::UnknownAuthority => {
                    state.invalidate_active(Utc::now(), PeerInvalidationReason::AuthorityUnknown)
                }
                MembershipUnreadyReason::MembershipRejected => {
                    state.invalidate_active(Utc::now(), PeerInvalidationReason::MembershipRevoked)
                }
                MembershipUnreadyReason::CheckpointExpired => {
                    state.invalidate_active(Utc::now(), PeerInvalidationReason::TrustExpired)
                }
                MembershipUnreadyReason::PersistenceUnavailable => state
                    .invalidate_active(Utc::now(), PeerInvalidationReason::PersistenceUnavailable),
                MembershipUnreadyReason::Cancelled => {
                    state.invalidate_active(Utc::now(), PeerInvalidationReason::RuntimeCancelled)
                }
                _ => Vec::new(),
            }
        };
        self.dispatch_invalidations(invalidations);
    }

    fn mark_cancelled(&self) -> Vec<Invalidation> {
        let mut state = self.state.lock().expect("membership state mutex poisoned");
        state.readiness = MembershipReadiness::Unready(MembershipUnreadyReason::Cancelled);
        state.invalidate_active(Utc::now(), PeerInvalidationReason::RuntimeCancelled)
    }

    fn dispatch_invalidations(&self, invalidations: Vec<Invalidation>) {
        for invalidation in invalidations {
            let _ = invalidation.reason_cell.compare_exchange(
                0,
                invalidation.reason.code(),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            invalidation.token.cancel();
            if let Some(callback) = invalidation.callback {
                callback(invalidation.identity, invalidation.reason);
            }
        }
    }
}

struct Invalidation {
    identity: PeerIdentity,
    token: CancellationToken,
    reason_cell: Arc<AtomicU8>,
    callback: Option<PeerInvalidationCallback>,
    reason: PeerInvalidationReason,
}

impl RuntimeState {
    fn snapshot(&self) -> MembershipSnapshot {
        let mut memberships = self
            .verifier
            .retained_memberships()
            .into_iter()
            .filter_map(|membership| self.redacted_membership(membership))
            .collect::<Vec<_>>();
        memberships.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        memberships.truncate(MAX_MEMBERSHIP_RECORDS);
        MembershipSnapshot {
            readiness: self.readiness.clone(),
            generation: self.generation,
            checkpoint_version: self.checkpoint_version,
            checkpoint_expires_at: self.checkpoint_expires_at,
            trust_expires_at: self.trust_expires_at,
            trust_deadline_ms: self.trust_deadline.map(crate::runtime::monotonic_millis_at),
            last_verified_at: self.last_verified_at,
            membership_count: memberships.len(),
            active_peer_count: self.active_peers.len(),
            memberships,
        }
    }

    fn redacted_membership(
        &self,
        membership: VerifiedMembership,
    ) -> Option<RedactedMembershipSnapshot> {
        let checkpoint = self.verifier.fresh_checkpoint(Utc::now()).ok()?;
        let minimum = checkpoint
            .checkpoint()
            .minimum_versions
            .get(membership.node_id())
            .copied()?;
        if membership.record().record_version < minimum {
            return None;
        }
        Some(RedactedMembershipSnapshot {
            node_id: membership.node_id().to_owned(),
            record_version: membership.record().record_version,
            publisher_key_id: membership.publisher_key_id().to_owned(),
            key_ids: membership
                .keys()
                .iter()
                .map(|key| key.key_id.clone())
                .collect(),
            spki_sha256: membership
                .keys()
                .iter()
                .map(|key| key.spki_sha256.clone())
                .collect(),
            valid_until: membership.record().expires_at,
        })
    }

    fn expire_if_needed(
        &mut self,
        now: DateTime<Utc>,
        monotonic_now: Instant,
    ) -> Vec<Invalidation> {
        let monotonic_expired = self
            .trust_deadline
            .is_some_and(|deadline| monotonic_now >= deadline);
        let wall_clock_invalid = self.trust_deadline.is_some()
            && (self
                .trust_expires_at
                .is_some_and(|expires_at| now >= expires_at)
                || self.verifier.fresh_checkpoint(now).is_err());
        if monotonic_expired || wall_clock_invalid {
            self.readiness =
                MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired);
            return self.invalidate_active(now, PeerInvalidationReason::TrustExpired);
        }
        let expired = self
            .active_peers
            .iter()
            .filter(|(_, peer)| peer.admission.deadline.expires_at <= monotonic_now)
            .map(|(identity, _)| identity.clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|identity| {
                self.active_peers
                    .remove(&identity)
                    .map(|peer| (identity, peer))
            })
            .map(|(identity, peer)| Invalidation {
                identity,
                token: peer.admission.invalidation,
                reason_cell: peer.admission.invalidation_reason,
                callback: self.callback.clone(),
                reason: PeerInvalidationReason::TrustExpired,
            })
            .collect()
    }

    fn invalidate_active(
        &mut self,
        _now: DateTime<Utc>,
        reason: PeerInvalidationReason,
    ) -> Vec<Invalidation> {
        let active = std::mem::take(&mut self.active_peers);
        active
            .into_iter()
            .map(|(identity, peer)| Invalidation {
                identity,
                token: peer.admission.invalidation,
                reason_cell: peer.admission.invalidation_reason,
                callback: self.callback.clone(),
                reason,
            })
            .collect()
    }

    /// Re-check every active admission against a freshly installed verified
    /// directory.
    ///
    /// **M7-C80.** A re-signed record for an unchanged node, boot, key,
    /// endpoint and server name, at a higher record version and with a trust
    /// boundary that did not shrink, is the publisher renewing the authority
    /// the admission already rests on. Invalidating it there killed every
    /// in-flight peer stream at every routine re-sign. Such an admission is
    /// now *re-bound*: it keeps its cancellation token, so the streams riding
    /// it survive, and takes the new record version, the new binding and the
    /// new deadline -- exactly what a fresh admission would get from the same
    /// evidence, but never earlier than the deadline it already had.
    ///
    /// Anything else still invalidates: a binding that no longer verifies
    /// (revoked or removed key), a changed key, endpoint or server name, a
    /// shrunk signed boundary, or a passed deadline.
    fn revalidate_active(
        &mut self,
        now: DateTime<Utc>,
        now_mono: Instant,
        default_reason: PeerInvalidationReason,
    ) -> Vec<Invalidation> {
        let mut invalidations = Vec::new();
        let peers = std::mem::take(&mut self.active_peers);
        for (identity, mut peer) in peers {
            let current = self.verifier.bind_peer(
                &identity.node_id,
                &identity.boot_id,
                &identity.spki_sha256,
                now,
            );
            let current_version = self
                .verifier
                .retained_memberships()
                .into_iter()
                .find(|membership| membership.node_id() == identity.node_id.as_str())
                .map(|membership| membership.record().record_version);
            let binding_changed = match current.as_ref() {
                Ok(binding) => !same_peer_binding(binding, peer.admission.binding()),
                Err(_) => true,
            };
            // Compare the signed wall-clock trust boundary. Recomputing a
            // monotonic deadline from each refresh receipt is not a valid
            // shrink test and can spuriously revoke an unchanged admission.
            let trust_deadline_shrank = self
                .trust_expires_at
                .zip(current.as_ref().ok())
                .is_none_or(|(expires_at, binding)| {
                    expires_at.min(binding.valid_until())
                        < peer.admission.deadline.trust_expires_at()
                });
            let permitted = rebind_permitted(RebindCheck {
                previous_version: peer.record_version,
                current_version,
                binding_changed,
                trust_deadline_shrank,
                deadline_expired: peer.admission.deadline.is_expired(),
            });
            match current {
                Ok(binding) if permitted => {
                    let signed_boundary = self
                        .trust_expires_at
                        .map_or(binding.valid_until(), |expires_at| {
                            expires_at.min(binding.valid_until())
                        });
                    // Re-convert only when the signed boundary actually
                    // moved later. An unchanged boundary keeps the monotonic
                    // deadline it was first converted to: re-converting the
                    // same wall-clock instant from each reconcile's receipt
                    // and keeping the latest would ratchet it later by
                    // clock-conversion drift, past the peer's own conversion
                    // of the same boundary (the M7-C86 trust-expiry race).
                    let renewed = renewed_deadline(
                        peer.admission.deadline.expires_at,
                        signed_boundary > peer.admission.deadline.trust_expires_at(),
                        self.trust_deadline,
                        monotonic_deadline(now, now_mono, binding.valid_until()),
                    );
                    peer.admission.deadline = AdmissionDeadline {
                        started_at: peer.admission.deadline.started_at,
                        expires_at: renewed,
                        trust_expires_at: signed_boundary,
                    };
                    peer.admission.expiry.set(renewed, signed_boundary);
                    peer.admission.binding = binding;
                    if let Some(version) = current_version {
                        peer.record_version = version;
                    }
                    self.active_peers.insert(identity, peer);
                }
                current => {
                    invalidations.push(Invalidation {
                        identity,
                        token: peer.admission.invalidation,
                        reason_cell: peer.admission.invalidation_reason,
                        callback: self.callback.clone(),
                        reason: if current.is_err() {
                            PeerInvalidationReason::MembershipRevoked
                        } else {
                            default_reason
                        },
                    });
                }
            }
        }
        invalidations
    }
}

/// The facts one re-bind decision rests on (M7-C80).
#[derive(Clone, Copy, Debug)]
struct RebindCheck {
    previous_version: u64,
    current_version: Option<u64>,
    binding_changed: bool,
    trust_deadline_shrank: bool,
    deadline_expired: bool,
}

/// Whether an active admission may be re-bound to freshly verified evidence
/// instead of invalidated. Every clause fails closed: a missing or lower
/// record version, a changed binding identity, a shrunk signed boundary or
/// an already-passed deadline each forbid the re-bind. The verifier already
/// refuses a lower or equal-version record, so the version clause is defence
/// in depth and is witnessed by a unit test rather than through a record.
const fn rebind_permitted(check: RebindCheck) -> bool {
    let version_ok = match check.current_version {
        Some(version) => version >= check.previous_version,
        None => false,
    };
    let deadline_ok = !check.deadline_expired;
    version_ok && !check.binding_changed && !check.trust_deadline_shrank && deadline_ok
}

/// The monotonic deadline of a re-bound admission. It is re-converted only
/// when the signed boundary moved later -- re-converting an unchanged
/// boundary on every reconcile would ratchet it later by clock-conversion
/// drift -- and it is never moved earlier than the deadline it already had.
fn renewed_deadline(
    previous: Instant,
    boundary_moved_later: bool,
    local_trust_deadline: Option<Instant>,
    peer_deadline: Instant,
) -> Instant {
    if !boundary_moved_later {
        return previous;
    }
    let bounded =
        local_trust_deadline.map_or(peer_deadline, |deadline| deadline.min(peer_deadline));
    bounded.max(previous)
}

/// Whether two verified bindings name the same peer authority: node, boot,
/// key, SPKI, endpoint and server name. The signed validity window is
/// deliberately excluded; a re-sign renewing it is compared separately as a
/// trust boundary that must not shrink (M7-C80).
fn same_peer_binding(left: &VerifiedPeerBinding, right: &VerifiedPeerBinding) -> bool {
    left.node_id() == right.node_id()
        && left.boot_id() == right.boot_id()
        && left.key_id() == right.key_id()
        && left.spki_sha256() == right.spki_sha256()
        && left.peer_endpoint() == right.peer_endpoint()
        && left.server_name() == right.server_name()
}

fn monotonic_deadline(
    request_started_wall: DateTime<Utc>,
    request_started_mono: Instant,
    expires_at: DateTime<Utc>,
) -> Instant {
    match (expires_at - request_started_wall).to_std() {
        Ok(remaining) => request_started_mono
            .checked_add(remaining)
            .unwrap_or(request_started_mono),
        Err(_) => request_started_mono,
    }
}

fn map_checkpoint_error(error: MembershipError) -> MembershipRuntimeError {
    if matches!(
        error,
        MembershipError::InvalidTime
            | MembershipError::InvalidTimeWindow
            | MembershipError::LifetimeExceeded
            | MembershipError::IssuedInFuture
            | MembershipError::NotYetValid
            | MembershipError::Expired
    ) {
        MembershipRuntimeError::CheckpointExpired
    } else {
        MembershipRuntimeError::Membership(error)
    }
}

fn is_spki_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Parsed, operator-configured HTTPS endpoint used by the rustls authority
/// client.  It contains no credentials and cannot be changed by a request.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedAuthorityEndpoint {
    uri: Uri,
    authority: String,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
}

impl ParsedAuthorityEndpoint {
    fn parse(endpoint: &str) -> Result<Self, CheckpointAuthorityError> {
        if endpoint.is_empty()
            || endpoint.len() > MAX_AUTHORITY_ENDPOINT_BYTES
            || endpoint
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(CheckpointAuthorityError::InvalidEndpoint);
        }
        let uri: Uri = endpoint
            .parse()
            .map_err(|_| CheckpointAuthorityError::InvalidEndpoint)?;
        if uri.scheme_str() != Some("https") || uri.query().is_some() {
            return Err(CheckpointAuthorityError::InvalidEndpoint);
        }
        let authority = uri
            .authority()
            .ok_or(CheckpointAuthorityError::InvalidEndpoint)?;
        if authority.as_str().contains('@') {
            return Err(CheckpointAuthorityError::InvalidEndpoint);
        }
        let authority_text = authority.as_str().to_owned();
        let authority_host = authority.host();
        let host = authority_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(authority_host)
            .to_owned();
        if host.is_empty() {
            return Err(CheckpointAuthorityError::InvalidEndpoint);
        }
        let port = authority.port_u16().unwrap_or(443);
        if port == 0 {
            return Err(CheckpointAuthorityError::InvalidEndpoint);
        }
        let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.clone())
                .map_err(|_| CheckpointAuthorityError::InvalidEndpoint)?
        };
        Ok(Self {
            uri,
            authority: authority_text,
            host,
            port,
            server_name,
        })
    }

    fn request_target(&self) -> &str {
        self.uri
            .path_and_query()
            .map_or("/", |path_and_query| path_and_query.as_str())
    }
}

/// Actual HTTPS checkpoint authority adapter.  It uses rustls server
/// verification against the operator-provisioned CA bundle and Hyper's HTTP/1
/// client connection over a Tokio TCP/TLS stream.  There is no plaintext or
/// certificate-skipping fallback.
pub struct HttpsCheckpointAuthority {
    endpoint: ParsedAuthorityEndpoint,
    tls: Arc<ClientConfig>,
    timeout: Duration,
}

impl fmt::Debug for HttpsCheckpointAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsCheckpointAuthority")
            .field("host", &self.endpoint.host)
            .field("port", &self.endpoint.port)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HttpsCheckpointAuthority {
    /// Construct from an endpoint and PEM trust bundle.  The trust bundle is
    /// copied into rustls state; private keys are neither accepted nor needed.
    pub fn new(
        endpoint: impl AsRef<str>,
        trust_bundle_pem: &[u8],
        timeout: Duration,
    ) -> Result<Self, CheckpointAuthorityError> {
        let endpoint = ParsedAuthorityEndpoint::parse(endpoint.as_ref())?;
        if timeout.is_zero() || timeout > MAX_CHECKPOINT_REQUEST_TIMEOUT {
            return Err(CheckpointAuthorityError::InvalidRequest);
        }
        let roots = parse_root_certificates(trust_bundle_pem)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| CheckpointAuthorityError::InvalidTrustBundle)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        Ok(Self {
            endpoint,
            tls: Arc::new(tls),
            timeout,
        })
    }

    /// Construct from the operator-provisioned cluster paths.
    pub fn from_cluster_config(cluster: &ClusterConfig) -> Result<Self, CheckpointAuthorityError> {
        let trust_bundle = std::fs::read(&cluster.checkpoint_authority_trust_path)
            .map_err(|_| CheckpointAuthorityError::InvalidTrustBundle)?;
        Self::new(
            &cluster.checkpoint_authority_endpoint,
            &trust_bundle,
            Duration::from_secs(cluster.checkpoint_timeout_seconds),
        )
    }

    async fn fetch_inner(
        &self,
        request: CheckpointRequest,
    ) -> Result<CheckpointResponse, CheckpointAuthorityError> {
        let body =
            serde_json::to_vec(&request).map_err(|_| CheckpointAuthorityError::InvalidRequest)?;
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .map_err(|_| CheckpointAuthorityError::Transport)?;
        tcp.set_nodelay(true)
            .map_err(|_| CheckpointAuthorityError::Transport)?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(self.endpoint.server_name.clone(), tcp)
            .await
            .map_err(|_| CheckpointAuthorityError::Transport)?;
        let io = TokioIo::new(tls);
        let (mut sender, connection) = http1::handshake(io)
            .await
            .map_err(|_| CheckpointAuthorityError::Transport)?;
        let mut driver = HttpDriver::spawn(connection);
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.endpoint.request_target())
            .header("host", self.endpoint.authority.as_str())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("content-length", body.len().to_string())
            .body(Full::<Bytes>::from(Bytes::from(body)))
            .map_err(|_| CheckpointAuthorityError::InvalidRequest)?;
        let result = self.send_request(&mut sender, request).await;
        driver.shutdown().await;
        result
    }

    async fn send_request(
        &self,
        sender: &mut http1::SendRequest<Full<Bytes>>,
        request: Request<Full<Bytes>>,
    ) -> Result<CheckpointResponse, CheckpointAuthorityError> {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| CheckpointAuthorityError::Transport)?;
        if response.status() != StatusCode::OK {
            return Err(CheckpointAuthorityError::HttpStatus(
                response.status().as_u16(),
            ));
        }
        if let Some(content_length) = response.headers().get("content-length") {
            let content_length = content_length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(CheckpointAuthorityError::InvalidResponse)?;
            if content_length > MAX_CHECKPOINT_BYTES {
                return Err(CheckpointAuthorityError::BodyTooLarge);
            }
        }
        read_checkpoint_body(response.into_body()).await
    }
}

impl CheckpointAuthority for HttpsCheckpointAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            request.validate()?;
            match tokio::time::timeout(self.timeout, self.fetch_inner(request)).await {
                Ok(result) => result,
                Err(_) => Err(CheckpointAuthorityError::DeadlineExceeded),
            }
        })
    }
}

struct HttpDriver {
    task: Option<JoinHandle<Result<(), hyper::Error>>>,
}

impl HttpDriver {
    fn spawn<I>(connection: hyper::client::conn::http1::Connection<I, Full<Bytes>>) -> Self
    where
        I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    {
        Self {
            task: Some(tokio::spawn(connection)),
        }
    }

    async fn shutdown(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for HttpDriver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn read_checkpoint_body(
    mut body: Incoming,
) -> Result<CheckpointResponse, CheckpointAuthorityError> {
    let mut bytes = Vec::with_capacity(MAX_CHECKPOINT_BYTES.min(4 * 1024));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| CheckpointAuthorityError::InvalidResponse)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if bytes.len().saturating_add(data.len()) > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointAuthorityError::BodyTooLarge);
        }
        bytes.extend_from_slice(&data);
    }
    CheckpointResponse::new(bytes).map_err(|_| CheckpointAuthorityError::InvalidResponse)
}

fn parse_root_certificates(pem: &[u8]) -> Result<RootCertStore, CheckpointAuthorityError> {
    let mut reader = std::io::BufReader::new(pem);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CheckpointAuthorityError::InvalidTrustBundle)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| CheckpointAuthorityError::InvalidTrustBundle)?;
    }
    if roots.is_empty() {
        return Err(CheckpointAuthorityError::InvalidTrustBundle);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rebind_check() -> RebindCheck {
        RebindCheck {
            previous_version: 3,
            current_version: Some(4),
            binding_changed: false,
            trust_deadline_shrank: false,
            deadline_expired: false,
        }
    }

    /// M7-C80: every clause of the re-bind guard fails closed on its own.
    #[test]
    fn every_rebind_clause_fails_closed_on_its_own() {
        assert!(
            rebind_permitted(rebind_check()),
            "control: a clean re-sign re-binds"
        );
        let mut equal = rebind_check();
        equal.current_version = Some(3);
        assert!(rebind_permitted(equal), "the same version still re-binds");
        type Mutation = fn(&mut RebindCheck);
        let cases: [(&str, Mutation); 5] = [
            ("a lower version", |c| c.current_version = Some(2)),
            ("a missing record", |c| c.current_version = None),
            ("a changed binding", |c| c.binding_changed = true),
            ("a shrunk boundary", |c| c.trust_deadline_shrank = true),
            ("a passed deadline", |c| c.deadline_expired = true),
        ];
        for (name, mutate) in cases {
            let mut check = rebind_check();
            mutate(&mut check);
            assert!(!rebind_permitted(check), "M7-C80: {name} was re-bound");
        }
    }

    /// M7-C80: a renewal never moves a deadline earlier, and an unchanged
    /// signed boundary keeps the deadline it was first converted to.
    #[test]
    fn a_renewed_deadline_is_never_earlier_and_unchanged_boundaries_keep_theirs() {
        let base = Instant::now();
        let previous = base + Duration::from_secs(10);
        let earlier = base + Duration::from_secs(9);
        let later = base + Duration::from_secs(20);
        assert_eq!(
            renewed_deadline(previous, true, Some(earlier), later),
            previous,
            "M7-C80: a renewal moved the deadline earlier than it already was"
        );
        assert_eq!(renewed_deadline(previous, true, None, earlier), previous);
        assert_eq!(renewed_deadline(previous, true, Some(later), later), later);
        assert_eq!(
            renewed_deadline(previous, true, Some(later + Duration::from_secs(1)), later),
            later,
            "the peer boundary still bounds the renewal"
        );
        assert_eq!(
            renewed_deadline(previous, false, Some(later), later),
            previous,
            "an unchanged boundary keeps its first conversion"
        );
    }

    #[test]
    fn request_rejects_invalid_nonce() {
        let request = CheckpointRequest {
            deployment_id: "deployment".into(),
            deployment_incarnation: "incarnation".into(),
            nonce: "short".into(),
        };
        assert_eq!(
            request.validate(),
            Err(CheckpointAuthorityError::InvalidRequest)
        );
    }

    #[test]
    fn local_spki_pin_is_bounded_and_lower_case() {
        let policy = PrivateEndpointPolicy::private_ip_only();
        let config = MembershipRuntimeConfig::new(
            "deployment",
            "incarnation",
            "relay-a",
            "fresh-boot",
            policy,
            Duration::from_secs(60),
            Duration::from_secs(20),
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .expect("runtime config");
        assert!(
            config
                .clone()
                .with_local_spki_sha256("A".repeat(64))
                .is_err()
        );
        assert!(config.with_local_spki_sha256("a".repeat(64)).is_ok());
    }

    #[test]
    fn endpoint_requires_https_and_rejects_credentials() {
        assert_eq!(
            ParsedAuthorityEndpoint::parse("http://authority.example/checkpoint"),
            Err(CheckpointAuthorityError::InvalidEndpoint)
        );
        assert_eq!(
            ParsedAuthorityEndpoint::parse("https://user:pass@authority.example/checkpoint"),
            Err(CheckpointAuthorityError::InvalidEndpoint)
        );
    }

    #[test]
    fn endpoint_normalizes_bracketed_ipv6_for_connect_and_sni() {
        let endpoint =
            ParsedAuthorityEndpoint::parse("https://[::1]:9443/checkpoint").expect("endpoint");
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.port, 9_443);
        assert_eq!(endpoint.request_target(), "/checkpoint");
    }

    #[test]
    fn monotonic_deadline_never_extends_from_receipt_time() {
        let wall = Utc::now();
        let monotonic = Instant::now();
        let deadline = monotonic_deadline(wall, monotonic, wall + ChronoDuration::seconds(10));
        assert!(deadline <= monotonic + Duration::from_secs(10));
    }

    struct TestCheckpointAuthority;

    impl CheckpointAuthority for TestCheckpointAuthority {
        fn fetch_checkpoint<'a>(
            &'a self,
            _request: CheckpointRequest,
        ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
            Box::pin(async { Err(CheckpointAuthorityError::Cancelled) })
        }
    }

    fn dispatcher_test_runtime() -> Arc<MembershipRuntime> {
        let config = MembershipRuntimeConfig::new(
            "dispatcher-deployment",
            "dispatcher-incarnation",
            "relay-a",
            "boot-a",
            PrivateEndpointPolicy::private_ip_only(),
            Duration::from_secs(60),
            Duration::from_secs(20),
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .expect("dispatcher runtime config");
        MembershipRuntime::with_source(
            Arc::new(StaticMembershipSource::new(Vec::new()).expect("empty test source")),
            Arc::new(TestCheckpointAuthority),
            config,
            [TrustedPublisherKey::new("dispatcher-publisher", [0x11; 32])
                .expect("dispatcher publisher")],
        )
        .expect("dispatcher runtime")
    }

    #[test]
    fn invalidation_dispatcher_keeps_first_trust_expiry_reason() {
        let runtime = dispatcher_test_runtime();
        let identity = PeerIdentity::new("peer-a", "boot-a", "test-spki");
        let token = CancellationToken::new();
        let reason_cell = Arc::new(AtomicU8::new(0));
        let cancellation = PeerAdmissionCancellation {
            token: token.clone(),
            reason: reason_cell.clone(),
            expires_at: None,
        };

        runtime.dispatch_invalidations(vec![Invalidation {
            identity: identity.clone(),
            token: token.clone(),
            reason_cell: reason_cell.clone(),
            callback: None,
            reason: PeerInvalidationReason::TrustExpired,
        }]);
        assert!(cancellation.is_cancelled());
        assert_eq!(
            cancellation.reason(),
            Some(PeerInvalidationReason::TrustExpired)
        );

        runtime.dispatch_invalidations(vec![Invalidation {
            identity,
            token,
            reason_cell,
            callback: None,
            reason: PeerInvalidationReason::MembershipChanged,
        }]);
        assert_eq!(
            cancellation.reason(),
            Some(PeerInvalidationReason::TrustExpired)
        );
    }

    #[test]
    fn admission_cancellation_keeps_first_invalidation_reason() {
        let token = CancellationToken::new();
        let reason = Arc::new(AtomicU8::new(0));
        let cancellation = PeerAdmissionCancellation {
            token: token.clone(),
            reason: reason.clone(),
            expires_at: None,
        };
        assert!(
            reason
                .compare_exchange(
                    0,
                    PeerInvalidationReason::TrustExpired.code(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        );
        assert!(
            reason
                .compare_exchange(
                    0,
                    PeerInvalidationReason::MembershipChanged.code(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        );
        token.cancel();
        assert_eq!(
            cancellation.reason(),
            Some(PeerInvalidationReason::TrustExpired)
        );
    }

    #[test]
    fn trust_expired_uses_typed_reason_or_passed_admission_deadline_only() {
        // No deadline and no invalidation: nothing is expired.
        let fresh = PeerAdmissionCancellation::from_token(CancellationToken::new());
        assert!(!fresh.trust_expired());
        assert_eq!(fresh.expires_at(), None);

        // A future monotonic deadline is not expiry, and neither is an
        // unclassified cancellation (for example a closed connection).
        let future = PeerAdmissionCancellation::from_token_with_deadline(
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        );
        assert!(!future.trust_expired());
        future.token().cancel();
        assert!(!future.trust_expired());

        // A passed deadline is positive evidence even before the dispatcher
        // cancels the edge.
        let passed = PeerAdmissionCancellation::from_token_with_deadline(
            CancellationToken::new(),
            Instant::now() - Duration::from_millis(1),
        );
        assert!(!passed.is_cancelled());
        assert!(passed.trust_expired());

        // The dispatcher's typed trust-expiry reason counts without a
        // deadline, while a different explicit reason is never reinterpreted
        // as expiry even after the deadline has passed.
        let typed = PeerAdmissionCancellation {
            token: CancellationToken::new(),
            reason: Arc::new(AtomicU8::new(PeerInvalidationReason::TrustExpired.code())),
            expires_at: None,
        };
        assert!(typed.trust_expired());
        let revoked_after_deadline = PeerAdmissionCancellation {
            token: CancellationToken::new(),
            reason: Arc::new(AtomicU8::new(
                PeerInvalidationReason::MembershipRevoked.code(),
            )),
            expires_at: Some(SharedAdmissionExpiry::new(
                Instant::now() - Duration::from_millis(1),
                None,
            )),
        };
        revoked_after_deadline.token().cancel();
        assert!(!revoked_after_deadline.trust_expired());
    }

    #[test]
    fn response_is_bounded() {
        assert_eq!(
            CheckpointResponse::new(vec![0; MAX_CHECKPOINT_BYTES + 1]),
            Err(CheckpointAuthorityError::BodyTooLarge)
        );
        let response = CheckpointResponse::new(vec![0xff, 0x00]).expect("bounded response");
        let debug = format!("{response:?}");
        assert!(!debug.contains("ff"));
    }

    #[test]
    fn membership_source_is_bounded_to_authorized_nodes() {
        let records = (0..=MAX_MEMBERSHIP_RECORDS)
            .map(|version| CatalogMembershipRecord {
                version: u64::try_from(version).expect("bounded test index") + 1,
                bytes: vec![1],
            })
            .collect();
        assert!(matches!(
            StaticMembershipSource::new(records),
            Err(MembershipSourceError::TooManyRecords)
        ));
    }

    #[tokio::test]
    async fn catalog_membership_source_reads_the_full_directory() {
        let catalog = Arc::new(tunnel_catalog::MemoryCatalog::new());
        let records = (0..3)
            .map(|index| CatalogMembershipRecord {
                version: index + 1,
                bytes: format!(r#"{{"node_id":"relay-{index}"}}"#).into_bytes(),
            })
            .collect::<Vec<_>>();
        catalog
            .set_signed_memberships(records.clone())
            .await
            .expect("bounded membership directory");
        let source = CatalogMembershipSource::new(catalog);
        assert_eq!(
            source
                .read_signed_memberships()
                .await
                .expect("catalog read"),
            records
        );
    }

    #[test]
    fn redacted_snapshot_does_not_serialize_signed_bytes_or_endpoint() {
        let snapshot = MembershipSnapshot {
            readiness: MembershipReadiness::Starting,
            generation: 1,
            checkpoint_version: Some(1),
            checkpoint_expires_at: None,
            trust_expires_at: None,
            trust_deadline_ms: None,
            last_verified_at: None,
            membership_count: 0,
            active_peer_count: 0,
            memberships: Vec::new(),
        };
        let encoded = serde_json::to_string(&snapshot).expect("snapshot JSON");
        assert!(!encoded.contains("signed"));
        assert!(!encoded.contains("endpoint"));
    }
}
