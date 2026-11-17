//! Reusable, bounded HTTP/3 transport for authenticated relay peers.
//!
//! This module owns the QUIC/HTTP/3 connection lifecycle and body chunk
//! accounting.  It deliberately does not know about relay ownership,
//! tenants, Redis, or application routing.  A caller supplies a policy which
//! is evaluated after the peer certificate has been verified and before a
//! request body is admitted.

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use thiserror::Error;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    peer_probe::{ApprovedPeerPins, PeerProbeError, verified_peer_identity},
    tls::TlsIdentity,
};

/// The default maximum size of one body chunk exposed by this transport.
pub const DEFAULT_PEER_BODY_CHUNK_BYTES: usize = 64 * 1024;

/// The default maximum body bytes counted for one request direction.
pub const DEFAULT_PEER_STREAM_BODY_BYTES: usize = 256 * 1024;

/// The default maximum body bytes counted across one HTTP/3 connection.
pub const DEFAULT_PEER_CONNECTION_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The default number of simultaneously admitted peer connections.
pub const DEFAULT_PEER_CONNECTIONS: usize = 16;

/// The default number of simultaneously admitted request streams per peer
/// connection.
pub const DEFAULT_PEER_STREAMS_PER_CONNECTION: usize = 128;

/// The default number of distinct destinations retained by a client pool.
pub const DEFAULT_PEER_DESTINATIONS: usize = 32;

/// The default HTTP/3 header section bound.
pub const DEFAULT_PEER_HEADER_BYTES: usize = 16 * 1024;

/// The default deadline for a QUIC/TLS handshake and HTTP/3 setup.
pub const DEFAULT_PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection checkout waits for a permit that is about to be
/// released before it reports typed capacity exhaustion.
///
/// Replacing an unusable pooled connection releases its permit when the last
/// handle drops, which is ordinarily immediate; this grace covers that handoff
/// without letting a caller sit on an exhausted pool. It is far below any
/// probe or request budget, so exhaustion stays observable as capacity rather
/// than surfacing as that caller's own timeout.
const CAPACITY_RELEASE_GRACE: Duration = Duration::from_millis(250);

/// The default absolute checkout/setup deadline for one request stream.
pub const DEFAULT_PEER_STREAM_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The default QUIC and per-operation peer inactivity timeout.
pub const DEFAULT_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The default bounded budget for a peer connection drain and joined shutdown.
pub const DEFAULT_PEER_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of relay peer SPKI keys retained by a dynamic pin
/// snapshot.  A membership coordinator may keep current and next keys for a
/// bounded relay roster; larger snapshots are rejected before allocation.
pub const MAX_DYNAMIC_PEER_PINS: usize = 64;

/// Bounds applied independently to peer connections, streams, and body
/// chunks.
///
/// `max_stream_body_bytes` and `max_connection_body_bytes` bound bytes that
/// are currently in flight through the transport in either direction.  A
/// returned receive chunk carries its reservation until the caller drops it;
/// a send reservation lasts until the write completes, is cancelled, or
/// fails.  An application forwarding queue must apply its own charged
/// reservation before retaining a copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerTransportLimits {
    /// Maximum body chunk accepted or returned by one API call.
    pub max_chunk_bytes: usize,
    /// Maximum in-flight body bytes across one request stream's directions.
    pub max_stream_body_bytes: usize,
    /// Maximum in-flight body bytes across one connection.
    pub max_connection_body_bytes: usize,
    /// Maximum active connections supervised by one server or client pool.
    pub max_connections: usize,
    /// Maximum active request streams on one connection.
    pub max_streams_per_connection: usize,
    /// Maximum distinct destinations retained by one client pool.
    pub max_destinations: usize,
    /// Maximum encoded HTTP/3 header section accepted from a peer.
    pub max_header_bytes: usize,
    /// Deadline for QUIC/TLS connection establishment and HTTP/3 setup.
    pub handshake_timeout: Duration,
    /// Absolute checkout/setup deadline for each admitted request stream.
    ///
    /// This is deliberately not a total lifetime for an admitted request.
    /// Long-lived streams are governed by [`Self::idle_timeout`] between
    /// transport operations.
    pub stream_timeout: Duration,
    /// Maximum allowed inactivity between HTTP/3 operations on a stream and
    /// the QUIC connection idle timeout advertised to the peer.
    pub idle_timeout: Duration,
    /// Absolute budget used while closing a peer connection and joining its
    /// child tasks.
    pub drain_timeout: Duration,
}

impl Default for PeerTransportLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_PEER_BODY_CHUNK_BYTES,
            max_stream_body_bytes: DEFAULT_PEER_STREAM_BODY_BYTES,
            max_connection_body_bytes: DEFAULT_PEER_CONNECTION_BODY_BYTES,
            max_connections: DEFAULT_PEER_CONNECTIONS,
            max_streams_per_connection: DEFAULT_PEER_STREAMS_PER_CONNECTION,
            max_destinations: DEFAULT_PEER_DESTINATIONS,
            max_header_bytes: DEFAULT_PEER_HEADER_BYTES,
            handshake_timeout: DEFAULT_PEER_HANDSHAKE_TIMEOUT,
            stream_timeout: DEFAULT_PEER_STREAM_TIMEOUT,
            idle_timeout: DEFAULT_PEER_IDLE_TIMEOUT,
            drain_timeout: DEFAULT_PEER_DRAIN_TIMEOUT,
        }
    }
}

impl PeerTransportLimits {
    /// Validate all configured bounds before creating a supervisor or pool.
    pub fn validate(&self) -> Result<(), PeerTransportError> {
        if self.max_chunk_bytes == 0
            || self.max_stream_body_bytes == 0
            || self.max_connection_body_bytes == 0
            || self.max_connections == 0
            || self.max_streams_per_connection == 0
            || self.max_destinations == 0
            || self.max_header_bytes == 0
            || self.handshake_timeout.is_zero()
            || self.stream_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.drain_timeout.is_zero()
            || self.max_chunk_bytes > self.max_stream_body_bytes
            || self.max_stream_body_bytes > self.max_connection_body_bytes
        {
            return Err(PeerTransportError::InvalidLimits);
        }
        Ok(())
    }

    /// Construct and validate transport limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_chunk_bytes: usize,
        max_stream_body_bytes: usize,
        max_connection_body_bytes: usize,
        max_connections: usize,
        max_streams_per_connection: usize,
        max_destinations: usize,
        max_header_bytes: usize,
        handshake_timeout: Duration,
        stream_timeout: Duration,
    ) -> Result<Self, PeerTransportError> {
        let limits = Self {
            max_chunk_bytes,
            max_stream_body_bytes,
            max_connection_body_bytes,
            max_connections,
            max_streams_per_connection,
            max_destinations,
            max_header_bytes,
            handshake_timeout,
            stream_timeout,
            idle_timeout: DEFAULT_PEER_IDLE_TIMEOUT,
            drain_timeout: DEFAULT_PEER_DRAIN_TIMEOUT,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Construct and validate transport limits with explicit idle and drain
    /// policy values.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_timeouts(
        max_chunk_bytes: usize,
        max_stream_body_bytes: usize,
        max_connection_body_bytes: usize,
        max_connections: usize,
        max_streams_per_connection: usize,
        max_destinations: usize,
        max_header_bytes: usize,
        handshake_timeout: Duration,
        stream_timeout: Duration,
        idle_timeout: Duration,
        drain_timeout: Duration,
    ) -> Result<Self, PeerTransportError> {
        Self::new(
            max_chunk_bytes,
            max_stream_body_bytes,
            max_connection_body_bytes,
            max_connections,
            max_streams_per_connection,
            max_destinations,
            max_header_bytes,
            handshake_timeout,
            stream_timeout,
        )?
        .with_timeouts(idle_timeout, drain_timeout)
    }

    /// Return these limits with the deployment's peer idle and drain policy.
    ///
    /// The idle timeout is refreshed by each successful transport operation,
    /// so an active stream is not killed merely because it has been open for a
    /// long time.
    pub fn with_timeouts(
        mut self,
        idle_timeout: Duration,
        drain_timeout: Duration,
    ) -> Result<Self, PeerTransportError> {
        self.idle_timeout = idle_timeout;
        self.drain_timeout = drain_timeout;
        self.validate()?;
        Ok(self)
    }

    /// Apply this peer policy to a QUIC server configuration before creating
    /// its endpoint. QUIC idle timeout and stream ceilings are negotiated
    /// during the handshake and cannot be added after a connection is
    /// established.
    pub fn apply_to_server_config(
        &self,
        config: &mut quinn::ServerConfig,
    ) -> Result<(), PeerTransportError> {
        config.transport_config(self.quic_transport_config()?);
        Ok(())
    }

    /// Apply this peer policy to a QUIC client configuration before it is
    /// installed on an endpoint.
    pub fn apply_to_client_config(
        &self,
        config: &mut quinn::ClientConfig,
    ) -> Result<(), PeerTransportError> {
        config.transport_config(self.quic_transport_config()?);
        Ok(())
    }

    fn quic_transport_config(&self) -> Result<Arc<quinn::TransportConfig>, PeerTransportError> {
        self.validate()?;
        let idle_timeout = quinn::IdleTimeout::try_from(self.idle_timeout)
            .map_err(|_| PeerTransportError::InvalidLimits)?;
        let streams = quinn::VarInt::from_u64(self.max_streams_per_connection as u64)
            .map_err(|_| PeerTransportError::InvalidLimits)?;
        // `configure_quic_connection` already uses 16 for H3 control/QPACK
        // unidirectional streams.  Advertise that same bounded value during
        // the handshake instead of briefly exposing Quinn's default of 100.
        let uni_streams = quinn::VarInt::from_u32(16);
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(idle_timeout))
            .max_concurrent_bidi_streams(streams)
            .max_concurrent_uni_streams(uni_streams);
        Ok(Arc::new(transport))
    }
}

/// A bounded body chunk returned by or supplied to the peer transport.
///
/// Chunks returned by a receive operation retain their in-flight transport
/// reservation for as long as any clone of the chunk is retained.  Consuming
/// a chunk with [`Self::into_bytes`] transfers ownership to the caller and
/// releases that transport reservation; caller-owned copies are governed by
/// the caller's own budget.  Zero-length chunks carry no reservation metadata.
pub struct PeerBodyChunk {
    bytes: Bytes,
    _charge: Option<Arc<BodyCharge>>,
}

impl Clone for PeerBodyChunk {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _charge: self._charge.clone(),
        }
    }
}

impl std::fmt::Debug for PeerBodyChunk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerBodyChunk")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl PartialEq for PeerBodyChunk {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for PeerBodyChunk {}

impl PeerBodyChunk {
    /// Construct a chunk using the default 64 KiB chunk bound.
    pub fn new(bytes: Bytes) -> Result<Self, PeerTransportError> {
        Self::with_limit(bytes, DEFAULT_PEER_BODY_CHUNK_BYTES)
    }

    /// Construct a chunk with an explicit caller-selected bound.
    pub fn with_limit(bytes: Bytes, maximum: usize) -> Result<Self, PeerTransportError> {
        if bytes.len() > maximum {
            return Err(PeerTransportError::ChunkTooLarge {
                observed: bytes.len(),
                maximum,
            });
        }
        Ok(Self {
            bytes,
            _charge: None,
        })
    }

    /// Return the chunk length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the chunk is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the chunk bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Consume the wrapper and return the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    fn from_received(bytes: Bytes, charge: BodyCharge) -> Self {
        let _charge = (charge.length != 0).then(|| Arc::new(charge));
        Self { bytes, _charge }
    }
}

/// A peer destination selected by the caller's membership snapshot.
///
/// The transport never resolves or chooses a destination.  The `server_name`
/// is used only for TLS certificate-name verification; the address must come
/// from an already-authorized membership record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerDestination {
    /// Private QUIC endpoint address.
    pub address: SocketAddr,
    /// TLS server name expected for the peer certificate.
    pub server_name: String,
}

impl PeerDestination {
    /// Construct a destination from an approved address and TLS name.
    #[must_use]
    pub fn new(address: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            address,
            server_name: server_name.into(),
        }
    }
}

/// A redacted snapshot of one pooled peer connection's admission state.
///
/// This is intentionally observational: it does not expose certificates,
/// payloads, or endpoint names, and it cannot alter pool admission.  The
/// capacity fixtures use it to distinguish a full stream semaphore from a
/// closed pooled connection whose connection permit is still retained by a
/// long-lived stream handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPoolConnectionStats {
    /// Number of stream permits currently available on this connection.
    pub available_stream_permits: usize,
    /// Configured stream permit ceiling for this connection.
    pub max_stream_permits: usize,
    /// Whether QUIC has reported a terminal close reason.
    pub closed: bool,
}

/// A bounded, redacted snapshot of the client pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPoolStats {
    /// Number of connection permits not currently owned by a connection.
    pub available_connection_permits: usize,
    /// Configured connection permit ceiling.
    pub max_connection_permits: usize,
    /// Connections currently retained in the destination map.
    pub pooled_connections: Vec<PeerPoolConnectionStats>,
}

/// The transport stage currently executing for one request-stream open.
///
/// This observer is optional and read-only.  It exists for bounded fixtures
/// that need to distinguish stream-permit checkout, taking a sender, and
/// HTTP/3 dispatch when their outer deadline cancels an open attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PeerTransportOpenStage {
    /// Waiting for the configured per-connection stream permit.
    StreamPermitCheckout = 0,
    /// Waiting for an HTTP/3 sender.  Each request dispatches on its own
    /// sender, so no attempt waits here and the stage is never recorded; the
    /// variant is kept so stage vocabularies stay stable.
    SenderLock = 1,
    /// Dispatching the HTTP/3 request, including QUIC bidi-stream checkout.
    H3Dispatch = 2,
    /// The request stream was returned to the caller.
    Complete = 3,
}

/// A bounded stage observer for one transport request-stream attempt.
#[derive(Clone, Debug)]
pub struct PeerOpenProgress {
    stage: Arc<AtomicU8>,
}

impl PeerOpenProgress {
    /// Create an observer whose initial stage is stream-permit checkout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stage: Arc::new(AtomicU8::new(
                PeerTransportOpenStage::StreamPermitCheckout as u8,
            )),
        }
    }

    /// Return the last stage recorded by this request attempt.
    #[must_use]
    pub fn stage(&self) -> PeerTransportOpenStage {
        match self.stage.load(Ordering::Acquire) {
            1 => PeerTransportOpenStage::SenderLock,
            2 => PeerTransportOpenStage::H3Dispatch,
            3 => PeerTransportOpenStage::Complete,
            _ => PeerTransportOpenStage::StreamPermitCheckout,
        }
    }

    fn set_stage(&self, stage: PeerTransportOpenStage) {
        self.stage.store(stage as u8, Ordering::Release);
    }
}

impl Default for PeerOpenProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded, immutable view of the relay SPKI pins currently approved by a
/// caller-owned membership coordinator.
///
/// An empty snapshot is fail-closed: it rejects every peer and causes active
/// connections whose pin is absent to close.  Transport does not mint or
/// validate membership records; callers must update [`SharedPeerPins`] only
/// from an already verified membership snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPinSnapshot {
    pins: Option<ApprovedPeerPins>,
    revision: u64,
}

impl PeerPinSnapshot {
    fn new(pins: Option<ApprovedPeerPins>, revision: u64) -> Self {
        Self { pins, revision }
    }

    /// Return whether this snapshot approves the supplied SPKI pin.
    #[must_use]
    pub fn contains(&self, pin: crate::SpkiSha256) -> bool {
        self.pins.as_ref().is_some_and(|pins| pins.contains(pin))
    }

    /// Return the number of approved SPKI pins in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.as_ref().map_or(0, ApprovedPeerPins::len)
    }

    /// Return whether this snapshot is fail-closed and approves no peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_none()
    }

    /// Return the monotonically increasing update revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn verify(&self, identity: &TlsIdentity) -> Result<(), PeerProbeError> {
        if !identity.role().is_peer() {
            return Err(PeerProbeError::WrongPeerRole);
        }
        if !self.contains(identity.spki_sha256()) {
            return Err(PeerProbeError::UnapprovedPeer(identity.spki_sha256()));
        }
        Ok(())
    }
}

/// Shared dynamic relay pin state for peer clients and servers.
///
/// Updates publish a bounded watch revision.  Existing connections observe
/// revocation and close themselves; callers can invoke
/// [`PeerClient::refresh_pins`] or [`PeerClient::close_peer`] when they need a
/// joined cleanup point.  Replacing with an empty iterator is supported and
/// deliberately fails closed.  Certificate expiry is also a caller concern:
/// the membership coordinator must remove expired keys (or publish an empty
/// snapshot) so the watcher can close the corresponding connection.
#[derive(Clone, Debug)]
pub struct SharedPeerPins {
    updates: watch::Sender<PeerPinSnapshot>,
}

impl SharedPeerPins {
    /// Create dynamic pin state from the non-empty static pin set.
    pub fn new(pins: ApprovedPeerPins) -> Result<Self, PeerTransportError> {
        if pins.len() > MAX_DYNAMIC_PEER_PINS {
            return Err(PeerTransportError::TooManyPeerPins {
                observed: pins.len(),
                maximum: MAX_DYNAMIC_PEER_PINS,
            });
        }
        let (updates, _receiver) = watch::channel(PeerPinSnapshot::new(Some(pins), 0));
        Ok(Self { updates })
    }

    /// Create fail-closed dynamic pin state with no approved keys.
    #[must_use]
    pub fn empty() -> Self {
        let (updates, _receiver) = watch::channel(PeerPinSnapshot::new(None, 0));
        Self { updates }
    }

    /// Return the current immutable pin snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PeerPinSnapshot {
        self.updates.borrow().clone()
    }

    /// Replace the approved key set from a bounded caller-owned membership
    /// snapshot.  Empty input revokes every key and fails closed.
    pub fn replace<I>(&self, pins: I) -> Result<(), PeerTransportError>
    where
        I: IntoIterator<Item = crate::SpkiSha256>,
    {
        let mut values = Vec::with_capacity(MAX_DYNAMIC_PEER_PINS.min(8));
        for pin in pins {
            values.push(pin);
            if values.len() > MAX_DYNAMIC_PEER_PINS {
                return Err(PeerTransportError::TooManyPeerPins {
                    observed: values.len(),
                    maximum: MAX_DYNAMIC_PEER_PINS,
                });
            }
        }
        values.sort_unstable();
        values.dedup();
        let pins = if values.is_empty() {
            None
        } else {
            Some(
                ApprovedPeerPins::new(values)
                    .map_err(|error| PeerTransportError::Authentication(error.to_string()))?,
            )
        };
        self.replace_snapshot(pins);
        Ok(())
    }

    /// Replace the approved key set using an existing static pin set.
    ///
    /// This is useful when a membership coordinator already validated and
    /// deduplicated its keys.  An empty set cannot be represented by
    /// [`ApprovedPeerPins`]; use [`SharedPeerPins::empty`] or
    /// [`SharedPeerPins::replace`] to revoke all keys.
    pub fn replace_approved(&self, pins: ApprovedPeerPins) -> Result<(), PeerTransportError> {
        if pins.len() > MAX_DYNAMIC_PEER_PINS {
            return Err(PeerTransportError::TooManyPeerPins {
                observed: pins.len(),
                maximum: MAX_DYNAMIC_PEER_PINS,
            });
        }
        self.replace_snapshot(Some(pins));
        Ok(())
    }

    fn replace_snapshot(&self, pins: Option<ApprovedPeerPins>) {
        let revision = self.updates.borrow().revision.saturating_add(1);
        self.updates
            .send_replace(PeerPinSnapshot::new(pins, revision));
    }

    fn subscribe(&self) -> watch::Receiver<PeerPinSnapshot> {
        self.updates.subscribe()
    }
}

/// Policy callback error returned when a caller rejects a request.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("peer request rejected by caller policy")]
pub struct PeerPolicyRejected;

/// Routing/membership policy consulted after TLS peer authentication and
/// before request body admission.
pub trait PeerRequestPolicy: Send + Sync + 'static {
    /// Return `true` only when this authenticated peer and request are
    /// allowed by the caller's current membership snapshot.
    fn authorize(&self, identity: &TlsIdentity, request: &Request<()>) -> bool;
}

impl<F> PeerRequestPolicy for F
where
    F: Fn(&TlsIdentity, &Request<()>) -> bool + Send + Sync + 'static,
{
    fn authorize(&self, identity: &TlsIdentity, request: &Request<()>) -> bool {
        self(identity, request)
    }
}

/// A boxed asynchronous server request handler.
pub type PeerHandlerFuture = Pin<Box<dyn Future<Output = Result<(), PeerTransportError>> + Send>>;

/// Application callback for admitted peer requests.
pub trait PeerRequestHandler: Send + Sync + 'static {
    /// Handle one request after its headers and authenticated peer identity
    /// have been admitted.
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture;
}

impl<F, Fut> PeerRequestHandler for F
where
    F: Fn(TlsIdentity, Request<()>, PeerServerStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), PeerTransportError>> + Send + 'static,
{
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        Box::pin(self(identity, request, stream))
    }
}

/// Errors from peer transport setup, admission, body bounds, or supervision.
#[derive(Debug, Error)]
pub enum PeerTransportError {
    /// One or more limits were zero, inconsistent, or otherwise unusable.
    #[error("peer transport limits are invalid")]
    InvalidLimits,
    /// The connection or destination pool is at capacity.
    #[error("peer transport capacity is exhausted")]
    Capacity,
    /// A dynamic pin snapshot exceeded its configured key bound.
    #[error("peer pin snapshot exceeds bound: observed {observed} keys, maximum {maximum}")]
    TooManyPeerPins {
        /// Number of keys observed before rejecting the snapshot.
        observed: usize,
        /// Maximum number of keys retained by one dynamic snapshot.
        maximum: usize,
    },
    /// The authenticated peer failed the role or SPKI check.
    #[error("peer authentication failed: {0}")]
    Authentication(String),
    /// No approved peer SPKI pins are published, so no peer can be dialled.
    ///
    /// This is a pre-dispatch outcome and is deliberately distinct from
    /// [`Self::Authentication`]: no peer certificate was examined, no socket
    /// was opened and nothing was written, because the caller's own
    /// membership coordinator currently publishes no trust evidence at all.
    /// A caller can therefore report it as `not_dispatched` and, since the
    /// coordinator republishes on its own bounded schedule, as retryable.
    #[error("no approved peer SPKI pins are published")]
    PinsUnavailable,
    /// A request was rejected by the caller-supplied policy.
    #[error("peer request rejected by caller policy")]
    PolicyRejected,
    /// A body chunk exceeded the explicit per-call bound.
    #[error("peer body chunk exceeds bound: observed {observed} bytes, maximum {maximum} bytes")]
    ChunkTooLarge {
        /// Bytes in the rejected chunk.
        observed: usize,
        /// Maximum permitted chunk bytes.
        maximum: usize,
    },
    /// A stream or connection body budget would be exceeded.
    #[error("peer body exceeds bound: observed {observed} bytes, maximum {maximum} bytes")]
    BodyTooLarge {
        /// Bytes observed after the rejected chunk.
        observed: usize,
        /// Maximum permitted bytes.
        maximum: usize,
    },
    /// A QUIC operation failed.
    #[error("peer QUIC operation failed: {0}")]
    Quic(String),
    /// An HTTP/3 operation failed.
    #[error("peer HTTP/3 operation failed: {0}")]
    H3(String),
    /// The peer is gracefully closing and did not process this request.
    ///
    /// This is a pre-dispatch outcome: either the request never reached the
    /// peer's request-stream admission boundary (HTTP/3 GOAWAY observed before
    /// the stream was created), or a raced stream was refused with
    /// `H3_REQUEST_REJECTED`, which per RFC 9114 means the peer did not process
    /// it.  Both are safe to report as `not_dispatched`.  A stream the peer
    /// reset for any other reason after it may have been dispatched still
    /// reports [`Self::H3`] or [`Self::Quic`], preserving `unknown` certainty.
    #[error("peer HTTP/3 connection is gracefully closing")]
    GoAway,
    /// A bounded operation exceeded its deadline.
    #[error("peer transport operation timed out")]
    Timeout,
    /// This relay retired the local peer identity the connection was
    /// established under (a completed key rotation, task row M8-C45), and
    /// closed it.  Nothing further is sent on the stream; whether the peer
    /// had already acted on an earlier request body is the caller's
    /// ordinary unknown-outcome question.  The peer sees an application
    /// close with reason [`LOCAL_IDENTITY_RETIRED_REASON`].
    #[error(
        "peer connection closed: this relay retired the local identity it was established under"
    )]
    LocalIdentityRetired,
    /// The caller cancelled a transport operation.
    #[error("peer transport operation cancelled")]
    Cancelled,
    /// A supervised task could not be joined.
    #[error("peer transport task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
}

type ClientSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientSendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ClientRecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerSendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ServerRecvStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Classify how a connection ended while its client driver was in a planned
/// GOAWAY drain.
///
/// Every local close of a pooled client connection -- `shutdown_until`, the
/// handle's `Drop` and the pin watcher -- cancels the connection's token
/// before it closes the connection.  So once that token is cancelled, the
/// close this driver observed may be the local one, which quinn reports as
/// `LocallyClosed` and h3 as `Remote error: Error undefined by h3: closed`.
/// That is the end the local side asked for, not a transport failure.  The
/// driver's cancellation arms are polled first, but on a multi-threaded
/// runtime the cancellation can land after the driver polled that arm and
/// before it polled the idle one, so the race has to be settled here (task
/// row M7-C105).  Without a local cancellation the peer's close is classified
/// by [`planned_idle_result`].
fn planned_drain_result(
    connection_result: h3::error::ConnectionError,
    cancel: &CancellationToken,
) -> Result<(), PeerTransportError> {
    if cancel.is_cancelled() {
        return Ok(());
    }
    planned_idle_result(connection_result)
}

fn planned_idle_result(
    connection_result: h3::error::ConnectionError,
) -> Result<(), PeerTransportError> {
    if connection_result.is_h3_no_error()
        || connection_result.is_remote_no_error_application_close()
    {
        Ok(())
    } else {
        Err(PeerTransportError::H3(connection_result.to_string()))
    }
}

/// Classify an HTTP/3 client stream error raised after a request stream was
/// created.  A peer that is gracefully closing refuses or resets the stream
/// with `RemoteClosing` or a `H3_REQUEST_REJECTED` terminate code; per
/// [RFC 9114 §8.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1)
/// `H3_REQUEST_REJECTED` means the owner did not process the request, so both
/// map to the typed pre-dispatch [`PeerTransportError::GoAway`]
/// (`not_dispatched`).  An already admitted stream that the owner reset for any
/// other reason keeps its generic HTTP/3 classification, preserving the
/// `unknown`-certainty contract for work that may have been dispatched.
fn classify_client_stream_error(error: h3::error::StreamError) -> PeerTransportError {
    match &error {
        h3::error::StreamError::RemoteClosing { .. } => PeerTransportError::GoAway,
        h3::error::StreamError::RemoteTerminate { code, .. }
            if *code == h3::error::Code::H3_REQUEST_REJECTED =>
        {
            PeerTransportError::GoAway
        }
        _ => PeerTransportError::H3(error.to_string()),
    }
}

struct StreamLease {
    _permit: OwnedSemaphorePermit,
}

struct BodyBudget {
    stream_bytes: Arc<AtomicUsize>,
    connection_bytes: Arc<AtomicUsize>,
    max_stream_bytes: usize,
    max_connection_bytes: usize,
    max_chunk_bytes: usize,
}

impl BodyBudget {
    fn reserve(&self, length: usize) -> Result<BodyCharge, PeerTransportError> {
        if length > self.max_chunk_bytes {
            return Err(PeerTransportError::ChunkTooLarge {
                observed: length,
                maximum: self.max_chunk_bytes,
            });
        }

        reserve_counter(&self.stream_bytes, length, self.max_stream_bytes).map_err(|observed| {
            PeerTransportError::BodyTooLarge {
                observed,
                maximum: self.max_stream_bytes,
            }
        })?;

        if let Err(observed) = reserve_counter(
            self.connection_bytes.as_ref(),
            length,
            self.max_connection_bytes,
        ) {
            self.stream_bytes.fetch_sub(length, Ordering::AcqRel);
            return Err(PeerTransportError::BodyTooLarge {
                observed,
                maximum: self.max_connection_bytes,
            });
        }
        Ok(BodyCharge {
            stream: self.stream_bytes.clone(),
            connection: self.connection_bytes.clone(),
            length,
        })
    }
}

/// An in-flight body reservation owned by one send operation or returned
/// receive chunk.  Dropping it releases both stream and connection bytes.
#[derive(Debug)]
struct BodyCharge {
    stream: Arc<AtomicUsize>,
    connection: Arc<AtomicUsize>,
    length: usize,
}

impl Drop for BodyCharge {
    fn drop(&mut self) {
        self.stream.fetch_sub(self.length, Ordering::AcqRel);
        self.connection.fetch_sub(self.length, Ordering::AcqRel);
    }
}

fn reserve_counter(counter: &AtomicUsize, length: usize, maximum: usize) -> Result<(), usize> {
    loop {
        let current = counter.load(Ordering::Acquire);
        let observed = current.saturating_add(length);
        if observed > maximum {
            return Err(observed);
        }
        if counter
            .compare_exchange(current, observed, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

fn body_budget(
    limits: &PeerTransportLimits,
    connection_bytes: Arc<AtomicUsize>,
) -> Arc<BodyBudget> {
    Arc::new(BodyBudget {
        stream_bytes: Arc::new(AtomicUsize::new(0)),
        connection_bytes,
        max_stream_bytes: limits.max_stream_body_bytes,
        max_connection_bytes: limits.max_connection_body_bytes,
        max_chunk_bytes: limits.max_chunk_bytes,
    })
}

fn map_probe_error(error: PeerProbeError) -> PeerTransportError {
    PeerTransportError::Authentication(error.to_string())
}

/// Await one checkout step without resetting the caller's absolute deadline.
/// Pool turn, capacity, handshake, and H3 setup waits all use the same
/// deadline so a slow or cancelled creator cannot strand later waiters behind
/// a sequence of fresh per-phase timers.
async fn with_checkout_deadline<F, T>(
    cancel: &CancellationToken,
    deadline: Instant,
    future: F,
) -> Result<T, PeerTransportError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(PeerTransportError::Cancelled),
        result = timeout_at(deadline, future) => {
            result.map_err(|_| PeerTransportError::Timeout)
        }
    }
}

/// Wait for one request-stream permit without confusing a bounded capacity
/// wait with a later HTTP/3 setup timeout.
///
/// A closed semaphore and an exhausted checkout deadline both mean that this
/// connection cannot admit another request stream.  Cancellation remains a
/// distinct result so shutdown and pin revocation still interrupt waiters.
async fn acquire_stream_permit_until(
    cancel: &CancellationToken,
    deadline: Instant,
    permits: Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, PeerTransportError> {
    tokio::select! {
        _ = cancel.cancelled() => Err(PeerTransportError::Cancelled),
        result = timeout_at(deadline, permits.acquire_owned()) => match result {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(PeerTransportError::Capacity),
        },
    }
}

fn spawn_pin_watcher(
    identity: &TlsIdentity,
    pins: &SharedPeerPins,
    connection: &quinn::Connection,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let pin = identity.spki_sha256();
    let mut updates = pins.subscribe();
    let connection = connection.clone();
    tokio::spawn(async move {
        loop {
            if !updates.borrow().contains(pin) {
                cancel.cancel();
                connection.close(quinn::VarInt::from_u32(0), b"peer pin revoked");
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = updates.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn configure_quic_connection(
    connection: &quinn::Connection,
    limits: &PeerTransportLimits,
) -> Result<(), PeerTransportError> {
    let window = quinn::VarInt::from_u64(limits.max_connection_body_bytes as u64)
        .map_err(|_| PeerTransportError::InvalidLimits)?;
    let streams = quinn::VarInt::from_u64(limits.max_streams_per_connection as u64)
        .map_err(|_| PeerTransportError::InvalidLimits)?;
    let uni_streams = quinn::VarInt::from_u64(16).map_err(|_| PeerTransportError::InvalidLimits)?;
    // These connection-local settings cap QUIC's receive and stream windows
    // independently of application frame budgets.  The HTTP/3 implementation
    // may retain a small amount of control/QPACK state outside this accounting.
    connection.set_receive_window(window);
    connection.set_send_window(limits.max_connection_body_bytes as u64);
    connection.set_max_concurrent_bi_streams(streams);
    connection.set_max_concurrent_uni_streams(uni_streams);
    Ok(())
}

/// Server-side stream with a request body and response body on the same
/// long-lived HTTP/3 request stream.
pub struct PeerServerStream {
    inner: Option<ServerStream>,
    budget: Arc<BodyBudget>,
    lease: Arc<StreamLease>,
    idle_timeout: Duration,
}

impl PeerServerStream {
    fn new(
        inner: ServerStream,
        budget: Arc<BodyBudget>,
        lease: Arc<StreamLease>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            inner: Some(inner),
            budget,
            lease,
            idle_timeout,
        }
    }

    /// Split request receive and response send directions so they can make
    /// progress concurrently.  This is required for response headers/body to
    /// be sent before the request body reaches request-end.
    pub fn split(mut self) -> (PeerServerSend, PeerServerRecv) {
        let inner = self.inner.take().expect("peer server stream is present");
        let (send, recv) = inner.split();
        (
            PeerServerSend {
                inner: send,
                budget: self.budget.clone(),
                _lease: self.lease.clone(),
                idle_timeout: self.idle_timeout,
            },
            PeerServerRecv {
                inner: recv,
                budget: self.budget,
                _lease: self.lease,
                idle_timeout: self.idle_timeout,
            },
        )
    }

    /// Send response headers before reading or finishing the request body.
    pub async fn send_response(
        &mut self,
        response: Response<()>,
    ) -> Result<(), PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer server stream is present");
        match timeout(self.idle_timeout, inner.send_response(response)).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Send one bounded response body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        send_server_chunk(
            self.inner.as_mut().expect("peer server stream is present"),
            &self.budget,
            self.idle_timeout,
            chunk,
        )
        .await
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// This preserves the supplied byte sequence as one application payload
    /// while allowing the transport to fragment it at its configured body
    /// chunk limit.  The peer record decoder reassembles records across these
    /// arbitrary HTTP/3 chunk boundaries.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        send_server_chunks(
            self.inner.as_mut().expect("peer server stream is present"),
            &self.budget,
            self.idle_timeout,
            bytes,
        )
        .await
    }

    /// Send one already bounded response body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the response body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer server stream is present");
        match timeout(self.idle_timeout, inner.finish()).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Receive one bounded request body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        recv_server_chunk(
            self.inner.as_mut().expect("peer server stream is present"),
            &self.budget,
            self.idle_timeout,
        )
        .await
    }

    /// Cancel both directions of this stream.
    pub fn cancel(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Server-side response sender returned by [`PeerServerStream::split`].
pub struct PeerServerSend {
    inner: ServerSendStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    idle_timeout: Duration,
}

impl PeerServerSend {
    /// Send response headers before request-end.
    pub async fn send_response(
        &mut self,
        response: Response<()>,
    ) -> Result<(), PeerTransportError> {
        match timeout(self.idle_timeout, self.inner.send_response(response)).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                self.inner
                    .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Send one bounded response body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        send_server_chunk(&mut self.inner, &self.budget, self.idle_timeout, chunk).await
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// The bytes remain one application payload; only the HTTP/3 body
    /// representation is fragmented at the configured transport limit.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        self.send_chunked_until(bytes, Instant::now() + self.idle_timeout)
            .await
    }

    /// Send one logical response body under an absolute deadline supplied by
    /// the caller's operation.  See
    /// [`PeerClientSend::send_chunked_until`] for the shared contract.
    pub async fn send_chunked_until(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PeerTransportError> {
        send_server_chunks_until(&mut self.inner, &self.budget, deadline, bytes).await
    }

    /// Send one already bounded response body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the response body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        match timeout(self.idle_timeout, self.inner.finish()).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                self.inner
                    .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Cancel the response direction.
    pub fn cancel(&mut self) {
        self.inner
            .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

/// Server-side request body receiver returned by [`PeerServerStream::split`].
pub struct PeerServerRecv {
    inner: ServerRecvStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    idle_timeout: Duration,
}

impl PeerServerRecv {
    /// Configured idle bound for this peer's request body.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Receive one bounded request body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        recv_server_chunk(&mut self.inner, &self.budget, self.idle_timeout).await
    }

    /// Receive one bounded request body chunk under an absolute deadline
    /// supplied by the caller's operation instead of the idle timeout.
    ///
    /// A peer that is legitimately silent because it waits on this side's
    /// parked response is not idle-faulted; the caller's own bound (the
    /// consumer's absolute authorization deadline) applies.  Resets, request
    /// end and malformed chunks are still surfaced immediately.
    pub async fn recv_chunk_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        recv_server_chunk_until(&mut self.inner, &self.budget, deadline).await
    }

    /// Ask the peer to stop sending the request body.
    pub fn cancel(&mut self) {
        self.inner
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

async fn send_server_chunk<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_server_chunk_until(stream, budget, Instant::now() + idle_timeout, chunk).await
}

/// Write one bounded body chunk against an already-created absolute deadline.
///
/// The deadline belongs to the caller's operation.  It is never recomputed
/// here, so a multi-chunk body cannot renew its own bound one physical write
/// at a time.  An elapsed deadline cancels the stream before returning.
async fn send_server_chunk_until<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    if chunk.len() > budget.max_chunk_bytes {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: chunk.len(),
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(chunk.len())?;
    let result = match timeout_at(deadline, stream.send_data(chunk)).await {
        Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
        Err(_) => {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            Err(PeerTransportError::Timeout)
        }
    };
    drop(charge);
    result
}

async fn send_server_chunks<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_server_chunks_until(stream, budget, Instant::now() + idle_timeout, bytes).await
}

/// Write one logical body as bounded chunks that all share one absolute
/// deadline.  The deadline is created once by the caller, so the total wall
/// clock cost of the body cannot grow with its chunk count.
async fn send_server_chunks_until<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    for chunk in bounded_body_chunks(bytes, budget.max_chunk_bytes) {
        send_server_chunk_until(stream, budget, deadline, Bytes::copy_from_slice(chunk)).await?;
    }
    Ok(())
}

async fn recv_server_chunk<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    recv_server_chunk_until(stream, budget, Instant::now() + idle_timeout).await
}

/// Read one bounded request body chunk against an absolute deadline.
async fn recv_server_chunk_until<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    let chunk = match timeout_at(deadline, stream.recv_data()).await {
        Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string()))?,
        Err(_) => {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerTransportError::Timeout);
        }
    };
    let Some(mut chunk) = chunk else {
        return Ok(None);
    };
    let length = chunk.remaining();
    if length > budget.max_chunk_bytes {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: length,
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(length)?;
    Ok(Some(PeerBodyChunk::from_received(
        chunk.copy_to_bytes(length),
        charge,
    )))
}

/// Client-side request/response stream before splitting its directions.
pub struct PeerClientStream {
    inner: Option<ClientStream>,
    budget: Arc<BodyBudget>,
    lease: Arc<StreamLease>,
    _connection: Arc<ClientConnection>,
    idle_timeout: Duration,
}

impl PeerClientStream {
    /// Split request sending and response receiving so both directions can
    /// make progress concurrently.
    pub fn split(mut self) -> (PeerClientSend, PeerClientRecv) {
        let inner = self.inner.take().expect("peer client stream is present");
        let (send, recv) = inner.split();
        (
            PeerClientSend {
                inner: send,
                budget: self.budget.clone(),
                _lease: self.lease.clone(),
                _connection: self._connection.clone(),
                idle_timeout: self.idle_timeout,
            },
            PeerClientRecv {
                inner: recv,
                budget: self.budget,
                _lease: self.lease,
                _connection: self._connection,
                idle_timeout: self.idle_timeout,
            },
        )
    }

    /// Send one bounded request body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        let result = send_client_chunk(
            self.inner.as_mut().expect("peer client stream is present"),
            &self.budget,
            self.idle_timeout,
            chunk,
        )
        .await;
        self._connection.observe_stream_result(result)
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// This preserves the supplied byte sequence as one application payload
    /// while allowing the transport to fragment it at its configured body
    /// chunk limit.  The peer record decoder reassembles records across these
    /// arbitrary HTTP/3 chunk boundaries.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        let result = send_client_chunks(
            self.inner.as_mut().expect("peer client stream is present"),
            &self.budget,
            self.idle_timeout,
            bytes,
        )
        .await;
        self._connection.observe_stream_result(result)
    }

    /// Send one already bounded request body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the request body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer client stream is present");
        let result = match timeout(self.idle_timeout, inner.finish()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Receive response headers.  This may complete before the request body
    /// has been finished.
    pub async fn recv_response(&mut self) -> Result<Response<()>, PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer client stream is present");
        let result = match timeout(self.idle_timeout, inner.recv_response()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Receive one bounded response body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        let result = recv_client_chunk(
            self.inner.as_mut().expect("peer client stream is present"),
            &self.budget,
            self.idle_timeout,
        )
        .await;
        self._connection.observe_stream_result(result)
    }

    /// Cancel both directions of this stream.
    pub fn cancel(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Client-side request sender returned by [`PeerClientStream::split`].
pub struct PeerClientSend {
    inner: ClientSendStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    _connection: Arc<ClientConnection>,
    idle_timeout: Duration,
}

impl PeerClientSend {
    /// Send one bounded request body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        let result =
            send_client_chunk(&mut self.inner, &self.budget, self.idle_timeout, chunk).await;
        self._connection.observe_stream_result(result)
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// The bytes remain one application payload; only the HTTP/3 body
    /// representation is fragmented at the configured transport limit.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        self.send_chunked_until(bytes, Instant::now() + self.idle_timeout)
            .await
    }

    /// Send one logical body under an absolute deadline supplied by the
    /// caller's operation.
    ///
    /// Every physical write of this body is bounded by the same instant, so a
    /// blackholed peer cannot hold the writer past the operation's budget by
    /// accepting one chunk at a time.  An elapsed deadline cancels the send
    /// stream and returns [`PeerTransportError::Timeout`].
    pub async fn send_chunked_until(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PeerTransportError> {
        let result = send_client_chunks_until(&mut self.inner, &self.budget, deadline, bytes).await;
        self._connection.observe_stream_result(result)
    }

    /// Send one already bounded request body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the request body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        let result = match timeout(self.idle_timeout, self.inner.finish()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                self.inner
                    .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Cancel the request direction.
    pub fn cancel(&mut self) {
        self.inner
            .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

/// Client-side response receiver returned by [`PeerClientStream::split`].
pub struct PeerClientRecv {
    inner: ClientRecvStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    _connection: Arc<ClientConnection>,
    idle_timeout: Duration,
}

impl PeerClientRecv {
    /// Receive response headers before request-end.
    pub async fn recv_response(&mut self) -> Result<Response<()>, PeerTransportError> {
        let result = match timeout(self.idle_timeout, self.inner.recv_response()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                self.inner
                    .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Receive one bounded response body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        let result = recv_client_chunk(&mut self.inner, &self.budget, self.idle_timeout).await;
        self._connection.observe_stream_result(result)
    }

    /// Receive one bounded response body chunk under an absolute deadline
    /// supplied by the caller's operation instead of the idle timeout.
    ///
    /// The mirror of [`PeerServerRecv::recv_chunk_until`] on the ingress
    /// side.  A saturated-but-healthy owner is legitimately silent while it
    /// queues this response, so it is not idle-faulted; the caller's own
    /// bound (the consumer's absolute authorization deadline) applies.
    /// Resets, response end and malformed chunks are still surfaced
    /// immediately, and the QUIC connection idle timeout remains the
    /// transport-level liveness check for a peer that has actually gone
    /// away.
    pub async fn recv_chunk_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        let result = recv_client_chunk_until(&mut self.inner, &self.budget, deadline).await;
        self._connection.observe_stream_result(result)
    }

    /// Ask the peer to stop sending the response body.
    pub fn cancel(&mut self) {
        self.inner
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

async fn send_client_chunk<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_client_chunk_until(stream, budget, Instant::now() + idle_timeout, chunk).await
}

/// Write one bounded request body chunk against an already-created absolute
/// deadline.  See [`send_server_chunk_until`] for the shared contract.
async fn send_client_chunk_until<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    if chunk.len() > budget.max_chunk_bytes {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: chunk.len(),
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(chunk.len())?;
    let result = match timeout_at(deadline, stream.send_data(chunk)).await {
        Ok(result) => result.map_err(classify_client_stream_error),
        Err(_) => {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            Err(PeerTransportError::Timeout)
        }
    };
    drop(charge);
    result
}

async fn send_client_chunks<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_client_chunks_until(stream, budget, Instant::now() + idle_timeout, bytes).await
}

/// Write one logical request body as bounded chunks that all share one
/// absolute deadline created by the caller.
async fn send_client_chunks_until<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    for chunk in bounded_body_chunks(bytes, budget.max_chunk_bytes) {
        send_client_chunk_until(stream, budget, deadline, Bytes::copy_from_slice(chunk)).await?;
    }
    Ok(())
}

fn bounded_body_chunks(bytes: &[u8], max_chunk_bytes: usize) -> impl Iterator<Item = &[u8]> {
    bytes.chunks(max_chunk_bytes)
}

async fn recv_client_chunk<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    recv_client_chunk_until(stream, budget, Instant::now() + idle_timeout).await
}

/// Read one bounded response body chunk against an absolute deadline.
async fn recv_client_chunk_until<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    let chunk = match timeout_at(deadline, stream.recv_data()).await {
        Ok(result) => result.map_err(classify_client_stream_error)?,
        Err(_) => {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerTransportError::Timeout);
        }
    };
    let Some(mut chunk) = chunk else {
        return Ok(None);
    };
    let length = chunk.remaining();
    if length > budget.max_chunk_bytes {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: length,
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(length)?;
    Ok(Some(PeerBodyChunk::from_received(
        chunk.copy_to_bytes(length),
        charge,
    )))
}

struct ClientConnection {
    destination: PeerDestination,
    identity: TlsIdentity,
    pin_provider: SharedPeerPins,
    connection: quinn::Connection,
    /// The connection's HTTP/3 request sender as it was built.  It is never
    /// used in place: every open dispatches on its own clone, which is how
    /// HTTP/3 shares one connection between concurrent requests.
    ///
    /// As built it still carries the connection's one GREASE frame, and so
    /// does every clone of it: a clone's first dispatched request stream
    /// writes that frame when it finishes.  Only opens that find
    /// `dispatched_sender` empty clone this one.
    sender: ClientSender,
    /// A sender that has dispatched a request, set once by the first open
    /// that succeeds.  Its GREASE frame is spent, so the clones every later
    /// open dispatches on write none: the frame goes out once per
    /// connection, as it did when all opens shared one sender.  Opens that
    /// race the connection's very first dispatch each still carry one.
    dispatched_sender: OnceLock<ClientSender>,
    /// Join requests to the one task that owns the handles of this
    /// connection's driver and pin watcher
    /// ([`supervise_client_connection`]).
    joins: mpsc::Sender<JoinRequest>,
    stream_permits: Arc<Semaphore>,
    connection_bytes: Arc<AtomicUsize>,
    limits: PeerTransportLimits,
    /// Emergency and local close.  Also cancelled from outside this
    /// connection: by the owning client's shutdown (it is a child of the
    /// client's token) and by the pin watcher on revocation.
    cancel: CancellationToken,
    /// Where this connection is in its life; see [`ClientConnectionPhase`].
    /// A peer-observed GOAWAY is kept apart from `cancel` so existing
    /// streams stay alive until their leases are returned.
    phase: watch::Sender<ClientConnectionPhase>,
    /// The local peer identity generation read immediately before this
    /// connection's handshake began (0 when the client has no rotating
    /// identity).  Read *before* the dial, so a rotation racing the handshake
    /// can only make a connection look older than it is -- which retires it
    /// early -- and never newer.
    local_generation: u64,
    _connection_permit: OwnedSemaphorePermit,
}

/// Why this side closed a pooled client connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalCloseCause {
    /// An ordinary shutdown, replacement or drop.
    Shutdown,
    /// [`PeerClient::retire_local_generations_before`] closed it; its streams
    /// report [`PeerTransportError::LocalIdentityRetired`].
    IdentityRetired,
}

/// The life of one pooled client connection.
///
/// `Live -> RemoteGoAway -> Closed`, or `Live -> Closed` directly.  The
/// tasks behind a closed connection are joined by its supervisor
/// ([`supervise_client_connection`]), whose own `Serving -> Joining ->
/// Joined` progress is that task's control flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientConnectionPhase {
    /// Usable for new request streams.
    Live,
    /// The peer sent (or implied) an HTTP/3 GOAWAY: no new stream is opened,
    /// and the driver acknowledges it once every stream lease is returned.
    RemoteGoAway,
    /// This side closed the connection.  `remote_goaway` records whether a
    /// peer GOAWAY had also been observed, so a later open is still refused
    /// as the pre-dispatch [`PeerTransportError::GoAway`].
    Closed {
        cause: LocalCloseCause,
        remote_goaway: bool,
    },
}

/// What can move a [`ClientConnectionPhase`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientConnectionEvent {
    /// A peer GOAWAY was observed, at request open, on an open stream, or by
    /// the driver.
    RemoteGoAway,
    /// This side is shutting the connection down.
    Shutdown,
    /// This side is closing the connection because its local identity was
    /// retired.
    IdentityRetired,
}

impl ClientConnectionPhase {
    /// The next phase, or `None` when `event` changes nothing.
    ///
    /// The phases only advance.  A repeated event is absorbed; a shutdown
    /// never demotes an identity retirement, so the typed cause is kept; and
    /// a retirement arriving after a shutdown takes the cause over, as the
    /// retirement is what the connection's streams then report.
    fn on_event(self, event: ClientConnectionEvent) -> Option<Self> {
        use ClientConnectionEvent as Event;
        let next = match (self, event) {
            (Self::Live, Event::RemoteGoAway) => Self::RemoteGoAway,
            (Self::RemoteGoAway, Event::RemoteGoAway) => return None,
            (
                Self::Closed {
                    cause,
                    remote_goaway: false,
                },
                Event::RemoteGoAway,
            ) => Self::Closed {
                cause,
                remote_goaway: true,
            },
            (
                Self::Closed {
                    remote_goaway: true,
                    ..
                },
                Event::RemoteGoAway,
            ) => return None,
            (Self::Live, Event::Shutdown) => Self::Closed {
                cause: LocalCloseCause::Shutdown,
                remote_goaway: false,
            },
            (Self::RemoteGoAway, Event::Shutdown) => Self::Closed {
                cause: LocalCloseCause::Shutdown,
                remote_goaway: true,
            },
            (Self::Closed { .. }, Event::Shutdown) => return None,
            (Self::Live, Event::IdentityRetired) => Self::Closed {
                cause: LocalCloseCause::IdentityRetired,
                remote_goaway: false,
            },
            (Self::RemoteGoAway, Event::IdentityRetired) => Self::Closed {
                cause: LocalCloseCause::IdentityRetired,
                remote_goaway: true,
            },
            (
                Self::Closed {
                    cause: LocalCloseCause::Shutdown,
                    remote_goaway,
                },
                Event::IdentityRetired,
            ) => Self::Closed {
                cause: LocalCloseCause::IdentityRetired,
                remote_goaway,
            },
            (
                Self::Closed {
                    cause: LocalCloseCause::IdentityRetired,
                    ..
                },
                Event::IdentityRetired,
            ) => return None,
        };
        Some(next)
    }

    /// Whether a peer GOAWAY has been observed on this connection.
    fn remote_goaway(self) -> bool {
        matches!(
            self,
            Self::RemoteGoAway
                | Self::Closed {
                    remote_goaway: true,
                    ..
                }
        )
    }

    /// Whether this connection was closed because its identity was retired.
    fn identity_retired(self) -> bool {
        matches!(
            self,
            Self::Closed {
                cause: LocalCloseCause::IdentityRetired,
                ..
            }
        )
    }
}

/// Apply `event` to a connection's published phase.  This is the only place
/// the phase changes; it returns whether it did.
fn publish_client_connection_event(
    phase: &watch::Sender<ClientConnectionPhase>,
    event: ClientConnectionEvent,
) -> bool {
    phase.send_if_modified(|phase| match phase.on_event(event) {
        Some(next) => {
            *phase = next;
            true
        }
        None => false,
    })
}

/// Resolve once a peer GOAWAY has been observed on the connection.
async fn remote_goaway_observed(phase: &mut watch::Receiver<ClientConnectionPhase>) {
    if phase.wait_for(|phase| phase.remote_goaway()).await.is_err() {
        // Every publisher is gone, so no GOAWAY can be published any more.
        std::future::pending::<()>().await;
    }
}

/// A request to join one client connection's driver and pin watcher.  The
/// first one joins them under its deadline; every later one is answered `Ok`
/// at once, whether or not that join has finished.
struct JoinRequest {
    deadline: Instant,
    reply: oneshot::Sender<Result<(), PeerTransportError>>,
}

/// Join requests buffered for one client connection's supervisor.
///
/// One: a caller whose request does not fit waits in `send`.  The supervisor
/// answers every request after the first without waiting, so the queue
/// drains as fast as the task is scheduled.
const CONNECTION_JOIN_QUEUE: usize = 1;

/// Own the handles of one client connection's driver and pin watcher.
///
/// Single ownership replaces a shared take-once slot: the two handles are
/// joined here exactly once.  The task is `Serving` until the first join
/// request, `Joining` while it joins the two tasks under that request's
/// deadline, and `Joined` afterwards.  When the connection is dropped
/// without a join, the request channel closes and both tasks are aborted.
async fn supervise_client_connection(
    mut joins: mpsc::Receiver<JoinRequest>,
    driver: JoinHandle<Result<(), PeerTransportError>>,
    pin_watcher: JoinHandle<()>,
) {
    // Serving.
    let Some(JoinRequest { deadline, reply }) = joins.recv().await else {
        driver.abort();
        pin_watcher.abort();
        return;
    };

    // Joining.  Later requests are answered while the join is in progress.
    let join = join_client_connection_tasks(driver, pin_watcher, deadline);
    tokio::pin!(join);
    let mut connection_alive = true;
    let result = loop {
        tokio::select! {
            biased;
            result = &mut join => break result,
            request = joins.recv(), if connection_alive => match request {
                Some(request) => {
                    let _ = request.reply.send(Ok(()));
                }
                None => connection_alive = false,
            },
        }
    };
    let _ = reply.send(result);

    // Joined.
    while let Some(request) = joins.recv().await {
        let _ = request.reply.send(Ok(()));
    }
}

/// Join a closed client connection's driver and pin watcher under one
/// absolute deadline, aborting whichever does not stop in time.
async fn join_client_connection_tasks(
    driver: JoinHandle<Result<(), PeerTransportError>>,
    pin_watcher: JoinHandle<()>,
    deadline: Instant,
) -> Result<(), PeerTransportError> {
    let mut first_error = None;
    match join_handle_until(driver, deadline).await {
        Some(Err(error)) => first_error = Some(PeerTransportError::Task(error)),
        Some(Ok(Err(error))) => first_error = Some(error),
        None => {
            first_error.get_or_insert(PeerTransportError::Timeout);
            tracing::warn!("peer HTTP/3 driver exceeded drain timeout");
        }
        Some(Ok(Ok(()))) => {}
    }
    match join_handle_until(pin_watcher, deadline).await {
        Some(Err(error)) => {
            first_error.get_or_insert(PeerTransportError::Task(error));
        }
        None => {
            first_error.get_or_insert(PeerTransportError::Timeout);
            tracing::warn!("peer pin watcher exceeded drain timeout");
        }
        Some(Ok(())) => {}
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// The QUIC application close code a relay uses when it closes a connection
/// established under a local peer identity it has retired.  Distinct from
/// the transport's ordinary `0` so a peer's diagnostics can tell a rotation
/// apart from a shutdown.
pub const LOCAL_IDENTITY_RETIRED_CODE: u32 = 0x4b52;

/// The close reason sent with [`LOCAL_IDENTITY_RETIRED_CODE`].
pub const LOCAL_IDENTITY_RETIRED_REASON: &[u8] = b"local identity retired";

impl ClientConnection {
    fn phase(&self) -> ClientConnectionPhase {
        *self.phase.borrow()
    }

    /// Apply `event` to this connection.  Closing it, for either cause, also
    /// cancels its token, as every local close does (M7-C105), so the driver
    /// classifies the close as the one this side asked for.
    fn on_event(&self, event: ClientConnectionEvent) {
        publish_client_connection_event(&self.phase, event);
        match event {
            ClientConnectionEvent::RemoteGoAway => {}
            ClientConnectionEvent::Shutdown | ClientConnectionEvent::IdentityRetired => {
                self.cancel.cancel();
            }
        }
    }

    /// Record a stream-level outcome on its pooled connection.
    ///
    /// A typed [`PeerTransportError::GoAway`] observed on an already opened
    /// stream means the peer is closing this connection, so later opens are
    /// gated pre-dispatch here exactly as they are after a GOAWAY observed at
    /// request open; the existing driver still owns the bounded
    /// acknowledgement and lease drain.  Every other result passes through.
    fn observe_stream_result<T>(
        &self,
        result: Result<T, PeerTransportError>,
    ) -> Result<T, PeerTransportError> {
        if matches!(result, Err(PeerTransportError::GoAway)) {
            self.on_event(ClientConnectionEvent::RemoteGoAway);
        }
        match result {
            // The typed cause wins over whatever the torn-down stream reported.
            Err(_) if self.phase().identity_retired() => {
                Err(PeerTransportError::LocalIdentityRetired)
            }
            other => other,
        }
    }

    /// Close this connection because its local identity was retired.
    async fn retire_local_identity(&self, deadline: Instant) {
        // Cancel before closing, as every local close does (M7-C105), so the
        // driver classifies the close as the one this side asked for.
        self.on_event(ClientConnectionEvent::IdentityRetired);
        self.connection.close(
            quinn::VarInt::from_u32(LOCAL_IDENTITY_RETIRED_CODE),
            LOCAL_IDENTITY_RETIRED_REASON,
        );
        let _ = self.shutdown_until(deadline).await;
    }

    async fn open(
        self: &Arc<Self>,
        request: Request<()>,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.open_until(request, Instant::now() + self.limits.stream_timeout)
            .await
    }

    /// Open a request stream before an absolute caller-owned deadline.
    ///
    /// The permit wait has its own configured stream checkout bound, clipped
    /// to the caller deadline, and is the only setup step classified as
    /// [`PeerTransportError::Capacity`] on expiry.  The H3 request dispatch
    /// retains the ordinary [`PeerTransportError::Timeout`] classification
    /// when its deadline expires.
    async fn open_until(
        self: &Arc<Self>,
        request: Request<()>,
        deadline: Instant,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.open_until_with_progress(request, deadline, None).await
    }

    async fn open_until_with_progress(
        self: &Arc<Self>,
        request: Request<()>,
        deadline: Instant,
        progress: Option<&PeerOpenProgress>,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.pin_provider
            .snapshot()
            .verify(&self.identity)
            .map_err(map_probe_error)?;
        if self.connection.close_reason().is_some() {
            return Err(PeerTransportError::Quic(
                "peer connection is closed".to_owned(),
            ));
        }
        if self.phase().remote_goaway() {
            // Once a peer GOAWAY has been observed, do not acquire a permit
            // or touch the sender again.  The existing driver owns the
            // bounded acknowledgement and stream-lease drain.
            return Err(PeerTransportError::GoAway);
        }
        let permit_deadline = std::cmp::min(deadline, Instant::now() + self.limits.stream_timeout);
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::StreamPermitCheckout);
        }
        let permit =
            acquire_stream_permit_until(&self.cancel, permit_deadline, self.stream_permits.clone())
                .await?;
        // `SenderLock` is never recorded: dispatch is no longer serialised
        // per connection, so no open waits for a sender.
        let (mut sender, first_dispatch) = match self.dispatched_sender.get() {
            Some(sender) => (sender.clone(), false),
            None => (self.sender.clone(), true),
        };
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::H3Dispatch);
        }
        let stream = with_checkout_deadline(&self.cancel, deadline, sender.send_request(request))
            .await?
            .map_err(|error| {
                let classified = classify_client_stream_error(error);
                if matches!(classified, PeerTransportError::GoAway) {
                    // Do not reuse the emergency token: a peer that is closing
                    // has not dispatched this request (`RemoteClosing`, or an
                    // `H3_REQUEST_REJECTED` reset of a raced stream), while
                    // existing streams must remain alive until their leases are
                    // returned.
                    self.on_event(ClientConnectionEvent::RemoteGoAway);
                }
                classified
            })?;
        if first_dispatch {
            // This sender's GREASE frame went to the stream just opened.
            // Losing the race to another first dispatch drops it instead.
            let _ = self.dispatched_sender.set(sender);
        } else {
            drop(sender);
        }

        let budget = body_budget(&self.limits, self.connection_bytes.clone());
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::Complete);
        }
        Ok(PeerClientStream {
            inner: Some(stream),
            budget,
            lease: Arc::new(StreamLease { _permit: permit }),
            _connection: self.clone(),
            idle_timeout: self.limits.idle_timeout,
        })
    }

    /// Cancel this connection's token and close QUIC, in that order and
    /// without yielding in between.
    fn close_for_shutdown(&self) {
        self.on_event(ClientConnectionEvent::Shutdown);
        self.connection
            .close(quinn::VarInt::from_u32(0), b"shutdown");
    }

    async fn shutdown_until(&self, deadline: Instant) -> Result<(), PeerTransportError> {
        self.close_for_shutdown();
        let (reply, joined) = oneshot::channel();
        if self
            .joins
            .send(JoinRequest { deadline, reply })
            .await
            .is_err()
        {
            // The supervisor is gone, and the tasks it owned with it.
            return Ok(());
        }
        joined.await.unwrap_or(Ok(()))
    }

    async fn shutdown(&self) -> Result<(), PeerTransportError> {
        self.shutdown_until(Instant::now() + self.limits.drain_timeout)
            .await
    }
}

async fn join_handle_until<T>(
    mut handle: JoinHandle<T>,
    deadline: Instant,
) -> Option<Result<T, tokio::task::JoinError>> {
    match timeout_at(deadline, &mut handle).await {
        Ok(result) => Some(result),
        Err(_) => {
            handle.abort();
            let _ = handle.await;
            None
        }
    }
}

async fn join_handle_until_bounded<T>(
    mut handle: JoinHandle<T>,
    deadline: Instant,
) -> Option<Result<T, tokio::task::JoinError>> {
    match timeout_at(deadline, &mut handle).await {
        Ok(result) => Some(result),
        Err(_) => {
            handle.abort();
            // Do not await an aborted planned-drain task beyond the shared
            // deadline.  A task that does not join in this final bounded
            // window is reported as incomplete by the caller; dropping the
            // handle here cannot extend the transport drain budget.
            let _ = timeout_at(deadline, &mut handle).await;
            None
        }
    }
}

const FORCED_JOIN_GRACE: Duration = Duration::from_millis(100);

/// How the bounded join of one task group ended.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DrainOutcome {
    /// Every task joined before the deadline.
    #[default]
    Joined,
    /// The deadline passed and the remaining tasks were aborted; they then
    /// joined.
    Forced,
    /// The aborted tasks did not join within the final bounded window.
    Incomplete,
}

impl DrainOutcome {
    /// Whether tasks had to be aborted at the deadline.
    fn forced(self) -> bool {
        self != Self::Joined
    }

    /// Whether aborted tasks were left unjoined.
    fn incomplete(self) -> bool {
        self == Self::Incomplete
    }
}

async fn drain_peer_tasks(
    tasks: &mut JoinSet<Result<(), PeerTransportError>>,
    deadline: Instant,
    cancellation_requested: bool,
    first_error: &mut Option<PeerTransportError>,
    label: &'static str,
) -> DrainOutcome {
    drain_peer_tasks_with_grace(
        tasks,
        deadline,
        cancellation_requested,
        first_error,
        label,
        true,
        true,
    )
    .await
}

/// Drain a task group without recording an individual task's own error as the
/// group's failure.  Used for forwarded-stream groups, where a stream ending
/// with an error is a stream-local lifecycle event (exactly as in normal
/// serving) and only a forced-deadline abort or a task panic fails the drain.
async fn drain_peer_tasks_without_recording_task_errors(
    tasks: &mut JoinSet<Result<(), PeerTransportError>>,
    deadline: Instant,
    cancellation_requested: bool,
    first_error: &mut Option<PeerTransportError>,
    label: &'static str,
) -> DrainOutcome {
    drain_peer_tasks_with_grace(
        tasks,
        deadline,
        cancellation_requested,
        first_error,
        label,
        true,
        false,
    )
    .await
}

async fn drain_peer_tasks_with_grace(
    tasks: &mut JoinSet<Result<(), PeerTransportError>>,
    deadline: Instant,
    cancellation_requested: bool,
    first_error: &mut Option<PeerTransportError>,
    label: &'static str,
    reserve_grace: bool,
    record_task_errors: bool,
) -> DrainOutcome {
    let wait_deadline = if cancellation_requested || !reserve_grace {
        deadline
    } else {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining > FORCED_JOIN_GRACE {
            deadline - FORCED_JOIN_GRACE
        } else {
            deadline
        }
    };
    let mut outcome = DrainOutcome::default();
    loop {
        match timeout_at(wait_deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) if cancellation_requested || !record_task_errors => {
                tracing::debug!(
                    ?error,
                    task_group = label,
                    "peer task stopped during shutdown"
                );
            }
            Ok(Some(Ok(Err(error)))) => {
                first_error.get_or_insert(error);
            }
            Ok(Some(Err(error))) => {
                first_error.get_or_insert(PeerTransportError::Task(error));
            }
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(
                    task_group = label,
                    "peer drain deadline exceeded; aborting tasks"
                );
                outcome = DrainOutcome::Forced;
                // A forced abort is a terminal timeout outcome even when all
                // cancelled tasks subsequently join. Never report a forced
                // drain as a clean success. Emergency cancellation preserves
                // the existing full join; planned drains reserve the final
                // grace window and report incomplete cleanup explicitly.
                if !cancellation_requested {
                    first_error.get_or_insert(PeerTransportError::Timeout);
                }
                tasks.abort_all();
                if cancellation_requested {
                    while tasks.join_next().await.is_some() {}
                    break;
                }
                loop {
                    match timeout_at(deadline, tasks.join_next()).await {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            outcome = DrainOutcome::Incomplete;
                            first_error.get_or_insert(PeerTransportError::Timeout);
                            tasks.abort_all();
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    outcome
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.on_event(ClientConnectionEvent::Shutdown);
        self.connection
            .close(quinn::VarInt::from_u32(0), b"connection dropped");
        // Dropping `joins` closes the supervisor's channel: if the driver
        // and the pin watcher were never joined, it aborts them.
    }
}

/// A reusable handle to one authenticated, pooled peer connection.
#[derive(Clone)]
pub struct PeerConnectionHandle {
    inner: Arc<ClientConnection>,
}

impl PeerConnectionHandle {
    /// Return the destination selected by the caller's membership snapshot.
    #[must_use]
    pub fn destination(&self) -> &PeerDestination {
        &self.inner.destination
    }

    /// Return the verified peer identity obtained from the TLS connection.
    #[must_use]
    pub fn peer_identity(&self) -> &TlsIdentity {
        &self.inner.identity
    }

    /// Body bytes currently charged against this connection's budget:
    /// in-flight sends and received chunks not yet dropped.  A payload-free
    /// diagnostic (task row M7-C120): it reads the same counter the budget
    /// enforces.
    #[must_use]
    pub fn body_bytes_charged(&self) -> usize {
        self.inner.connection_bytes.load(Ordering::Acquire)
    }

    /// Open one request stream on this reusable connection.
    pub async fn open(&self, request: Request<()>) -> Result<PeerClientStream, PeerTransportError> {
        self.inner.open(request).await
    }

    /// Open one request stream before an absolute transport deadline.
    ///
    /// This is used by bounded health probes so stream-permit exhaustion can
    /// be reported as capacity even when the probe deadline is shorter than
    /// the connection's normal stream checkout timeout.  HTTP/3 dispatch
    /// retains its normal timeout classification.
    pub async fn open_until(
        &self,
        request: Request<()>,
        deadline: Instant,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.inner.open_until(request, deadline).await
    }

    /// Open one request stream while recording the bounded transport stage.
    ///
    /// The observer is scoped to this attempt and does not alter admission,
    /// deadlines, or transport error classification.
    pub async fn open_with_progress(
        &self,
        request: Request<()>,
        progress: &PeerOpenProgress,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.inner
            .open_until_with_progress(
                request,
                Instant::now() + self.inner.limits.stream_timeout,
                Some(progress),
            )
            .await
    }

    /// Authorize and open a request using a caller-owned membership snapshot.
    ///
    /// This check is local to the caller and is deliberately repeated by a
    /// receiving [`PeerServer`] before it admits the request body.
    pub async fn open_with_policy<P>(
        &self,
        request: Request<()>,
        policy: &P,
    ) -> Result<PeerClientStream, PeerTransportError>
    where
        P: PeerRequestPolicy,
    {
        if !policy.authorize(&self.inner.identity, &request) {
            return Err(PeerTransportError::PolicyRejected);
        }
        self.inner.open(request).await
    }

    /// Cancel and join the connection's HTTP/3 driver task.
    pub async fn shutdown(&self) -> Result<(), PeerTransportError> {
        self.inner.shutdown().await
    }
}

/// What every clone of one [`PeerClient`] shares: the way to its pool task
/// and the pool's published drain set.
struct PeerPoolShared {
    /// Commands to the pool task ([`run_peer_pool`]).  Set once, by the
    /// first asynchronous use of the client, which is where the task is
    /// spawned: constructing a client needs no runtime.
    commands: OnceLock<mpsc::Sender<PoolCommand>>,
    /// The connections draining under a superseded local identity, as last
    /// published by the pool task, its only writer.  Read synchronously by
    /// [`PeerClient::draining_connection_count`].
    draining: watch::Sender<Vec<std::sync::Weak<ClientConnection>>>,
}

impl PeerPoolShared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            commands: OnceLock::new(),
            draining: watch::Sender::new(Vec::new()),
        })
    }
}

struct DrainingConnection {
    connection: std::sync::Weak<ClientConnection>,
    local_generation: u64,
}

/// The most connections a client keeps draining under a superseded local
/// peer identity at once.
///
/// Each drained predecessor has exactly one replacement dialed under the
/// current identity, so this bounds the **additional outbound** connections a
/// rotation adds to four.  `docs/cluster.md` budgets "at most four additional
/// key-rotation replacement connections per node across both directions";
/// this constant enforces the outbound half.  The inbound half -- connections
/// peers opened to this relay under its predecessor -- is not replaced by
/// this relay at all (task row M8-C47), so it adds none.  When the bound is
/// reached, a destination keeps using its predecessor connection -- whose key
/// is still approved during the overlap -- instead of tearing it down.
pub const MAX_ROTATION_DRAINING_CONNECTIONS: usize = 4;

/// Commands buffered for a client's pool task.
///
/// The pool task never waits on the network: every command is answered from
/// the state it owns, so the queue only fills for as long as the task is not
/// scheduled.  A caller whose command does not fit waits in `send`; a
/// checkout waits under its handshake deadline and the client's cancellation
/// and reports their expiry as it did when it waited for the pool.
const POOL_COMMAND_QUEUE: usize = 64;

/// A request to the task that owns a client's connection pool.
enum PoolCommand {
    /// Ask for a connection to `destination`: the pooled one, or the turn to
    /// dial it.  At most one turn per destination is out at a time; a
    /// checkout that arrives meanwhile is answered when that turn ends.
    Checkout {
        destination: PeerDestination,
        /// The caller's pin snapshot, taken when its checkout began.
        pins: PeerPinSnapshot,
        /// Read by the pool task when it answers, so a caller that waited
        /// for a turn decides with the identity current at that moment.
        local_identity: Option<Arc<crate::RotatingPeerIdentity>>,
        reply: oneshot::Sender<Result<Checkout, PeerTransportError>>,
    },
    /// The pooled connection for `destination`, left in the pool.
    Get {
        destination: PeerDestination,
        reply: oneshot::Sender<Option<Arc<ClientConnection>>>,
    },
    /// Every pooled connection, left in the pool.
    List {
        reply: oneshot::Sender<Vec<Arc<ClientConnection>>>,
    },
    /// Remove and return the pooled connection for `destination`.
    Take {
        destination: PeerDestination,
        reply: oneshot::Sender<Option<Arc<ClientConnection>>>,
    },
    /// Remove and return every pooled connection whose pin `pins` no longer
    /// approves.
    TakeUnpinned {
        pins: PeerPinSnapshot,
        reply: oneshot::Sender<Vec<Arc<ClientConnection>>>,
    },
    /// Remove and return every connection, draining first and then pooled,
    /// established under a local identity generation older than `generation`.
    TakeGenerationsBefore {
        generation: u64,
        reply: oneshot::Sender<Vec<Arc<ClientConnection>>>,
    },
    /// Begin the client's shutdown: cancel its token, close every pooled
    /// connection, and return them, still pooled, to be joined.  Cancelling
    /// and closing are one step of the pool task, so no pooled connection's
    /// driver is left cancelled but not yet closed while the caller waits to
    /// be scheduled (M7-C105).
    BeginShutdown {
        reply: oneshot::Sender<Vec<Arc<ClientConnection>>>,
    },
    /// Forget every pooled connection.
    Clear { reply: oneshot::Sender<()> },
}

/// The pool's answer to a checkout.
enum Checkout {
    /// The pooled connection is usable as it is.
    Reuse(Arc<ClientConnection>),
    /// The caller holds the destination's dial turn.
    Dial {
        /// An unusable pooled connection the pool removed for this
        /// destination.  The caller shuts it down before dialing.
        previous: Option<Arc<ClientConnection>>,
        /// The local identity generation the pool read when it granted the
        /// turn; the dialed connection records it.
        local_generation: u64,
        turn: DialTurn,
    },
}

/// The right to dial one destination, held by exactly one caller at a time.
///
/// Handing the dialed connection back pools it and ends the turn.  Dropping
/// the turn -- a failed dial, an expired deadline, a cancelled caller -- ends
/// it as well: the pool task observes either without the holder awaiting
/// anything, so a turn is released from synchronous code and from `Drop`.
struct DialTurn {
    outcome: oneshot::Sender<DialOutcome>,
}

impl DialTurn {
    /// Hand the dialed connection to the pool.  The receiver resolves with
    /// whether the pool kept it: `false` once the client has begun shutting
    /// down, in which case the pool closed it and the caller joins it.  It
    /// resolves with an error only when the pool task is gone.
    fn connected(self, connection: Arc<ClientConnection>) -> oneshot::Receiver<bool> {
        let (pooled, answer) = oneshot::channel();
        let _ = self.outcome.send(DialOutcome { connection, pooled });
        answer
    }
}

/// What a successful dial turn hands back to the pool.
struct DialOutcome {
    connection: Arc<ClientConnection>,
    /// Told whether the pool kept the connection.
    pooled: oneshot::Sender<bool>,
}

/// A checkout waiting for its destination's dial turn to end.
struct CheckoutWaiter {
    pins: PeerPinSnapshot,
    local_identity: Option<Arc<crate::RotatingPeerIdentity>>,
    reply: oneshot::Sender<Result<Checkout, PeerTransportError>>,
}

/// The dial state of one destination a client has a slot for.
///
/// `Idle <-> Dialing`.  A slot exists from a destination's first checkout
/// and counts against `max_destinations`.  It is kept, `Idle`, while its
/// latest checkout succeeded, and removed when a turn ends in failure with
/// no caller left waiting.
enum DialSlot {
    /// No dial in flight: the next checkout is answered at once.
    Idle,
    /// One caller holds the turn.  `outcome` resolves when the turn ends:
    /// with the dialed connection, or with an error when it was dropped.
    /// Checkouts that arrive meanwhile wait, in arrival order; there is one
    /// entry per suspended caller.
    Dialing {
        outcome: oneshot::Receiver<DialOutcome>,
        waiters: std::collections::VecDeque<CheckoutWaiter>,
    },
}

/// How a queued or new checkout was answered.
enum Served {
    /// The caller is no longer waiting; nothing was decided.
    Gone,
    /// The pooled connection was usable.
    Reused,
    /// The caller was given the dial turn.
    TurnGranted(oneshot::Receiver<DialOutcome>),
    /// The pool decided to dial but the caller had stopped waiting.
    TurnAbandoned,
}

/// Everything a client's pool task owns.
struct PeerPool {
    limits: PeerTransportLimits,
    /// The owning client's token: cancels rotation drains at shutdown.
    cancel: CancellationToken,
    /// One usable connection per destination.
    connections: HashMap<PeerDestination, Arc<ClientConnection>>,
    /// One slot per admitted destination; see [`DialSlot`].
    dials: HashMap<PeerDestination, DialSlot>,
    /// Connections established under a superseded local peer identity that
    /// still carry in-flight streams.  Bounded by
    /// [`MAX_ROTATION_DRAINING_CONNECTIONS`]; each is closed when its streams
    /// finish, at the drain budget, or when its generation is retired.
    draining: Vec<DrainingConnection>,
    /// Where `draining` is published for synchronous readers.
    draining_view: watch::Sender<Vec<std::sync::Weak<ClientConnection>>>,
}

impl PeerPool {
    fn new(
        limits: PeerTransportLimits,
        cancel: CancellationToken,
        draining_view: watch::Sender<Vec<std::sync::Weak<ClientConnection>>>,
    ) -> Self {
        Self {
            limits,
            cancel,
            connections: HashMap::new(),
            dials: HashMap::new(),
            draining: Vec::new(),
            draining_view,
        }
    }

    fn publish_draining(&self) {
        self.draining_view.send_replace(
            self.draining
                .iter()
                .map(|entry| entry.connection.clone())
                .collect(),
        );
    }

    fn handle(&mut self, command: PoolCommand) {
        match command {
            PoolCommand::Checkout {
                destination,
                pins,
                local_identity,
                reply,
            } => self.checkout(
                destination,
                CheckoutWaiter {
                    pins,
                    local_identity,
                    reply,
                },
            ),
            PoolCommand::Get { destination, reply } => {
                let _ = reply.send(self.connections.get(&destination).cloned());
            }
            PoolCommand::List { reply } => {
                let _ = reply.send(self.connections.values().cloned().collect());
            }
            PoolCommand::Take { destination, reply } => {
                let _ = reply.send(self.connections.remove(&destination));
            }
            PoolCommand::TakeUnpinned { pins, reply } => {
                let stale: Vec<PeerDestination> = self
                    .connections
                    .iter()
                    .filter(|(_, connection)| !pins.contains(connection.identity.spki_sha256()))
                    .map(|(destination, _)| destination.clone())
                    .collect();
                let _ = reply.send(
                    stale
                        .into_iter()
                        .filter_map(|destination| self.connections.remove(&destination))
                        .collect(),
                );
            }
            PoolCommand::TakeGenerationsBefore { generation, reply } => {
                let _ = reply.send(self.take_generations_before(generation));
            }
            PoolCommand::BeginShutdown { reply } => {
                self.cancel.cancel();
                for connection in self.connections.values() {
                    connection.close_for_shutdown();
                }
                let _ = reply.send(self.connections.values().cloned().collect());
            }
            PoolCommand::Clear { reply } => {
                self.connections.clear();
                let _ = reply.send(());
            }
        }
    }

    /// Admit one checkout: answer it now when its destination has no dial in
    /// flight, queue it behind the turn that is, or refuse a destination
    /// beyond the pool bound.
    fn checkout(&mut self, destination: PeerDestination, waiter: CheckoutWaiter) {
        match self.dials.get_mut(&destination) {
            Some(DialSlot::Dialing { waiters, .. }) => {
                waiters.push_back(waiter);
                return;
            }
            Some(DialSlot::Idle) => {}
            None => {
                if self.dials.len() >= self.limits.max_destinations {
                    let _ = waiter.reply.send(Err(PeerTransportError::Capacity));
                    return;
                }
                self.dials.insert(destination.clone(), DialSlot::Idle);
            }
        }
        // The slot is `Idle`: whether it is kept is decided by this checkout
        // and the ones that queue behind it.
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(waiter);
        self.settle(destination, queue, false);
    }

    /// A dial turn ended: pool what it dialed, then answer the waiters.
    ///
    /// Once the client has begun shutting down nothing is pooled any more:
    /// shutdown has already taken the connections it joins, so one pooled
    /// now would stay open, holding its connection permit, until the last
    /// clone of the client is dropped.  It is closed here instead and its
    /// dialer, told so, joins it.
    fn finish_turn(&mut self, destination: PeerDestination, outcome: Option<DialOutcome>) {
        let waiters = match self.dials.remove(&destination) {
            Some(DialSlot::Dialing { waiters, .. }) => waiters,
            Some(DialSlot::Idle) | None => std::collections::VecDeque::new(),
        };
        let mut connected = false;
        if let Some(DialOutcome { connection, pooled }) = outcome {
            if self.cancel.is_cancelled() {
                connection.close_for_shutdown();
            } else {
                self.connections.insert(destination.clone(), connection);
                connected = true;
            }
            let _ = pooled.send(connected);
        }
        self.settle(destination, waiters, connected);
    }

    /// Answer `waiters` in arrival order until one of them takes the dial
    /// turn, then leave the destination's slot in the state that follows.
    ///
    /// This is the only place a [`DialSlot`] changes.  `retain` is whether
    /// the latest decided checkout for the destination succeeded: with no
    /// turn out and nobody waiting, a slot is kept `Idle` after a success and
    /// removed after a failure.
    fn settle(
        &mut self,
        destination: PeerDestination,
        mut waiters: std::collections::VecDeque<CheckoutWaiter>,
        mut retain: bool,
    ) {
        while let Some(waiter) = waiters.pop_front() {
            match self.serve(&destination, waiter) {
                Served::Gone => {}
                Served::Reused => retain = true,
                Served::TurnAbandoned => retain = false,
                Served::TurnGranted(outcome) => {
                    self.dials
                        .insert(destination, DialSlot::Dialing { outcome, waiters });
                    return;
                }
            }
        }
        if retain {
            self.dials.insert(destination, DialSlot::Idle);
        } else {
            self.dials.remove(&destination);
        }
    }

    /// Decide one checkout against the pooled connection for its destination.
    fn serve(&mut self, destination: &PeerDestination, waiter: CheckoutWaiter) -> Served {
        let CheckoutWaiter {
            pins,
            local_identity,
            reply,
        } = waiter;
        if reply.is_closed() {
            return Served::Gone;
        }
        let local_generation = local_identity
            .as_ref()
            .map_or(0, |identity| identity.generation());
        let usable = self
            .connections
            .get(destination)
            .filter(|connection| {
                connection.connection.close_reason().is_none()
                    && !connection.cancel.is_cancelled()
                    && pins.verify(&connection.identity).is_ok()
            })
            .cloned();
        let previous = match usable {
            Some(connection) => {
                // Same local identity: reuse.  A superseded local identity:
                // drain the predecessor and dial with the current one -- unless
                // the bounded drain set is full, in which case the predecessor
                // (still approved during the overlap) keeps serving.
                if connection.local_generation >= local_generation
                    || !self.begin_rotation_drain(&connection)
                {
                    let _ = reply.send(Ok(Checkout::Reuse(connection)));
                    return Served::Reused;
                }
                self.connections.remove(destination);
                None
            }
            // An unusable pooled connection is replaced: the turn holder
            // shuts it down before it dials.
            None => self.connections.remove(destination),
        };
        let (outcome, turn_ended) = oneshot::channel();
        match reply.send(Ok(Checkout::Dial {
            previous,
            local_generation,
            turn: DialTurn { outcome },
        })) {
            Ok(()) => Served::TurnGranted(turn_ended),
            Err(_) => Served::TurnAbandoned,
        }
    }

    /// Move `connection` into the bounded drain set, or refuse when the set
    /// is full.  A drained connection closes when its last stream lease is
    /// returned, at the drain budget, or when its generation is retired.
    fn begin_rotation_drain(&mut self, connection: &Arc<ClientConnection>) -> bool {
        self.draining
            .retain(|entry| entry.connection.strong_count() > 0);
        if self
            .draining
            .iter()
            .any(|entry| std::ptr::eq(entry.connection.as_ptr(), Arc::as_ptr(connection)))
        {
            self.publish_draining();
            return true;
        }
        if self.draining.len() >= MAX_ROTATION_DRAINING_CONNECTIONS {
            self.publish_draining();
            return false;
        }
        self.draining.push(DrainingConnection {
            connection: Arc::downgrade(connection),
            local_generation: connection.local_generation,
        });
        self.publish_draining();
        let weak = Arc::downgrade(connection);
        let permits = connection.stream_permits.clone();
        let permit_count =
            u32::try_from(self.limits.max_streams_per_connection).unwrap_or(u32::MAX);
        let budget = self.limits.drain_timeout;
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let deadline = Instant::now() + budget;
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = timeout_at(deadline, permits.acquire_many_owned(permit_count)) => {}
            }
            if let Some(connection) = weak.upgrade() {
                let _ = connection
                    .shutdown_until(Instant::now() + Duration::from_secs(1))
                    .await;
            }
        });
        true
    }

    fn take_generations_before(&mut self, generation: u64) -> Vec<Arc<ClientConnection>> {
        let mut retired: Vec<Arc<ClientConnection>> = Vec::new();
        self.draining.retain(|entry| {
            if entry.local_generation < generation {
                if let Some(connection) = entry.connection.upgrade() {
                    retired.push(connection);
                }
                false
            } else {
                entry.connection.strong_count() > 0
            }
        });
        self.publish_draining();
        let stale: Vec<PeerDestination> = self
            .connections
            .iter()
            .filter(|(_, connection)| connection.local_generation < generation)
            .map(|(destination, _)| destination.clone())
            .collect();
        for destination in stale {
            if let Some(connection) = self.connections.remove(&destination) {
                retired.push(connection);
            }
        }
        retired
    }

    /// Resolve when a dial turn ends, with its destination and what it
    /// dialed (`None` when the turn was dropped).  Pending while no turn is
    /// out.
    async fn turn_ended(&mut self) -> (PeerDestination, Option<DialOutcome>) {
        std::future::poll_fn(|context| {
            for (destination, slot) in &mut self.dials {
                if let DialSlot::Dialing { outcome, .. } = slot
                    && let std::task::Poll::Ready(result) = Pin::new(outcome).poll(context)
                {
                    return std::task::Poll::Ready((destination.clone(), result.ok()));
                }
            }
            std::task::Poll::Pending
        })
        .await
    }
}

/// Own one client's connection pool: its pooled connections, its
/// per-destination dial turns and its rotation drain set.
///
/// Everything that used to be serialised around those three maps is now a
/// step of this one task.  Ended dial turns are handled before commands, so
/// a connection handed back by a caller is pooled before any command that
/// caller, or anyone it wakes, sends afterwards.  The task ends when the
/// last clone of its client is dropped.
async fn run_peer_pool(mut commands: mpsc::Receiver<PoolCommand>, mut pool: PeerPool) {
    loop {
        tokio::select! {
            biased;
            (destination, outcome) = pool.turn_ended() => {
                pool.finish_turn(destination, outcome);
            }
            command = commands.recv() => match command {
                Some(command) => pool.handle(command),
                None => break,
            },
        }
    }
}

/// An on-demand authenticated peer client with one pooled connection and one
/// in-flight dial per destination.
#[derive(Clone)]
pub struct PeerClient {
    endpoint: quinn::Endpoint,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    connections: Arc<Semaphore>,
    state: Arc<PeerPoolShared>,
    cancel: CancellationToken,
    local_identity: Option<Arc<crate::RotatingPeerIdentity>>,
}

impl PeerClient {
    /// Construct a client from a Quinn endpoint configured with the mandatory
    /// TLS 1.3 peer client configuration.
    pub fn new(
        endpoint: quinn::Endpoint,
        approved_pins: ApprovedPeerPins,
        limits: PeerTransportLimits,
    ) -> Result<Self, PeerTransportError> {
        let pin_provider = SharedPeerPins::new(approved_pins)?;
        Self::new_with_pin_provider(endpoint, pin_provider, limits)
    }

    /// Construct a client backed by a caller-updated dynamic peer pin
    /// snapshot.  The initial snapshot may be empty, which fails closed until
    /// the caller publishes approved keys.
    pub fn new_with_pin_provider(
        endpoint: quinn::Endpoint,
        pin_provider: SharedPeerPins,
        limits: PeerTransportLimits,
    ) -> Result<Self, PeerTransportError> {
        limits.validate()?;
        Ok(Self {
            endpoint,
            pin_provider,
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            state: PeerPoolShared::new(),
            cancel: CancellationToken::new(),
            limits,
            local_identity: None,
        })
    }

    /// Track the rotating local identity this client's endpoint presents.
    ///
    /// The endpoint's client configuration must resolve its certificate
    /// through the same [`crate::RotatingPeerIdentity`]
    /// ([`crate::RotatingPeerIdentity::quinn_client_config`]).  With it, a
    /// pooled connection established under an older generation is not used
    /// for new streams once the identity changes: it moves to a bounded drain
    /// set and a fresh connection presents the current identity.
    #[must_use]
    pub fn with_local_identity(mut self, identity: Arc<crate::RotatingPeerIdentity>) -> Self {
        self.local_identity = Some(identity);
        self
    }

    /// The way to this client's pool task, which the first use spawns.
    fn pool(&self) -> &mpsc::Sender<PoolCommand> {
        self.state.commands.get_or_init(|| {
            let (commands, receiver) = mpsc::channel(POOL_COMMAND_QUEUE);
            tokio::spawn(run_peer_pool(
                receiver,
                PeerPool::new(
                    self.limits.clone(),
                    self.cancel.clone(),
                    self.state.draining.clone(),
                ),
            ));
            commands
        })
    }

    /// Send one command to the pool task and wait for its answer.  `None`
    /// when the task is gone, which only a stopped runtime causes.
    async fn ask_pool<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> PoolCommand,
    ) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.pool().send(command(reply)).await.ok()?;
        answer.await.ok()
    }

    /// Close every connection -- pooled or draining -- established under a
    /// local identity generation older than `generation`, and return how many
    /// were closed.  In-flight streams on them end with a transport error.
    pub async fn retire_local_generations_before(&self, generation: u64) -> usize {
        let retired = self
            .ask_pool(|reply| PoolCommand::TakeGenerationsBefore { generation, reply })
            .await
            .unwrap_or_default();
        let count = retired.len();
        let deadline = Instant::now() + Duration::from_secs(1);
        for connection in retired {
            connection.retire_local_identity(deadline).await;
        }
        count
    }

    /// The number of connections still draining under a superseded local
    /// peer identity.  Bounded by [`MAX_ROTATION_DRAINING_CONNECTIONS`].
    #[must_use]
    pub fn draining_connection_count(&self) -> usize {
        self.state
            .draining
            .borrow()
            .iter()
            .filter(|connection| connection.strong_count() > 0)
            .count()
    }

    /// Return a pooled connection, dialing at most once concurrently for this
    /// destination.
    pub async fn connect(
        &self,
        destination: PeerDestination,
    ) -> Result<PeerConnectionHandle, PeerTransportError> {
        if self.cancel.is_cancelled() {
            return Err(PeerTransportError::Cancelled);
        }
        let current_pins = self.pin_provider.snapshot();
        if current_pins.is_empty() {
            return Err(PeerTransportError::PinsUnavailable);
        }
        let deadline = Instant::now() + self.limits.handshake_timeout;
        let (reply, checkout) = oneshot::channel();
        with_checkout_deadline(
            &self.cancel,
            deadline,
            self.pool().send(PoolCommand::Checkout {
                destination: destination.clone(),
                pins: current_pins,
                local_identity: self.local_identity.clone(),
                reply,
            }),
        )
        .await?
        .map_err(|_| PeerTransportError::Cancelled)?;
        // Waiting here is waiting for this destination's dial turn: the pool
        // answers once no other caller is dialing it.
        let checkout = with_checkout_deadline(&self.cancel, deadline, checkout)
            .await?
            .map_err(|_| PeerTransportError::Cancelled)??;
        let (previous, local_generation, turn) = match checkout {
            Checkout::Reuse(connection) => return Ok(PeerConnectionHandle { inner: connection }),
            Checkout::Dial {
                previous,
                local_generation,
                turn,
            } => (previous, local_generation, turn),
        };
        // An error below drops `turn`, which ends it as a failed dial.
        if let Some(previous) = previous {
            previous.shutdown_until(deadline).await?;
        }
        let dialed = self.dial(destination, local_generation, deadline).await?;
        self.finish_dial(turn, dialed).await
    }

    /// End a dial turn with the connection it dialed.
    ///
    /// A dial that finishes after [`Self::shutdown`] began is not pooled:
    /// the pool closes it, this joins its tasks as shutdown joins the
    /// others, and the caller gets the same `Cancelled` a dial interrupted
    /// by shutdown gets.  Its connection permit is released with it.
    async fn finish_dial(
        &self,
        turn: DialTurn,
        dialed: Arc<ClientConnection>,
    ) -> Result<PeerConnectionHandle, PeerTransportError> {
        match turn.connected(dialed.clone()).await {
            // No pool task is left to refuse it, which only a stopped
            // runtime causes.
            Ok(true) | Err(_) => Ok(PeerConnectionHandle { inner: dialed }),
            Ok(false) => {
                let _ = dialed
                    .shutdown_until(Instant::now() + self.limits.drain_timeout)
                    .await;
                Err(PeerTransportError::Cancelled)
            }
        }
    }

    /// Dial `destination` and build its pooled connection.  Only the holder
    /// of the destination's [`DialTurn`] calls this.
    async fn dial(
        &self,
        destination: PeerDestination,
        local_generation: u64,
        deadline: Instant,
    ) -> Result<Arc<ClientConnection>, PeerTransportError> {
        // Connection-pool exhaustion is a typed capacity condition and must
        // be reported as one, promptly.  Waiting on the semaphore under the
        // handshake deadline reported `Timeout` instead: it is
        // `with_checkout_deadline` that maps deadline expiry to `Timeout`,
        // and the `?` propagated that before the `map_err` intended to
        // produce `Capacity`, which only ever saw the semaphore's own closed
        // error.  So a caller learned nothing about capacity, and learned it
        // only after the whole handshake budget: the readiness probe
        // recorded the route `Unreachable` rather than `CapacityExhausted`,
        // collapsing the distinction that model is built on.
        //
        // A permit can also be moments from release: the caller has just
        // shut down the unusable pooled connection the pool removed for this
        // destination, and its permit lands when the last handle to it
        // drops.  Refusing instantly turns that ordinary replacement into a
        // spurious capacity error (measured: the peer-capacity gate went
        // from roughly one failure in six to five in fourteen).  So take a
        // free permit immediately, otherwise wait a short bounded grace
        // that stays well inside a probe's budget, and report exhaustion as
        // typed capacity either way.
        let connection_permit = match self.connections.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let grace = deadline.min(Instant::now() + CAPACITY_RELEASE_GRACE);
                match timeout_at(grace, self.connections.clone().acquire_owned()).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) | Err(_) => return Err(PeerTransportError::Capacity),
                }
            }
        };
        let connecting = self
            .endpoint
            .connect(destination.address, &destination.server_name)
            .map_err(|error| PeerTransportError::Quic(error.to_string()))?;
        let connection = with_checkout_deadline(&self.cancel, deadline, connecting)
            .await?
            .map_err(|error| PeerTransportError::Quic(error.to_string()))?;
        configure_quic_connection(&connection, &self.limits)?;
        let identity = verified_peer_identity(&connection).map_err(map_probe_error)?;
        self.pin_provider
            .snapshot()
            .verify(&identity)
            .map_err(map_probe_error)?;

        let quic = h3_quinn::Connection::new(connection.clone());
        let mut builder = h3::client::builder();
        builder.max_field_section_size(self.limits.max_header_bytes as u64);
        let (driver, sender) =
            with_checkout_deadline(&self.cancel, deadline, builder.build::<_, _, Bytes>(quic))
                .await?
                .map_err(|error| PeerTransportError::H3(error.to_string()))?;
        let connection_cancel = self.cancel.child_token();
        let driver_cancel = connection_cancel.clone();
        let phase = watch::Sender::new(ClientConnectionPhase::Live);
        let driver_phase = phase.clone();
        let mut driver_phase_updates = phase.subscribe();
        let driver_stream_permits =
            Arc::new(Semaphore::new(self.limits.max_streams_per_connection));
        let driver_wait_permits = driver_stream_permits.clone();
        let driver_max_streams = self.limits.max_streams_per_connection;
        let driver_drain_timeout = self.limits.drain_timeout;
        let driver_connection = connection.clone();
        let driver_task = tokio::spawn(async move {
            let mut driver = driver;
            loop {
                tokio::select! {
                    biased;
                    _ = driver_cancel.cancelled() => {
                        let _ = driver.shutdown(0).await;
                        break Ok(());
                    }
                    _ = remote_goaway_observed(&mut driver_phase_updates) => {
                    let permit_count = match u32::try_from(driver_max_streams) {
                        Ok(count) => count,
                        Err(_) => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"invalid peer stream permit bound",
                            );
                            return Err(PeerTransportError::InvalidLimits);
                        }
                    };
                    let deadline = Instant::now() + driver_drain_timeout;
                    // Keep polling the HTTP/3 driver while existing stream
                    // leases drain.  Waiting only on the semaphore can
                    // starve control/QPACK progress for an admitted stream.
                    let mut idle = Box::pin(driver.wait_idle());
                    let all_streams = tokio::select! {
                        biased;
                        _ = driver_cancel.cancelled() => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer emergency during GOAWAY acknowledgement",
                            );
                            return Ok(());
                        }
                        connection_result = &mut idle => {
                            // The connection went idle before the stream
                            // leases drained.  That is only a failure if
                            // the close itself was one: a peer that
                            // finished its own planned close first ends
                            // the connection with no error, and the wait
                            // below classifies exactly that case with
                            // `planned_idle_result`.  Classifying it the
                            // same way here is what keeps a benign close
                            // from being reported as a transport failure
                            // depending on which branch of this race wins.
                            let result =
                                planned_drain_result(connection_result, &driver_cancel);
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                if result.is_ok() {
                                    b"peer connection closed cleanly during GOAWAY drain"
                                        as &[u8]
                                } else {
                                    b"peer HTTP/3 driver stopped during GOAWAY drain" as &[u8]
                                },
                            );
                            return result;
                        }
                        result = timeout_at(
                            deadline,
                            driver_wait_permits.acquire_many_owned(permit_count),
                        ) => result,
                    };
                    drop(idle);
                    let Ok(Ok(_all_streams)) = all_streams else {
                        driver_connection.close(
                            quinn::VarInt::from_u32(0),
                            b"peer GOAWAY stream drain deadline",
                        );
                        return Err(PeerTransportError::Timeout);
                    };
                    let shutdown = tokio::select! {
                        biased;
                        _ = driver_cancel.cancelled() => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer emergency during GOAWAY acknowledgement",
                            );
                            return Ok(());
                        }
                        result = timeout_at(deadline, driver.shutdown(0)) => result,
                    };
                    match shutdown {
                        Ok(Ok(())) => {}
                        // This connection's own shutdown, drop or pin
                        // withdrawal closed it while the acknowledgement
                        // was being written (M7-C105).
                        Ok(Err(_)) if driver_cancel.is_cancelled() => return Ok(()),
                        // The peer finished its own planned close first:
                        // it closed the connection cleanly (application
                        // code 0 or H3_NO_ERROR) while this side was
                        // writing its acknowledgement.  That is the end
                        // the drain waits for, not a failure, and the
                        // idle wait below classifies it the same way
                        // (M7-C116).
                        Ok(Err(error))
                            if error.is_h3_no_error()
                                || error.is_remote_no_error_application_close() =>
                        {
                            return Ok(());
                        }
                        Ok(Err(error)) => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer GOAWAY acknowledgement failed",
                            );
                            return Err(PeerTransportError::H3(error.to_string()));
                        }
                        Err(_) => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer GOAWAY acknowledgement deadline",
                            );
                            return Err(PeerTransportError::Timeout);
                        }
                    }
                    let idle = tokio::select! {
                        biased;
                        _ = driver_cancel.cancelled() => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer emergency during GOAWAY wait",
                            );
                            return Ok(());
                        }
                        result = timeout_at(deadline, driver.wait_idle()) => result,
                    };
                    let idle_result = match idle {
                        Err(_) => {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer GOAWAY idle deadline",
                            );
                            Err(PeerTransportError::Timeout)
                        }
                        Ok(connection_result) => {
                            let result =
                                planned_drain_result(connection_result, &driver_cancel);
                            if result.is_err() {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer GOAWAY idle failure",
                                );
                            }
                            result
                        }
                    };
                    break idle_result;
                    }
                    result = driver.wait_for_remote_goaway() => {
                        if result.is_ok() {
                            // Reuse the same bounded acknowledgement path
                            // as an attempted post-GOAWAY open. The typed
                            // gate remains in `open_until`; this passive
                            // event only removes the need for a failed
                            // probe to wake the driver.
                            publish_client_connection_event(
                                &driver_phase,
                                ClientConnectionEvent::RemoteGoAway,
                            );
                        } else {
                            // A normal close or protocol error before
                            // GOAWAY preserves the existing terminal
                            // driver behavior and is never promoted to a
                            // planned drain.
                            break Ok(());
                        }
                    }
                }
            }
        });
        let pin_watcher = spawn_pin_watcher(
            &identity,
            &self.pin_provider,
            &connection,
            connection_cancel.clone(),
        );

        let (joins, join_requests) = mpsc::channel(CONNECTION_JOIN_QUEUE);
        tokio::spawn(supervise_client_connection(
            join_requests,
            driver_task,
            pin_watcher,
        ));

        let pooled = Arc::new(ClientConnection {
            destination,
            identity,
            pin_provider: self.pin_provider.clone(),
            connection,
            sender,
            dispatched_sender: OnceLock::new(),
            joins,
            stream_permits: driver_stream_permits,
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            limits: self.limits.clone(),
            cancel: connection_cancel,
            phase,
            local_generation,
            _connection_permit: connection_permit,
        });
        Ok(pooled)
    }

    /// Return the current dynamic peer pin snapshot used for admission.
    #[must_use]
    pub fn pin_snapshot(&self) -> PeerPinSnapshot {
        self.pin_provider.snapshot()
    }

    fn connection_stats(&self, connection: &ClientConnection) -> PeerPoolConnectionStats {
        PeerPoolConnectionStats {
            available_stream_permits: connection.stream_permits.available_permits(),
            max_stream_permits: self.limits.max_streams_per_connection,
            closed: connection.connection.close_reason().is_some()
                || connection.cancel.is_cancelled(),
        }
    }

    /// Return bounded, redacted pool admission counters for diagnostics.
    ///
    /// The snapshot deliberately reports only semaphore counts and terminal
    /// state.  It is read-only and does not keep any pooled connection alive.
    pub async fn pool_stats(&self) -> PeerPoolStats {
        let pooled_connections = self
            .ask_pool(|reply| PoolCommand::List { reply })
            .await
            .unwrap_or_default()
            .iter()
            .map(|connection| self.connection_stats(connection))
            .collect();
        PeerPoolStats {
            available_connection_permits: self.connections.available_permits(),
            max_connection_permits: self.limits.max_connections,
            pooled_connections,
        }
    }

    /// Return one bounded, redacted admission snapshot for a selected route.
    ///
    /// This diagnostic view correlates a caller's route with its pooled
    /// connection without exposing the destination address or TLS name.
    pub async fn pool_stats_for(
        &self,
        destination: &PeerDestination,
    ) -> Option<PeerPoolConnectionStats> {
        let destination = destination.clone();
        self.ask_pool(|reply| PoolCommand::Get { destination, reply })
            .await
            .flatten()
            .map(|connection| self.connection_stats(&connection))
    }

    /// Close and join one pooled peer connection, if present.
    pub async fn close_peer(
        &self,
        destination: &PeerDestination,
    ) -> Result<(), PeerTransportError> {
        let destination = destination.clone();
        let connection = self
            .ask_pool(|reply| PoolCommand::Take { destination, reply })
            .await
            .flatten();
        if let Some(connection) = connection {
            connection
                .shutdown_until(Instant::now() + self.limits.drain_timeout)
                .await?;
        }
        Ok(())
    }

    /// Close and join every pooled connection whose SPKI pin is absent from
    /// the current dynamic snapshot.
    ///
    /// Pin watchers close revoked connections immediately; this method gives
    /// callers an explicit joined cleanup point after publishing a snapshot.
    pub async fn refresh_pins(&self) -> Result<usize, PeerTransportError> {
        let pins = self.pin_provider.snapshot();
        let stale = self
            .ask_pool(|reply| PoolCommand::TakeUnpinned { pins, reply })
            .await
            .unwrap_or_default();
        let count = stale.len();
        let deadline = Instant::now() + self.limits.drain_timeout;
        let mut first_error = None;
        for connection in stale {
            if let Err(error) = connection.shutdown_until(deadline).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(count)
    }

    /// Open a request using a pooled connection selected from the destination.
    pub async fn open(
        &self,
        destination: PeerDestination,
        request: Request<()>,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.connect(destination).await?.open(request).await
    }

    /// Authorize and open a request using a caller-owned membership snapshot.
    pub async fn open_with_policy<P>(
        &self,
        destination: PeerDestination,
        request: Request<()>,
        policy: &P,
    ) -> Result<PeerClientStream, PeerTransportError>
    where
        P: PeerRequestPolicy,
    {
        self.connect(destination)
            .await?
            .open_with_policy(request, policy)
            .await
    }

    /// Cancel and join every pooled connection driver task.
    pub async fn shutdown(&self) -> Result<(), PeerTransportError> {
        let connections = self
            .ask_pool(|reply| PoolCommand::BeginShutdown { reply })
            .await
            .unwrap_or_default();
        // Already cancelled by the pool task; this covers one that is gone.
        self.cancel.cancel();
        let deadline = Instant::now() + self.limits.drain_timeout;
        let mut first_error = None;
        for connection in connections {
            if let Err(error) = connection.shutdown_until(deadline).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        let _ = self.ask_pool(|reply| PoolCommand::Clear { reply }).await;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerShutdownMode {
    Emergency,
    PlannedDrain,
}

/// Where one planned listener drain is.
///
/// `Serving -> AdmissionClosed -> Draining(deadline)`.  The deadline exists
/// only once the drain has begun, and the drain can only begin after
/// admission closed, so every connection task that observes the drain reads
/// the same absolute budget with it.  Emergency server shutdown never leaves
/// `Serving`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedDrainPhase {
    /// Streams are admitted.
    Serving,
    /// The admission boundary: a stream not yet dispatched is refused as
    /// not processed.
    AdmissionClosed,
    /// Established connections send GOAWAY and join their admitted streams
    /// before this shared absolute deadline.
    Draining(Instant),
}

/// What can move a [`PlannedDrainPhase`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedDrainEvent {
    CloseAdmission,
    BeginDrain(Instant),
}

/// An event its planned-drain phase has no transition for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IllegalPlannedDrainEvent;

impl PlannedDrainPhase {
    /// The only place a planned drain changes phase.
    fn on_event(self, event: PlannedDrainEvent) -> Result<Self, IllegalPlannedDrainEvent> {
        match (self, event) {
            (Self::Serving, PlannedDrainEvent::CloseAdmission) => Ok(Self::AdmissionClosed),
            (Self::AdmissionClosed, PlannedDrainEvent::BeginDrain(deadline)) => {
                Ok(Self::Draining(deadline))
            }
            (Self::Serving, PlannedDrainEvent::BeginDrain(_))
            | (Self::AdmissionClosed | Self::Draining(_), PlannedDrainEvent::CloseAdmission)
            | (Self::Draining(_), PlannedDrainEvent::BeginDrain(_)) => {
                Err(IllegalPlannedDrainEvent)
            }
        }
    }
}

/// Shared signal for one planned server drain.
///
/// The listener supervisor is its only writer; connection and stream tasks
/// sample the published [`PlannedDrainPhase`] and wait for it to change.
#[derive(Clone)]
struct PlannedDrainSignal {
    phase: watch::Sender<PlannedDrainPhase>,
}

impl PlannedDrainSignal {
    fn new() -> Self {
        Self {
            phase: watch::Sender::new(PlannedDrainPhase::Serving),
        }
    }

    fn on_event(&self, event: PlannedDrainEvent) -> Result<(), IllegalPlannedDrainEvent> {
        let mut applied = Ok(());
        self.phase
            .send_if_modified(|phase| match phase.on_event(event) {
                Ok(next) => {
                    *phase = next;
                    true
                }
                Err(refused) => {
                    applied = Err(refused);
                    false
                }
            });
        applied
    }

    /// Close the admission boundary.  Closing it again changes nothing.
    fn close_admission(&self) {
        let _ = self.on_event(PlannedDrainEvent::CloseAdmission);
    }

    /// Begin the drain with its shared absolute deadline.  Refused unless
    /// admission is closed and no drain has begun.
    fn begin_drain(&self, deadline: Instant) {
        let _ = self.on_event(PlannedDrainEvent::BeginDrain(deadline));
    }

    fn phase(&self) -> PlannedDrainPhase {
        *self.phase.borrow()
    }

    fn admission_closed(&self) -> bool {
        self.phase() != PlannedDrainPhase::Serving
    }

    fn begin_admission(&self) -> bool {
        // This final check is the admission linearization point.  A stream
        // that passes it before close_admission is already admitted and may
        // finish after GOAWAY; a resolver/policy path that reaches it after
        // the boundary is rejected before handler dispatch.
        !self.admission_closed()
    }

    /// The shared drain deadline, once the drain has begun.
    fn draining_deadline(&self) -> Option<Instant> {
        match self.phase() {
            PlannedDrainPhase::Draining(deadline) => Some(deadline),
            PlannedDrainPhase::Serving | PlannedDrainPhase::AdmissionClosed => None,
        }
    }

    fn is_draining(&self) -> bool {
        self.draining_deadline().is_some()
    }

    /// Resolve once the drain has begun.
    async fn draining(&self) {
        let mut phase = self.phase.subscribe();
        if phase
            .wait_for(|phase| matches!(phase, PlannedDrainPhase::Draining(_)))
            .await
            .is_err()
        {
            std::future::pending::<()>().await;
        }
    }
}

/// A server supervisor for authenticated, long-lived HTTP/3 peer requests.
pub struct PeerServer<P, H>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    endpoint: quinn::Endpoint,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    policy: Arc<P>,
    handler: Arc<H>,
    diagnostics: Arc<PeerServerDiagnostics>,
    /// The free list of diagnostics cells, owned by the listener supervisor.
    diagnostics_slots: mpsc::Receiver<usize>,
}

/// A bounded snapshot of one authenticated incoming peer connection.
///
/// The counters describe the target-side H3 stream lifecycle.  The QUIC
/// frame counters are cumulative for the connection and intentionally expose
/// only stream-credit/control categories; they contain no request payload or
/// header values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerServerConnectionStats {
    /// Verified peer role identity.
    pub peer_node_id: String,
    /// The TLS server name the calling peer presented when it opened this
    /// connection, when the handshake carried one.
    ///
    /// This is the caller's SNI as the listener observed it, not a value this
    /// side chose.  It is a bounded identifier with no payload or credential
    /// content, and it lets an observer check that a dialling relay used the
    /// server name from its verified membership record.
    pub observed_server_name: Option<String>,
    /// Listener-local diagnostic identifier for this connection lifetime.
    ///
    /// Identifiers are allocated from a monotonic counter starting at one, so
    /// zero always means "no connection" to callers and an identifier is never
    /// reused by a later connection on the same listener, unlike the QUIC
    /// stack's slab-indexed stable id.
    pub connection_id: usize,
    /// H3 requests accepted by the target connection.
    pub accepted_streams: u64,
    /// Accepted requests currently resolving headers/policy.
    pub resolving_streams: u64,
    /// Requests currently owned by the application handler.
    pub active_streams: u64,
    /// Requests whose handler completed without an error.
    pub completed_streams: u64,
    /// Requests cancelled before normal completion, including requests
    /// rejected because the target stream permit ceiling was reached.
    pub cancelled_streams: u64,
    /// Requests that ended with a transport, authentication, or policy error.
    pub error_streams: u64,
    /// Server-side H3 stream permits available at the snapshot instant.
    pub available_stream_permits: usize,
    /// Configured server-side H3 stream permit ceiling.
    pub max_stream_permits: usize,
    /// Number of MAX_STREAMS (bidirectional) frames sent by the target.
    pub frame_tx_max_streams_bidi: u64,
    /// Number of MAX_STREAMS (bidirectional) frames received by the target.
    pub frame_rx_max_streams_bidi: u64,
    /// Number of STREAMS_BLOCKED (bidirectional) frames sent by the target.
    pub frame_tx_streams_blocked_bidi: u64,
    /// Number of STREAMS_BLOCKED (bidirectional) frames received by the target.
    pub frame_rx_streams_blocked_bidi: u64,
    /// Number of RESET_STREAM frames sent by the target.
    pub frame_tx_reset_stream: u64,
    /// Number of RESET_STREAM frames received by the target.
    pub frame_rx_reset_stream: u64,
    /// Number of STOP_SENDING frames sent by the target.
    pub frame_tx_stop_sending: u64,
    /// Number of STOP_SENDING frames received by the target.
    pub frame_rx_stop_sending: u64,
    /// Whether this connection successfully wrote its planned H3 GOAWAY.
    pub planned_goaway_sent: bool,
    /// Whether the planned drain had to cancel an admitted stream at its
    /// shared deadline.
    pub forced_stream_cancellation: bool,
    /// Whether the planned drain had to close QUIC at its shared deadline.
    pub forced_connection_close: bool,
    /// Whether a bounded cleanup join could not complete before the deadline.
    pub drain_join_incomplete: bool,
}

/// A bounded target-side snapshot of currently supervised peer connections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerServerStats {
    /// One entry per currently supervised authenticated QUIC connection.
    pub connections: Vec<PeerServerConnectionStats>,
}

/// How a planned GOAWAY drain of one incoming peer connection was cut short.
/// In every case this side closed QUIC before the drain completed in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainAbort {
    /// Writing GOAWAY failed with an HTTP/3 error.
    GoAwayFailed,
    /// Writing GOAWAY did not finish before the shared deadline.
    GoAwayDeadline,
    /// A pin revocation or connection-local emergency arrived while waiting
    /// for the HTTP/3 completion boundary.
    EmergencyAwaitingH3,
    /// HTTP/3 failed while waiting for its completion boundary.
    H3Failed,
    /// The shared deadline passed while waiting for the HTTP/3 completion
    /// boundary; `streams_outstanding` is whether admitted streams were
    /// still running.
    DeadlineAwaitingH3 { streams_outstanding: bool },
    /// An emergency arrived while joining admitted streams.
    EmergencyAwaitingStreams,
    /// The shared deadline passed while joining admitted streams.
    DeadlineAwaitingStreams,
}

impl DrainAbort {
    fn goaway_sent(self) -> bool {
        !matches!(self, Self::GoAwayFailed | Self::GoAwayDeadline)
    }

    /// Whether QUIC was closed because the drain ran out of its budget.
    fn forced_connection_close(self) -> bool {
        matches!(
            self,
            Self::GoAwayDeadline
                | Self::DeadlineAwaitingH3 { .. }
                | Self::EmergencyAwaitingStreams
                | Self::DeadlineAwaitingStreams
        )
    }

    /// Whether an admitted stream was cancelled by that close.
    fn forced_stream_cancellation(self) -> bool {
        matches!(
            self,
            Self::DeadlineAwaitingH3 {
                streams_outstanding: true
            } | Self::EmergencyAwaitingStreams
                | Self::DeadlineAwaitingStreams
        )
    }
}

/// The in-order steps of a planned GOAWAY drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedDrainStep {
    /// The listener's drain reached this connection; GOAWAY is not written.
    Requested,
    /// GOAWAY is written; HTTP/3 is driven to its completion boundary.
    GoAwaySent,
    /// HTTP/3 reported completion; admitted streams are being joined.
    H3Complete,
    /// Every admitted stream returned before the deadline.
    StreamsReturned,
}

/// Which way a finished connection left serving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainRoute {
    /// The planned drain completed in order.
    Planned,
    /// The planned drain was cut short.
    Aborted(DrainAbort),
    /// The emergency ordering: process cancellation, pin revocation, a
    /// connection-local failure, or the peer closing first.
    Emergency { planned_deadline_published: bool },
}

/// The shutdown of one incoming peer connection.
///
/// ```text
/// Serving -> Planned(Requested -> GoAwaySent -> H3Complete -> StreamsReturned) -> Finished
///         |          \-> Aborted(cause) -------------------------------------/
///         \-> Emergency -----------------------------------------------------/
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerConnectionDrain {
    /// Accepting and serving request streams.
    Serving,
    /// A planned GOAWAY drain, in order so far.
    Planned(PlannedDrainStep),
    /// The planned drain was cut short and QUIC is closed.
    Aborted(DrainAbort),
    /// The emergency ordering.  `planned_deadline_published` is whether the
    /// listener had begun its planned drain, in which case this connection
    /// shares that deadline and reports how its cleanup went.
    Emergency { planned_deadline_published: bool },
    /// Stream tasks are joined (or abandoned at the deadline): terminal.
    Finished {
        route: DrainRoute,
        streams: DrainOutcome,
        pin_watcher_joined: bool,
    },
}

/// What can move a [`PeerConnectionDrain`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainEvent {
    /// The listener's planned drain was observed while serving.
    PlannedRequested,
    /// Serving ended any other way.
    EmergencyRequested {
        planned_deadline_published: bool,
    },
    GoAwaySent,
    GoAwayFailed,
    GoAwayDeadline,
    H3Complete,
    H3Failed,
    /// Connection-local cancellation during a planned drain.
    Emergency,
    /// The shared drain deadline passed during a planned drain.
    Deadline {
        streams_outstanding: bool,
    },
    StreamsReturned,
    /// The final bounded join of the stream tasks ended.
    TasksJoined(DrainOutcome),
    /// The pin watcher did not join before the deadline.
    PinWatcherAbandoned,
}

/// An event its connection drain state has no transition for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IllegalDrainEvent;

/// The four drain facts [`PeerServerConnectionStats`] exposes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DrainReport {
    planned_goaway_sent: bool,
    forced_stream_cancellation: bool,
    forced_connection_close: bool,
    drain_join_incomplete: bool,
}

impl PeerConnectionDrain {
    /// The only place a connection's drain state changes.
    fn on_event(self, event: DrainEvent) -> Result<Self, IllegalDrainEvent> {
        use DrainEvent as Event;
        use PlannedDrainStep as Step;
        let next = match (self, event) {
            (Self::Serving, Event::PlannedRequested) => Self::Planned(Step::Requested),
            (
                Self::Serving,
                Event::EmergencyRequested {
                    planned_deadline_published,
                },
            ) => Self::Emergency {
                planned_deadline_published,
            },

            (Self::Planned(Step::Requested), Event::GoAwaySent) => Self::Planned(Step::GoAwaySent),
            (Self::Planned(Step::Requested), Event::GoAwayFailed) => {
                Self::Aborted(DrainAbort::GoAwayFailed)
            }
            (Self::Planned(Step::Requested), Event::GoAwayDeadline) => {
                Self::Aborted(DrainAbort::GoAwayDeadline)
            }

            (Self::Planned(Step::GoAwaySent), Event::H3Complete) => Self::Planned(Step::H3Complete),
            (Self::Planned(Step::GoAwaySent), Event::H3Failed) => {
                Self::Aborted(DrainAbort::H3Failed)
            }
            (Self::Planned(Step::GoAwaySent), Event::Emergency) => {
                Self::Aborted(DrainAbort::EmergencyAwaitingH3)
            }
            (
                Self::Planned(Step::GoAwaySent),
                Event::Deadline {
                    streams_outstanding,
                },
            ) => Self::Aborted(DrainAbort::DeadlineAwaitingH3 {
                streams_outstanding,
            }),

            (Self::Planned(Step::H3Complete), Event::StreamsReturned) => {
                Self::Planned(Step::StreamsReturned)
            }
            (Self::Planned(Step::H3Complete), Event::Emergency) => {
                Self::Aborted(DrainAbort::EmergencyAwaitingStreams)
            }
            (Self::Planned(Step::H3Complete), Event::Deadline { .. }) => {
                Self::Aborted(DrainAbort::DeadlineAwaitingStreams)
            }

            (Self::Planned(Step::StreamsReturned), Event::TasksJoined(streams)) => Self::Finished {
                route: DrainRoute::Planned,
                streams,
                pin_watcher_joined: true,
            },
            (Self::Aborted(cause), Event::TasksJoined(streams)) => Self::Finished {
                route: DrainRoute::Aborted(cause),
                streams,
                pin_watcher_joined: true,
            },
            (
                Self::Emergency {
                    planned_deadline_published,
                },
                Event::TasksJoined(streams),
            ) => Self::Finished {
                route: DrainRoute::Emergency {
                    planned_deadline_published,
                },
                streams,
                pin_watcher_joined: true,
            },

            (
                Self::Finished {
                    route,
                    streams,
                    pin_watcher_joined: true,
                },
                Event::PinWatcherAbandoned,
            ) => Self::Finished {
                route,
                streams,
                pin_watcher_joined: false,
            },

            _ => return Err(IllegalDrainEvent),
        };
        Ok(next)
    }

    /// What the diagnostics report in this state.
    ///
    /// A written GOAWAY is reported as soon as it is written.  The forced
    /// and incomplete facts are reported once the stream tasks are joined,
    /// and only for a connection that took part in a planned drain.
    fn report(self) -> DrainReport {
        match self {
            Self::Serving | Self::Emergency { .. } | Self::Planned(PlannedDrainStep::Requested) => {
                DrainReport::default()
            }
            Self::Planned(_) => DrainReport {
                planned_goaway_sent: true,
                ..DrainReport::default()
            },
            Self::Aborted(cause) => DrainReport {
                planned_goaway_sent: cause.goaway_sent(),
                ..DrainReport::default()
            },
            Self::Finished {
                route:
                    DrainRoute::Emergency {
                        planned_deadline_published: false,
                    },
                ..
            } => DrainReport::default(),
            Self::Finished {
                route,
                streams,
                pin_watcher_joined,
            } => {
                let (planned_goaway_sent, forced_close, forced_cancellation) = match route {
                    DrainRoute::Planned => (true, false, false),
                    DrainRoute::Aborted(cause) => (
                        cause.goaway_sent(),
                        cause.forced_connection_close(),
                        cause.forced_stream_cancellation(),
                    ),
                    DrainRoute::Emergency { .. } => (false, false, false),
                };
                DrainReport {
                    planned_goaway_sent,
                    forced_stream_cancellation: forced_cancellation || streams.forced(),
                    forced_connection_close: forced_close || streams.forced(),
                    drain_join_incomplete: streams.incomplete() || !pin_watcher_joined,
                }
            }
        }
    }
}

/// One incoming connection's drain state, published to its diagnostics.
///
/// The connection task is the only writer.
struct ConnectionDrain {
    state: PeerConnectionDrain,
    diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>,
}

impl ConnectionDrain {
    fn new(diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>) -> Self {
        Self {
            state: PeerConnectionDrain::Serving,
            diagnostics,
        }
    }

    fn state(&self) -> PeerConnectionDrain {
        self.state
    }

    fn on_event(&mut self, event: DrainEvent) {
        match self.state.on_event(event) {
            Ok(next) => {
                self.state = next;
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.drain.send_replace(next);
                }
            }
            Err(IllegalDrainEvent) => {
                tracing::warn!(
                    state = ?self.state,
                    ?event,
                    "peer connection drain refused an out-of-order event"
                );
            }
        }
    }
}

struct PeerServerConnectionDiagnostics {
    peer_node_id: String,
    observed_server_name: Option<String>,
    connection_id: usize,
    connection: quinn::Connection,
    stream_permits: Arc<Semaphore>,
    max_stream_permits: usize,
    accepted_streams: AtomicU64,
    resolving_streams: AtomicU64,
    active_streams: AtomicU64,
    completed_streams: AtomicU64,
    cancelled_streams: AtomicU64,
    error_streams: AtomicU64,
    /// The connection's drain state, published by its own task.
    drain: watch::Sender<PeerConnectionDrain>,
    /// Set once a later registration found this connection already closed:
    /// the entry stops being reported while its task finishes.
    superseded: AtomicBool,
}

/// In-process, bounded target-side peer diagnostics.
///
/// This is intentionally a library-owned observation point instead of an
/// unauthenticated endpoint.  At most `max_connections` entries are retained:
/// there is one cell per connection the listener can serve at once, and a
/// closed connection's entry stops being reported when a replacement is
/// registered.
///
/// Each cell is written only by the connection task that holds its
/// [`DiagnosticsSlot`], so every cell has one writer at a time and
/// [`Self::snapshot`] samples them without waiting.
pub struct PeerServerDiagnostics {
    next_connection_id: AtomicUsize,
    slots: Box<[watch::Sender<Option<Arc<PeerServerConnectionDiagnostics>>>]>,
    /// Returns a released cell's index to the listener, which hands indices
    /// out.  It holds exactly the indices not leased, so it never overflows.
    free_slots: mpsc::Sender<usize>,
}

/// The lease of one diagnostics cell, held by one connection task.  Dropping
/// it clears the cell and returns its index to the listener.
struct DiagnosticsSlot {
    diagnostics: Arc<PeerServerDiagnostics>,
    index: usize,
}

impl Drop for DiagnosticsSlot {
    fn drop(&mut self) {
        if let Some(cell) = self.diagnostics.slots.get(self.index) {
            cell.send_replace(None);
        }
        let _ = self.diagnostics.free_slots.try_send(self.index);
    }
}

impl PeerServerDiagnostics {
    /// The diagnostics and the free list of its cells, which the listener
    /// supervisor owns.
    fn new(max_connections: usize) -> (Arc<Self>, mpsc::Receiver<usize>) {
        let (free_slots, free) = mpsc::channel(max_connections.max(1));
        for index in 0..max_connections {
            let _ = free_slots.try_send(index);
        }
        let diagnostics = Arc::new(Self {
            next_connection_id: AtomicUsize::new(1),
            slots: (0..max_connections)
                .map(|_| watch::Sender::new(None))
                .collect(),
            free_slots,
        });
        (diagnostics, free)
    }

    /// Return a bounded snapshot without exposing request payloads.
    pub fn snapshot(&self) -> PeerServerStats {
        let connections = self
            .slots
            .iter()
            .filter_map(|cell| cell.borrow().clone())
            .filter(|connection| !connection.superseded.load(Ordering::Acquire))
            .map(|connection| {
                let stats = connection.connection.stats();
                let drain = connection.drain.borrow().report();
                PeerServerConnectionStats {
                    peer_node_id: connection.peer_node_id.clone(),
                    observed_server_name: connection.observed_server_name.clone(),
                    connection_id: connection.connection_id,
                    accepted_streams: connection.accepted_streams.load(Ordering::Acquire),
                    resolving_streams: connection.resolving_streams.load(Ordering::Acquire),
                    active_streams: connection.active_streams.load(Ordering::Acquire),
                    completed_streams: connection.completed_streams.load(Ordering::Acquire),
                    cancelled_streams: connection.cancelled_streams.load(Ordering::Acquire),
                    error_streams: connection.error_streams.load(Ordering::Acquire),
                    available_stream_permits: connection.stream_permits.available_permits(),
                    max_stream_permits: connection.max_stream_permits,
                    frame_tx_max_streams_bidi: stats.frame_tx.max_streams_bidi,
                    frame_rx_max_streams_bidi: stats.frame_rx.max_streams_bidi,
                    frame_tx_streams_blocked_bidi: stats.frame_tx.streams_blocked_bidi,
                    frame_rx_streams_blocked_bidi: stats.frame_rx.streams_blocked_bidi,
                    frame_tx_reset_stream: stats.frame_tx.reset_stream,
                    frame_rx_reset_stream: stats.frame_rx.reset_stream,
                    frame_tx_stop_sending: stats.frame_tx.stop_sending,
                    frame_rx_stop_sending: stats.frame_rx.stop_sending,
                    planned_goaway_sent: drain.planned_goaway_sent,
                    forced_stream_cancellation: drain.forced_stream_cancellation,
                    forced_connection_close: drain.forced_connection_close,
                    drain_join_incomplete: drain.drain_join_incomplete,
                }
            })
            .collect();
        PeerServerStats { connections }
    }

    /// Publish one connection in the cell `slot` leases.
    fn register(
        &self,
        slot: &DiagnosticsSlot,
        peer_node_id: &str,
        connection: &quinn::Connection,
        stream_permits: Arc<Semaphore>,
        max_stream_permits: usize,
    ) -> Option<Arc<PeerServerConnectionDiagnostics>> {
        let cell = self.slots.get(slot.index)?;
        // Completed connection entries stop being reported when a
        // replacement is registered.
        for other in &self.slots {
            if let Some(entry) = other.borrow().as_ref()
                && entry.connection.close_reason().is_some()
            {
                entry.superseded.store(true, Ordering::Release);
            }
        }
        let observation = Arc::new(PeerServerConnectionDiagnostics {
            peer_node_id: peer_node_id.to_owned(),
            observed_server_name: observed_server_name(connection),
            // Monotonic and non-zero: zero is the callers' "no connection"
            // sentinel, and a slab-indexed QUIC stable id could be reused by a
            // later connection while an earlier entry is still being drained.
            connection_id: self.next_connection_id.fetch_add(1, Ordering::AcqRel),
            connection: connection.clone(),
            stream_permits,
            max_stream_permits,
            accepted_streams: AtomicU64::new(0),
            resolving_streams: AtomicU64::new(0),
            active_streams: AtomicU64::new(0),
            completed_streams: AtomicU64::new(0),
            cancelled_streams: AtomicU64::new(0),
            error_streams: AtomicU64::new(0),
            drain: watch::Sender::new(PeerConnectionDrain::Serving),
            superseded: AtomicBool::new(false),
        });
        cell.send_replace(Some(observation.clone()));
        Some(observation)
    }
}

/// Read the TLS server name the calling peer presented on this connection.
///
/// The value comes from the completed handshake, so it is what the caller
/// actually sent rather than anything this side derived. Returning `None`
/// when the handshake carried no server name keeps the observation honest
/// instead of substituting a local default.
fn observed_server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .server_name
}

#[derive(Clone, Copy)]
enum PeerServerRequestStage {
    Resolving,
    Active,
}

#[derive(Clone, Copy)]
enum PeerServerRequestOutcome {
    Pending,
    Completed,
    Cancelled,
    Error,
}

struct PeerServerRequestDiagnosticsGuard {
    diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>,
    stage: PeerServerRequestStage,
    outcome: PeerServerRequestOutcome,
}

impl PeerServerRequestDiagnosticsGuard {
    fn new(diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>) -> Self {
        if let Some(diagnostics) = &diagnostics {
            diagnostics.resolving_streams.fetch_add(1, Ordering::AcqRel);
        }
        Self {
            diagnostics,
            stage: PeerServerRequestStage::Resolving,
            outcome: PeerServerRequestOutcome::Pending,
        }
    }

    fn mark_active(&mut self) {
        if !matches!(self.stage, PeerServerRequestStage::Resolving) {
            return;
        }
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.resolving_streams.fetch_sub(1, Ordering::AcqRel);
            diagnostics.active_streams.fetch_add(1, Ordering::AcqRel);
        }
        self.stage = PeerServerRequestStage::Active;
    }

    fn finish(&mut self, cancelled: bool, result: &Result<(), PeerTransportError>) {
        self.outcome = if cancelled || matches!(result, Err(PeerTransportError::Cancelled)) {
            PeerServerRequestOutcome::Cancelled
        } else if result.is_ok() {
            PeerServerRequestOutcome::Completed
        } else {
            PeerServerRequestOutcome::Error
        };
    }
}

impl Drop for PeerServerRequestDiagnosticsGuard {
    fn drop(&mut self) {
        let Some(diagnostics) = &self.diagnostics else {
            return;
        };
        match self.stage {
            PeerServerRequestStage::Resolving => {
                diagnostics.resolving_streams.fetch_sub(1, Ordering::AcqRel);
            }
            PeerServerRequestStage::Active => {
                diagnostics.active_streams.fetch_sub(1, Ordering::AcqRel);
            }
        }
        match self.outcome {
            PeerServerRequestOutcome::Pending | PeerServerRequestOutcome::Cancelled => {
                diagnostics.cancelled_streams.fetch_add(1, Ordering::AcqRel);
            }
            PeerServerRequestOutcome::Completed => {
                diagnostics.completed_streams.fetch_add(1, Ordering::AcqRel);
            }
            PeerServerRequestOutcome::Error => {
                diagnostics.error_streams.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

impl<P, H> PeerServer<P, H>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    /// Construct a server over a Quinn endpoint configured with mandatory
    /// TLS 1.3 relay peer authentication.
    pub fn new(
        endpoint: quinn::Endpoint,
        approved_pins: ApprovedPeerPins,
        limits: PeerTransportLimits,
        policy: P,
        handler: H,
    ) -> Result<Self, PeerTransportError> {
        let pin_provider = SharedPeerPins::new(approved_pins)?;
        Self::new_with_pin_provider(endpoint, pin_provider, limits, policy, handler)
    }

    /// Construct a server backed by caller-updated dynamic peer pin state.
    /// The initial snapshot may be empty, which rejects every peer until the
    /// caller publishes approved keys.
    pub fn new_with_pin_provider(
        endpoint: quinn::Endpoint,
        pin_provider: SharedPeerPins,
        limits: PeerTransportLimits,
        policy: P,
        handler: H,
    ) -> Result<Self, PeerTransportError> {
        limits.validate()?;
        let (diagnostics, diagnostics_slots) = PeerServerDiagnostics::new(limits.max_connections);
        Ok(Self {
            endpoint,
            pin_provider,
            limits,
            policy: Arc::new(policy),
            handler: Arc::new(handler),
            diagnostics,
            diagnostics_slots,
        })
    }

    /// Return the bounded in-process target-side diagnostics view.
    pub fn diagnostics(&self) -> Arc<PeerServerDiagnostics> {
        self.diagnostics.clone()
    }

    /// Run until cancellation, then close the endpoint and join all
    /// connection and request tasks immediately.
    pub async fn serve(self, cancel: CancellationToken) -> Result<(), PeerTransportError> {
        self.serve_with_mode(cancel, PeerShutdownMode::Emergency)
            .await
    }

    /// Run until cancellation, then send HTTP/3 GOAWAY to established
    /// connections and join admitted streams under the transport drain
    /// deadline.  Pin revocation and connection-local cancellation remain
    /// emergency closes; this mode only applies to the caller's planned
    /// listener shutdown signal.
    pub async fn serve_planned(self, cancel: CancellationToken) -> Result<(), PeerTransportError> {
        self.serve_with_mode(cancel, PeerShutdownMode::PlannedDrain)
            .await
    }

    /// Run with independent emergency and planned listener signals.
    ///
    /// An ordinary process/identity/pin cancellation remains emergency and
    /// closes immediately.  The separate planned token is the only signal
    /// allowed to enter the bounded HTTP/3 GOAWAY drain.  This seam is used by
    /// the in-process three-relay acceptance fixture; it does not change the
    /// default [`Self::serve`] behavior.
    pub async fn serve_with_planned_shutdown(
        self,
        emergency: CancellationToken,
        planned: CancellationToken,
    ) -> Result<(), PeerTransportError> {
        serve_peer_inner(
            self.endpoint,
            self.pin_provider,
            self.limits,
            self.policy,
            self.handler,
            self.diagnostics,
            self.diagnostics_slots,
            emergency,
            PeerShutdownMode::PlannedDrain,
            Some(planned),
        )
        .await
    }

    async fn serve_with_mode(
        self,
        cancel: CancellationToken,
        mode: PeerShutdownMode,
    ) -> Result<(), PeerTransportError> {
        serve_peer_inner(
            self.endpoint,
            self.pin_provider,
            self.limits,
            self.policy,
            self.handler,
            self.diagnostics,
            self.diagnostics_slots,
            cancel,
            mode,
            None,
        )
        .await
    }
}

/// Serve authenticated peer HTTP/3 requests until cancellation.
pub async fn serve_peer<P, H>(
    endpoint: quinn::Endpoint,
    approved_pins: ApprovedPeerPins,
    limits: PeerTransportLimits,
    policy: P,
    handler: H,
    cancel: CancellationToken,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    PeerServer::new(endpoint, approved_pins, limits, policy, handler)?
        .serve(cancel)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_peer_inner<P, H>(
    endpoint: quinn::Endpoint,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    policy: Arc<P>,
    handler: Arc<H>,
    diagnostics: Arc<PeerServerDiagnostics>,
    mut diagnostics_slots: mpsc::Receiver<usize>,
    cancel: CancellationToken,
    mode: PeerShutdownMode,
    planned_cancel: Option<CancellationToken>,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();
    let child_cancel = cancel.child_token();
    let planned = PlannedDrainSignal::new();
    let planned_cancel_enabled = planned_cancel.is_some();
    let mut requested_mode = mode;
    let mut supervisor_error = None;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                // With the dual-signal API this is the emergency path. The
                // legacy PlannedDrain API has no second token, so its caller
                // cancellation remains the planned signal.
                requested_mode = if planned_cancel_enabled {
                    PeerShutdownMode::Emergency
                } else {
                    mode
                };
                break;
            }
            _ = async {
                if let Some(token) = &planned_cancel {
                    token.cancelled().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if planned_cancel_enabled => {
                requested_mode = PeerShutdownMode::PlannedDrain;
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let pin_provider = pin_provider.clone();
                let limits = limits.clone();
                let policy = policy.clone();
                let handler = handler.clone();
                // A connection permit and a diagnostics cell are released
                // together, the cell first, so a cell is free whenever a
                // permit is.  A connection without one is served unobserved.
                let diagnostics_slot =
                    diagnostics_slots
                        .try_recv()
                        .ok()
                        .map(|index| DiagnosticsSlot {
                            diagnostics: diagnostics.clone(),
                            index,
                        });
                // In planned mode the caller cancellation is the drain
                // request itself.  Keep established connection/stream
                // cancellation independent so admitted handlers survive
                // long enough to observe GOAWAY and finish under the shared
                // deadline.  Emergency mode retains the existing child
                // token propagation.
                // A dual-signal server gives established connection tasks an
                // emergency child token while the planned signal is carried by
                // `planned`. The legacy PlannedDrain form already has a
                // cancelled parent token, so it keeps its independent token.
                let connection_cancel = if planned_cancel_enabled {
                    child_cancel.child_token()
                } else {
                    match mode {
                        PeerShutdownMode::Emergency => child_cancel.child_token(),
                        PeerShutdownMode::PlannedDrain => CancellationToken::new(),
                    }
                };
                let planned = planned.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let diagnostics_slot = diagnostics_slot;
                    let handshake_cancel = connection_cancel.clone();
                    let handshake_planned = planned.clone();
                    let connection = tokio::select! {
                        biased;
                        _ = handshake_cancel.cancelled() => {
                            return Ok(())
                        }
                        _ = handshake_planned.draining(), if mode == PeerShutdownMode::PlannedDrain => {
                            return Ok(())
                        }
                        result = timeout(limits.handshake_timeout, incoming) => {
                            result
                                .map_err(|_| PeerTransportError::Timeout)?
                                .map_err(|error| PeerTransportError::Quic(error.to_string()))?
                        }
                    };
                    serve_incoming_connection(
                        connection,
                        &pin_provider,
                        &limits,
                        policy,
                        handler,
                        diagnostics_slot,
                        connection_cancel,
                        mode,
                        planned,
                    )
                    .await
                });
            }
            Some(result) = tasks.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(?error, "HTTP/3 peer connection closed"),
                    Err(error) => {
                        supervisor_error = Some(PeerTransportError::Task(error));
                        break;
                    }
                }
            }
        }
    }

    let deadline = Instant::now() + limits.drain_timeout;
    match requested_mode {
        PeerShutdownMode::Emergency => {
            child_cancel.cancel();
            endpoint.close(quinn::VarInt::from_u32(0), b"peer shutdown");
            let _ = drain_peer_tasks(
                &mut tasks,
                deadline,
                cancel.is_cancelled(),
                &mut supervisor_error,
                "peer-connections",
            )
            .await;
        }
        PeerShutdownMode::PlannedDrain => {
            // Quinn Endpoint::close() also closes established connections.
            // Remove the server configuration first so existing H3
            // connections can send GOAWAY and drain independently.
            endpoint.set_server_config(None);
            planned.close_admission();
            planned.begin_drain(deadline);
            let _ = drain_peer_tasks_with_grace(
                &mut tasks,
                deadline,
                false,
                &mut supervisor_error,
                "peer-connections",
                false,
                true,
            )
            .await;
            // All connection tasks have either drained or been joined/aborted
            // at the shared deadline before the endpoint is closed.
            endpoint.close(quinn::VarInt::from_u32(0), b"peer planned drain");
            child_cancel.cancel();
        }
    }
    if let Some(error) = supervisor_error {
        return Err(error);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_incoming_connection<P, H>(
    connection: quinn::Connection,
    pin_provider: &SharedPeerPins,
    limits: &PeerTransportLimits,
    policy: Arc<P>,
    handler: Arc<H>,
    diagnostics_slot: Option<DiagnosticsSlot>,
    cancel: CancellationToken,
    mode: PeerShutdownMode,
    planned: PlannedDrainSignal,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    configure_quic_connection(&connection, limits)?;
    let identity = verified_peer_identity(&connection).map_err(map_probe_error)?;
    pin_provider
        .snapshot()
        .verify(&identity)
        .map_err(map_probe_error)?;

    let quic = h3_quinn::Connection::new(connection.clone());
    let mut builder = h3::server::builder();
    builder.max_field_section_size(limits.max_header_bytes as u64);
    let mut h3_connection = timeout(limits.handshake_timeout, builder.build::<_, Bytes>(quic))
        .await
        .map_err(|_| PeerTransportError::Timeout)?
        .map_err(|error| PeerTransportError::H3(error.to_string()))?;
    let pin_watcher = spawn_pin_watcher(&identity, pin_provider, &connection, cancel.clone());
    let stream_permits = Arc::new(Semaphore::new(limits.max_streams_per_connection));
    // The cell lease is held to the end of this connection: dropping it
    // removes the entry registered here.
    let connection_diagnostics = diagnostics_slot.as_ref().and_then(|slot| {
        slot.diagnostics.register(
            slot,
            identity.role_id(),
            &connection,
            stream_permits.clone(),
            limits.max_streams_per_connection,
        )
    });
    let connection_bytes = Arc::new(AtomicUsize::new(0));
    let mut stream_tasks = JoinSet::new();
    let stream_cancel = cancel.child_token();
    let mut connection_error = None;
    let mut drain = ConnectionDrain::new(connection_diagnostics.clone());

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                // A pin revocation or connection-local emergency wins if it
                // races the listener's planned signal.  If the planned
                // signal was already published, the deadline selection below
                // retains its absolute budget while preserving the emergency
                // close path.
                break;
            }
            _ = planned.draining(), if mode == PeerShutdownMode::PlannedDrain => {
                drain.on_event(DrainEvent::PlannedRequested);
                break;
            }
            result = h3_connection.accept() => {
                let resolver = match result {
                    Ok(Some(resolver)) => resolver,
                    Ok(None) => break,
                    Err(error) => {
                        connection_error = Some(PeerTransportError::H3(error.to_string()));
                        break;
                    }
                };
                if let Some(connection_diagnostics) = &connection_diagnostics {
                    connection_diagnostics
                        .accepted_streams
                        .fetch_add(1, Ordering::AcqRel);
                }
                let permit = match stream_permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        if let Some(connection_diagnostics) = &connection_diagnostics {
                            connection_diagnostics
                                .cancelled_streams
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        resolver.reject(h3::error::Code::H3_REQUEST_REJECTED);
                        continue;
                    }
                };
                let identity = identity.clone();
                let policy = policy.clone();
                let handler = handler.clone();
                let limits = limits.clone();
                let pin_provider = pin_provider.clone();
                let stream_cancel = stream_cancel.child_token();
                let connection_bytes = connection_bytes.clone();
                let connection_diagnostics = connection_diagnostics.clone();
                let planned = planned.clone();
                stream_tasks.spawn(async move {
                    handle_incoming_stream(
                        resolver,
                        identity,
                        pin_provider,
                        policy,
                        handler,
                        limits,
                        connection_bytes,
                        permit,
                        connection_diagnostics,
                        stream_cancel,
                        planned,
                    )
                    .await
                });
            }
            Some(result) = stream_tasks.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(?error, "HTTP/3 peer stream closed"),
                    Err(error) => {
                        connection_error = Some(PeerTransportError::Task(error));
                        break;
                    }
                }
            }
        }
    }

    // Once the listener has begun its planned drain, every connection task
    // -- including one leaving by the emergency ordering -- shares that
    // drain's absolute deadline.
    let planned_deadline = match mode {
        PeerShutdownMode::PlannedDrain => planned.draining_deadline(),
        PeerShutdownMode::Emergency => None,
    };
    if drain.state() == PeerConnectionDrain::Serving {
        drain.on_event(DrainEvent::EmergencyRequested {
            planned_deadline_published: planned_deadline.is_some(),
        });
    }
    let deadline = planned_deadline.unwrap_or_else(|| Instant::now() + limits.drain_timeout);
    if matches!(drain.state(), PeerConnectionDrain::Planned(_)) {
        let drain_wait_deadline = {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining > FORCED_JOIN_GRACE {
                deadline - FORCED_JOIN_GRACE
            } else {
                deadline
            }
        };
        // Send GOAWAY while QUIC is still open.  The accepted stream tasks
        // remain live while the H3 connection is driven to its post-GOAWAY
        // completion boundary.
        match timeout_at(drain_wait_deadline, h3_connection.shutdown(0)).await {
            Ok(Ok(())) => drain.on_event(DrainEvent::GoAwaySent),
            Ok(Err(error)) => {
                connection_error = Some(PeerTransportError::H3(error.to_string()));
                connection.close(quinn::VarInt::from_u32(0), b"peer planned drain failure");
                drain.on_event(DrainEvent::GoAwayFailed);
            }
            Err(_) => {
                connection_error = Some(PeerTransportError::Timeout);
                connection.close(quinn::VarInt::from_u32(0), b"peer planned drain failure");
                drain.on_event(DrainEvent::GoAwayDeadline);
            }
        }
        while drain.state() == PeerConnectionDrain::Planned(PlannedDrainStep::GoAwaySent) {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    // A pin revocation or connection-local emergency
                    // cancellation wins over a planned drain already in
                    // progress. The watcher has already closed QUIC;
                    // leave the planned loop immediately and join below.
                    connection_error.get_or_insert(PeerTransportError::Cancelled);
                    connection.close(quinn::VarInt::from_u32(0), b"peer emergency during drain");
                    drain.on_event(DrainEvent::Emergency);
                }
                _ = sleep_until(drain_wait_deadline) => {
                    connection_error.get_or_insert(PeerTransportError::Timeout);
                    let streams_outstanding = !stream_tasks.is_empty();
                    connection.close(quinn::VarInt::from_u32(0), b"peer planned drain deadline");
                    drain.on_event(DrainEvent::Deadline { streams_outstanding });
                }
                result = h3_connection.accept() => match result {
                    Ok(Some(resolver)) => {
                        // h3 rejects streams above the GOAWAY boundary
                        // before returning a resolver. If a resolver does
                        // surface here, consume and reset it with
                        // H3_REQUEST_REJECTED ("not processed") without
                        // dispatching; it is a bounded late-admission
                        // observation, not an application success.
                        if let Ok(Ok((_request, mut stream))) =
                            timeout_at(
                                drain_wait_deadline,
                                resolver.resolve_request_with_rejection_on_cancel(
                                    h3::error::Code::H3_REQUEST_REJECTED,
                                ),
                            ).await
                        {
                            stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                        }
                    }
                    Ok(None) => drain.on_event(DrainEvent::H3Complete),
                    Err(error) => {
                        connection_error = Some(PeerTransportError::H3(error.to_string()));
                        connection.close(quinn::VarInt::from_u32(0), b"peer planned H3 error");
                        drain.on_event(DrainEvent::H3Failed);
                    }
                },
                Some(result) = stream_tasks.join_next() => match result {
                    Ok(Ok(())) => {}
                    // A forwarded stream ending with an error is a
                    // stream-local lifecycle event, exactly as in normal
                    // serving.  Peers tearing down around GOAWAY reset
                    // their streams (H3_REQUEST_CANCELLED/REJECTED); that
                    // is the expected drain outcome, not a listener
                    // failure.  Only a task panic or the forced-deadline
                    // path above fails the drain.
                    Ok(Err(error)) => {
                        tracing::debug!(
                            ?error,
                            "peer stream closed during planned drain"
                        );
                    }
                    Err(error) => {
                        connection_error = Some(PeerTransportError::Task(error));
                    }
                },
            }
        }
        while drain.state() == PeerConnectionDrain::Planned(PlannedDrainStep::H3Complete) {
            if stream_tasks.is_empty() {
                drain.on_event(DrainEvent::StreamsReturned);
                break;
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    connection_error.get_or_insert(PeerTransportError::Cancelled);
                    connection.close(quinn::VarInt::from_u32(0), b"peer emergency during drain");
                    drain.on_event(DrainEvent::Emergency);
                }
                _ = sleep_until(drain_wait_deadline) => {
                    connection_error.get_or_insert(PeerTransportError::Timeout);
                    connection.close(quinn::VarInt::from_u32(0), b"peer planned drain deadline");
                    drain.on_event(DrainEvent::Deadline { streams_outstanding: true });
                }
                Some(result) = stream_tasks.join_next() => match result {
                    Ok(Ok(())) => {}
                    // A forwarded stream's own error is stream-local, as in
                    // normal serving; the drain joins it rather than
                    // treating an expected GOAWAY-induced reset as a
                    // listener failure.
                    Ok(Err(error)) => {
                        tracing::debug!(
                            ?error,
                            "peer stream closed during planned drain"
                        );
                    }
                    Err(error) => {
                        connection_error = Some(PeerTransportError::Task(error));
                    }
                },
            }
        }
        stream_cancel.cancel();
        // Join any stragglers.  Stream-handler errors here are stream-local and
        // must not fail the listener (matching normal serving); only a forced
        // abort at the shared deadline is reported as incomplete cleanup.
        let stream_drain = drain_peer_tasks_without_recording_task_errors(
            &mut stream_tasks,
            deadline,
            false,
            &mut connection_error,
            "peer-streams",
        )
        .await;
        // This is the terminal action after GOAWAY/accepted-stream draining.
        // A drain that was cut short has already closed QUIC, with the
        // reason for it.
        let completed_in_order =
            drain.state() == PeerConnectionDrain::Planned(PlannedDrainStep::StreamsReturned);
        drain.on_event(DrainEvent::TasksJoined(stream_drain));
        if completed_in_order {
            connection.close(
                quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value())
                    .expect("H3_NO_ERROR fits a QUIC application close code"),
                b"peer planned drain",
            );
        }
    } else {
        // Preserve the existing emergency ordering for process cancellation,
        // pin revocation, and connection-local failures.
        stream_cancel.cancel();
        connection.close(quinn::VarInt::from_u32(0), b"peer drain");
        if timeout_at(deadline, h3_connection.shutdown(0))
            .await
            .is_err()
        {
            tracing::warn!("HTTP/3 peer connection drain deadline exceeded");
        }
        // A forwarded stream's own terminal error is stream-local; the
        // emergency close already cancelled it, and an expected reset must not
        // be promoted to a listener failure.  Only a forced-deadline abort is
        // reported as incomplete cleanup below.
        let stream_drain = drain_peer_tasks_without_recording_task_errors(
            &mut stream_tasks,
            deadline,
            cancel.is_cancelled() && planned_deadline.is_none(),
            &mut connection_error,
            "peer-streams",
        )
        .await;
        drain.on_event(DrainEvent::TasksJoined(stream_drain));
    }
    cancel.cancel();
    let pin_watcher_result = if planned_deadline.is_some() {
        join_handle_until_bounded(pin_watcher, deadline).await
    } else {
        join_handle_until(pin_watcher, deadline).await
    };
    match pin_watcher_result {
        Some(Err(error)) => {
            connection_error.get_or_insert(PeerTransportError::Task(error));
        }
        None => {
            tracing::warn!("peer pin watcher exceeded drain timeout");
            connection_error.get_or_insert(PeerTransportError::Timeout);
            drain.on_event(DrainEvent::PinWatcherAbandoned);
        }
        Some(Ok(())) => {}
    }
    if let Some(error) = connection_error {
        return Err(error);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_stream<P, H>(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    identity: TlsIdentity,
    pin_provider: SharedPeerPins,
    policy: Arc<P>,
    handler: Arc<H>,
    limits: PeerTransportLimits,
    connection_bytes: Arc<AtomicUsize>,
    permit: OwnedSemaphorePermit,
    diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>,
    cancel: CancellationToken,
    planned: PlannedDrainSignal,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    let mut diagnostics = PeerServerRequestDiagnosticsGuard::new(diagnostics);
    let result = async {
        if !pin_provider.snapshot().contains(identity.spki_sha256()) {
            resolver.reject(h3::error::Code::H3_REQUEST_CANCELLED);
            cancel.cancel();
            return Err(PeerTransportError::Authentication(
                "peer SPKI pin was revoked".to_owned(),
            ));
        }
        let (request, stream) = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = planned.draining() => return Ok(()),
            result = timeout(
                limits.idle_timeout,
                resolver.resolve_request_with_rejection_on_cancel(
                    h3::error::Code::H3_REQUEST_REJECTED,
                ),
            ) => {
                result
                    .map_err(|_| PeerTransportError::Timeout)?
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?
            }
        };
        if planned.admission_closed() {
            // A planned drain closed admission before this stream was
            // dispatched.  Reset with H3_REQUEST_REJECTED ("not processed")
            // so the caller classifies it as a pre-dispatch GoAway rather than
            // an ambiguous cancellation.
            let mut stream = stream;
            stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            return Ok(());
        }
        diagnostics.mark_active();
        if !policy.authorize(&identity, &request) {
            let mut stream = stream;
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerTransportError::PolicyRejected);
        }
        if !planned.begin_admission() {
            // The planned-drain admission boundary closed while this stream was
            // resolving; it was never dispatched, so signal not-processed.
            let mut stream = stream;
            stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            return Ok(());
        }
        let budget = body_budget(&limits, connection_bytes);
        let stream = PeerServerStream::new(
            stream,
            budget,
            Arc::new(StreamLease { _permit: permit }),
            limits.idle_timeout,
        );
        let handler_future = handler.handle(identity, request, stream);
        tokio::select! {
            biased;
            // The handler owns the request stream after admission.  On
            // cancellation its future is dropped, then the enclosing
            // connection performs the bounded QUIC close/join at the shared
            // deadline; do not move the stream into two select branches.
            _ = cancel.cancelled() => Ok(()),
            result = handler_future => result,
        }
    }
    .await;
    diagnostics.finish(cancel.is_cancelled() || planned.is_draining(), &result);
    result
}

#[cfg(test)]
#[path = "peer_resolver_lifecycle_tests.rs"]
mod resolver_lifecycle_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dialling_with_no_published_pins_is_its_own_typed_refusal() {
        // M7-C83.  An empty pin snapshot means the caller's membership
        // coordinator currently publishes no trust evidence at all.  The dial
        // is refused before a socket is opened or a certificate examined, so
        // it must not share a variant with a peer that *was* dialled and
        // failed its SPKI check: a caller that cannot tell them apart has to
        // report the first as `unknown` too, and deny a safe request the
        // retry it is entitled to.
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("bind a client endpoint");
        let client = PeerClient::new_with_pin_provider(
            endpoint,
            SharedPeerPins::empty(),
            PeerTransportLimits::default(),
        )
        .expect("client with fail-closed pins");
        let destination = PeerDestination::new("127.0.0.1:1".parse().unwrap(), "peer.test");
        assert!(matches!(
            client.connect(destination).await,
            Err(PeerTransportError::PinsUnavailable)
        ));
    }

    #[test]
    fn limits_are_explicit_and_bounded() {
        let defaults = PeerTransportLimits::default();
        assert!(defaults.validate().is_ok());
        assert_eq!(defaults.idle_timeout, DEFAULT_PEER_IDLE_TIMEOUT);
        assert_eq!(defaults.drain_timeout, DEFAULT_PEER_DRAIN_TIMEOUT);
        assert_eq!(
            defaults
                .clone()
                .with_timeouts(Duration::from_secs(7), Duration::from_secs(3))
                .unwrap()
                .idle_timeout,
            Duration::from_secs(7)
        );
        assert!(matches!(
            defaults.with_timeouts(Duration::ZERO, Duration::from_secs(3)),
            Err(PeerTransportError::InvalidLimits)
        ));
        assert!(matches!(
            PeerTransportLimits::new(
                0,
                1,
                1,
                1,
                1,
                1,
                1,
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(PeerTransportError::InvalidLimits)
        ));
        assert!(matches!(
            PeerBodyChunk::new(Bytes::from(vec![0; DEFAULT_PEER_BODY_CHUNK_BYTES + 1])),
            Err(PeerTransportError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn body_budget_rejects_stream_and_connection_limits() {
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 4,
            max_connection_bytes: 8,
            max_chunk_bytes: 4,
        };
        let held = budget.reserve(4).unwrap();
        assert!(matches!(
            budget.reserve(1),
            Err(PeerTransportError::BodyTooLarge { maximum: 4, .. })
        ));
        drop(held);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn body_budget_retained_chunks_saturate_and_connection_failure_rolls_back() {
        let connection_bytes = Arc::new(AtomicUsize::new(0));
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: connection_bytes.clone(),
            max_stream_bytes: 8,
            max_connection_bytes: 8,
            max_chunk_bytes: 8,
        };
        let first = budget.reserve(4).unwrap();
        let retained = PeerBodyChunk::from_received(Bytes::from_static(b"1234"), first);
        let retained_clone = retained.clone();
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 4);
        assert_eq!(connection_bytes.load(Ordering::Acquire), 4);
        assert!(matches!(
            budget.reserve(5),
            Err(PeerTransportError::BodyTooLarge { maximum: 8, .. })
        ));
        drop(retained);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 4);
        drop(retained_clone);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(connection_bytes.load(Ordering::Acquire), 0);

        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 8,
            max_connection_bytes: 4,
            max_chunk_bytes: 8,
        };
        let held = budget.reserve(4).unwrap();
        assert!(matches!(
            budget.reserve(4),
            Err(PeerTransportError::BodyTooLarge { maximum: 4, .. })
        ));
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 4);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 4);
        drop(held);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn body_budget_allows_repeated_transfers_after_each_write_releases() {
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 4,
            max_connection_bytes: 4,
            max_chunk_bytes: 4,
        };
        // The byte ceilings are in-flight bounds, not a lifetime transfer
        // quota: completed writes release their charge and a long-lived H3
        // stream can keep transferring bounded chunks.
        for _ in 0..256 {
            let charge = budget.reserve(4).unwrap();
            drop(charge);
        }
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bounded_body_chunks_preserve_order_and_configured_boundaries() {
        let maximum = DEFAULT_PEER_BODY_CHUNK_BYTES;
        let mut body = Vec::with_capacity(maximum + 72);
        body.extend((0..maximum + 72).map(|index| (index % 251) as u8));

        let chunks: Vec<&[u8]> = bounded_body_chunks(&body, maximum).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), maximum);
        assert_eq!(chunks[1].len(), 72);
        assert!(chunks.iter().all(|chunk| chunk.len() <= maximum));

        let reconstructed: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        assert_eq!(reconstructed, body);

        let smaller: Vec<&[u8]> = bounded_body_chunks(&body[..23], 7).collect();
        assert_eq!(
            smaller.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [7, 7, 7, 2]
        );
        assert_eq!(smaller.concat(), &body[..23]);
    }

    #[test]
    fn bounded_body_chunks_exact_limit_has_no_empty_tail() {
        let body = vec![0x5a; DEFAULT_PEER_BODY_CHUNK_BYTES];
        let chunks: Vec<&[u8]> =
            bounded_body_chunks(&body, DEFAULT_PEER_BODY_CHUNK_BYTES).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], body.as_slice());
        assert!(
            bounded_body_chunks(&[], DEFAULT_PEER_BODY_CHUNK_BYTES)
                .next()
                .is_none()
        );
    }

    #[test]
    fn zero_length_receive_chunks_do_not_retain_budget_metadata() {
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 4,
            max_connection_bytes: 4,
            max_chunk_bytes: 4,
        };
        let zero = PeerBodyChunk::from_received(Bytes::new(), budget.reserve(0).unwrap());
        assert!(zero._charge.is_none());
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn dynamic_pin_snapshots_are_bounded_and_fail_closed() {
        let first = crate::SpkiSha256::from_bytes([1; 32]);
        let second = crate::SpkiSha256::from_bytes([2; 32]);
        let approved = ApprovedPeerPins::new([first, second]).unwrap();
        let shared = SharedPeerPins::new(approved).unwrap();
        let initial = shared.snapshot();
        assert_eq!(initial.len(), 2);
        assert!(initial.contains(first));
        assert_eq!(initial.revision(), 0);

        shared.replace(std::iter::empty()).unwrap();
        let revoked = shared.snapshot();
        assert!(revoked.is_empty());
        assert!(!revoked.contains(first));
        assert_eq!(revoked.revision(), 1);

        let too_many = (0..=MAX_DYNAMIC_PEER_PINS)
            .map(|value| crate::SpkiSha256::from_bytes([value as u8; 32]));
        assert!(matches!(
            shared.replace(too_many),
            Err(PeerTransportError::TooManyPeerPins { .. })
        ));
        assert!(shared.snapshot().is_empty());
    }

    fn dial_pool(max_destinations: usize) -> PeerPool {
        PeerPool::new(
            PeerTransportLimits {
                max_destinations,
                ..PeerTransportLimits::default()
            },
            CancellationToken::new(),
            watch::Sender::new(Vec::new()),
        )
    }

    fn checkout(
        pool: &mut PeerPool,
        destination: &PeerDestination,
    ) -> oneshot::Receiver<Result<Checkout, PeerTransportError>> {
        let (reply, answer) = oneshot::channel();
        pool.handle(PoolCommand::Checkout {
            destination: destination.clone(),
            pins: SharedPeerPins::empty().snapshot(),
            local_identity: None,
            reply,
        });
        answer
    }

    /// The dial turn a checkout was answered with, when it was.
    fn granted_turn(
        answer: &mut oneshot::Receiver<Result<Checkout, PeerTransportError>>,
    ) -> Option<DialTurn> {
        match answer.try_recv() {
            Ok(Ok(Checkout::Dial { previous, turn, .. })) => {
                assert!(previous.is_none());
                Some(turn)
            }
            Ok(Ok(Checkout::Reuse(_))) => panic!("nothing is pooled in this fixture"),
            Ok(Err(error)) => panic!("checkout refused: {error:?}"),
            Err(_) => None,
        }
    }

    /// Let the pool observe one ended dial turn, as its task does.
    async fn observe_ended_turn(pool: &mut PeerPool) {
        let (destination, outcome) = timeout(Duration::from_secs(5), pool.turn_ended())
            .await
            .expect("a dial turn ended");
        pool.finish_turn(destination, outcome);
    }

    #[tokio::test]
    async fn dial_pool_releases_an_abandoned_turn_before_enforcing_saturation() {
        let destination = PeerDestination::new("127.0.0.1:1".parse().unwrap(), "peer.test");
        let other = PeerDestination::new("127.0.0.1:2".parse().unwrap(), "peer.test");
        let mut pool = dial_pool(1);
        let mut first = checkout(&mut pool, &destination);
        let abandoned = granted_turn(&mut first).expect("the first checkout dials");
        // The destination being dialed is accounted against the pool bound.
        assert!(matches!(
            checkout(&mut pool, &other).try_recv(),
            Ok(Err(PeerTransportError::Capacity))
        ));

        // A creator that is cancelled mid-dial drops its turn.  The pool
        // retires that slot, so the same destination dials afresh ...
        drop(abandoned);
        observe_ended_turn(&mut pool).await;
        assert!(pool.dials.is_empty());
        let mut replacement = checkout(&mut pool, &destination);
        let replacement_turn = granted_turn(&mut replacement).expect("a fresh dial turn");
        // ... while other destinations remain bounded by the live one.
        assert!(matches!(
            checkout(&mut pool, &other).try_recv(),
            Ok(Err(PeerTransportError::Capacity))
        ));
        drop(replacement_turn);
        observe_ended_turn(&mut pool).await;
        let mut admitted = checkout(&mut pool, &other);
        assert!(granted_turn(&mut admitted).is_some());
    }

    #[tokio::test]
    async fn dial_pool_grants_one_turn_per_destination_in_arrival_order() {
        let destination = PeerDestination::new("127.0.0.1:1".parse().unwrap(), "peer.test");
        let mut pool = dial_pool(4);
        let mut first = checkout(&mut pool, &destination);
        let mut second = checkout(&mut pool, &destination);
        let third = checkout(&mut pool, &destination);
        let mut fourth = checkout(&mut pool, &destination);
        let first_turn = granted_turn(&mut first).expect("the first checkout dials");
        // At most one dial per destination: the others wait for it.
        assert!(granted_turn(&mut second).is_none());
        assert!(granted_turn(&mut fourth).is_none());
        assert_eq!(pool.dials.len(), 1);

        // The first dial fails: the next waiter, and only it, dials.
        drop(first_turn);
        observe_ended_turn(&mut pool).await;
        let second_turn = granted_turn(&mut second).expect("the second checkout dials next");
        assert!(granted_turn(&mut fourth).is_none());

        // A waiter that stopped waiting is passed over.
        drop(third);
        drop(second_turn);
        observe_ended_turn(&mut pool).await;
        let fourth_turn = granted_turn(&mut fourth).expect("the fourth checkout dials last");

        // The last turn fails with nobody waiting: the slot is released.
        drop(fourth_turn);
        observe_ended_turn(&mut pool).await;
        assert!(pool.dials.is_empty());
    }

    #[tokio::test]
    async fn checkout_deadline_is_absolute_and_cancellation_wakes_waiters() {
        let cancel = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_millis(35);
        with_checkout_deadline(
            &cancel,
            deadline,
            tokio::time::sleep(Duration::from_millis(10)),
        )
        .await
        .unwrap();
        assert!(matches!(
            with_checkout_deadline(
                &cancel,
                deadline,
                tokio::time::sleep(Duration::from_millis(50)),
            )
            .await,
            Err(PeerTransportError::Timeout)
        ));

        cancel.cancel();
        assert!(matches!(
            with_checkout_deadline(
                &cancel,
                Instant::now() + Duration::from_secs(1),
                tokio::time::sleep(Duration::from_secs(1)),
            )
            .await,
            Err(PeerTransportError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn cancelled_dial_creator_releases_its_pool_marker() {
        let mut pool = dial_pool(4);
        let destination = PeerDestination::new("127.0.0.1:1".parse().unwrap(), "peer.test");
        // A creator whose dial fails releases its turn by dropping it.
        let mut failed = checkout(&mut pool, &destination);
        drop(granted_turn(&mut failed).expect("a dial turn"));
        observe_ended_turn(&mut pool).await;
        assert!(pool.dials.is_empty());

        // A creator that is cancelled while it holds the turn never takes
        // its answer: the turn inside the unread answer is dropped with it.
        let dropped_destination = PeerDestination::new("127.0.0.1:2".parse().unwrap(), "peer.test");
        drop(checkout(&mut pool, &dropped_destination));
        assert_eq!(pool.dials.len(), 1);
        observe_ended_turn(&mut pool).await;
        assert!(pool.dials.is_empty());

        // A creator cancelled before the pool answered is never given one.
        let (reply, answer) = oneshot::channel();
        drop(answer);
        pool.handle(PoolCommand::Checkout {
            destination: dropped_destination,
            pins: SharedPeerPins::empty().snapshot(),
            local_identity: None,
            reply,
        });
        assert!(pool.dials.is_empty());
    }

    #[tokio::test]
    async fn connection_supervisor_joins_once_and_answers_later_requests_at_once() {
        let (joins, requests) = mpsc::channel(CONNECTION_JOIN_QUEUE);
        let (finish_driver, driver_may_finish) = oneshot::channel::<()>();
        let driver = tokio::spawn(async move {
            let _ = driver_may_finish.await;
            Err(PeerTransportError::PolicyRejected)
        });
        let pin_watcher = tokio::spawn(async {});
        tokio::spawn(supervise_client_connection(requests, driver, pin_watcher));
        let deadline = Instant::now() + Duration::from_secs(5);
        let (reply, mut first) = oneshot::channel();
        assert!(joins.send(JoinRequest { deadline, reply }).await.is_ok());
        // A second caller is answered while the first is still joining.
        let (reply, second) = oneshot::channel();
        assert!(joins.send(JoinRequest { deadline, reply }).await.is_ok());
        assert!(matches!(
            timeout(Duration::from_secs(5), second).await,
            Ok(Ok(Ok(())))
        ));
        assert!(first.try_recv().is_err());

        // The first caller, and only it, gets the driver's own result.
        finish_driver.send(()).unwrap();
        assert!(matches!(
            timeout(Duration::from_secs(5), first).await,
            Ok(Ok(Err(PeerTransportError::PolicyRejected)))
        ));
        let (reply, third) = oneshot::channel();
        assert!(joins.send(JoinRequest { deadline, reply }).await.is_ok());
        assert!(matches!(
            timeout(Duration::from_secs(5), third).await,
            Ok(Ok(Ok(())))
        ));
    }

    #[tokio::test]
    async fn connection_supervisor_aborts_unjoined_tasks_when_the_connection_is_dropped() {
        let (joins, requests) = mpsc::channel::<JoinRequest>(CONNECTION_JOIN_QUEUE);
        let (driver_alive, driver_gone) = oneshot::channel::<()>();
        let (watcher_alive, watcher_gone) = oneshot::channel::<()>();
        let driver = tokio::spawn(async move {
            let _alive = driver_alive;
            std::future::pending::<Result<(), PeerTransportError>>().await
        });
        let pin_watcher = tokio::spawn(async move {
            let _alive = watcher_alive;
            std::future::pending::<()>().await
        });
        tokio::spawn(supervise_client_connection(requests, driver, pin_watcher));

        drop(joins);
        assert!(matches!(
            timeout(Duration::from_secs(5), driver_gone).await,
            Ok(Err(_))
        ));
        assert!(matches!(
            timeout(Duration::from_secs(5), watcher_gone).await,
            Ok(Err(_))
        ));
    }

    #[tokio::test]
    async fn peer_shutdown_uses_one_shared_drain_deadline() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });
        let started = Instant::now();
        let mut first_error = None;
        let _ = drain_peer_tasks(
            &mut tasks,
            started + Duration::from_millis(25),
            true,
            &mut first_error,
            "test-drain",
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(tasks.is_empty());
        assert!(first_error.is_none());
    }

    #[test]
    fn planned_admission_gate_preserves_preboundary_and_rejects_postboundary() {
        let planned = PlannedDrainSignal::new();
        let preadmitted = planned.begin_admission();
        planned.close_admission();

        assert!(preadmitted);
        assert!(!planned.begin_admission());
    }

    #[test]
    fn planned_drain_phase_transition_table() {
        use PlannedDrainEvent::{BeginDrain, CloseAdmission};
        use PlannedDrainPhase::{AdmissionClosed, Draining, Serving};
        let deadline = Instant::now() + Duration::from_secs(30);
        let later = deadline + Duration::from_secs(1);
        assert_eq!(Serving.on_event(CloseAdmission), Ok(AdmissionClosed));
        assert_eq!(
            AdmissionClosed.on_event(BeginDrain(deadline)),
            Ok(Draining(deadline))
        );
        // The drain cannot begin before admission is closed, admission
        // cannot close twice, and a begun drain keeps its deadline.
        for (phase, event) in [
            (Serving, BeginDrain(deadline)),
            (AdmissionClosed, CloseAdmission),
            (Draining(deadline), CloseAdmission),
            (Draining(deadline), BeginDrain(later)),
        ] {
            assert_eq!(phase.on_event(event), Err(IllegalPlannedDrainEvent));
        }
    }

    #[tokio::test]
    async fn planned_drain_signal_publishes_the_deadline_with_the_drain() {
        let planned = PlannedDrainSignal::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        assert_eq!(planned.draining_deadline(), None);
        assert_eq!(
            planned.on_event(PlannedDrainEvent::BeginDrain(deadline)),
            Err(IllegalPlannedDrainEvent)
        );
        assert!(planned.begin_admission() && !planned.is_draining());

        let observer = planned.clone();
        let observed = tokio::spawn(async move {
            observer.draining().await;
            observer.draining_deadline()
        });
        planned.close_admission();
        assert!(planned.admission_closed() && !planned.is_draining());
        planned.begin_drain(deadline);
        // Whoever observes the drain reads its deadline with it.
        assert_eq!(observed.await.unwrap(), Some(deadline));
        planned.begin_drain(deadline + Duration::from_secs(1));
        assert_eq!(planned.draining_deadline(), Some(deadline));
    }

    #[test]
    fn client_connection_phase_transition_table() {
        use ClientConnectionEvent::{IdentityRetired, RemoteGoAway, Shutdown};
        use ClientConnectionPhase::{Closed, Live};
        let closed = |cause, remote_goaway| Closed {
            cause,
            remote_goaway,
        };
        let goaway = ClientConnectionPhase::RemoteGoAway;
        let shutdown = LocalCloseCause::Shutdown;
        let retired = LocalCloseCause::IdentityRetired;
        for (phase, event, next) in [
            (Live, RemoteGoAway, Some(goaway)),
            (Live, Shutdown, Some(closed(shutdown, false))),
            (Live, IdentityRetired, Some(closed(retired, false))),
            (goaway, RemoteGoAway, None),
            (goaway, Shutdown, Some(closed(shutdown, true))),
            (goaway, IdentityRetired, Some(closed(retired, true))),
            (
                closed(shutdown, false),
                RemoteGoAway,
                Some(closed(shutdown, true)),
            ),
            (closed(shutdown, true), RemoteGoAway, None),
            (closed(shutdown, false), Shutdown, None),
            (
                closed(shutdown, true),
                IdentityRetired,
                Some(closed(retired, true)),
            ),
            (
                closed(retired, false),
                RemoteGoAway,
                Some(closed(retired, true)),
            ),
            // A shutdown never demotes a retirement, and nothing reopens.
            (closed(retired, false), Shutdown, None),
            (closed(retired, true), IdentityRetired, None),
        ] {
            assert_eq!(phase.on_event(event), next, "{phase:?} + {event:?}");
        }
        assert!(!Live.remote_goaway() && !Live.identity_retired());
        assert!(goaway.remote_goaway() && !goaway.identity_retired());
        assert!(closed(shutdown, true).remote_goaway());
        assert!(!closed(shutdown, true).identity_retired());
        assert!(closed(retired, false).identity_retired());
        assert!(!closed(retired, false).remote_goaway());

        let published = watch::Sender::new(Live);
        assert!(publish_client_connection_event(&published, RemoteGoAway));
        assert!(!publish_client_connection_event(&published, RemoteGoAway));
        assert!(publish_client_connection_event(&published, IdentityRetired));
        assert_eq!(*published.borrow(), closed(retired, true));
    }

    fn drained(events: &[DrainEvent]) -> PeerConnectionDrain {
        events
            .iter()
            .fold(PeerConnectionDrain::Serving, |state, event| {
                state
                    .on_event(*event)
                    .unwrap_or_else(|_| panic!("{state:?} refused {event:?}"))
            })
    }

    fn report(goaway: bool, streams: bool, close: bool, incomplete: bool) -> DrainReport {
        DrainReport {
            planned_goaway_sent: goaway,
            forced_stream_cancellation: streams,
            forced_connection_close: close,
            drain_join_incomplete: incomplete,
        }
    }

    #[test]
    fn peer_connection_drain_reports_each_route() {
        use DrainEvent as Event;
        use DrainOutcome::{Forced, Incomplete, Joined};
        let planned = [Event::PlannedRequested, Event::GoAwaySent];
        // The planned drain in order: GOAWAY is reported as soon as it is
        // written, and nothing is forced.
        assert_eq!(
            drained(&[Event::PlannedRequested]).report(),
            DrainReport::default()
        );
        assert_eq!(
            drained(&planned).report(),
            report(true, false, false, false)
        );
        let clean = [
            Event::PlannedRequested,
            Event::GoAwaySent,
            Event::H3Complete,
            Event::StreamsReturned,
            Event::TasksJoined(Joined),
        ];
        assert_eq!(drained(&clean).report(), report(true, false, false, false));
        assert_eq!(
            drained(&clean)
                .on_event(Event::PinWatcherAbandoned)
                .unwrap()
                .report(),
            report(true, false, false, true)
        );

        // Cut short: what was forced is reported once the tasks are joined.
        for (cut, joined, expected) in [
            (
                Event::GoAwayFailed,
                Joined,
                report(false, false, false, false),
            ),
            (
                Event::GoAwayFailed,
                Forced,
                report(false, true, true, false),
            ),
            (
                Event::GoAwayDeadline,
                Joined,
                report(false, false, true, false),
            ),
            (
                Event::GoAwayDeadline,
                Incomplete,
                report(false, true, true, true),
            ),
        ] {
            let aborted = drained(&[Event::PlannedRequested, cut]);
            assert_eq!(aborted.report(), DrainReport::default());
            assert_eq!(
                aborted
                    .on_event(Event::TasksJoined(joined))
                    .unwrap()
                    .report(),
                expected,
                "{cut:?} then {joined:?}"
            );
        }
        for (cut, joined, expected) in [
            (Event::H3Failed, Joined, report(true, false, false, false)),
            (Event::Emergency, Joined, report(true, false, false, false)),
            (Event::Emergency, Forced, report(true, true, true, false)),
            (
                Event::Deadline {
                    streams_outstanding: false,
                },
                Joined,
                report(true, false, true, false),
            ),
            (
                Event::Deadline {
                    streams_outstanding: true,
                },
                Joined,
                report(true, true, true, false),
            ),
        ] {
            let aborted = drained(&[Event::PlannedRequested, Event::GoAwaySent, cut]);
            assert_eq!(aborted.report(), report(true, false, false, false));
            assert_eq!(
                aborted
                    .on_event(Event::TasksJoined(joined))
                    .unwrap()
                    .report(),
                expected,
                "{cut:?} then {joined:?}"
            );
        }
        for cut in [
            Event::Emergency,
            Event::Deadline {
                streams_outstanding: false,
            },
        ] {
            let aborted = drained(&[
                Event::PlannedRequested,
                Event::GoAwaySent,
                Event::H3Complete,
                cut,
                Event::TasksJoined(Joined),
            ]);
            assert_eq!(aborted.report(), report(true, true, true, false), "{cut:?}");
        }

        // The emergency ordering reports its cleanup only when the listener
        // had begun a planned drain.
        for (published, joined, abandoned, expected) in [
            (false, Incomplete, true, DrainReport::default()),
            (true, Joined, false, DrainReport::default()),
            (true, Forced, false, report(false, true, true, false)),
            (true, Incomplete, false, report(false, true, true, true)),
            (true, Joined, true, report(false, false, false, true)),
        ] {
            let mut state = drained(&[
                Event::EmergencyRequested {
                    planned_deadline_published: published,
                },
                Event::TasksJoined(joined),
            ]);
            if abandoned {
                state = state.on_event(Event::PinWatcherAbandoned).unwrap();
            }
            assert_eq!(
                state.report(),
                expected,
                "{published} {joined:?} {abandoned}"
            );
        }
    }

    #[test]
    fn peer_connection_drain_refuses_out_of_order_events() {
        use DrainEvent as Event;
        use DrainOutcome::Joined;
        let serving = PeerConnectionDrain::Serving;
        let requested = drained(&[Event::PlannedRequested]);
        let goaway_sent = drained(&[Event::PlannedRequested, Event::GoAwaySent]);
        let h3_complete = drained(&[
            Event::PlannedRequested,
            Event::GoAwaySent,
            Event::H3Complete,
        ]);
        let emergency = drained(&[Event::EmergencyRequested {
            planned_deadline_published: true,
        }]);
        let finished = drained(&[
            Event::EmergencyRequested {
                planned_deadline_published: true,
            },
            Event::TasksJoined(Joined),
        ]);
        for (state, event) in [
            // Nothing drains before serving ends, and serving ends once.
            (serving, Event::GoAwaySent),
            (serving, Event::TasksJoined(Joined)),
            (requested, Event::PlannedRequested),
            // GOAWAY comes before the HTTP/3 boundary, which comes before
            // the streams are joined.
            (requested, Event::H3Complete),
            (requested, Event::StreamsReturned),
            (requested, Event::TasksJoined(Joined)),
            (goaway_sent, Event::GoAwaySent),
            (goaway_sent, Event::StreamsReturned),
            (goaway_sent, Event::TasksJoined(Joined)),
            (h3_complete, Event::H3Complete),
            (h3_complete, Event::H3Failed),
            (h3_complete, Event::TasksJoined(Joined)),
            // The emergency ordering has no planned steps.
            (emergency, Event::GoAwaySent),
            (emergency, Event::PlannedRequested),
            (emergency, Event::PinWatcherAbandoned),
            // A finished connection only records an abandoned pin watcher,
            // and only once.
            (finished, Event::TasksJoined(Joined)),
            (finished, Event::Emergency),
            (
                finished.on_event(Event::PinWatcherAbandoned).unwrap(),
                Event::PinWatcherAbandoned,
            ),
        ] {
            assert_eq!(
                state.on_event(event),
                Err(IllegalDrainEvent),
                "{state:?} + {event:?}"
            );
        }
        assert!(!DrainOutcome::Joined.forced() && !DrainOutcome::Joined.incomplete());
        assert!(DrainOutcome::Forced.forced() && !DrainOutcome::Forced.incomplete());
        assert!(DrainOutcome::Incomplete.forced() && DrainOutcome::Incomplete.incomplete());
    }
}
