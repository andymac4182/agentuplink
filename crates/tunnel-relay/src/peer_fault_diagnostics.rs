//! Bounded peer stage and cause tuples published through relay dispatch.
//!
//! Every peer fault the relay observes while dispatching a consumer request
//! to a remote owner, or while serving one as the owner, is reduced to a
//! closed `(role, stage, cause)` tuple plus the bounded identifiers needed to
//! correlate it with the owner's session: tenant, device, session, owner
//! epoch, owner node, service and request identifiers.  Transport error text,
//! peer payloads, bearer tokens, endpoints and filesystem paths never cross
//! this boundary.  The state keeps saturating counters, the latest event per
//! stage and a short ring of recent events so a fault survives the owner's
//! own state removal.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use serde::Serialize;
use tunnel_catalog::OwnerToken;
use tunnel_transport::PeerTransportError;
use uuid::Uuid;

use crate::{
    peer_runtime::{PeerOpenDiagnostic, PeerOpenDiagnosticStage, PeerRuntimeError},
    peer_transport_diagnostics::cells::{
        Arena, Entry, Ledger, Order, Place, WordReader, WordWriter, bump, code_of, variant,
    },
};

/// Maximum number of recent tuples retained in the ring.
pub const MAX_RECENT_PEER_FAULTS: usize = 32;

/// Maximum number of task closure records retained in the ring.
pub const MAX_TASK_CLOSURES: usize = 32;

/// Which relay task body reached its ordinary lifecycle end.
///
/// This is a lifecycle position, not a fault: the peer fault vocabulary above
/// names peer ingress and owner-side *failures*, and an ordinary socket close
/// is neither.  Keeping the two vocabularies apart is what stops a routine
/// close from inflating `fault_count` or a per-stage fault latch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClosureStage {
    /// The owner-local device control socket task.
    Control,
    /// The owner-local device data carrier task.
    Data,
    /// The public consumer stream adapter task.
    ConsumerStream,
}

impl TaskClosureStage {
    /// Every stage, for the closure counters and for decoding a tuple.
    pub const ALL: [Self; 3] = [Self::Control, Self::Data, Self::ConsumerStream];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
            Self::ConsumerStream => "consumer_stream",
        }
    }
}

/// Closed, payload-free causes for one task closure.
///
/// Every variant is a structural property of the socket loop's exit.  None is
/// derived from a request body, header, ticket, endpoint or error text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClosureCause {
    /// The remote endpoint closed, ended or errored its half of the socket.
    PeerClosed,
    /// A relay-to-peer write did not complete.
    WriteFailed,
    /// A bounded codec rejected an inbound frame.
    ProtocolError,
    /// An inbound frame exceeded this socket's bounded input window.
    RecordTooLarge,
    /// A message kind this socket does not serve arrived.
    UnexpectedMessage,
    /// The relay actor closed the socket, or its outbound channel ended.
    ServerClose,
    /// The owner closed the consumer stream under the adapter.
    StreamClosed,
    /// The absolute consumer authorization deadline elapsed.
    Expired,
    /// A stream write returned a typed failure or an unusable response frame.
    StreamFailed,
    /// Task row M6-C68: the device sent no frame of any kind -- not even the
    /// Pong owed to the relay's Ping -- for the device control idle timeout,
    /// so its path is presumed gone and the session is released.
    LivenessTimeout,
}

impl TaskClosureCause {
    /// Every cause, for the closure counters and for decoding a tuple.
    pub const ALL: [Self; 10] = [
        Self::PeerClosed,
        Self::WriteFailed,
        Self::ProtocolError,
        Self::RecordTooLarge,
        Self::UnexpectedMessage,
        Self::ServerClose,
        Self::StreamClosed,
        Self::Expired,
        Self::StreamFailed,
        Self::LivenessTimeout,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerClosed => "peer_closed",
            Self::WriteFailed => "write_failed",
            Self::ProtocolError => "protocol_error",
            Self::RecordTooLarge => "record_too_large",
            Self::UnexpectedMessage => "unexpected_message",
            Self::ServerClose => "server_close",
            Self::StreamClosed => "stream_closed",
            Self::Expired => "expired",
            Self::StreamFailed => "stream_failed",
            Self::LivenessTimeout => "liveness_timeout",
        }
    }
}

/// Bounded correlation identifiers for one task closure.
///
/// The fields are the same owner-registration identifiers
/// [`crate::runtime::OwnerUnregisterEvent`] carries, so a closure record and
/// the tombstone for the state it refers to can be matched without any
/// request-derived content passing through.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskClosureScope {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    /// Present only for the consumer adapter, whose unregistered owner state
    /// is one stream inside the session rather than the session itself.
    pub stream_id: Option<u64>,
}

/// One bounded task closure tuple with its correlation identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskClosureEventSnapshot {
    /// Position on the shared diagnostic clock, drawn from the same counter
    /// as peer fault tuples and owner unregister stamps.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    pub observed_at_ms: u64,
    pub stage: TaskClosureStage,
    pub cause: TaskClosureCause,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: Option<u64>,
}

/// The relay-local side that observed the peer fault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerFaultRole {
    /// The public ingress relay dispatching to a remote owner.
    Ingress,
    /// The owner relay serving a forwarded peer request.
    Owner,
}

impl PeerFaultRole {
    /// In the order of the fault cells.
    const ALL: [Self; 2] = [Self::Ingress, Self::Owner];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Owner => "owner",
        }
    }
}

/// Closed, payload-free causes for one peer fault.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerFaultCause {
    /// No live owner claim exists for the scope.
    NoLiveOwner,
    /// The owner catalog could not be read.
    Catalog,
    /// Membership, checkpoint, lease or scope evidence did not authorize the
    /// request.
    Membership,
    /// The signed peer endpoint is not usable.
    InvalidEndpoint,
    /// The peer certificate or envelope identity did not match.
    IdentityMismatch,
    /// The peer transport deadline elapsed.
    TransportTimeout,
    /// The owner announced a planned drain.
    #[serde(rename = "transport_goaway")]
    TransportGoAway,
    /// The transport attempt was cancelled.
    TransportCancelled,
    /// An HTTP/3 error terminated the attempt.
    TransportH3,
    /// A QUIC error terminated the attempt.
    TransportQuic,
    /// The transport pool or permit budget was exhausted.
    TransportCapacity,
    /// This relay publishes no approved peer trust evidence, so no peer could
    /// be dialled.  Nothing was written to any owner.
    TransportPinsUnavailable,
    /// A bounded body or chunk limit was exceeded.
    TransportBodyLimit,
    /// Any other typed transport failure.
    TransportOther,
    /// The bounded envelope codec rejected the request.
    Envelope,
    /// The bounded record codec rejected a message.
    Frame,
    /// The owner rejected the request as unauthorized.
    RemoteUnauthorized,
    /// The owner rejected the request as forbidden.
    RemoteForbidden,
    /// The owner rejected the request with another bounded status.
    RemoteStatus,
    /// The internal route has no private endpoint.
    InvalidRoute,
    /// The first record was not the expected control record.
    UnexpectedRecord,
    /// The owner is committed but not ready.
    OwnerNotReady,
    /// The owner held the request across a scheduled data-rotation freeze
    /// and the freeze outlasted the bound, or the hold was full (M3-15).
    RotationFreeze,
    /// The owner's bounded stream limit is full.
    Capacity,
    /// The peer does not hold the owner token the request named (M7-C110).
    OwnerChanged,
    /// The peer membership admission expired.
    MembershipExpired,
    /// The peer stream was already closed.
    Closed,
    /// The relay's own operation deadline elapsed around the attempt.
    Deadline,
}

impl PeerFaultCause {
    /// Every cause, for tables that must enumerate the closed vocabulary.
    ///
    /// The C11 capture scanner keeps its own copy of these labels and refuses
    /// any snapshot carrying one outside it, so the two lists must not drift:
    /// `harness_peer_fault_causes_match_the_relay_vocabulary` in
    /// `tunnel-test-harness` compares them, and the exhaustive match in
    /// `every_cause_is_enumerated` below fails to compile if a variant is
    /// added without being listed here.
    pub const ALL: [Self; 28] = [
        Self::NoLiveOwner,
        Self::Catalog,
        Self::Membership,
        Self::InvalidEndpoint,
        Self::IdentityMismatch,
        Self::TransportTimeout,
        Self::TransportGoAway,
        Self::TransportCancelled,
        Self::TransportH3,
        Self::TransportQuic,
        Self::TransportCapacity,
        Self::TransportPinsUnavailable,
        Self::TransportBodyLimit,
        Self::TransportOther,
        Self::Envelope,
        Self::Frame,
        Self::RemoteUnauthorized,
        Self::RemoteForbidden,
        Self::RemoteStatus,
        Self::InvalidRoute,
        Self::UnexpectedRecord,
        Self::OwnerNotReady,
        Self::RotationFreeze,
        Self::Capacity,
        Self::OwnerChanged,
        Self::MembershipExpired,
        Self::Closed,
        Self::Deadline,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLiveOwner => "no_live_owner",
            Self::Catalog => "catalog",
            Self::Membership => "membership",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::IdentityMismatch => "identity_mismatch",
            Self::TransportTimeout => "transport_timeout",
            Self::TransportGoAway => "transport_goaway",
            Self::TransportCancelled => "transport_cancelled",
            Self::TransportH3 => "transport_h3",
            Self::TransportQuic => "transport_quic",
            Self::TransportCapacity => "transport_capacity",
            Self::TransportPinsUnavailable => "transport_pins_unavailable",
            Self::TransportBodyLimit => "transport_body_limit",
            Self::TransportOther => "transport_other",
            Self::Envelope => "envelope",
            Self::Frame => "frame",
            Self::RemoteUnauthorized => "remote_unauthorized",
            Self::RemoteForbidden => "remote_forbidden",
            Self::RemoteStatus => "remote_status",
            Self::InvalidRoute => "invalid_route",
            Self::UnexpectedRecord => "unexpected_record",
            Self::OwnerNotReady => "owner_not_ready",
            Self::RotationFreeze => "rotation_freeze",
            Self::Capacity => "capacity",
            Self::OwnerChanged => "owner_changed",
            Self::MembershipExpired => "membership_expired",
            Self::Closed => "closed",
            Self::Deadline => "deadline",
        }
    }

    /// Classify a typed runtime error without retaining any of its text.
    #[must_use]
    pub fn from_error(error: &PeerRuntimeError) -> Self {
        match error {
            PeerRuntimeError::Routing(crate::routing::OwnerRoutingError::NoLiveOwner(_)) => {
                Self::NoLiveOwner
            }
            PeerRuntimeError::Routing(_) => Self::Catalog,
            PeerRuntimeError::Membership(_) => Self::Membership,
            PeerRuntimeError::InvalidEndpoint(_) => Self::InvalidEndpoint,
            PeerRuntimeError::PeerIdentityMismatch => Self::IdentityMismatch,
            PeerRuntimeError::Transport(error) => match error {
                PeerTransportError::Timeout => Self::TransportTimeout,
                PeerTransportError::GoAway => Self::TransportGoAway,
                PeerTransportError::Cancelled => Self::TransportCancelled,
                PeerTransportError::H3(_) => Self::TransportH3,
                PeerTransportError::Quic(_) => Self::TransportQuic,
                PeerTransportError::Capacity => Self::TransportCapacity,
                PeerTransportError::PinsUnavailable => Self::TransportPinsUnavailable,
                PeerTransportError::ChunkTooLarge { .. }
                | PeerTransportError::BodyTooLarge { .. } => Self::TransportBodyLimit,
                _ => Self::TransportOther,
            },
            PeerRuntimeError::Envelope(_) => Self::Envelope,
            PeerRuntimeError::Frame(_) => Self::Frame,
            PeerRuntimeError::RemoteStatus(status)
                if *status == axum::http::StatusCode::UNAUTHORIZED =>
            {
                Self::RemoteUnauthorized
            }
            PeerRuntimeError::RemoteStatus(status)
                if *status == axum::http::StatusCode::FORBIDDEN =>
            {
                Self::RemoteForbidden
            }
            PeerRuntimeError::RemoteStatus(_) => Self::RemoteStatus,
            PeerRuntimeError::InvalidRoute(_) => Self::InvalidRoute,
            PeerRuntimeError::UnexpectedRecord(_) => Self::UnexpectedRecord,
            PeerRuntimeError::OwnerNotReady { .. } => Self::OwnerNotReady,
            PeerRuntimeError::RotationFreeze { .. } => Self::RotationFreeze,
            PeerRuntimeError::Capacity { .. } => Self::Capacity,
            PeerRuntimeError::OwnerChanged { .. } => Self::OwnerChanged,
            PeerRuntimeError::MembershipExpired => Self::MembershipExpired,
            PeerRuntimeError::Closed => Self::Closed,
        }
    }

    /// Whether this cause is the owner's own admission decision rather than a
    /// transport or ingress-local failure.
    #[must_use]
    pub const fn is_owner_decision(self) -> bool {
        matches!(
            self,
            Self::RemoteUnauthorized
                | Self::RemoteForbidden
                | Self::RemoteStatus
                | Self::OwnerNotReady
                | Self::RotationFreeze
                | Self::Capacity
                | Self::OwnerChanged
        )
    }
}

/// Bounded correlation identifiers for one peer fault.
///
/// Every field is an identifier or counter; none is derived from a request
/// body, bearer token, endpoint or path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerFaultContext {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: Option<String>,
    pub owner_epoch: Option<u64>,
    pub owner_node_id: Option<String>,
    pub service_id: Option<Uuid>,
    pub request_id: Option<String>,
}

impl PeerFaultContext {
    /// Context for a fault observed before any owner was selected.
    #[must_use]
    pub fn unrouted(tenant_id: Uuid, device_id: Uuid, service_id: Option<Uuid>) -> Self {
        Self {
            tenant_id,
            device_id,
            session_id: None,
            owner_epoch: None,
            owner_node_id: None,
            service_id,
            request_id: None,
        }
    }

    /// Context for a fault against a selected owner token.
    #[must_use]
    pub fn for_owner(
        owner: &OwnerToken,
        service_id: Option<Uuid>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            tenant_id: owner.tenant_id,
            device_id: owner.device_id,
            session_id: Some(owner.session_id.clone()),
            owner_epoch: Some(owner.epoch),
            owner_node_id: Some(owner.node_id.clone()),
            service_id,
            request_id,
        }
    }
}

/// One bounded peer fault tuple with its correlation identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerFaultEventSnapshot {
    /// Saturating process-local sequence number.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    pub observed_at_ms: u64,
    pub role: PeerFaultRole,
    pub stage: PeerOpenDiagnosticStage,
    pub cause: PeerFaultCause,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: Option<String>,
    pub owner_epoch: Option<u64>,
    pub owner_node_id: Option<String>,
    pub service_id: Option<Uuid>,
    pub request_id: Option<String>,
}

/// One payload-free position on the peer fault diagnostic clock.
///
/// A stamp carries a sequence number and a monotonic millisecond reading and
/// nothing else: no request, route, body, status or peer identity.  It is
/// drawn from the *same* counter and the same process origin that
/// [`PeerFaultDiagnostics::record`] uses for a fault tuple, so a stamp and a
/// tuple can be totally ordered against each other.  This is what makes the
/// EC-061 ordering clause observable from outside: the relay stamps the
/// unregister of the owner state a fault tuple refers to, and
/// `fault.sequence < unregister.sequence` proves the tuple was recorded
/// first rather than merely coexisting with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticStamp {
    /// Saturating process-local sequence number, shared with fault tuples.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    pub at_ms: u64,
}

/// Redacted peer fault tuples retained by the typed relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerFaultDiagnosticSnapshot {
    /// Total faults observed by this relay in either role.
    pub fault_count: u64,
    /// Faults observed while this relay was the public ingress.
    pub ingress_count: u64,
    /// Faults observed while this relay was the selected owner.
    pub owner_count: u64,
    /// Saturating count per stage label.
    pub stage_counts: BTreeMap<&'static str, u64>,
    /// Saturating count per cause label.
    pub cause_counts: BTreeMap<&'static str, u64>,
    /// Latest tuple per stage label.
    pub last_by_stage: BTreeMap<&'static str, PeerFaultEventSnapshot>,
    /// The most recent tuples, oldest first, bounded by
    /// [`MAX_RECENT_PEER_FAULTS`].
    pub recent: Vec<PeerFaultEventSnapshot>,
    /// Saturating count per task closure stage label.
    pub closure_stage_counts: BTreeMap<&'static str, u64>,
    /// Saturating count per task closure cause label.
    pub closure_cause_counts: BTreeMap<&'static str, u64>,
    /// The most recent task closure tuples, oldest first, bounded by
    /// [`MAX_TASK_CLOSURES`].  These are lifecycle ends, not faults: they are
    /// kept in their own ring so a routine close never appears in
    /// `fault_count`, `cause_counts`, `last_by_stage` or `recent`.
    pub closures: Vec<TaskClosureEventSnapshot>,
    /// True only when this snapshot could not be taken because too many
    /// reads of these diagnostics were in progress at once.  Every other
    /// field is then a placeholder and not an observation: the counts are
    /// unknown, not zero.  Absent from the serialized snapshot otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

/// The cap on this diagnostic's storage: 2^17 blocks of 88 bytes, 11.5 MB.
/// About five hundred blocks are retained; the rest is head-room for
/// recorders in flight and for blocks parked behind a reader.  At the cap a
/// fault or closure is refused and counted, never half-recorded.
const BLOCKS: usize = 1 << 17;

const ROLES: usize = PeerFaultRole::ALL.len();
const STAGES: usize = PeerOpenDiagnosticStage::ALL.len();
const CAUSES: usize = PeerFaultCause::ALL.len();
const CLOSURE_STAGES: usize = TaskClosureStage::ALL.len();
const CLOSURE_CAUSES: usize = TaskClosureCause::ALL.len();

/// The ledger group holding the recent ring, and the group holding each
/// stage's latest tuple at the stage's position.
const RECENT: usize = 0;
const LATEST: usize = 1;

/// The shared diagnostic clock and the two ledgers.
///
/// A fault is counted once, in the `(role, stage, cause)` cell of the fault
/// ledger; a closure once, in the `(stage, cause)` cell of the closure
/// ledger.  Every total and breakdown a snapshot reports is a sum over one
/// read of those cells, so the breakdowns agree with the total and with
/// each other in every snapshot, and the retained tuples come from the same
/// state as the cells that count them.
struct PeerFaultDiagnosticState {
    arena: Arena,
    sequence: AtomicU64,
    faults: Ledger,
    closures: Ledger,
}

impl Default for PeerFaultDiagnosticState {
    fn default() -> Self {
        Self::with_blocks(BLOCKS)
    }
}

impl PeerFaultDiagnosticState {
    fn with_blocks(blocks: usize) -> Self {
        Self {
            arena: Arena::new(blocks),
            sequence: AtomicU64::new(0),
            faults: Ledger::new(ROLES * STAGES * CAUSES, &[MAX_RECENT_PEER_FAULTS, STAGES]),
            closures: Ledger::new(CLOSURE_STAGES * CLOSURE_CAUSES, &[MAX_TASK_CLOSURES]),
        }
    }
}

fn index(code: u64) -> usize {
    usize::try_from(code).unwrap_or(usize::MAX)
}

fn encode_fault(event: &PeerFaultEventSnapshot) -> WordWriter {
    let mut record = WordWriter::new();
    record.u64(event.observed_at_ms);
    record.u64(code_of(&PeerFaultRole::ALL, &event.role));
    record.u64(code_of(&PeerOpenDiagnosticStage::ALL, &event.stage));
    record.u64(code_of(&PeerFaultCause::ALL, &event.cause));
    record.uuid(event.tenant_id);
    record.uuid(event.device_id);
    record.opt_text(event.session_id.as_deref());
    record.opt_u64(event.owner_epoch);
    record.opt_text(event.owner_node_id.as_deref());
    record.opt_uuid(event.service_id);
    record.opt_text(event.request_id.as_deref());
    record
}

fn decode_fault(sequence: u64, mut record: WordReader) -> Option<PeerFaultEventSnapshot> {
    Some(PeerFaultEventSnapshot {
        sequence,
        observed_at_ms: record.u64()?,
        role: variant(&PeerFaultRole::ALL, record.u64()?)?,
        stage: variant(&PeerOpenDiagnosticStage::ALL, record.u64()?)?,
        cause: variant(&PeerFaultCause::ALL, record.u64()?)?,
        tenant_id: record.uuid()?,
        device_id: record.uuid()?,
        session_id: record.opt_text()?,
        owner_epoch: record.opt_u64()?,
        owner_node_id: record.opt_text()?,
        service_id: record.opt_uuid()?,
        request_id: record.opt_text()?,
    })
}

fn decode_closure(sequence: u64, mut record: WordReader) -> Option<TaskClosureEventSnapshot> {
    Some(TaskClosureEventSnapshot {
        sequence,
        observed_at_ms: record.u64()?,
        stage: variant(&TaskClosureStage::ALL, record.u64()?)?,
        cause: variant(&TaskClosureCause::ALL, record.u64()?)?,
        tenant_id: record.uuid()?,
        device_id: record.uuid()?,
        session_id: record.text()?,
        epoch: record.u64()?,
        stream_id: record.opt_u64()?,
    })
}

fn add(counts: &mut BTreeMap<&'static str, u64>, label: &'static str, count: u64) {
    let total = counts.entry(label).or_insert(0);
    *total = total.saturating_add(count);
}

/// Cloneable bounded state for peer fault tuples.
#[derive(Clone, Default)]
pub(crate) struct PeerFaultDiagnostics {
    state: Arc<PeerFaultDiagnosticState>,
}

impl PeerFaultDiagnostics {
    /// Record one tuple without retaining any error text.
    ///
    /// The tuple's cell, the stage's latest tuple and the recent ring change
    /// in one atomic step, and that step draws the tuple's sequence (again,
    /// if it loses the race to install), so tuples are installed in sequence
    /// order: the stage keeps the tuple with the highest sequence, the ring
    /// keeps the highest sequences, and the tuple is in both when this
    /// returns.  The step costs the tree nodes on the paths to the four
    /// words it changes (8 to 10 blocks) plus the tuple encoded twice, for
    /// the ring and for the stage (4 or 5 blocks each), whatever the size
    /// of the cell matrix.
    pub(crate) fn record(
        &self,
        context: &PeerFaultContext,
        role: PeerFaultRole,
        stage: PeerOpenDiagnosticStage,
        cause: PeerFaultCause,
    ) {
        let state = &*self.state;
        let event = PeerFaultEventSnapshot {
            // Assigned by the commit that installs the tuple.
            sequence: 0,
            observed_at_ms: diagnostic_now_ms(),
            role,
            stage,
            cause,
            tenant_id: context.tenant_id,
            device_id: context.device_id,
            session_id: context.session_id.clone(),
            owner_epoch: context.owner_epoch,
            owner_node_id: context.owner_node_id.clone(),
            service_id: context.service_id,
            request_id: context.request_id.clone(),
        };
        let role = index(code_of(&PeerFaultRole::ALL, &role));
        let stage = code_of(&PeerOpenDiagnosticStage::ALL, &stage);
        let cause = index(code_of(&PeerFaultCause::ALL, &cause));
        let cell = role
            .saturating_mul(STAGES)
            .saturating_add(index(stage))
            .saturating_mul(CAUSES)
            .saturating_add(cause);
        state.faults.commit(
            &state.arena,
            Some(&state.sequence),
            &[cell],
            vec![
                Entry {
                    place: Place::Push(RECENT),
                    order: Order::Sequence,
                    record: encode_fault(&event),
                },
                Entry {
                    place: Place::Key(LATEST, index(stage)),
                    order: Order::Sequence,
                    record: encode_fault(&event),
                },
            ],
        );
    }

    /// Record one bounded task closure tuple and return its position on the
    /// shared diagnostic clock.
    ///
    /// EC-061 requires every closure to report a bounded lifecycle stage and
    /// cause *before* the owner state it refers to is unregistered.  A task
    /// meets that by calling this, and letting it return, before it stamps
    /// and unregisters.
    ///
    /// The sequence is drawn by the atomic step that installs the tuple
    /// (and drawn again if that step loses the race to install), so
    /// closures enter the ring in sequence order and the ring holds the
    /// [`MAX_TASK_CLOSURES`] highest sequences.  The tuple is therefore in
    /// the ring when this returns, and stays until that many later closures
    /// have displaced it.  The one exception is diagnostic storage at its
    /// cap, in which case neither the tuple nor its count is recorded,
    /// the drop is counted (`diagnostic_records_dropped` in the HTTP
    /// forward snapshot), and the stamp returned is still a fresh position
    /// on the clock.
    ///
    /// The sequence comes from the same atomic counter that
    /// [`Self::record`] and [`Self::stamp`] use, so a closure tuple and an
    /// owner unregister tombstone are totally ordered against each other by
    /// the identical predicate.  `closure.sequence < unregister.sequence`
    /// proves exactly that the tuple's installing step drew its position
    /// before the unregister's stamp drew its own.  When both are drawn by
    /// one task in program order, as the closing task does, the tuple is in
    /// the ring before the stamp is drawn; between two tasks racing each
    /// other it orders the two draws and nothing later.
    ///
    /// A closure is not a fault.  It touches only the closure ring and the
    /// closure counters; `fault_count`, `cause_counts`, `last_by_stage` and
    /// `recent` keep their existing shape and meaning, so an ordinary
    /// lifecycle end can never be misread as a peer fault.  The call takes
    /// no session state and performs no I/O, so it cannot change when the
    /// close it attributes actually lands.
    pub(crate) fn record_closure(
        &self,
        scope: &TaskClosureScope,
        stage: TaskClosureStage,
        cause: TaskClosureCause,
    ) -> DiagnosticStamp {
        let state = &*self.state;
        let at_ms = diagnostic_now_ms();
        let stage = code_of(&TaskClosureStage::ALL, &stage);
        let cause = code_of(&TaskClosureCause::ALL, &cause);
        let mut record = WordWriter::new();
        record.u64(at_ms);
        record.u64(stage);
        record.u64(cause);
        record.uuid(scope.tenant_id);
        record.uuid(scope.device_id);
        record.text(&scope.session_id);
        record.u64(scope.epoch);
        record.opt_u64(scope.stream_id);
        let cell = index(stage)
            .saturating_mul(CLOSURE_CAUSES)
            .saturating_add(index(cause));
        let committed = state.closures.commit(
            &state.arena,
            Some(&state.sequence),
            &[cell],
            vec![Entry {
                place: Place::Push(RECENT),
                order: Order::Sequence,
                record,
            }],
        );
        DiagnosticStamp {
            sequence: committed.map_or_else(|| bump(&state.sequence), |done| done.sequence),
            at_ms,
        }
    }

    /// Draw the next position on this relay's diagnostic clock without
    /// recording a fault.
    ///
    /// The sequence comes from the same atomic counter as [`Self::record`],
    /// so a stamp is drawn after every tuple that holds a lower sequence
    /// drew its own.  The caller stamps the moment *before* it unregisters
    /// owner state, having already recorded what it had to record, so a
    /// tuple of its own with a lower sequence was recorded first.  A stamp
    /// retains nothing and is not itself a fault: no counter, ring or
    /// per-stage latch is touched.
    #[must_use]
    pub(crate) fn stamp(&self) -> DiagnosticStamp {
        DiagnosticStamp {
            sequence: bump(&self.state.sequence),
            at_ms: diagnostic_now_ms(),
        }
    }

    /// Call `hook` at each step of every later record, to park a recorder
    /// between its steps.
    #[cfg(test)]
    fn park_recorders(&self, hook: Arc<dyn Fn(&'static str) + Send + Sync>) {
        let faults = Arc::clone(&hook);
        self.state
            .faults
            .park_commits(Box::new(move |step| faults(step)));
        self.state
            .closures
            .park_commits(Box::new(move |step| hook(step)));
    }

    /// Diagnostics with a storage cap other than the relay's.
    #[cfg(test)]
    fn with_blocks(blocks: usize) -> Self {
        Self {
            state: Arc::new(PeerFaultDiagnosticState::with_blocks(blocks)),
        }
    }

    /// Passes snapshots have made over the fault and closure states.
    #[cfg(test)]
    fn read_passes(&self) -> u64 {
        self.state.faults.read_passes() + self.state.closures.read_passes()
    }

    /// Return the bounded typed view used by the relay snapshot.
    ///
    /// Faults and closures are two states read one after the other; nothing
    /// a snapshot reports relates one to the other.  Each is read in one
    /// pass that no recorder can force to repeat, so a snapshot's work is
    /// bounded by the size of the two states, plus two bounded batches of
    /// reclamation, however many faults are being recorded meanwhile.  If
    /// too many reads are already in progress the snapshot says it is
    /// unavailable instead of reporting counts it did not read.
    #[must_use]
    pub(crate) fn snapshot(&self) -> PeerFaultDiagnosticSnapshot {
        let state = &*self.state;
        let (Some(faults), Some(closures)) = (
            state.faults.read(&state.arena),
            state.closures.read(&state.arena),
        ) else {
            return PeerFaultDiagnosticSnapshot {
                unavailable: true,
                ..PeerFaultDiagnosticSnapshot::default()
            };
        };
        let mut snapshot = PeerFaultDiagnosticSnapshot::default();
        let cells = PeerFaultRole::ALL.iter().flat_map(|role| {
            PeerOpenDiagnosticStage::ALL.iter().flat_map(move |stage| {
                PeerFaultCause::ALL
                    .iter()
                    .map(move |cause| (*role, *stage, *cause))
            })
        });
        for ((role, stage, cause), count) in cells.zip(&faults.counts) {
            if *count == 0 {
                continue;
            }
            snapshot.fault_count = snapshot.fault_count.saturating_add(*count);
            let by_role = match role {
                PeerFaultRole::Ingress => &mut snapshot.ingress_count,
                PeerFaultRole::Owner => &mut snapshot.owner_count,
            };
            *by_role = by_role.saturating_add(*count);
            add(&mut snapshot.stage_counts, stage.as_str(), *count);
            add(&mut snapshot.cause_counts, cause.as_str(), *count);
        }
        for retained in faults.retained {
            let Some(event) = decode_fault(retained.order, retained.record) else {
                continue;
            };
            if retained.group == RECENT {
                snapshot.recent.push(event);
            } else {
                snapshot.last_by_stage.insert(event.stage.as_str(), event);
            }
        }
        let cells = TaskClosureStage::ALL.iter().flat_map(|stage| {
            TaskClosureCause::ALL
                .iter()
                .map(move |cause| (*stage, *cause))
        });
        for ((stage, cause), count) in cells.zip(&closures.counts) {
            if *count == 0 {
                continue;
            }
            add(&mut snapshot.closure_stage_counts, stage.as_str(), *count);
            add(&mut snapshot.closure_cause_counts, cause.as_str(), *count);
        }
        snapshot.closures = closures
            .retained
            .into_iter()
            .filter_map(|retained| decode_closure(retained.order, retained.record))
            .collect();
        snapshot
    }
}

/// A per-request observer that tracks the current peer stage and records at
/// most one fault tuple for that request.
///
/// It wraps the transport-aware [`PeerOpenDiagnostic`] so the stage reached
/// inside pooled HTTP/3 admission is reported exactly, and extends it with
/// the head, body, lease and owner stages the dispatch and owner paths mark
/// themselves.  Recording is idempotent: a fault classified deep inside a
/// handler is not overwritten by the outer error mapping.
pub struct PeerFaultObserver {
    diagnostic: PeerOpenDiagnostic,
    context: PeerFaultContext,
    role: PeerFaultRole,
    recorded: AtomicBool,
}

impl PeerFaultObserver {
    #[must_use]
    pub fn new(role: PeerFaultRole, context: PeerFaultContext) -> Self {
        Self {
            diagnostic: PeerOpenDiagnostic::new(),
            context,
            role,
            recorded: AtomicBool::new(false),
        }
    }

    /// The transport-aware open observer for this request.
    #[must_use]
    pub fn diagnostic(&self) -> &PeerOpenDiagnostic {
        &self.diagnostic
    }

    /// Replace the correlation context once an owner has been selected.
    pub fn set_context(&mut self, context: PeerFaultContext) {
        self.context = context;
    }

    #[must_use]
    pub fn context(&self) -> &PeerFaultContext {
        &self.context
    }

    /// Mark the stage this request has reached.
    pub fn mark(&self, stage: PeerOpenDiagnosticStage) {
        self.diagnostic.mark(stage);
    }

    /// The last stage reached by this request.
    #[must_use]
    pub fn stage(&self) -> PeerOpenDiagnosticStage {
        self.diagnostic.stage()
    }

    /// Whether a tuple has already been recorded for this request.
    #[must_use]
    pub fn recorded(&self) -> bool {
        self.recorded.load(Ordering::Acquire)
    }

    /// Record the tuple for a typed error at the current stage, once.
    ///
    /// An owner admission decision observed while the ingress was waiting for
    /// the response head is attributed to the `owner` stage: the transport
    /// completed and the owner itself refused the request.
    pub(crate) fn record_error(
        &self,
        diagnostics: &PeerFaultDiagnostics,
        error: &PeerRuntimeError,
    ) {
        let cause = PeerFaultCause::from_error(error);
        let stage = match self.stage() {
            PeerOpenDiagnosticStage::Head if cause.is_owner_decision() => {
                PeerOpenDiagnosticStage::Owner
            }
            stage => stage,
        };
        self.record_tuple(diagnostics, stage, cause);
    }

    /// Record an explicit tuple at a caller-selected stage, once.
    pub(crate) fn record_tuple(
        &self,
        diagnostics: &PeerFaultDiagnostics,
        stage: PeerOpenDiagnosticStage,
        cause: PeerFaultCause,
    ) {
        if self
            .recorded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        diagnostics.record(&self.context, self.role, stage, cause);
    }
}

static DIAGNOSTIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn diagnostic_now_ms() -> u64 {
    DIAGNOSTIC_ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    /// Adding a `PeerFaultCause` variant must also add it to
    /// [`PeerFaultCause::ALL`] and to the C11 scanner's copy of the
    /// vocabulary in `tunnel-test-harness`; otherwise a relay snapshot
    /// carrying the new cause is rejected as outside the closed vocabulary
    /// and `verify-m7-c11-diagnostics` fails at capture time rather than at
    /// compile time.  The exhaustive match below is the compile-time half.
    #[test]
    fn every_cause_is_enumerated() {
        use super::PeerFaultCause;
        for cause in PeerFaultCause::ALL {
            match cause {
                PeerFaultCause::NoLiveOwner
                | PeerFaultCause::Catalog
                | PeerFaultCause::Membership
                | PeerFaultCause::InvalidEndpoint
                | PeerFaultCause::IdentityMismatch
                | PeerFaultCause::TransportTimeout
                | PeerFaultCause::TransportGoAway
                | PeerFaultCause::TransportCancelled
                | PeerFaultCause::TransportH3
                | PeerFaultCause::TransportQuic
                | PeerFaultCause::TransportCapacity
                | PeerFaultCause::TransportPinsUnavailable
                | PeerFaultCause::TransportBodyLimit
                | PeerFaultCause::TransportOther
                | PeerFaultCause::Envelope
                | PeerFaultCause::Frame
                | PeerFaultCause::RemoteUnauthorized
                | PeerFaultCause::RemoteForbidden
                | PeerFaultCause::RemoteStatus
                | PeerFaultCause::InvalidRoute
                | PeerFaultCause::UnexpectedRecord
                | PeerFaultCause::OwnerNotReady
                | PeerFaultCause::RotationFreeze
                | PeerFaultCause::Capacity
                | PeerFaultCause::OwnerChanged
                | PeerFaultCause::MembershipExpired
                | PeerFaultCause::Closed
                | PeerFaultCause::Deadline => {}
            }
        }
        let mut labels: Vec<&str> = PeerFaultCause::ALL.iter().map(|c| c.as_str()).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "cause labels must be distinct");
    }

    use super::*;
    use crate::routing::OwnerRoutingError;
    use crate::routing::OwnerScope;

    fn owner() -> OwnerToken {
        OwnerToken {
            deployment_incarnation: "incarnation-1".to_owned(),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "session-7".to_owned(),
            epoch: 9,
            node_id: "relay-b".to_owned(),
            boot_id: "boot-1".to_owned(),
        }
    }

    #[test]
    fn every_runtime_error_maps_to_a_closed_cause_without_text() {
        let secret = "secret-endpoint-text";
        let cases: Vec<(PeerRuntimeError, PeerFaultCause)> = vec![
            (
                PeerRuntimeError::Routing(OwnerRoutingError::NoLiveOwner(OwnerScope::new(
                    Uuid::nil(),
                    Uuid::nil(),
                ))),
                PeerFaultCause::NoLiveOwner,
            ),
            (
                PeerRuntimeError::Membership(secret.to_owned()),
                PeerFaultCause::Membership,
            ),
            (
                PeerRuntimeError::InvalidEndpoint(secret.to_owned()),
                PeerFaultCause::InvalidEndpoint,
            ),
            (
                PeerRuntimeError::PeerIdentityMismatch,
                PeerFaultCause::IdentityMismatch,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Timeout),
                PeerFaultCause::TransportTimeout,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::GoAway),
                PeerFaultCause::TransportGoAway,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Cancelled),
                PeerFaultCause::TransportCancelled,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::H3(secret.to_owned())),
                PeerFaultCause::TransportH3,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Quic(secret.to_owned())),
                PeerFaultCause::TransportQuic,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::Capacity),
                PeerFaultCause::TransportCapacity,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::BodyTooLarge {
                    observed: 2,
                    maximum: 1,
                }),
                PeerFaultCause::TransportBodyLimit,
            ),
            (
                PeerRuntimeError::Transport(PeerTransportError::PolicyRejected),
                PeerFaultCause::TransportOther,
            ),
            (
                PeerRuntimeError::RemoteStatus(axum::http::StatusCode::UNAUTHORIZED),
                PeerFaultCause::RemoteUnauthorized,
            ),
            (
                PeerRuntimeError::RemoteStatus(axum::http::StatusCode::FORBIDDEN),
                PeerFaultCause::RemoteForbidden,
            ),
            (
                PeerRuntimeError::RemoteStatus(axum::http::StatusCode::BAD_GATEWAY),
                PeerFaultCause::RemoteStatus,
            ),
            (
                PeerRuntimeError::OwnerNotReady { retry_after_ms: 1 },
                PeerFaultCause::OwnerNotReady,
            ),
            (
                PeerRuntimeError::Capacity { retry_after_ms: 1 },
                PeerFaultCause::Capacity,
            ),
            (
                PeerRuntimeError::MembershipExpired,
                PeerFaultCause::MembershipExpired,
            ),
            (PeerRuntimeError::Closed, PeerFaultCause::Closed),
        ];
        for (error, expected) in cases {
            let cause = PeerFaultCause::from_error(&error);
            assert_eq!(cause, expected, "{error}");
            let label = serde_json::to_string(&cause).expect("cause serializes");
            assert_eq!(label, format!("\"{}\"", cause.as_str()));
            assert!(!label.contains(secret));
        }
    }

    #[test]
    fn stage_and_cause_json_labels_match_their_closed_vocabulary() {
        for stage in PeerOpenDiagnosticStage::ALL {
            let label = serde_json::to_string(&stage).expect("stage serializes");
            assert_eq!(label, format!("\"{}\"", stage.as_str()));
        }
        let stages: Vec<&str> = PeerOpenDiagnosticStage::ALL
            .iter()
            .map(|stage| stage.as_str())
            .collect();
        assert_eq!(
            stages,
            [
                "validation",
                "pool_connect",
                "stream_permit_checkout",
                "sender_lock",
                "h3_dispatch",
                "envelope_send",
                "complete",
                "head",
                "body",
                "lease",
                "owner",
            ]
        );
    }

    #[test]
    fn observer_records_once_at_the_reached_stage_with_bounded_identity() {
        let diagnostics = PeerFaultDiagnostics::default();
        let observer = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::for_owner(
                &owner(),
                Some(Uuid::from_u128(3)),
                Some("request-11".to_owned()),
            ),
        );
        observer.mark(PeerOpenDiagnosticStage::Lease);
        observer.record_error(
            &diagnostics,
            &PeerRuntimeError::OwnerNotReady { retry_after_ms: 5 },
        );
        // A second classification for the same request is ignored.
        observer.record_error(&diagnostics, &PeerRuntimeError::Closed);
        assert!(observer.recorded());

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.fault_count, 1);
        assert_eq!(snapshot.ingress_count, 1);
        assert_eq!(snapshot.owner_count, 0);
        assert_eq!(snapshot.stage_counts.get("lease"), Some(&1));
        assert_eq!(snapshot.cause_counts.get("owner_not_ready"), Some(&1));
        let event = snapshot
            .last_by_stage
            .get("lease")
            .expect("lease tuple retained");
        assert_eq!(event.sequence, 1);
        assert_eq!(event.role, PeerFaultRole::Ingress);
        assert_eq!(event.stage, PeerOpenDiagnosticStage::Lease);
        assert_eq!(event.cause, PeerFaultCause::OwnerNotReady);
        assert_eq!(event.tenant_id, Uuid::from_u128(1));
        assert_eq!(event.device_id, Uuid::from_u128(2));
        assert_eq!(event.session_id.as_deref(), Some("session-7"));
        assert_eq!(event.owner_epoch, Some(9));
        assert_eq!(event.owner_node_id.as_deref(), Some("relay-b"));
        assert_eq!(event.service_id, Some(Uuid::from_u128(3)));
        assert_eq!(event.request_id.as_deref(), Some("request-11"));
        assert_eq!(snapshot.recent, vec![event.clone()]);
    }

    #[test]
    fn head_stage_owner_decisions_are_attributed_to_the_owner_stage() {
        let diagnostics = PeerFaultDiagnostics::default();
        let observer = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None),
        );
        observer.mark(PeerOpenDiagnosticStage::Head);
        observer.record_error(
            &diagnostics,
            &PeerRuntimeError::RemoteStatus(axum::http::StatusCode::UNAUTHORIZED),
        );
        let snapshot = diagnostics.snapshot();
        let event = snapshot
            .last_by_stage
            .get("owner")
            .expect("owner tuple retained");
        assert_eq!(event.cause, PeerFaultCause::RemoteUnauthorized);
        assert_eq!(event.session_id, None);
        assert_eq!(event.owner_epoch, None);

        let transport = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None),
        );
        transport.mark(PeerOpenDiagnosticStage::Head);
        transport.record_error(
            &diagnostics,
            &PeerRuntimeError::Transport(PeerTransportError::GoAway),
        );
        let snapshot = diagnostics.snapshot();
        assert_eq!(
            snapshot.last_by_stage.get("head").map(|event| event.cause),
            Some(PeerFaultCause::TransportGoAway)
        );
    }

    #[test]
    fn stamps_and_fault_tuples_share_one_sequence_and_one_clock() {
        let diagnostics = PeerFaultDiagnostics::default();
        let context = PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None);
        diagnostics.record(
            &context,
            PeerFaultRole::Owner,
            PeerOpenDiagnosticStage::Body,
            PeerFaultCause::Closed,
        );
        let first = diagnostics.stamp();
        diagnostics.record(
            &context,
            PeerFaultRole::Owner,
            PeerOpenDiagnosticStage::Head,
            PeerFaultCause::Closed,
        );
        let second = diagnostics.stamp();

        let snapshot = diagnostics.snapshot();
        let before = snapshot
            .last_by_stage
            .get("body")
            .expect("first tuple retained");
        let after = snapshot
            .last_by_stage
            .get("head")
            .expect("second tuple retained");
        // One counter, interleaved: a stamp is comparable with a tuple.
        assert_eq!(
            (
                before.sequence,
                first.sequence,
                after.sequence,
                second.sequence
            ),
            (1, 2, 3, 4)
        );
        assert!(before.observed_at_ms <= first.at_ms);
        assert!(first.at_ms <= after.observed_at_ms);
        assert!(after.observed_at_ms <= second.at_ms);
        // A stamp is not a fault: only the two records are counted.
        assert_eq!(snapshot.fault_count, 2);
        assert_eq!(snapshot.recent.len(), 2);
    }

    /// A recorded closure names its stage and cause by table position, so a
    /// variant missing from a table would neither count nor decode.
    #[test]
    fn every_closure_stage_and_cause_is_enumerated() {
        for stage in TaskClosureStage::ALL {
            match stage {
                TaskClosureStage::Control
                | TaskClosureStage::Data
                | TaskClosureStage::ConsumerStream => {}
            }
        }
        for cause in TaskClosureCause::ALL {
            match cause {
                TaskClosureCause::PeerClosed
                | TaskClosureCause::WriteFailed
                | TaskClosureCause::ProtocolError
                | TaskClosureCause::RecordTooLarge
                | TaskClosureCause::UnexpectedMessage
                | TaskClosureCause::ServerClose
                | TaskClosureCause::StreamClosed
                | TaskClosureCause::Expired
                | TaskClosureCause::StreamFailed
                | TaskClosureCause::LivenessTimeout => {}
            }
        }
        let mut labels: Vec<&str> = TaskClosureCause::ALL.iter().map(|c| c.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), TaskClosureCause::ALL.len());
    }

    #[test]
    fn closures_keep_their_own_ring_counters_and_clock_position() {
        let diagnostics = PeerFaultDiagnostics::default();
        let scope = TaskClosureScope {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "session-7".to_owned(),
            epoch: 9,
            stream_id: Some(41),
        };
        let total = MAX_TASK_CLOSURES + 3;
        let mut last = None;
        for _ in 0..total {
            last = Some(diagnostics.record_closure(
                &scope,
                TaskClosureStage::ConsumerStream,
                TaskClosureCause::Expired,
            ));
        }
        let after = diagnostics.stamp();
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.fault_count, 0);
        assert!(snapshot.recent.is_empty());
        assert!(snapshot.last_by_stage.is_empty());
        assert_eq!(snapshot.closures.len(), MAX_TASK_CLOSURES);
        assert_eq!(
            snapshot.closure_stage_counts.get("consumer_stream"),
            Some(&(total as u64))
        );
        assert_eq!(
            snapshot.closure_cause_counts.get("expired"),
            Some(&(total as u64))
        );
        assert_eq!(snapshot.closure_stage_counts.len(), 1);
        let sequences: Vec<u64> = snapshot.closures.iter().map(|c| c.sequence).collect();
        assert_eq!(sequences, (4..=total as u64).collect::<Vec<u64>>());
        let newest = snapshot.closures.last().expect("closure retained");
        assert_eq!(Some(newest.sequence), last.map(|stamp| stamp.sequence));
        assert!(newest.sequence < after.sequence);
        assert_eq!(newest.stage, TaskClosureStage::ConsumerStream);
        assert_eq!(newest.cause, TaskClosureCause::Expired);
        assert_eq!(newest.tenant_id, scope.tenant_id);
        assert_eq!(newest.device_id, scope.device_id);
        assert_eq!(newest.session_id, scope.session_id);
        assert_eq!(newest.epoch, scope.epoch);
        assert_eq!(newest.stream_id, scope.stream_id);
    }

    /// What the C11 capture scanner requires of every snapshot it reads
    /// (`validate_peer_fault_table` in `tunnel-test-harness`).
    fn assert_scanner_invariants(snapshot: &PeerFaultDiagnosticSnapshot) {
        let faults = snapshot.fault_count;
        assert_eq!(snapshot.ingress_count + snapshot.owner_count, faults);
        assert_eq!(snapshot.stage_counts.values().sum::<u64>(), faults);
        assert_eq!(snapshot.cause_counts.values().sum::<u64>(), faults);
        // A count of n means the n-th tuple is visible: the ring is exactly
        // as full as the count allows, never shorter and never longer.
        assert_eq!(
            snapshot.recent.len() as u64,
            faults.min(MAX_RECENT_PEER_FAULTS as u64)
        );
        assert!(
            snapshot
                .recent
                .windows(2)
                .all(|w| w[0].sequence < w[1].sequence)
        );
        for (stage, event) in &snapshot.last_by_stage {
            assert_eq!(event.stage.as_str(), *stage);
            assert!(snapshot.stage_counts.get(stage).is_some_and(|c| *c > 0));
            // The stage's latest tuple is at least as new as any of that
            // stage in the ring.
            assert!(
                snapshot
                    .recent
                    .iter()
                    .filter(|recent| recent.stage == event.stage)
                    .all(|recent| recent.sequence <= event.sequence)
            );
        }
        assert_eq!(
            snapshot.last_by_stage.len(),
            snapshot.stage_counts.len(),
            "every counted stage has its latest tuple"
        );
        let closures: u64 = snapshot.closure_stage_counts.values().sum();
        assert_eq!(
            snapshot.closure_cause_counts.values().sum::<u64>(),
            closures
        );
        assert_eq!(
            snapshot.closures.len() as u64,
            closures.min(MAX_TASK_CLOSURES as u64)
        );
        assert!(
            snapshot
                .closures
                .windows(2)
                .all(|w| w[0].sequence < w[1].sequence)
        );
    }

    /// Recorders on several threads are parked between the steps of their
    /// records -- sometimes for far longer than a snapshot takes -- while a
    /// reader snapshots continuously.  Every snapshot must satisfy the
    /// scanner's invariants; none may show a count without its tuple.
    #[test]
    fn parked_recorders_never_break_a_snapshot_invariant() {
        const WRITERS: usize = 4;
        const PER_WRITER: usize = 400;
        let diagnostics = PeerFaultDiagnostics::default();
        let steps = Arc::new(AtomicU64::new(0));
        {
            let steps = Arc::clone(&steps);
            diagnostics.park_recorders(Arc::new(move |_step| {
                if steps.fetch_add(1, Ordering::SeqCst).is_multiple_of(53) {
                    std::thread::sleep(std::time::Duration::from_micros(400));
                } else {
                    std::thread::yield_now();
                }
            }));
        }
        let writers: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let diagnostics = diagnostics.clone();
                std::thread::spawn(move || {
                    let context = PeerFaultContext::for_owner(
                        &owner(),
                        Some(Uuid::from_u128(3)),
                        Some(format!("request-{writer}")),
                    );
                    let scope = TaskClosureScope {
                        tenant_id: Uuid::from_u128(1),
                        device_id: Uuid::from_u128(2),
                        session_id: "session-7".to_owned(),
                        epoch: 9,
                        stream_id: Some(writer as u64),
                    };
                    for round in 0..PER_WRITER {
                        let pick = writer + round;
                        diagnostics.record(
                            &context,
                            PeerFaultRole::ALL[pick % 2],
                            PeerOpenDiagnosticStage::ALL[pick % PeerOpenDiagnosticStage::ALL.len()],
                            PeerFaultCause::ALL[pick % PeerFaultCause::ALL.len()],
                        );
                        let closure = diagnostics.record_closure(
                            &scope,
                            TaskClosureStage::ALL[pick % TaskClosureStage::ALL.len()],
                            TaskClosureCause::ALL[pick % TaskClosureCause::ALL.len()],
                        );
                        // The closure is in the ring when the call returns.
                        if round % 16 == 0 {
                            let stamp = diagnostics.stamp();
                            assert!(closure.sequence < stamp.sequence);
                        }
                    }
                })
            })
            .collect();
        let mut samples = 0_u64;
        let mut last = 0;
        while writers.iter().any(|writer| !writer.is_finished()) {
            let snapshot = diagnostics.snapshot();
            assert_scanner_invariants(&snapshot);
            assert!(snapshot.fault_count >= last);
            last = snapshot.fault_count;
            samples += 1;
        }
        for writer in writers {
            writer.join().expect("recorder finishes");
        }
        assert!(samples > 0);
        let snapshot = diagnostics.snapshot();
        assert_scanner_invariants(&snapshot);
        let total = (WRITERS * PER_WRITER) as u64;
        assert_eq!(snapshot.fault_count, total);
        assert_eq!(snapshot.closure_stage_counts.values().sum::<u64>(), total);
        // Faults, closures and stamps share one clock: the ring holds the
        // highest fault sequences drawn, all of them late on that clock.
        let lowest_kept = snapshot.recent.first().map(|event| event.sequence);
        assert!(lowest_kept.is_some_and(|sequence| sequence > total));
    }

    /// Faults and closures are recorded without pause for as long as a
    /// reader is snapshotting.  Every snapshot completes in exactly one pass
    /// over each of the two states -- continuous recording cannot make the
    /// reader try again -- and satisfies the scanner's invariants, and a
    /// lone recorder's closure is in the ring when its call returns.
    #[test]
    fn a_reader_under_continuous_faults_finishes_each_snapshot_in_one_pass() {
        const SNAPSHOTS: u64 = 4_000;
        // Recording here is unbounded in rate, so the storage cap is lifted:
        // a reader descheduled by a busy machine would otherwise turn this
        // into a test of the cap, which has its own tests.
        let diagnostics = PeerFaultDiagnostics::with_blocks(1 << 22);
        let stop = Arc::new(AtomicBool::new(false));
        let writers: Vec<_> = (0..4_usize)
            .map(|writer| {
                let diagnostics = diagnostics.clone();
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let context = PeerFaultContext::for_owner(
                        &owner(),
                        Some(Uuid::from_u128(3)),
                        Some(format!("request-{writer}")),
                    );
                    let scope = TaskClosureScope {
                        tenant_id: Uuid::from_u128(1),
                        device_id: Uuid::from_u128(2),
                        session_id: "session-7".to_owned(),
                        epoch: 9,
                        stream_id: Some(writer as u64),
                    };
                    let mut pick = writer;
                    let mut records = 0_u64;
                    while !stop.load(Ordering::SeqCst) {
                        pick += 5;
                        diagnostics.record(
                            &context,
                            PeerFaultRole::ALL[pick % 2],
                            PeerOpenDiagnosticStage::ALL[pick % PeerOpenDiagnosticStage::ALL.len()],
                            PeerFaultCause::ALL[pick % PeerFaultCause::ALL.len()],
                        );
                        diagnostics.record_closure(
                            &scope,
                            TaskClosureStage::ALL[pick % TaskClosureStage::ALL.len()],
                            TaskClosureCause::ALL[pick % TaskClosureCause::ALL.len()],
                        );
                        records += 1;
                    }
                    records
                })
            })
            .collect();
        let mut last = 0;
        for _ in 0..SNAPSHOTS {
            let snapshot = diagnostics.snapshot();
            assert_scanner_invariants(&snapshot);
            assert!(snapshot.fault_count >= last);
            last = snapshot.fault_count;
        }
        // The recorders were still recording when the last snapshot ended.
        assert!(writers.iter().all(|writer| !writer.is_finished()));
        assert_eq!(diagnostics.read_passes(), 2 * SNAPSHOTS);
        stop.store(true, Ordering::SeqCst);
        let records: u64 = writers
            .into_iter()
            .map(|writer| writer.join().expect("recorder finishes"))
            .sum();
        let snapshot = diagnostics.snapshot();
        assert_scanner_invariants(&snapshot);
        assert_eq!(snapshot.fault_count, records);
        assert_eq!(snapshot.closure_stage_counts.values().sum::<u64>(), records);

        // With the others stopped, a closure is retained by the time its
        // call returns, and is the newest in the ring.
        let scope = TaskClosureScope {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "session-8".to_owned(),
            epoch: 10,
            stream_id: None,
        };
        let stamp =
            diagnostics.record_closure(&scope, TaskClosureStage::ALL[0], TaskClosureCause::ALL[0]);
        let newest = diagnostics.snapshot().closures.pop();
        assert_eq!(newest.map(|closure| closure.sequence), Some(stamp.sequence));
    }

    /// With every reader cell taken a snapshot says it is unavailable --
    /// in the typed value and in its JSON -- rather than reporting zero
    /// faults; with a cell free it reports the faults and the marker is
    /// absent, so the serialized shape is unchanged.
    #[test]
    fn a_refused_snapshot_is_unavailable_not_empty() {
        let diagnostics = PeerFaultDiagnostics::default();
        let context = PeerFaultContext::for_owner(&owner(), Some(Uuid::from_u128(3)), None);
        diagnostics.record(
            &context,
            PeerFaultRole::Owner,
            PeerOpenDiagnosticStage::ALL[0],
            PeerFaultCause::ALL[0],
        );
        let held = diagnostics.state.arena.occupy_readers();
        let refused = diagnostics.snapshot();
        assert!(refused.unavailable);
        let json = serde_json::to_string(&refused).expect("snapshot serializes");
        assert!(json.contains("\"unavailable\":true"), "{json}");
        drop(held);
        let snapshot = diagnostics.snapshot();
        assert!(!snapshot.unavailable);
        assert_eq!(snapshot.fault_count, 1);
        assert_scanner_invariants(&snapshot);
        let json = serde_json::to_string(&snapshot).expect("snapshot serializes");
        assert!(!json.contains("unavailable"), "{json}");
    }

    /// At its storage cap the recorder refuses whole records: every
    /// snapshot still satisfies the scanner's invariants, and recording
    /// resumes when the stalled reader is gone.
    #[test]
    fn faults_at_the_storage_cap_are_refused_whole() {
        let diagnostics = PeerFaultDiagnostics::with_blocks(512);
        let context = PeerFaultContext::for_owner(&owner(), Some(Uuid::from_u128(3)), None);
        let record = |pick: usize| {
            diagnostics.record(
                &context,
                PeerFaultRole::ALL[pick % 2],
                PeerOpenDiagnosticStage::ALL[pick % PeerOpenDiagnosticStage::ALL.len()],
                PeerFaultCause::ALL[pick % PeerFaultCause::ALL.len()],
            );
        };
        let mut stalled = diagnostics.state.arena.occupy_readers();
        for pick in 0..400 {
            record(pick);
        }
        assert!(diagnostics.state.arena.dropped() > 0);
        assert!(diagnostics.state.arena.allocated() <= 512);
        stalled.pop();
        let capped = diagnostics.snapshot();
        assert_scanner_invariants(&capped);
        assert!(capped.fault_count > 0 && capped.fault_count < 400);
        drop(stalled);
        // Each snapshot reclaims a bounded batch of the parked blocks.
        for _ in 0..64 {
            assert_scanner_invariants(&diagnostics.snapshot());
        }
        let dropped = diagnostics.state.arena.dropped();
        for pick in 0..100 {
            record(pick);
        }
        assert_eq!(diagnostics.state.arena.dropped(), dropped);
        let snapshot = diagnostics.snapshot();
        assert_scanner_invariants(&snapshot);
        assert_eq!(snapshot.fault_count, capped.fault_count + 100);
    }

    #[test]
    fn recent_ring_and_counters_stay_bounded() {
        let diagnostics = PeerFaultDiagnostics::default();
        let context = PeerFaultContext::unrouted(Uuid::from_u128(1), Uuid::from_u128(2), None);
        for _ in 0..(MAX_RECENT_PEER_FAULTS + 5) {
            diagnostics.record(
                &context,
                PeerFaultRole::Owner,
                PeerOpenDiagnosticStage::Body,
                PeerFaultCause::Closed,
            );
        }
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.recent.len(), MAX_RECENT_PEER_FAULTS);
        assert_eq!(snapshot.fault_count, (MAX_RECENT_PEER_FAULTS + 5) as u64);
        assert_eq!(snapshot.owner_count, (MAX_RECENT_PEER_FAULTS + 5) as u64);
        assert_eq!(snapshot.recent.first().map(|event| event.sequence), Some(6));
        assert_eq!(snapshot.last_by_stage.len(), 1);
        let json = serde_json::to_string(&snapshot).expect("snapshot serializes");
        assert!(json.contains("\"stage\":\"body\""));
        assert!(json.contains("\"cause\":\"closed\""));
        assert!(json.contains("\"role\":\"owner\""));
    }
}
