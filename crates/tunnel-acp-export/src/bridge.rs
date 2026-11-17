//! The in-process ACP HTTP/SSE handler (M8 chunk 3, the bridge half of
//! M8-02).
//!
//! [`AcpExport::handle`] is an [`HttpHandler`][h] the connector registers
//! through `HttpHandlers::with_export`: it takes the gate-2 bridge's typed
//! request and returns a response whose body streams.  **There is no address,
//! no listener and no socket anywhere in this file**; `tunnel_http_bridge::serve`
//! calls the handler directly, and `tests/no_listener.rs` reads the process's
//! own socket table to say so rather than asserting the absence of a call.
//!
//! [h]: https://docs.rs/tunnel-client
//!
//! # The 202 rule
//!
//! `docs/acp.md`: "HTTP 202 means accepted by the bridge, not that an agent
//! finished or committed an action."  Every POST but `initialize` answers 202
//! and the JSON-RPC result arrives later on a **different exchange** — the
//! connection GET for `session/new`, the session GET for `session/prompt`.
//! Nothing in this file infers completion from a status, and no test of it may
//! terminate on one.
//!
//! # Wire order
//!
//! Agent→host messages reach this bridge on one channel from the supervisor's
//! one stdout reader ([`OutboundMessage`]), and each SSE stream has one
//! bounded queue and one draining task.  Wire order is therefore the order the
//! agent wrote, with nothing downstream reordering it.  A bridge-composed
//! result — a `session/new` or `session/prompt` answer — is enqueued by the
//! task that awaited it, which cannot run until the supervisor's reader has
//! already forwarded everything that preceded the result on the child's
//! stdout.
//!
//! # Subscribers
//!
//! One subscriber per connection and one per session, enforced by *taking* the
//! queue's receiving half: a second GET finds nothing to take and is refused
//! **409**.  A pre-subscription message is charged to the same bounded queue,
//! as `docs/acp.md` requires, rather than dropped or buffered without limit.
//!
//! # What this file does not do
//!
//! There is **no principal in this chunk**.  `docs/acp.md` derives the
//! principal at the relay ingress, and the in-process gate-2 bridge has no
//! ingress in front of it, exactly as `tunnel_mcp_export` records for M3-01 and
//! M3-02: every request here carries `tunnel-principal-binding: None`, which
//! binds a connection to "no principal" and still refuses any other value.
//! Binding to a real authenticated principal, the cluster, rotation and
//! cross-tenant isolation are chunks 4 and 5.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tunnel_acp::lifecycle::{LifecycleRule, PermissionOutcome, RequestId};
use tunnel_acp::message::{
    AcpMessage, AcpRejection, AcpRule, MessageKind, validate_delete, validate_get, validate_post,
};
use tunnel_acp::{AcpLimits, AcpProfile};
use tunnel_http_bridge::{ChannelBody, Profile};

use crate::config::{AcpConfigError, AcpExportConfig, ValidatedAcp};
use crate::sse::{
    self, ChannelResponseBody, ExportBody, StreamFailure, StreamSender, json_response, no_body,
    rejection, sse_event, sse_head,
};
use crate::supervisor::{
    ConnectionScope, OutboundMessage, Supervisor, SupervisorConfig, SupervisorError,
};

/// Messages queued for one not-yet-subscribed or slow SSE stream.
///
/// `docs/acp.md`: "Charge pre-subscription messages to the same bounded
/// queues."  This is that bound, and it is finite.
pub const STREAM_BACKLOG: usize = 32;

/// How often a connection's watchdog reads its clock.
const WATCHDOG_TICK: Duration = Duration::from_millis(20);

/// Commands queued towards one connection's owning task, which holds the
/// connection's streams.  A sender waits for room; the owner serves commands
/// even while it is tearing the connection down, so the queue always drains.
const CONNECTION_COMMAND_QUEUE: usize = 32;

/// Connections queued for listing by the export's registry task.  An
/// `initialize` waits for room, and for the listing to be published, before
/// it answers.
const REGISTRY_QUEUE: usize = 32;

/// ACP transport connections this export tracks at once.
///
/// **Copied from `tunnel_mcp_export::http_backend`'s session table (M3-04),
/// design and all, rather than re-derived.**  Two caps, and the refusal is at
/// the door:
///
/// * a global cap, so one export cannot grow without bound; and
/// * a per-principal cap of an eighth of it, so one authorized principal
///   cannot fill the table.
///
/// **Nothing is ever evicted to make room.**  An evict-oldest table of this
/// shape is a cross-principal denial channel: eviction picks by age, not by
/// owner, so any single authorized principal could open `MAX + 1` connections
/// and evict every other principal's live ones — turning a legitimate
/// capability into a denial capability against unrelated tenants.  Refusing the
/// newcomer is what closes that, and the per-principal cap is what stops one
/// principal from starving the global cap for everybody.
///
/// An ACP connection owns a child process, so the refusal is taken **before
/// the child is spawned**: the export never starts an agent it could not track.
pub const MAX_TRACKED_CONNECTIONS: usize = 256;

/// Connections one principal may hold at once.
pub const MAX_CONNECTIONS_PER_BINDING: usize = MAX_TRACKED_CONNECTIONS / 8;

/// How long one message may wait for room on a stream's queue before the
/// connection is ended.
///
/// `docs/acp.md`'s limits table: "Output credit stall | 30 seconds, then
/// cancel/close; **never drop an event and continue**."  The second half is the
/// rule that matters — a bridge that skipped the event and carried on would
/// leave a silent hole in a stream that has no `Last-Event-ID` replay to fill
/// it, and the consumer would have no way to know.  So the stall is terminal.
pub const OUTPUT_STALL_DEADLINE: Duration = Duration::from_secs(30);

/// Whether an export holding `live` connections, of which `held` belong to the
/// principal asking, may open one more.
///
/// **Both caps, and the newcomer is the one refused.**  The global cap bounds
/// the export; the per-principal cap is what makes the global one safe, because
/// without it one authorized principal reaches `MAX_TRACKED_CONNECTIONS` alone
/// and every other principal is refused from then on.  Neither cap ever evicts:
/// see [`MAX_TRACKED_CONNECTIONS`] for why evict-oldest is a cross-principal
/// denial channel rather than a capacity policy.
///
/// It is a free function so the rule can be tested as arithmetic.  Proving the
/// denial property against real connections would mean spawning 257 child
/// processes to establish a property that is entirely about two comparisons.
#[must_use]
pub const fn admits(live: usize, held: usize) -> bool {
    live < MAX_TRACKED_CONNECTIONS && held < MAX_CONNECTIONS_PER_BINDING
}

/// An exchange the export interrupts instead of answering.  It carries no
/// message: the peer learns only the bridge's sanitized code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportError;

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("acp export interrupted the exchange")
    }
}

impl std::error::Error for ExportError {}

/// Payload-free counters of one ACP export.
#[derive(Debug, Default)]
struct Counters {
    connections_opened: AtomicU64,
    connections_closed: AtomicU64,
    connection_subscribe_expired: AtomicU64,
    session_subscribe_expired: AtomicU64,
    subscribers_refused: AtomicU64,
    sessions_opened: AtomicU64,
    prompts_accepted: AtomicU64,
    prompts_refused_not_ready: AtomicU64,
    permissions_answered: AtomicU64,
    batches_refused: AtomicU64,
    rejected: AtomicU64,
    sse_events: AtomicU64,
    sse_bytes: AtomicU64,
    /// The last measured **microseconds** a subscription deadline actually ran
    /// before the watchdog expired it, with the bound it exceeded.  Strictly
    /// greater than the bound.
    ///
    /// Microseconds rather than milliseconds because the bound is a whole
    /// number of milliseconds: a watchdog that fires at 300.4 ms reports 300
    /// once truncated, and "strictly greater" then reads as equal. The
    /// resolution has to be finer than the bound for the measurement to say
    /// anything.
    last_expiry_elapsed_us: AtomicU64,
    last_expiry_bound_us: AtomicU64,
    /// SSE streams whose subscriber went away while messages were still being
    /// routed to them.
    streams_lost: AtomicU64,
    /// Messages dropped because their stream was already over.
    messages_dropped_on_closed_stream: AtomicU64,
    /// Connections ended because their child did.
    connections_ended_by_child: AtomicU64,
    /// The child's own refused-batch and refused-line counts, folded in when a
    /// connection ends, so they survive the connection they belonged to.
    child_batch_output: AtomicU64,
    child_invalid_output: AtomicU64,
    /// `initialize` refused because the export, or this principal's share of
    /// it, was full.  No child was spawned for any of these.
    connections_refused_at_capacity: AtomicU64,
    /// Connections terminated because an **established** required SSE stream
    /// broke.  Distinct from a stream that never arrived, which is a
    /// subscription deadline and a different rule.
    connections_ended_by_subscriber_loss: AtomicU64,
    /// Permissions resolved `cancelled` because the transport was terminated
    /// under them.  Never approved.
    permissions_cancelled_by_loss: AtomicU64,
    /// Connections terminated because a message could not be queued within
    /// [`OUTPUT_STALL_DEADLINE`].
    output_stalls: AtomicU64,
    /// The last measured **microseconds** a message actually waited for queue
    /// room before the stall deadline ended its connection, with the bound it
    /// exceeded.  Strictly greater than the bound, and in microseconds for the
    /// same reason the subscription deadlines are.
    last_stall_elapsed_us: AtomicU64,
    last_stall_bound_us: AtomicU64,
    /// Operations this export classified through
    /// [`tunnel_acp::terminal::AcpTerminal`], counted by the outcome that rule
    /// produced.
    ///
    /// **This is what makes the mapping a rule the product applies.**  Without
    /// it `terminal.rs` would be a table only its own unit tests read, and a
    /// gate asserting `AcpTerminal::LostAfterDispatch.result_status()` would be
    /// evaluating a pure function rather than observing a decision.  These are
    /// incremented where the export decides, and read back from
    /// [`AcpDiagnostics`].
    terminals_succeeded: AtomicU64,
    terminals_cancelled: AtomicU64,
    terminals_failed: AtomicU64,
    terminals_unknown: AtomicU64,
}

/// Classify one ended operation and count it by the outcome the rule gave.
///
/// The `match` is on the rule's own output, so a change to
/// [`tunnel_acp::terminal`] changes what this export reports.  An outcome the
/// protocol vocabulary does not contain is impossible by that module's own
/// test, and is counted as unknown here rather than silently dropped.
fn record_terminal(counters: &Counters, terminal: tunnel_acp::terminal::AcpTerminal) {
    let counter = match terminal.result_status() {
        "succeeded" => &counters.terminals_succeeded,
        "cancelled" => &counters.terminals_cancelled,
        "failed" => &counters.terminals_failed,
        _ => &counters.terminals_unknown,
    };
    counter.fetch_add(1, Ordering::Release);
}

/// A snapshot of an export's counters.  Identifiers, phases and counters
/// only; never a payload or a credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcpDiagnostics {
    pub connections_opened: u64,
    pub connections_closed: u64,
    pub connection_subscribe_expired: u64,
    pub session_subscribe_expired: u64,
    pub subscribers_refused: u64,
    pub sessions_opened: u64,
    pub prompts_accepted: u64,
    pub prompts_refused_not_ready: u64,
    pub permissions_answered: u64,
    pub batches_refused: u64,
    pub rejected: u64,
    pub sse_events: u64,
    pub sse_bytes: u64,
    pub last_expiry_elapsed_us: u64,
    pub last_expiry_bound_us: u64,
    pub streams_lost: u64,
    pub messages_dropped_on_closed_stream: u64,
    pub connections_ended_by_child: u64,
    pub child_batch_output: u64,
    pub child_invalid_output: u64,
    pub connections_refused_at_capacity: u64,
    pub connections_ended_by_subscriber_loss: u64,
    pub permissions_cancelled_by_loss: u64,
    pub output_stalls: u64,
    pub last_stall_elapsed_us: u64,
    pub last_stall_bound_us: u64,
    pub terminals_succeeded: u64,
    pub terminals_cancelled: u64,
    pub terminals_failed: u64,
    pub terminals_unknown: u64,
    pub live_connections: u64,
}

/// Where one SSE stream is in its life.
///
/// The queue's receiving half, the live body's sender and the two latches a
/// stream used to carry are one value here, so the combinations that never
/// meant anything -- subscribed with the receiving half still parked, a body
/// watched on a stream nobody subscribed to -- cannot be written down.
#[derive(Debug)]
enum TargetPhase {
    /// No subscriber yet.  The receiving half waits here, and *taking* it is
    /// what makes "one subscriber" structural: a second GET finds nothing to
    /// take.
    Awaiting(mpsc::Receiver<Bytes>),
    /// The one subscriber took the queue.  A clone of its body's sender is
    /// parked here.
    ///
    /// **This is what makes a broken established stream observable while the
    /// agent is silent.**  The stream's pump only discovers its body is gone
    /// when it next writes, so a connection with nothing to say would not
    /// notice the break at all -- and `docs/acp.md`'s policy is about the
    /// break, not about the next message.  The watchdog asks this on its own
    /// tick.
    Established(StreamSender),
    /// This stream is over: its subscriber went away, its window expired, or
    /// its connection closed.  `established` remembers which kind of ending
    /// it was, because losing an established stream ends the transport and a
    /// stream that never had a subscriber does not.
    ///
    /// **It is per stream, and that is the whole point.**  A dropped SSE body
    /// is an ordinary event, and marking one stream over and carrying on is
    /// what stops one lost subscriber from silently disabling a connection.
    Over { established: bool },
}

/// What can happen to a stream.
#[derive(Debug)]
enum TargetEvent {
    /// A GET asks to be the stream's subscriber, bringing its body's sender.
    Subscribe(StreamSender),
    /// The stream ended: lost, expired, or closed with its connection.
    Close,
}

/// What a [`TargetEvent`] produced.
#[derive(Debug)]
enum TargetEffect {
    /// The subscriber took the queue.
    Granted(mpsc::Receiver<Bytes>),
    /// The stream is now over.
    Closed,
    /// The event was refused and nothing changed: a second subscriber, a
    /// subscriber to a stream that is over, or a second close.
    Refused,
}

impl TargetPhase {
    /// The only place a stream's phase changes.
    fn on_event(self, event: TargetEvent) -> (Self, TargetEffect) {
        match (self, event) {
            (Self::Awaiting(queue), TargetEvent::Subscribe(body)) => {
                (Self::Established(body), TargetEffect::Granted(queue))
            }
            // Nothing may subscribe to a stream that is over, so the
            // receiving half goes with it: a later GET is refused 409 by the
            // same rule that refuses a second subscriber.
            (Self::Awaiting(_), TargetEvent::Close) => {
                (Self::Over { established: false }, TargetEffect::Closed)
            }
            (Self::Established(_), TargetEvent::Close) => {
                (Self::Over { established: true }, TargetEffect::Closed)
            }
            (phase @ (Self::Established(_) | Self::Over { .. }), TargetEvent::Subscribe(_))
            | (phase @ Self::Over { .. }, TargetEvent::Close) => (phase, TargetEffect::Refused),
        }
    }
}

/// One SSE destination: a bounded queue whose receiving half the single
/// subscriber takes.  Owned by its connection's task and by nothing else.
#[derive(Debug)]
struct Target {
    tx: mpsc::Sender<Bytes>,
    created: Instant,
    phase: TargetPhase,
}

impl Target {
    /// A fresh stream, and the sending half of its queue.
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(STREAM_BACKLOG);
        Self {
            tx,
            created: Instant::now(),
            phase: TargetPhase::Awaiting(rx),
        }
    }

    fn apply(&mut self, event: TargetEvent) -> TargetEffect {
        // The placeholder is never observed: `on_event` returns the phase
        // that replaces it before anything else can look.
        let phase = std::mem::replace(&mut self.phase, TargetPhase::Over { established: false });
        let (next, effect) = phase.on_event(event);
        self.phase = next;
        effect
    }

    /// Whether this stream was established and has since broken.
    ///
    /// Deliberately **not** true for a stream that never had a subscriber:
    /// that is a subscription deadline, which is a different rule with a
    /// different consequence, and conflating them would let a slow consumer's
    /// missing GET masquerade as a lost one.  Not true for a stream that is
    /// already over either: that ending was counted when it happened.
    fn established_and_broken(&self) -> bool {
        matches!(&self.phase, TargetPhase::Established(body) if body.is_closed())
    }

    const fn is_closed(&self) -> bool {
        matches!(self.phase, TargetPhase::Over { .. })
    }

    /// Whether a subscriber ever took this stream.
    const fn is_subscribed(&self) -> bool {
        matches!(
            self.phase,
            TargetPhase::Established(_) | TargetPhase::Over { established: true }
        )
    }

    /// Whether this stream is still waiting for its subscriber after `bound`.
    fn unsubscribed_past(&self, bound: Duration) -> Option<Duration> {
        let waited = self.created.elapsed();
        (matches!(self.phase, TargetPhase::Awaiting(_)) && waited > bound).then_some(waited)
    }
}

/// Where a message for one stream should go.
enum Routing {
    /// Onto this queue.
    Open(mpsc::Sender<Bytes>),
    /// Nowhere: that stream is over.
    Over,
    /// Nowhere: the connection itself is closed.
    ConnectionClosed,
}

/// What a GET asking to subscribe was told.
enum Subscription {
    Granted(mpsc::Receiver<Bytes>),
    /// The one-subscriber rule, or a stream that is over.
    Refused,
    ConnectionClosed,
}

/// What the connection's other tasks ask of the task that owns its streams.
enum ConnectionCommand {
    /// Where does a message for this stream go?  A session's stream is
    /// created on first mention.
    Route {
        session: Option<String>,
        reply: oneshot::Sender<Routing>,
    },
    /// Make this GET the stream's one subscriber.
    Subscribe {
        session: Option<String>,
        body: StreamSender,
        reply: oneshot::Sender<Subscription>,
    },
    /// A send to this stream failed: mark it over, and say whether it had
    /// been established.
    StreamLost {
        session: Option<String>,
        established: oneshot::Sender<bool>,
    },
    /// Close every stream.
    Close { closed: oneshot::Sender<()> },
}

/// A connection's streams.  Owned by the connection's task; every other task
/// reaches them through a [`ConnectionCommand`].
enum ConnectionState {
    Open {
        connection: Target,
        sessions: BTreeMap<String, Target>,
    },
    /// Closed.  The streams are gone with it, so nothing can be routed to or
    /// subscribed on a closed connection.
    Closed,
}

impl ConnectionState {
    fn new(connection: Target) -> Self {
        Self::Open {
            connection,
            sessions: BTreeMap::new(),
        }
    }

    /// The stream a message or a subscriber names, creating a session's on
    /// first mention.
    ///
    /// Both the dispatcher and the POST that created the session reach for a
    /// session's stream, and which of them arrives first is a race the agent
    /// decides: an update can be on the wire before `session/new`'s own
    /// result has been read.  Creating on demand is what keeps that from
    /// being delivered to the wrong stream.  A stream that is over stays
    /// over: its entry is kept, so one that was expired or lost cannot be
    /// resurrected by the next message that mentions its identifier.
    fn target(&mut self, session: Option<String>) -> Option<&mut Target> {
        match self {
            Self::Closed => None,
            Self::Open {
                connection,
                sessions,
            } => Some(match session {
                None => connection,
                Some(session) => sessions.entry(session).or_insert_with(Target::new),
            }),
        }
    }

    /// The only place a connection's streams close together.  The caller has
    /// already cancelled the connection's `shutdown`, so a stream's pump that
    /// finds its queue ended reads a broken transport and not an orderly end.
    fn close(&mut self) {
        *self = Self::Closed;
    }

    fn serve(&mut self, command: ConnectionCommand, shutdown: &CancellationToken) {
        match command {
            ConnectionCommand::Route { session, reply } => {
                let routing = match self.target(session) {
                    None => Routing::ConnectionClosed,
                    Some(target) if target.is_closed() => Routing::Over,
                    Some(target) => Routing::Open(target.tx.clone()),
                };
                let _ = reply.send(routing);
            }
            ConnectionCommand::Subscribe {
                session,
                body,
                reply,
            } => {
                let subscription = match self.target(session) {
                    None => Subscription::ConnectionClosed,
                    Some(target) => match target.apply(TargetEvent::Subscribe(body)) {
                        TargetEffect::Granted(queue) => Subscription::Granted(queue),
                        TargetEffect::Closed | TargetEffect::Refused => Subscription::Refused,
                    },
                };
                let _ = reply.send(subscription);
            }
            ConnectionCommand::StreamLost {
                session,
                established,
            } => {
                let was_established = self.target(session).is_some_and(|target| {
                    let _ = target.apply(TargetEvent::Close);
                    target.is_subscribed()
                });
                let _ = established.send(was_established);
            }
            ConnectionCommand::Close { closed } => {
                shutdown.cancel();
                self.close();
                let _ = closed.send(());
            }
        }
    }

    /// Whether an established required stream has broken.  Both the
    /// connection stream and every session stream are required.
    fn any_established_and_broken(&self) -> bool {
        match self {
            Self::Closed => false,
            Self::Open {
                connection,
                sessions,
            } => {
                connection.established_and_broken()
                    || sessions.values().any(Target::established_and_broken)
            }
        }
    }

    /// How long the connection stream has waited, if that is past `bound`
    /// and its subscriber never arrived.
    fn connection_unsubscribed_past(&self, bound: Duration) -> Option<Duration> {
        match self {
            Self::Closed => None,
            Self::Open { connection, .. } => connection.unsubscribed_past(bound),
        }
    }

    /// Close every session stream whose subscriber never arrived within
    /// `bound`, returning how long each had waited.
    ///
    /// **An expiry happens once.**  This sweep runs on every watchdog tick,
    /// and an expired stream is over, so it never matches again: the entry is
    /// kept -- that is what lets a late session GET find a stream that is over
    /// and be refused 409 rather than fall through to 404 -- but its phase is
    /// no longer one that waits (M8-C25).
    fn expire_sessions(&mut self, bound: Duration) -> Vec<Duration> {
        let Self::Open { sessions, .. } = self else {
            return Vec::new();
        };
        let mut expired = Vec::new();
        for target in sessions.values_mut() {
            if let Some(waited) = target.unsubscribed_past(bound) {
                // Closing the stream is what stops a later GET from
                // subscribing to a session whose window has closed: the same
                // rule as the one-subscriber rule, so an expired session
                // answers 409 and never silently reopens.
                let _ = target.apply(TargetEvent::Close);
                expired.push(waited);
            }
        }
        expired
    }
}

/// One live ACP transport connection: its child, its streams and its
/// deadlines.
struct Connection {
    id: String,
    supervisor: Supervisor,
    /// The opaque per-principal binding the ingress derived, or `None`.  In
    /// this chunk it is always `None`: there is no ingress in front of the
    /// in-process bridge.
    principal: Option<String>,
    workspace: String,
    limits: AcpLimits,
    /// The connection GET's window and a session GET's window, bounded
    /// separately (task row M8-C12).
    connection_subscribe_deadline: Duration,
    session_subscribe_deadline: Duration,
    /// To the task that owns this connection's streams.  A send that fails
    /// means that task is gone, which is the connection having closed.
    commands: mpsc::Sender<ConnectionCommand>,
    /// The connection stream's queue.  Its sending half never changes, so it
    /// is held here; whether anything is still reading it is the owner's to
    /// say.
    stream: mpsc::Sender<Bytes>,
    /// Whether the export still lists this connection.  Cleared exactly once,
    /// by whichever path ends it.
    listed: AtomicBool,
    counters: Arc<Counters>,
    shutdown: CancellationToken,
    /// A **weak** handle on the supervisor's transport channel, so a finished
    /// turn's result is queued behind every message the agent wrote before it
    /// (task row M8-C27).
    ///
    /// The agent writes its last `session/update` and then the prompt's
    /// response.  The reader forwards the update into this channel and only
    /// then resolves the prompt's waiter, so a result sent into the *same*
    /// channel afterwards is FIFO-ordered behind it.  Sent anywhere else — the
    /// session target directly, as it once was — it raced the dispatcher and
    /// could overtake an update still queued here, so a consumer read the turn
    /// as finished before the update that belonged to it.
    ///
    /// Weak, because the dispatcher holds this `Connection` and ends only when
    /// every strong sender is gone: a strong sender here would keep it alive
    /// for as long as the connection itself.  A prompt upgrades it while the
    /// child is alive and holds the strong sender only until its turn ends.
    outbound: mpsc::WeakSender<OutboundMessage>,
}

impl Connection {
    /// End this connection's listing.  `true` for exactly one caller.
    fn unlist(&self) -> bool {
        self.listed.swap(false, Ordering::SeqCst)
    }

    fn is_listed(&self) -> bool {
        self.listed.load(Ordering::SeqCst)
    }

    /// Where a message for `session`'s stream, or the connection's, goes.
    async fn route(&self, session: Option<&str>) -> Routing {
        let (reply, routed) = oneshot::channel();
        let command = ConnectionCommand::Route {
            session: session.map(ToOwned::to_owned),
            reply,
        };
        if self.commands.send(command).await.is_err() {
            return Routing::ConnectionClosed;
        }
        routed.await.unwrap_or(Routing::ConnectionClosed)
    }

    async fn subscribe(&self, session: Option<String>, body: StreamSender) -> Subscription {
        let (reply, subscribed) = oneshot::channel();
        let command = ConnectionCommand::Subscribe {
            session,
            body,
            reply,
        };
        if self.commands.send(command).await.is_err() {
            return Subscription::ConnectionClosed;
        }
        subscribed.await.unwrap_or(Subscription::ConnectionClosed)
    }

    /// Mark a stream a send just failed on as over.  `true` when it had been
    /// established and its connection is still open.
    async fn stream_lost(&self, session: Option<&str>) -> bool {
        let (established, answer) = oneshot::channel();
        let command = ConnectionCommand::StreamLost {
            session: session.map(ToOwned::to_owned),
            established,
        };
        if self.commands.send(command).await.is_err() {
            return false;
        }
        answer.await.unwrap_or(false)
    }

    /// Ask the owner to close every stream, returning once it has -- or at
    /// once, when the owner is already gone and there is nothing to close.
    async fn close_streams(&self) {
        let (closed, done) = oneshot::channel();
        if self
            .commands
            .send(ConnectionCommand::Close { closed })
            .await
            .is_ok()
        {
            let _ = done.await;
        }
    }
}

/// The connections an export holds, as last published by its registry task.
type Listing = Arc<BTreeMap<String, Arc<Connection>>>;

/// One connection to list, and where to say it is visible.
struct List {
    connection: Arc<Connection>,
    listed: oneshot::Sender<()>,
}

/// The export's handle on the task that owns its connection map.
///
/// **One task owns the map; everyone else reads what it published.**  A
/// connection enters by being sent to that task, which publishes a new
/// immutable listing before it answers.  A connection *leaves* by its own
/// [`Connection::unlist`] latch: one atomic swap, so a synchronous caller
/// ([`AcpExport::shutdown`]) can take it as well as an asynchronous one, and
/// exactly one caller does.  The task is then nudged to drop the entry.  Every
/// reader treats a published connection whose latch is cleared as absent.
struct Registry {
    additions: mpsc::Sender<List>,
    published: watch::Receiver<Listing>,
    /// Nudges the owning task to drop connections that were unlisted.
    prune: Arc<Notify>,
}

impl Registry {
    /// Start the owning task.  Called from an exchange, so a runtime is
    /// running.
    fn start() -> Self {
        let (additions, inbox) = mpsc::channel(REGISTRY_QUEUE);
        let (publish, published) = watch::channel(Listing::default());
        let prune = Arc::new(Notify::new());
        tokio::spawn(own_connections(inbox, publish, Arc::clone(&prune)));
        Self {
            additions,
            published,
            prune,
        }
    }

    /// The connections as last published.  Entries may have been unlisted
    /// since.
    fn listing(&self) -> Listing {
        Arc::clone(&self.published.borrow())
    }
}

/// The registry task: the only writer of the connection map.
///
/// It ends when the last export handle is dropped, which drops every
/// connection it still listed -- and a dropped connection's supervisor ends
/// its child.
async fn own_connections(
    mut additions: mpsc::Receiver<List>,
    publish: watch::Sender<Listing>,
    prune: Arc<Notify>,
) {
    let mut connections: BTreeMap<String, Arc<Connection>> = BTreeMap::new();
    loop {
        let addition = tokio::select! {
            addition = additions.recv() => match addition {
                Some(addition) => Some(addition),
                None => return,
            },
            () = prune.notified() => None,
        };
        connections.retain(|_, connection| connection.is_listed());
        let listed = addition.map(|List { connection, listed }| {
            // A connection that ended before it could be listed is dropped
            // here rather than kept: nothing would ever nudge it out.
            if connection.is_listed() {
                connections.insert(connection.id.clone(), connection);
            }
            listed
        });
        publish.send_replace(Arc::new(connections.clone()));
        if let Some(listed) = listed {
            let _ = listed.send(());
        }
    }
}

/// One configured ACP export.
#[derive(Clone)]
pub struct AcpExport {
    inner: Arc<Inner>,
}

struct Inner {
    validated: ValidatedAcp,
    /// The live connections.  Started by the first `initialize`, because an
    /// export may be built where no runtime is running yet.
    registry: OnceLock<Registry>,
    counters: Arc<Counters>,
    next: AtomicU64,
    epoch: u64,
}

impl std::fmt::Debug for AcpExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpExport")
            .field("profile", &self.inner.validated.profile)
            .finish_non_exhaustive()
    }
}

impl AcpExport {
    /// Build an export from validated operator configuration.
    ///
    /// # Errors
    /// The first configuration rule violated.
    pub fn from_config(config: &AcpExportConfig) -> Result<Self, AcpConfigError> {
        let validated = config.validate()?;
        Ok(Self {
            inner: Arc::new(Inner {
                validated,
                registry: OnceLock::new(),
                counters: Arc::new(Counters::default()),
                next: AtomicU64::new(0),
                epoch: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_nanos() as u64),
            }),
        })
    }

    #[must_use]
    pub fn profile(&self) -> AcpProfile {
        self.inner.validated.profile
    }

    /// The selected profile's `http-forward/1` policies with this export's
    /// limits, so the device validates heads against exactly the allowlist the
    /// relay enforces.
    ///
    /// # Errors
    /// Only if the pinned profile tables are inconsistent.
    pub fn profile_policies(&self) -> Result<Profile, tunnel_http_forward::PolicyError> {
        self.inner
            .validated
            .profile
            .policies(self.inner.validated.limits)
    }

    /// Payload-free counters.
    #[must_use]
    pub fn diagnostics(&self) -> AcpDiagnostics {
        let counters = &self.inner.counters;
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        AcpDiagnostics {
            connections_opened: load(&counters.connections_opened),
            connections_closed: load(&counters.connections_closed),
            // **Acquire, and read before the measurement below.** The watchdog
            // publishes `last_expiry_*` and then releases these counters, so a
            // reader that saw the count with a relaxed load could still read a
            // stale elapsed and compare 0 against 0 — which passes, and proves
            // nothing. This pairing is what makes the measurement readable at
            // all.
            connection_subscribe_expired: counters
                .connection_subscribe_expired
                .load(Ordering::Acquire),
            session_subscribe_expired: counters.session_subscribe_expired.load(Ordering::Acquire),
            subscribers_refused: load(&counters.subscribers_refused),
            sessions_opened: load(&counters.sessions_opened),
            prompts_accepted: load(&counters.prompts_accepted),
            prompts_refused_not_ready: load(&counters.prompts_refused_not_ready),
            permissions_answered: load(&counters.permissions_answered),
            batches_refused: load(&counters.batches_refused),
            rejected: load(&counters.rejected),
            sse_events: load(&counters.sse_events),
            sse_bytes: load(&counters.sse_bytes),
            last_expiry_elapsed_us: load(&counters.last_expiry_elapsed_us),
            last_expiry_bound_us: load(&counters.last_expiry_bound_us),
            streams_lost: load(&counters.streams_lost),
            messages_dropped_on_closed_stream: load(&counters.messages_dropped_on_closed_stream),
            connections_ended_by_child: counters.connections_ended_by_child.load(Ordering::Acquire),
            child_batch_output: load(&counters.child_batch_output),
            child_invalid_output: load(&counters.child_invalid_output),
            connections_refused_at_capacity: load(&counters.connections_refused_at_capacity),
            // Acquire, and read before the measurements below, for the same
            // reason the expiry counters are: the terminating task publishes
            // the elapsed time and then releases the count, so a relaxed read
            // could see the count with a stale elapsed and compare 0 against 0.
            connections_ended_by_subscriber_loss: counters
                .connections_ended_by_subscriber_loss
                .load(Ordering::Acquire),
            permissions_cancelled_by_loss: load(&counters.permissions_cancelled_by_loss),
            output_stalls: counters.output_stalls.load(Ordering::Acquire),
            last_stall_elapsed_us: load(&counters.last_stall_elapsed_us),
            last_stall_bound_us: load(&counters.last_stall_bound_us),
            terminals_succeeded: counters.terminals_succeeded.load(Ordering::Acquire),
            terminals_cancelled: counters.terminals_cancelled.load(Ordering::Acquire),
            terminals_failed: counters.terminals_failed.load(Ordering::Acquire),
            terminals_unknown: counters.terminals_unknown.load(Ordering::Acquire),
            live_connections: self.listed().count() as u64,
        }
    }

    /// The connections this export still lists.
    fn listed(&self) -> impl Iterator<Item = Arc<Connection>> + use<> {
        let listing = self.inner.registry.get().map(Registry::listing);
        let connections: Vec<Arc<Connection>> = listing
            .iter()
            .flat_map(|listing| listing.values())
            .filter(|connection| connection.is_listed())
            .cloned()
            .collect();
        connections.into_iter()
    }

    /// The child's process id for each live connection, so a test can read the
    /// process table rather than a counter.
    #[must_use]
    pub fn child_pids(&self) -> Vec<u32> {
        self.listed()
            .filter_map(|connection| connection.supervisor.pid())
            .collect()
    }

    /// End every connection this export holds, draining each child and
    /// signalling its process group.
    ///
    /// Dropping the export's last handle does the same through the
    /// supervisor's own `Drop`; this is the explicit form, for a connector
    /// that stops its handlers before dropping them.  Idempotent.
    ///
    /// **Exactly what this call unlisted is ended and counted** (M8-C33).
    /// This used to snapshot the map and clear it in two steps, then count
    /// every snapshot entry, so a connection [`Self::remove`]d between the two
    /// was counted closed twice, and one inserted between them was cleared
    /// without being killed or counted.  Each connection now leaves by its own
    /// latch, which one caller wins: a connection another path is ending is
    /// not counted here, and one listed after this pass is still listed.  No
    /// ending counter is released here, so the ordering rule on `remove` has
    /// nothing further to order.
    pub fn shutdown(&self) {
        let Some(registry) = self.inner.registry.get() else {
            return;
        };
        for connection in registry.listing().values() {
            if !connection.unlist() {
                continue;
            }
            // Cancelling is what closes the connection's streams: their owner
            // stops serving and drops them as soon as it observes this.
            connection.shutdown.cancel();
            connection.supervisor.kill();
            self.inner
                .counters
                .connections_closed
                .fetch_add(1, Ordering::Relaxed);
        }
        registry.prune.notify_one();
    }

    /// Whether a new connection for `binding` fits under **both** caps.
    fn has_room_for(&self, binding: Option<&String>) -> bool {
        let (mut live, mut held) = (0, 0);
        for connection in self.listed() {
            live += 1;
            if connection.principal.as_ref() == binding {
                held += 1;
            }
        }
        admits(live, held)
    }

    fn connection(&self, id: &str) -> Option<Arc<Connection>> {
        self.inner
            .registry
            .get()?
            .listing()
            .get(id)
            .filter(|connection| connection.is_listed())
            .cloned()
    }

    /// List a connection, returning once a lookup can find it.
    ///
    /// The connection's own tasks are already running when this is called,
    /// so an exchange dropped while it waits here leaves a connection that
    /// still expires, rather than a listed child nothing watches.
    async fn list(&self, connection: Arc<Connection>) {
        let registry = self.inner.registry.get_or_init(Registry::start);
        let (listed, visible) = oneshot::channel();
        let addition = List { connection, listed };
        if registry.additions.send(addition).await.is_ok() {
            let _ = visible.await;
        }
    }

    /// Take a connection out of the export, counting it closed once.
    ///
    /// **Call this before releasing the counter that announces why the
    /// connection ended.** A reader waits on that counter (`output_stalls`,
    /// `connection_subscribe_expired`, `connections_ended_by_child`,
    /// `connections_ended_by_subscriber_loss`) with an `Acquire` load and then
    /// reads `live_connections`, which counts only connections whose latch is
    /// still set, so an unlisting sequenced before the `Release` is
    /// guaranteed visible to it. Released first, the count announced an ended
    /// connection that was still listed live, and a reader that landed in the
    /// gap saw both (M8-C31). Idempotent: a second call finds the latch
    /// already cleared and counts nothing, and a caller that gets `false`
    /// back did not end the connection and must not count an ending for it
    /// (M8-C32).  It takes the connection rather than its identifier, so it
    /// does not matter whether the listing has been published yet.
    ///
    /// [`Self::shutdown`] is the one path that does not call this: it clears
    /// the same latch for every listed connection and counts exactly the ones
    /// it cleared (M8-C33).
    fn remove(&self, connection: &Connection) -> bool {
        if !connection.unlist() {
            return false;
        }
        self.inner
            .counters
            .connections_closed
            .fetch_add(1, Ordering::Relaxed);
        if let Some(registry) = self.inner.registry.get() {
            registry.prune.notify_one();
        }
        true
    }

    /// Serve one exchange in process.
    ///
    /// # Errors
    /// [`ExportError`] when the exchange must be interrupted rather than
    /// answered.
    pub async fn handle(
        &self,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let (parts, body) = request.into_parts();
        match parts.method {
            http::Method::POST => self.post(&parts.headers, body).await,
            http::Method::GET => Ok(self.get(&parts.headers).await),
            http::Method::DELETE => Ok(self.delete(&parts.headers).await),
            // The codec routes only these three; anything else never reaches
            // the handler.  Answering rather than panicking keeps a future
            // routing mistake a 405 instead of a killed exchange.
            _ => Ok(no_body(StatusCode::METHOD_NOT_ALLOWED)),
        }
    }

    fn refuse(&self, rejection_value: &AcpRejection) -> Response<ExportBody> {
        self.inner.counters.rejected.fetch_add(1, Ordering::Relaxed);
        if rejection_value.rule == AcpRule::BatchNotSupported {
            self.inner
                .counters
                .batches_refused
                .fetch_add(1, Ordering::Relaxed);
        }
        rejection(rejection_value)
    }

    async fn post(
        &self,
        headers: &http::HeaderMap,
        body: ChannelBody,
    ) -> Result<Response<ExportBody>, ExportError> {
        let limit = self.inner.validated.limits.request_body();
        let Ok(bytes) = collect_limited(body, limit).await else {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"request body exceeds the configured limit\"},\"id\":null}"),
            ));
        };
        // Buffered and fully validated before anything is dispatched to a
        // child: a batch is refused here, by its own rule and its own 501.
        let message = match validate_post(headers, &bytes) {
            Ok(message) => message,
            Err(rejected) => return Ok(self.refuse(&rejected)),
        };
        if message.is_initialize() {
            return self.initialize(headers, message).await;
        }
        let Some(id) = header(headers, tunnel_acp::headers::ACP_CONNECTION_ID) else {
            // `validate_post` already required it; this is the unreachable
            // half of the same rule, answered rather than unwrapped.
            return Ok(self.refuse(&AcpRejection::new(
                AcpRule::ConnectionHeaderRequired,
                "Acp-Connection-Id is required",
            )));
        };
        let Some(connection) = self.connection(&id) else {
            return Ok(not_found());
        };
        if connection.principal != principal_binding(headers) {
            // The binding is compared, never interpreted and never derived
            // here.  In this chunk both sides are `None`.
            return Ok(not_found());
        }
        self.dispatch(&connection, headers, message).await
    }

    async fn initialize(
        &self,
        headers: &http::HeaderMap,
        message: AcpMessage,
    ) -> Result<Response<ExportBody>, ExportError> {
        let validated = &self.inner.validated;
        // **The capacity decision is taken before the child is spawned**, so
        // the export never starts an agent it could not track, and a refusal
        // costs a would-be attacker a process nobody created.  Refuse, never
        // evict: see [`MAX_TRACKED_CONNECTIONS`].
        let binding = principal_binding(headers);
        if !self.has_room_for(binding.as_ref()) {
            self.inner
                .counters
                .connections_refused_at_capacity
                .fetch_add(1, Ordering::Relaxed);
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32002,\"message\":\"the export is at its connection limit\"},\"id\":null}"),
            ));
        }
        let sequence = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("acp-{:016x}-{sequence:x}", self.inner.epoch);
        let scope = ConnectionScope {
            // There is no tenant, principal or device identity in the
            // in-process bridge.  These are the *scope* of a JSON-RPC id, not
            // an authorization claim, and they are fixed synthetic values here
            // so that two connections still scope their ids apart by the one
            // identifier this chunk actually has.
            tenant: "in-process".to_owned(),
            principal: binding.clone().unwrap_or_else(|| "none".to_owned()),
            device: "in-process".to_owned(),
            service: "acp".to_owned(),
            connection: id.clone(),
        };
        let mut supervisor_config = SupervisorConfig::new(validated.child.clone(), scope);
        supervisor_config.permission_timeout = validated.permission_timeout;
        supervisor_config.session_limit = validated.session_limit;

        let (forward_tx, forward_rx) = mpsc::channel(STREAM_BACKLOG);
        let outbound = forward_tx.downgrade();
        let Ok((supervisor, mut events)) =
            Supervisor::start_forwarding(supervisor_config, Some(forward_tx))
        else {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"the configured agent could not be started\"},\"id\":null}"),
            ));
        };
        // The diagnostic channel must be drained or the reader blocks; the
        // bridge has no use for it beyond that, and it carries no payload.
        tokio::spawn(async move { while events.recv().await.is_some() {} });

        let params = message
            .value
            .get("params")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let result = match supervisor.initialize_with(params).await {
            Ok(result) => result,
            Err(_) => {
                supervisor.drain().await;
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"the agent did not complete initialization\"},\"id\":null}"),
                ));
            }
        };
        // The agent's own negotiated version, refused by the pinned profile's
        // rule if it is not 1 — in the **result** as well as the request.
        if let Err(rejected) = check_result_version(&result) {
            supervisor.drain().await;
            return Ok(self.refuse(&rejected));
        }

        let stream = Target::new();
        let (commands, inbox) = mpsc::channel(CONNECTION_COMMAND_QUEUE);
        let connection = Arc::new(Connection {
            id: id.clone(),
            supervisor,
            principal: binding,
            workspace: validated.workspace.to_string_lossy().into_owned(),
            limits: validated.limits,
            connection_subscribe_deadline: validated.connection_subscribe_deadline,
            session_subscribe_deadline: validated.session_subscribe_deadline,
            commands,
            stream: stream.tx.clone(),
            listed: AtomicBool::new(true),
            counters: Arc::clone(&self.inner.counters),
            shutdown: CancellationToken::new(),
            outbound,
        });
        self.inner
            .counters
            .connections_opened
            .fetch_add(1, Ordering::Relaxed);

        tokio::spawn(dispatch_outbound(
            self.clone(),
            Arc::clone(&connection),
            forward_rx,
            validated.output_stall_deadline,
        ));
        tokio::spawn(own_connection(
            self.clone(),
            Arc::clone(&connection),
            ConnectionState::new(stream),
            inbox,
        ));
        // Listed after its tasks exist and before the identifier is
        // returned: no request can name this connection until it is visible.
        self.list(Arc::clone(&connection)).await;

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": message.id.clone().unwrap_or(Value::Null),
            "result": result,
        }))
        .unwrap_or_default();
        let mut response = json_response(StatusCode::OK, Bytes::from(body));
        if let Ok(value) = http::HeaderValue::from_str(&id) {
            response.headers_mut().insert(
                http::HeaderName::from_static(tunnel_acp::headers::ACP_CONNECTION_ID),
                value,
            );
        }
        Ok(response)
    }

    async fn dispatch(
        &self,
        connection: &Arc<Connection>,
        headers: &http::HeaderMap,
        message: AcpMessage,
    ) -> Result<Response<ExportBody>, ExportError> {
        let params = message
            .value
            .get("params")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match message.kind {
            MessageKind::Response => self.answer_permission(connection, &message).await,
            MessageKind::Notification | MessageKind::Request => {
                match message.method.as_deref() {
                    Some("session/new") => {
                        Ok(self.new_session(connection, &message, params).await)
                    }
                    Some("session/prompt") => {
                        Ok(self.prompt(connection, &message, headers, params).await)
                    }
                    Some("session/cancel") => {
                        let session = header(headers, tunnel_acp::headers::ACP_SESSION_ID)
                            .or_else(|| message.session_id().map(ToOwned::to_owned));
                        if let Some(session) = session {
                            let _ = connection.supervisor.cancel_session(&session, params).await;
                        }
                        Ok(no_body(StatusCode::ACCEPTED))
                    }
                    // `session/load` is an accepted method of the profile but
                    // has no policy yet: `docs/acp.md` requires an authorized
                    // stored session/workspace mapping and a negotiated
                    // capability before cross-connection loading. Refusing is
                    // the honest answer; forwarding it would be a claim.
                    Some(_) | None => Ok(json_response(
                        StatusCode::NOT_IMPLEMENTED,
                        Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"this method is not carried by this export\"},\"id\":null}"),
                    )),
                }
            }
        }
    }

    async fn new_session(
        &self,
        connection: &Arc<Connection>,
        message: &AcpMessage,
        params: Value,
    ) -> Response<ExportBody> {
        // The host cannot select a working directory: `docs/acp.md` requires
        // `cwd` to be the configured workspace, and a mismatch is refused
        // before anything reaches the agent.  Empty `mcpServers` only.
        if params.get("cwd").and_then(Value::as_str) != Some(connection.workspace.as_str())
            || !params
                .get("mcpServers")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        {
            return json_response(
                StatusCode::BAD_REQUEST,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"cwd must be the configured workspace and mcpServers must be empty\"},\"id\":null}"),
            );
        }
        let host_id = message.id.clone().unwrap_or(Value::Null);
        let connection = Arc::clone(connection);
        let counters = Arc::clone(&self.inner.counters);
        // 202 now; the result travels on the connection GET.
        tokio::spawn(async move {
            let Ok(session) = connection.supervisor.new_session_with(params).await else {
                return;
            };
            counters.sessions_opened.fetch_add(1, Ordering::Relaxed);
            // Create the queue before publishing the identifier, so a host
            // that opens the session GET the instant it reads the result finds
            // a stream, and so anything the agent already said is in it.
            let _ = connection.route(Some(&session)).await;
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": host_id,
                "result": {"sessionId": session},
            }))
            .unwrap_or_default();
            let _ = connection.stream.send(Bytes::from(body)).await;
        });
        no_body(StatusCode::ACCEPTED)
    }

    async fn prompt(
        &self,
        connection: &Arc<Connection>,
        message: &AcpMessage,
        headers: &http::HeaderMap,
        params: Value,
    ) -> Response<ExportBody> {
        let Some(session) = header(headers, tunnel_acp::headers::ACP_SESSION_ID) else {
            return self.refuse(&AcpRejection::new(
                AcpRule::SessionHeaderRequired,
                "this method is session-scoped and requires Acp-Session-Id",
            ));
        };
        if !connection.supervisor.has_session(&session).await {
            return not_found();
        }
        let ticket = match connection.supervisor.prompt_with(&session, params).await {
            Ok(ticket) => ticket,
            Err(error) => {
                if error.rule() == Some(LifecycleRule::SessionNotReady) {
                    self.inner
                        .counters
                        .prompts_refused_not_ready
                        .fetch_add(1, Ordering::Relaxed);
                }
                return supervisor_refusal(&error);
            }
        };
        self.inner
            .counters
            .prompts_accepted
            .fetch_add(1, Ordering::Relaxed);
        let host_id = message.id.clone().unwrap_or(Value::Null);
        let connection = Arc::clone(connection);
        // Taken now, while the child is alive and the reader still holds its
        // own sender, so the upgrade succeeds for every prompt that could
        // still be answered (M8-C27).
        let ordered = connection.outbound.upgrade();
        let stall_deadline = self.inner.validated.output_stall_deadline;
        tokio::spawn(async move {
            // The session's queue, asked for now: `None` when that stream is
            // already over, in which case there is nowhere left for the
            // fallback below to deliver.
            let target = match connection.route(Some(&session)).await {
                Routing::ConnectionClosed => return,
                Routing::Over => None,
                Routing::Open(queue) => Some(queue),
            };
            // `stop_reason` runs the pinned crate's own v1 turn-completion
            // reader: a v2 acknowledgement with no `stopReason` is refused by
            // its own rule rather than delivered as a finished turn.
            let body = match ticket.completion().await {
                Ok((terminal, stop)) => {
                    // The export classifies the turn it just finished, through
                    // the one rule that decides terminals.
                    record_terminal(&connection.counters, terminal);
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": host_id,
                        "result": {"stopReason": stop},
                    }))
                }
                Err(error) => {
                    // The child is gone, or its answer was refused, with the
                    // prompt already dispatched: `docs/acp.md` marks dispatched
                    // unresolved work `outcome_unknown`.
                    record_terminal(
                        &connection.counters,
                        tunnel_acp::terminal::AcpTerminal::LostAfterDispatch,
                    );
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": host_id,
                        "error": {"code": -32603, "message": error.to_string()},
                    }))
                }
            }
            .unwrap_or_default();
            // **Behind the turn's own updates** (M8-C27), on both paths: the
            // reader queued every earlier agent message on this channel before
            // it resolved the waiter this task just woke from, so the
            // dispatcher delivers them first and applies the same stall and
            // loss rules to the result or the error.  Only when the dispatcher
            // is already gone -- the connection closed -- is the body handed
            // to the stream's queue directly, still bounded by the stall
            // deadline, and whether anything still reads that queue decides.
            let body = match ordered {
                Some(ordered) => match ordered
                    .send(OutboundMessage {
                        session: Some(session.clone()),
                        kind: MessageKind::Response,
                        compact: body,
                    })
                    .await
                {
                    Ok(()) => return,
                    Err(mpsc::error::SendError(unsent)) => unsent.compact,
                },
                None => body,
            };
            if let Some(queue) = target {
                let _ = tokio::time::timeout(stall_deadline, queue.send(Bytes::from(body))).await;
            }
        });
        no_body(StatusCode::ACCEPTED)
    }

    async fn answer_permission(
        &self,
        connection: &Arc<Connection>,
        message: &AcpMessage,
    ) -> Result<Response<ExportBody>, ExportError> {
        let Some(id) = message.id.as_ref().and_then(request_id) else {
            return Ok(self.refuse(&AcpRejection::new(
                AcpRule::RequestId,
                "a response must carry the id of the request it answers",
            )));
        };
        let Some(outcome) = permission_outcome(&message.value) else {
            return Ok(self.refuse(&AcpRejection::new(
                AcpRule::NotJsonRpcMessage,
                "a permission response must carry result.outcome",
            )));
        };
        match connection.supervisor.answer_permission(&id, outcome).await {
            Ok(()) => {
                self.inner
                    .counters
                    .permissions_answered
                    .fetch_add(1, Ordering::Relaxed);
                Ok(no_body(StatusCode::ACCEPTED))
            }
            Err(error) => Ok(supervisor_refusal(&error)),
        }
    }

    async fn get(&self, headers: &http::HeaderMap) -> Response<ExportBody> {
        if let Err(rejected) = validate_get(headers) {
            return self.refuse(&rejected);
        }
        let Some(id) = header(headers, tunnel_acp::headers::ACP_CONNECTION_ID) else {
            return not_found();
        };
        let Some(connection) = self.connection(&id) else {
            return not_found();
        };
        if connection.principal != principal_binding(headers) {
            return not_found();
        }
        let session = header(headers, tunnel_acp::headers::ACP_SESSION_ID);
        if let Some(session) = &session
            && !connection.supervisor.has_session(session).await
        {
            return not_found();
        }
        let bytes = Arc::new(AtomicU64::new(0));
        let (sender, body) =
            ChannelResponseBody::channel(connection.limits.sse_response_body(), bytes);
        // A clone of the body's sender goes with the request to subscribe, so
        // the connection's watchdog can see this stream break even if the
        // agent never sends another message. Without it, a broken stream on a
        // quiet connection is invisible until the next write.
        let queue = match connection.subscribe(session.clone(), sender.clone()).await {
            Subscription::Granted(queue) => queue,
            Subscription::ConnectionClosed if session.is_some() => return not_found(),
            Subscription::Refused | Subscription::ConnectionClosed => {
                // The one-subscriber rule, and it is structural: there is
                // nothing left to take.
                self.inner
                    .counters
                    .subscribers_refused
                    .fetch_add(1, Ordering::Relaxed);
                return no_body(StatusCode::CONFLICT);
            }
        };
        if let Some(session) = &session {
            // A session admits its prompt only once its subscriber is ready,
            // and this is the moment it becomes so.
            let _ = connection.supervisor.subscriber_ready(session).await;
        }
        tokio::spawn(pump_stream(
            queue,
            sender,
            Arc::clone(&self.inner.counters),
            connection.shutdown.clone(),
        ));
        let mut response = Response::new(sse::stream_body(body));
        *response.status_mut() = StatusCode::OK;
        sse_head(&mut response, &connection.id);
        response
    }

    async fn delete(&self, headers: &http::HeaderMap) -> Response<ExportBody> {
        if let Err(rejected) = validate_delete(headers) {
            return self.refuse(&rejected);
        }
        let Some(id) = header(headers, tunnel_acp::headers::ACP_CONNECTION_ID) else {
            return not_found();
        };
        let Some(connection) = self.connection(&id) else {
            return not_found();
        };
        if connection.principal != principal_binding(headers) {
            return not_found();
        }
        self.remove(&connection);
        // 202: accepted by the bridge.  Teardown — cancelling outstanding
        // permissions, killing the child's process group, reaping it — is not
        // finished when this status is written, which is exactly what
        // `docs/acp.md` says 202 means.
        close_connection(&connection).await;
        no_body(StatusCode::ACCEPTED)
    }
}

/// Route one agent→host message to the stream it belongs on, in the order the
/// agent wrote it.
///
/// **One lost subscriber closes one stream, and nothing else.** This task is
/// the connection's only reader of the supervisor's forward channel, so
/// returning from it stops every stream on the connection at once and hangs
/// every outstanding prompt — which is what it used to do on the first failed
/// send. A target whose body has gone away is marked closed and its messages
/// are dropped; the loop carries on.
///
/// **Subscriber loss on an *established* stream ends the transport** (M8 chunk
/// 4), which is `docs/acp.md`'s documented v0 policy and was M8-03's open half.
/// Chunk 3 deliberately kept the connection alive here, because the behaviour it
/// was replacing — the first failed send silently disabling every other stream
/// and hanging every prompt until DELETE — was worse than either policy. That
/// was a stopgap and said so. The policy is now implemented: see
/// [`end_with_subscriber_loss`]. A target that never had a subscriber is *not*
/// this rule; that is a subscription deadline.
///
/// **The output-credit stall is terminal, and the event is never skipped.**
/// `docs/acp.md`: "Output credit stall | 30 seconds, then cancel/close; never
/// drop an event and continue." A bridge that dropped the message and carried
/// on would leave a hole in a stream with no `Last-Event-ID` replay to fill it,
/// and the consumer could not tell. So a stall ends the connection with the
/// message still unsent.
async fn dispatch_outbound(
    export: AcpExport,
    connection: Arc<Connection>,
    mut inbox: mpsc::Receiver<OutboundMessage>,
    stall_deadline: Duration,
) {
    let bound_us = u64::try_from(stall_deadline.as_micros()).unwrap_or(u64::MAX);
    while let Some(message) = inbox.recv().await {
        let queue = match connection.route(message.session.as_deref()).await {
            Routing::Open(queue) => queue,
            // The connection itself is closed; there is nothing left to
            // route a session's message to and the child is on its way out.
            Routing::ConnectionClosed if message.session.is_some() => return,
            Routing::Over | Routing::ConnectionClosed => {
                connection
                    .counters
                    .messages_dropped_on_closed_stream
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let waited = Instant::now();
        match tokio::time::timeout(stall_deadline, queue.send(Bytes::from(message.compact))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                // The body went away while this message was queued: the
                // established stream broke.
                let established = connection.stream_lost(message.session.as_deref()).await;
                connection
                    .counters
                    .streams_lost
                    .fetch_add(1, Ordering::Relaxed);
                // **A latency path, not a separate rule.** The connection's
                // watchdog notices the same break within a tick, and a
                // guard-deletion run confirmed that removing this branch
                // reddens nothing. It is kept because ending at the moment a
                // message could not be delivered is better than ending up to
                // a tick later, not because anything depends on it.
                if established {
                    end_with_subscriber_loss(&export, &connection).await;
                    close_connection(&connection).await;
                    return;
                }
            }
            Err(_) => {
                // The stall bound elapsed with no room. Publish the
                // measurement **before** the counter a reader waits on, for
                // the same reason the expiry measurements are ordered that
                // way, then end the connection. `message.compact` was moved
                // into the send future and is gone with it: nothing here
                // skips it and continues.
                let elapsed = u64::try_from(waited.elapsed().as_micros()).unwrap_or(u64::MAX);
                // Out of the listing before the counter: see
                // [`AcpExport::remove`].
                export.remove(&connection);
                connection
                    .counters
                    .last_stall_elapsed_us
                    .store(elapsed, Ordering::Relaxed);
                connection
                    .counters
                    .last_stall_bound_us
                    .store(bound_us, Ordering::Relaxed);
                connection
                    .counters
                    .output_stalls
                    .fetch_add(1, Ordering::Release);
                end_with_subscriber_loss(&export, &connection).await;
                close_connection(&connection).await;
                return;
            }
        }
    }
}

/// End a connection because an established required SSE stream broke, or
/// because output credit stalled past its bound.
///
/// `docs/acp.md`: "Once an established required SSE stream breaks, terminate
/// that ACP transport connection in v0: refuse new prompts, resolve pending
/// permissions as cancelled, request cancellation of active turns, close
/// streams, and clean up the child. A reconnect must initialize anew."
///
/// Each of those five is a separate consequence and each is done here:
///
/// 1. **New prompts are refused** — the connection leaves the export's map
///    first, so a later POST finds nothing and is answered 404.
/// 2. **Pending permissions resolve `cancelled`** — never approved, and the
///    agent is told on the wire while it is still alive to hear it.
/// 3. **Active turns are asked to cancel** — a real `session/cancel` per open
///    session, sent *before* the child is killed, because the policy says
///    request cancellation rather than merely stop.
/// 4. **Streams close** — every open body is failed, not ended cleanly. That
///    step is the caller's, because who may close a connection's streams
///    depends on who is asking: the task that owns them closes them itself,
///    and any other task asks it to ([`close_connection`]).
/// 5. **A reconnect must initialize anew** — there is no connection left to
///    reattach to, which is the same fact as (1) seen from the GET side.
async fn end_with_subscriber_loss(export: &AcpExport, connection: &Arc<Connection>) {
    // (1) and (5): out of the map before anything slow happens, so no further
    // work is admitted while the teardown runs.
    export.remove(connection);
    // (2): resolve, count, and tell the agent.
    let cancelled = connection.supervisor.cancel_all_permissions().await;
    connection
        .counters
        .permissions_cancelled_by_loss
        .fetch_add(cancelled as u64, Ordering::Relaxed);
    // (3): ask each open turn to cancel before the child is killed. A child
    // that is about to be killed cannot answer, which is exactly why this is a
    // request and not a claim that the turn ended cleanly.
    for session in connection.supervisor.open_sessions().await {
        let _ = connection
            .supervisor
            .cancel_session(&session, json!({"sessionId": session}))
            .await;
    }
    connection
        .counters
        .connections_ended_by_subscriber_loss
        .fetch_add(1, Ordering::Release);
}

/// Drain one stream's queue into its SSE body, framing each message.
async fn pump_stream(
    mut queue: mpsc::Receiver<Bytes>,
    sender: StreamSender,
    counters: Arc<Counters>,
    shutdown: CancellationToken,
) {
    loop {
        let compact = tokio::select! {
            () = shutdown.cancelled() => {
                // A connection that ended while a stream was open fails the
                // body rather than ending it cleanly: `docs/acp.md` refuses to
                // let a broken ACP stream look like an orderly one.
                sender.fail(StreamFailure::Interrupted).await;
                return;
            }
            message = queue.recv() => message,
        };
        let Some(compact) = compact else {
            // The queue ended.  **Which ending that is depends on why**, and
            // the two must not be confused: a connection that was closed ends
            // its targets and then drops them, so the queue running dry *after*
            // the shutdown signal is a broken stream, not an orderly one. A
            // `select!` that happened to pick this branch first would otherwise
            // deliver a clean end of stream for a transport that failed.
            if shutdown.is_cancelled() {
                sender.fail(StreamFailure::Interrupted).await;
            }
            return;
        };
        let event = sse_event(&compact);
        counters.sse_events.fetch_add(1, Ordering::Relaxed);
        counters
            .sse_bytes
            .fetch_add(event.len() as u64, Ordering::Relaxed);
        if sender.send(event).await.is_err() {
            return;
        }
    }
}

/// Serve the connection's commands until `work` finishes.
///
/// The owner of a connection's streams must keep answering while it does
/// anything slow.  The dispatcher asks it where each message goes, and a
/// dispatcher left waiting stops draining the supervisor's forward channel,
/// which stops the supervisor's reader, which is the very task a teardown is
/// waiting on to hear the child.
async fn serve_while<W: Future>(
    state: &mut ConnectionState,
    inbox: &mut mpsc::Receiver<ConnectionCommand>,
    shutdown: &CancellationToken,
    work: W,
) -> W::Output {
    let mut work = std::pin::pin!(work);
    loop {
        tokio::select! {
            output = &mut work => return output,
            Some(command) = inbox.recv() => state.serve(command, shutdown),
        }
    }
}

/// The owner's own close: fail every open body, drop the streams, stop
/// answering, and drain the child.
async fn close_owned(
    connection: &Connection,
    mut state: ConnectionState,
    inbox: mpsc::Receiver<ConnectionCommand>,
) {
    // Every open body is failed rather than ended cleanly: `docs/acp.md`
    // refuses to let a broken ACP stream look like an orderly one, so a
    // consumer sees an error and not an end of stream.  Cancelled before the
    // streams are dropped, so a pump that finds its queue ended reads the
    // cancellation with it.
    connection.shutdown.cancel();
    state.close();
    // A command still queued, or sent later, finds its reply dropped and
    // reads that as a closed connection.
    drop(inbox);
    connection.supervisor.drain().await;
}

/// One connection's owning task: it holds the connection's streams, answers
/// the other tasks' questions about them, and is the watchdog that reads the
/// clock.
///
/// The deadlines are **measured**, not assumed: the elapsed time one actually
/// ran is recorded with the bound it exceeded, so a test reads what happened
/// rather than the constant it was configured with.
///
/// **The streams are never dropped before `shutdown` is cancelled.**  A
/// stream's pump reads an ended queue as an orderly end of stream unless the
/// cancellation is already visible, so every path out of this task either
/// follows a cancellation or cancels first.
async fn own_connection(
    export: AcpExport,
    connection: Arc<Connection>,
    mut state: ConnectionState,
    mut inbox: mpsc::Receiver<ConnectionCommand>,
) {
    // **Two windows, two bounds (M8-C12).** One configured value used to
    // bound both, so shortening the session window shortened the connection
    // window with it.
    let connection_bound = connection.connection_subscribe_deadline;
    let connection_bound_us = u64::try_from(connection_bound.as_micros()).unwrap_or(u64::MAX);
    let session_bound = connection.session_subscribe_deadline;
    let session_bound_us = u64::try_from(session_bound.as_micros()).unwrap_or(u64::MAX);
    let mut ticker = tokio::time::interval(WATCHDOG_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // A connection that was closed or shut down has no streams to own.
        if connection.shutdown.is_cancelled() {
            return;
        }
        tokio::select! {
            () = connection.shutdown.cancelled() => return,
            command = inbox.recv() => {
                // Never `None`: this task holds the connection, which holds
                // a sender.
                if let Some(command) = command
                    && !connection.shutdown.is_cancelled()
                {
                    state.serve(command, &connection.shutdown);
                }
                continue;
            }
            // **A child that is gone ends its transport.** `docs/acp.md`: "A
            // child crash closes the transport and invalidates live sessions."
            // Without this the connection would stay listed with a dead child
            // behind it until someone sent a DELETE, and every open stream
            // would hang without an ending. A child can end for reasons that
            // are the profile's own — a batch, a malformed line, an oversized
            // line, each of which kills it by its own `AcpRule` — so this is
            // the path those refusals reach the host on.
            () = connection.supervisor.wait_exited() => {
                if end_with_child(&export, &connection) {
                    close_owned(&connection, state, inbox).await;
                } else {
                    // Some other ending owns this teardown and will cancel
                    // `shutdown` when it closes the connection.  The streams
                    // stay owned, and answered for, until it does.
                    serve_while(
                        &mut state,
                        &mut inbox,
                        &connection.shutdown,
                        connection.shutdown.cancelled(),
                    )
                    .await;
                }
                return;
            }
            _ = ticker.tick() => {}
        }
        // **An established required stream that broke ends the transport**, and
        // it is checked here so that a connection whose agent has gone quiet
        // still notices. Both the connection stream and every session stream
        // are required; `docs/acp.md` asks each to be broken independently and
        // each has the same consequence.
        if state.any_established_and_broken() {
            serve_while(
                &mut state,
                &mut inbox,
                &connection.shutdown,
                end_with_subscriber_loss(&export, &connection),
            )
            .await;
            close_owned(&connection, state, inbox).await;
            return;
        }
        if let Some(waited) = state.connection_unsubscribed_past(connection_bound) {
            let elapsed = u64::try_from(waited.as_micros()).unwrap_or(u64::MAX);
            // The measurement is published **before** the counter that makes it
            // findable. A reader that sees the count and then reads a stale
            // elapsed would compare 0 against 0 and pass; that is not the
            // observation this is for. The connection leaves the listing
            // before either, for the reason [`AcpExport::remove`] gives.
            export.remove(&connection);
            connection
                .counters
                .last_expiry_elapsed_us
                .store(elapsed, Ordering::Relaxed);
            connection
                .counters
                .last_expiry_bound_us
                .store(connection_bound_us, Ordering::Relaxed);
            connection
                .counters
                .connection_subscribe_expired
                .fetch_add(1, Ordering::Release);
            close_owned(&connection, state, inbox).await;
            return;
        }
        // **An expiry is counted once**: `expire_sessions` closes each stream
        // it reports, and a stream that is over never matches again, so
        // `session_subscribe_expired` counts expiries and not ticks, and the
        // measurement pair below belongs to the expiry rather than to an
        // arbitrary later tick (M8-C25).
        for waited in state.expire_sessions(session_bound) {
            let elapsed = u64::try_from(waited.as_micros()).unwrap_or(u64::MAX);
            // Published before the counter, for the reason above.
            connection
                .counters
                .last_expiry_elapsed_us
                .store(elapsed, Ordering::Relaxed);
            connection
                .counters
                .last_expiry_bound_us
                .store(session_bound_us, Ordering::Relaxed);
            connection
                .counters
                .session_subscribe_expired
                .fetch_add(1, Ordering::Release);
        }
    }
}

/// Record that a connection ended because its child did, folding the child's
/// own refusal counters in first so they outlive the connection that carried
/// them.  `true` when this call is the one that ended the connection, and the
/// caller must then close it.
fn end_with_child(export: &AcpExport, connection: &Arc<Connection>) -> bool {
    // Out of the listing before the counter a reader waits on is released,
    // for the reason [`AcpExport::remove`] gives.
    //
    // **And only if this call is the one that removed it** (M8-C32). Every
    // other ending — a stall, a lost subscriber, an expiry, a DELETE,
    // `shutdown` — removes the connection and then kills the child in
    // `close_connection`, which cancels `shutdown` first and kills second. A
    // watchdog whose `select!` wakes with both of those ready may take this
    // branch for a connection the child did not end, and it used to count
    // `connections_ended_by_child` for it regardless.
    if !export.remove(connection) {
        return false;
    }
    let child = connection.supervisor.diagnostics();
    connection
        .counters
        .child_batch_output
        .fetch_add(child.batch_output, Ordering::Relaxed);
    connection
        .counters
        .child_invalid_output
        .fetch_add(child.invalid_output, Ordering::Relaxed);
    // Published before the counter a reader waits on, for the same reason the
    // deadline measurements are.
    connection
        .counters
        .connections_ended_by_child
        .fetch_add(1, Ordering::Release);
    true
}

/// Close a connection from a task that does not own its streams: ask the
/// owner to close them, then fail every open body and drain the child.
async fn close_connection(connection: &Arc<Connection>) {
    connection.close_streams().await;
    // Every open body is failed rather than ended cleanly: `docs/acp.md`
    // refuses to let a broken ACP stream look like an orderly one, so a
    // consumer sees an error and not an end of stream.
    connection.shutdown.cancel();
    connection.supervisor.drain().await;
}

fn not_found() -> Response<ExportBody> {
    json_response(
        StatusCode::NOT_FOUND,
        Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"no such connection or session\"},\"id\":null}"),
    )
}

/// The HTTP answer for a lifecycle refusal.
///
/// A refusal is a *bridge* outcome and may terminate on a status: nothing was
/// dispatched to an agent, so there is no later message for it to anchor to.
/// The claims that must not terminate on a status are the ones about a prompt,
/// a session or a permission having happened.
fn supervisor_refusal(error: &SupervisorError) -> Response<ExportBody> {
    let (status, code) = match error.rule() {
        Some(LifecycleRule::UnknownRequestId | LifecycleRule::UnknownSession) => {
            (StatusCode::NOT_FOUND, -32001)
        }
        Some(LifecycleRule::SessionLimit | LifecycleRule::PendingLimit) => {
            (StatusCode::TOO_MANY_REQUESTS, -32002)
        }
        Some(_) => (StatusCode::CONFLICT, -32003),
        None => (StatusCode::SERVICE_UNAVAILABLE, -32603),
    };
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {"code": code, "message": error.to_string()},
    }))
    .unwrap_or_default();
    json_response(status, Bytes::from(body))
}

fn header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The opaque per-principal binding the relay ingress derived, or `None`.
///
/// The device never interprets the value and never derives one: it compares it
/// for equality with the value the connection was opened with.  A deployment
/// with no relay ingress in front of the export — every test in this chunk —
/// has no authenticated principal at all, so every request carries `None`,
/// which binds a connection to "no principal" and still refuses any other
/// value.  This is the same sentence `tunnel_mcp_export` records for M3-04,
/// and it is deliberately not a claim of principal binding.
fn principal_binding(headers: &http::HeaderMap) -> Option<String> {
    header(headers, tunnel_acp::headers::TUNNEL_PRINCIPAL_BINDING)
}

fn request_id(value: &Value) -> Option<RequestId> {
    match value {
        Value::String(text) => Some(RequestId::Text(text.clone())),
        Value::Number(number) => number.as_i64().map(RequestId::Number),
        _ => None,
    }
}

fn permission_outcome(message: &Value) -> Option<PermissionOutcome> {
    let outcome = message.pointer("/result/outcome")?;
    match outcome.get("outcome").and_then(Value::as_str)? {
        "selected" => outcome
            .get("optionId")
            .and_then(Value::as_str)
            .map(|option| PermissionOutcome::Selected(option.to_owned())),
        "cancelled" => Some(PermissionOutcome::Cancelled),
        _ => None,
    }
}

/// The agent's `initialize` result must negotiate version 1.
fn check_result_version(result: &Value) -> Result<(), AcpRejection> {
    let Some(version) = result.get("protocolVersion") else {
        return Err(AcpRejection::new(
            AcpRule::ProtocolVersionShape,
            "protocolVersion is required",
        ));
    };
    tunnel_acp::message::negotiate_protocol_version(version).map(|_| ())
}

async fn collect_limited(body: ChannelBody, limit: u64) -> Result<Bytes, ()> {
    use http_body_util::BodyExt;
    let mut body = std::pin::pin!(body);
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if (out.len() as u64).saturating_add(data.len() as u64) > limit {
                return Err(());
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod capacity_tests {
    use super::{MAX_CONNECTIONS_PER_BINDING, MAX_TRACKED_CONNECTIONS, admits};

    /// The per-principal cap is a real fraction of the table, not the table
    /// itself.  If these were equal the second test below could not fail, and
    /// the whole discipline would be one cap wearing two names.
    #[test]
    fn the_per_principal_cap_is_a_share_of_the_table() {
        assert_eq!(MAX_TRACKED_CONNECTIONS, 256);
        assert_eq!(MAX_CONNECTIONS_PER_BINDING, 32);
        const { assert!(MAX_CONNECTIONS_PER_BINDING < MAX_TRACKED_CONNECTIONS) };
    }

    #[test]
    fn both_caps_are_exact_at_the_boundary_and_refuse_one_beyond() {
        // The global cap, with this principal holding nothing.
        assert!(admits(MAX_TRACKED_CONNECTIONS - 1, 0));
        assert!(!admits(MAX_TRACKED_CONNECTIONS, 0));
        // The per-principal cap, with the table otherwise empty.
        assert!(admits(0, MAX_CONNECTIONS_PER_BINDING - 1));
        assert!(!admits(0, MAX_CONNECTIONS_PER_BINDING));
    }

    /// **The cross-principal denial channel is closed.**
    ///
    /// One principal at its own cap cannot grow the table any further, so it
    /// cannot drive the global count to `MAX_TRACKED_CONNECTIONS` and refuse
    /// everybody else.  The most it can occupy is its share, and seven eighths
    /// of the table remain for other principals — which is the property
    /// evict-oldest destroys, because eviction picks by age rather than by
    /// owner.
    #[test]
    fn one_principal_cannot_fill_the_table_and_deny_the_rest() {
        let mine = MAX_CONNECTIONS_PER_BINDING;
        assert!(
            !admits(mine, mine),
            "a principal at its share is refused its next connection"
        );
        // A different principal, with the table holding only the first one's
        // full share, is still admitted.
        assert!(
            admits(mine, 0),
            "another principal is unaffected by the first one's share"
        );
        // A `const` block: the compiler refuses the build if one principal's
        // share ever grows past an eighth of the table, which is stronger than
        // a test that has to be run.
        const {
            assert!(
                MAX_TRACKED_CONNECTIONS - MAX_CONNECTIONS_PER_BINDING
                    >= MAX_TRACKED_CONNECTIONS * 7 / 8,
                "seven eighths of the table survive one principal's maximum"
            )
        };
    }

    /// A full table refuses rather than evicting: there is no input to
    /// [`admits`] that both reports full and admits.
    #[test]
    fn a_full_table_has_no_admitting_input() {
        for held in 0..=MAX_CONNECTIONS_PER_BINDING {
            assert!(
                !admits(MAX_TRACKED_CONNECTIONS, held),
                "a full table admitted a newcomer holding {held}"
            );
        }
    }
}

/// How a connection's ending is counted: once, by the path that ended it.
///
/// These build real connections around a real child, `/bin/cat`, which reads
/// its stdin until it is killed and writes nothing on its own. A connection's
/// own tasks are never spawned, so each test drives exactly the ending it names
/// and no watchdog or dispatcher can race it; only the export's registry task
/// runs, because listing a connection is asking it to. Unix-only: the child is
/// `/bin/cat`, which Windows does not have.
#[cfg(all(test, unix))]
mod ending_tests {
    use std::path::Path;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::{
        AcpExport, Arc, AtomicBool, Connection, ConnectionScope, Ordering, Supervisor,
        SupervisorConfig, close_connection, end_with_child,
    };
    use crate::child::ChildConfig;
    use crate::config::AcpExportConfig;

    fn export(workspace: &Path) -> AcpExport {
        let text = format!(
            "profile = \"acp-http-v1\"\n[agent]\ncommand = \"/bin/cat\"\nworkspace = \"{}\"\n",
            workspace.display()
        );
        let config: AcpExportConfig = toml::from_str(&text).expect("export config");
        AcpExport::from_config(&config).expect("valid acp export")
    }

    /// A connection around a live `/bin/cat`, **not** yet in the export's map.
    fn connection(export: &AcpExport, workspace: &Path, id: &str) -> Arc<Connection> {
        let child = ChildConfig {
            command: "/bin/cat".into(),
            args: Vec::new(),
            workspace: workspace.to_path_buf(),
            inherit_env: Vec::new(),
            env: std::collections::BTreeMap::new(),
            message_limit: 1 << 20,
            stderr_cap: 1 << 16,
        };
        let scope = ConnectionScope {
            tenant: "tenant-a".to_owned(),
            principal: "principal-a".to_owned(),
            device: "device-a".to_owned(),
            service: "service-a".to_owned(),
            connection: id.to_owned(),
        };
        let (supervisor, mut events) =
            Supervisor::start(SupervisorConfig::new(child, scope)).expect("/bin/cat starts");
        tokio::spawn(async move { while events.recv().await.is_some() {} });
        Arc::new(Connection {
            id: id.to_owned(),
            supervisor,
            principal: None,
            workspace: workspace.to_string_lossy().into_owned(),
            limits: export.inner.validated.limits,
            connection_subscribe_deadline: export.inner.validated.connection_subscribe_deadline,
            session_subscribe_deadline: export.inner.validated.session_subscribe_deadline,
            // No owning task in this fixture: its command queue and the
            // connection stream are both already closed.
            commands: tokio::sync::mpsc::channel(1).0,
            stream: tokio::sync::mpsc::channel(1).0,
            listed: AtomicBool::new(true),
            counters: Arc::clone(&export.inner.counters),
            shutdown: CancellationToken::new(),
            // No dispatcher in this fixture: a sender that is already gone.
            outbound: tokio::sync::mpsc::channel::<crate::OutboundMessage>(1)
                .0
                .downgrade(),
        })
    }

    async fn insert(export: &AcpExport, connection: &Arc<Connection>) {
        export.list(Arc::clone(connection)).await;
        export
            .inner
            .counters
            .connections_opened
            .fetch_add(1, Ordering::Relaxed);
    }

    /// The control: a child that ends its own connection is counted as such.
    /// Without this the test below could pass by `end_with_child` counting
    /// nothing at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_child_that_ends_its_connection_is_counted_once() {
        let workspace = tempfile::tempdir().expect("workspace");
        let export = export(workspace.path());
        let connection = connection(&export, workspace.path(), "c-1");
        insert(&export, &connection).await;

        assert!(end_with_child(&export, &connection));
        close_connection(&connection).await;

        let diagnostics = export.diagnostics();
        assert_eq!(diagnostics.connections_ended_by_child, 1, "{diagnostics:?}");
        assert_eq!(diagnostics.connections_closed, 1, "{diagnostics:?}");
        assert_eq!(diagnostics.live_connections, 0, "{diagnostics:?}");
    }

    /// **A connection some other ending already removed is not credited to
    /// its child** (M8-C32). This is the state the watchdog is in when its
    /// `select!` finds `wait_exited` ready because `close_connection` killed
    /// the child for a stall, a lost subscriber, an expiry or a DELETE.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_already_ended_elsewhere_is_not_counted_as_ended_by_its_child() {
        let workspace = tempfile::tempdir().expect("workspace");
        let export = export(workspace.path());
        let ended = connection(&export, workspace.path(), "c-1");
        insert(&export, &ended).await;
        // Another ending got there first.
        assert!(export.remove(&ended));
        ended.supervisor.kill();

        assert!(
            !end_with_child(&export, &ended),
            "a connection another path ended is not this call's to close"
        );

        let diagnostics = export.diagnostics();
        assert_eq!(
            diagnostics.connections_ended_by_child, 0,
            "the child did not end this connection: {diagnostics:?}"
        );
        assert_eq!(
            diagnostics.connections_closed, 1,
            "and it is closed exactly once: {diagnostics:?}"
        );
        ended.supervisor.drain().await;
    }

    /// **`shutdown` counts a connection removed concurrently exactly once**
    /// (M8-C33). It used to snapshot the map and clear it in two separate
    /// steps, then count every snapshot entry, so a `remove` between the two
    /// was counted by both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_and_a_concurrent_remove_count_a_connection_once() {
        let workspace = tempfile::tempdir().expect("workspace");
        let export = export(workspace.path());
        let first = connection(&export, workspace.path(), "c-1");
        let second = connection(&export, workspace.path(), "c-2");
        insert(&export, &first).await;
        insert(&export, &second).await;

        let stopping = export.clone();
        let shutdown = std::thread::spawn(move || stopping.shutdown());
        std::thread::sleep(Duration::from_millis(50));
        let _ = export.remove(&first);
        shutdown.join().expect("shutdown");

        let diagnostics = export.diagnostics();
        assert_eq!(
            diagnostics.connections_closed, 2,
            "two connections, each closed once: {diagnostics:?}"
        );
        assert_eq!(diagnostics.live_connections, 0, "{diagnostics:?}");
        first.supervisor.kill();
        first.supervisor.drain().await;
        second.supervisor.drain().await;
    }

    /// **`shutdown` never clears a connection it does not end** (M8-C33). A
    /// connection inserted between its snapshot and its clear used to leave
    /// the map uncounted, with its child still running and nothing left that
    /// could find it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_inserted_during_shutdown_is_ended_or_kept_never_dropped() {
        let workspace = tempfile::tempdir().expect("workspace");
        let export = export(workspace.path());
        let first = connection(&export, workspace.path(), "c-1");
        let late = connection(&export, workspace.path(), "c-2");
        insert(&export, &first).await;

        let stopping = export.clone();
        let shutdown = std::thread::spawn(move || stopping.shutdown());
        std::thread::sleep(Duration::from_millis(50));
        insert(&export, &late).await;
        shutdown.join().expect("shutdown");

        let diagnostics = export.diagnostics();
        let late_live = export.connection(&late.id).is_some();
        assert!(
            late_live || late.shutdown.is_cancelled(),
            "the late connection is either still held or was ended, never silently dropped: \
             {diagnostics:?}"
        );
        assert_eq!(
            diagnostics.connections_closed + diagnostics.live_connections,
            diagnostics.connections_opened,
            "every opened connection is closed or live: {diagnostics:?}"
        );
        export.shutdown();
        first.supervisor.drain().await;
        late.supervisor.kill();
        late.supervisor.drain().await;
    }
}

/// The stream and connection phases, as a transition table.
#[cfg(test)]
mod phase_tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    use super::{
        ConnectionCommand, ConnectionState, Routing, Subscription, Target, TargetEffect,
        TargetEvent, TargetPhase,
    };
    use crate::sse::{ChannelResponseBody, StreamSender};

    /// A live body's sender, and the body that keeps it open.
    fn body() -> (StreamSender, ChannelResponseBody) {
        ChannelResponseBody::channel(1 << 20, Arc::new(AtomicU64::new(0)))
    }

    #[test]
    fn a_waiting_stream_grants_its_queue_to_the_first_subscriber_only() {
        let mut target = Target::new();
        assert!(!target.is_subscribed());
        assert!(!target.is_closed());
        let (first, _first_body) = body();
        assert!(matches!(
            target.apply(TargetEvent::Subscribe(first)),
            TargetEffect::Granted(_)
        ));
        assert!(matches!(target.phase, TargetPhase::Established(_)));
        assert!(target.is_subscribed());
        // The one-subscriber rule: there is nothing left to take.
        let (second, _second_body) = body();
        assert!(matches!(
            target.apply(TargetEvent::Subscribe(second)),
            TargetEffect::Refused
        ));
        assert!(matches!(target.phase, TargetPhase::Established(_)));
    }

    #[test]
    fn a_stream_that_never_had_a_subscriber_closes_as_not_established() {
        let mut target = Target::new();
        assert!(matches!(
            target.apply(TargetEvent::Close),
            TargetEffect::Closed
        ));
        assert!(matches!(
            target.phase,
            TargetPhase::Over { established: false }
        ));
        assert!(target.is_closed());
        assert!(!target.is_subscribed());
        // Its queue went with it: a send finds nobody reading.
        assert!(target.tx.is_closed());
    }

    #[test]
    fn an_established_stream_closes_as_established() {
        let mut target = Target::new();
        let (sender, _body) = body();
        let _queue = target.apply(TargetEvent::Subscribe(sender));
        assert!(matches!(
            target.apply(TargetEvent::Close),
            TargetEffect::Closed
        ));
        assert!(matches!(
            target.phase,
            TargetPhase::Over { established: true }
        ));
        assert!(target.is_closed());
        assert!(target.is_subscribed());
    }

    #[test]
    fn a_stream_that_is_over_refuses_a_subscriber_and_a_second_close() {
        for established in [false, true] {
            let mut target = Target::new();
            target.phase = TargetPhase::Over { established };
            let (sender, _body) = body();
            assert!(matches!(
                target.apply(TargetEvent::Subscribe(sender)),
                TargetEffect::Refused
            ));
            assert!(matches!(
                target.apply(TargetEvent::Close),
                TargetEffect::Refused
            ));
            assert!(
                matches!(target.phase, TargetPhase::Over { established: kept } if kept == established)
            );
        }
    }

    #[test]
    fn only_an_established_stream_whose_body_is_gone_is_broken() {
        let mut target = Target::new();
        assert!(!target.established_and_broken(), "never subscribed");
        let (sender, live) = body();
        let _queue = target.apply(TargetEvent::Subscribe(sender));
        assert!(!target.established_and_broken(), "its body is alive");
        drop(live);
        assert!(target.established_and_broken());
        let _ = target.apply(TargetEvent::Close);
        assert!(
            !target.established_and_broken(),
            "an ending already counted is not counted again"
        );
    }

    #[test]
    fn only_a_stream_still_waiting_can_run_out_its_window() {
        let mut target = Target::new();
        std::thread::sleep(Duration::from_millis(5));
        assert!(target.unsubscribed_past(Duration::ZERO).is_some());
        assert!(
            target
                .unsubscribed_past(Duration::from_secs(3600))
                .is_none()
        );
        let (sender, _body) = body();
        let _queue = target.apply(TargetEvent::Subscribe(sender));
        assert!(target.unsubscribed_past(Duration::ZERO).is_none());
        let _ = target.apply(TargetEvent::Close);
        assert!(target.unsubscribed_past(Duration::ZERO).is_none());
    }

    fn route(state: &mut ConnectionState, session: Option<&str>) -> Routing {
        let (reply, mut routed) = oneshot::channel();
        state.serve(
            ConnectionCommand::Route {
                session: session.map(ToOwned::to_owned),
                reply,
            },
            &CancellationToken::new(),
        );
        routed.try_recv().expect("the owner answers at once")
    }

    fn subscribe(state: &mut ConnectionState, session: Option<&str>) -> Subscription {
        let (sender, live) = body();
        // The body is leaked on purpose: these tests are about the phase, not
        // about a stream breaking.
        std::mem::forget(live);
        let (reply, mut subscribed) = oneshot::channel();
        state.serve(
            ConnectionCommand::Subscribe {
                session: session.map(ToOwned::to_owned),
                body: sender,
                reply,
            },
            &CancellationToken::new(),
        );
        subscribed.try_recv().expect("the owner answers at once")
    }

    fn lose(state: &mut ConnectionState, session: Option<&str>) -> bool {
        let (established, mut answer) = oneshot::channel();
        state.serve(
            ConnectionCommand::StreamLost {
                session: session.map(ToOwned::to_owned),
                established,
            },
            &CancellationToken::new(),
        );
        answer.try_recv().expect("the owner answers at once")
    }

    #[test]
    fn an_open_connection_creates_a_sessions_stream_on_first_mention() {
        let mut state = ConnectionState::new(Target::new());
        assert!(matches!(route(&mut state, None), Routing::Open(_)));
        assert!(matches!(route(&mut state, Some("s-1")), Routing::Open(_)));
        assert!(matches!(
            subscribe(&mut state, Some("s-1")),
            Subscription::Granted(_)
        ));
        assert!(matches!(
            subscribe(&mut state, Some("s-1")),
            Subscription::Refused
        ));
        // Another session's stream is its own.
        assert!(matches!(
            subscribe(&mut state, Some("s-2")),
            Subscription::Granted(_)
        ));
    }

    #[test]
    fn a_lost_stream_stays_over_and_says_whether_it_was_established() {
        let mut state = ConnectionState::new(Target::new());
        assert!(matches!(
            route(&mut state, Some("waiting")),
            Routing::Open(_)
        ));
        assert!(!lose(&mut state, Some("waiting")), "never subscribed");
        assert!(matches!(route(&mut state, Some("waiting")), Routing::Over));
        assert!(matches!(
            subscribe(&mut state, Some("waiting")),
            Subscription::Refused
        ));

        assert!(matches!(
            subscribe(&mut state, Some("live")),
            Subscription::Granted(_)
        ));
        assert!(lose(&mut state, Some("live")), "it had a subscriber");
        assert!(matches!(route(&mut state, Some("live")), Routing::Over));
        // The connection's own stream is untouched by either.
        assert!(matches!(route(&mut state, None), Routing::Open(_)));
    }

    #[test]
    fn an_expired_session_stream_is_reported_once_and_then_refuses_a_subscriber() {
        let mut state = ConnectionState::new(Target::new());
        assert!(matches!(route(&mut state, Some("late")), Routing::Open(_)));
        assert!(matches!(
            subscribe(&mut state, Some("prompt")),
            Subscription::Granted(_)
        ));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(state.expire_sessions(Duration::ZERO).len(), 1);
        assert!(
            state.expire_sessions(Duration::ZERO).is_empty(),
            "an expiry is counted once, not once a tick"
        );
        assert!(matches!(
            subscribe(&mut state, Some("late")),
            Subscription::Refused
        ));
        // The connection stream's window is the connection's, not a session's.
        assert!(state.connection_unsubscribed_past(Duration::ZERO).is_some());
    }

    #[test]
    fn closing_cancels_first_and_a_closed_connection_refuses_everything() {
        let mut state = ConnectionState::new(Target::new());
        let Subscription::Granted(_queue) = subscribe(&mut state, None) else {
            panic!("the first subscriber is granted");
        };
        let shutdown = CancellationToken::new();
        let (closed, mut done) = oneshot::channel();
        state.serve(ConnectionCommand::Close { closed }, &shutdown);
        assert!(done.try_recv().is_ok());
        assert!(shutdown.is_cancelled());
        assert!(matches!(state, ConnectionState::Closed));

        assert!(matches!(route(&mut state, None), Routing::ConnectionClosed));
        assert!(matches!(
            route(&mut state, Some("s-1")),
            Routing::ConnectionClosed
        ));
        assert!(matches!(
            subscribe(&mut state, None),
            Subscription::ConnectionClosed
        ));
        assert!(!lose(&mut state, None));
        assert!(!state.any_established_and_broken());
        assert!(state.connection_unsubscribed_past(Duration::ZERO).is_none());
        assert!(state.expire_sessions(Duration::ZERO).is_empty());
        // Closing again changes nothing.
        state.close();
        assert!(matches!(state, ConnectionState::Closed));
    }
}
