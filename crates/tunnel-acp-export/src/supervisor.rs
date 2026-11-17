//! One supervisor per ACP transport connection.
//!
//! It owns the child, the clock and the bounded channels. Every **decision**
//! is `tunnel_acp::lifecycle`'s, which owns none of those: the supervisor
//! reads `Instant` and hands the reading to [`CallbackTable::observe`], the
//! way `tunnel-http-forward`'s `RecordDeadline` is driven. That is the only
//! clock in this path, and it is deliberately on this side of the boundary.
//!
//! **One owner of the connection state.** The lifecycle, the callback table,
//! the waiters and the request-id counter change together, so they are plain
//! fields of one task ([`Owner`]) and nothing else can reach them. Everything
//! else — the public [`Supervisor`] methods, the stdout reader, the deadline
//! ticker — sends that task a [`Command`] over a bounded queue and, where it
//! needs the result, awaits a `oneshot` reply. Each command is applied whole
//! before the next is looked at, which is the atomicity the fields need.
//!
//! The owner never awaits anything but its own queue: it performs no child
//! I/O and never sends on a host-facing channel. That is why it is a task of
//! its own rather than the stdout reader: the reader has to wait on bounded
//! host-facing queues, and a state owner parked there would make `prompt` wait
//! for the host to drain its events.
//!
//! **A separate reader.** The task that reads the child's stdout is not the
//! task that is waiting for a prompt's `stopReason`, so an agent callback is
//! handled while a prompt is pending. A prompt hands the caller a
//! [`PromptTicket`] instead of blocking.
//!
//! **What is not here.** HTTP, SSE, sessions over the wire, the tunnel, a
//! relay and any real ACP client. Chunks 3 to 5.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tunnel_acp::lifecycle::{
    AcpConnection, CallbackTable, ChildLifecycle, Direction, ExpiredPermission, IdScope,
    LifecycleEvent, LifecycleRejection, LifecycleRule, MAX_PENDING_PER_DIRECTION,
    MAX_SESSIONS_PER_CONNECTION, Outcome, PendingKind, PermissionOutcome, RequestId,
};
use tunnel_acp::message::{AcpRule, MessageKind, read_turn_completion};
use tunnel_acp::terminal::AcpTerminal;

use crate::child::{ChildConfig, ChildCounters, ChildEnd, ChildEvent, ChildHandle, SpawnError};

/// Commands queued towards the state owner.
///
/// The owner only ever waits on this queue, so it drains as fast as commands
/// arrive; when the queue is full a sender waits its turn, which is the
/// backpressure. Nothing is dropped and nothing is unbounded.
const COMMAND_QUEUE: usize = 64;

/// The identifiers a JSON-RPC id is scoped by, minus the direction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionScope {
    pub tenant: String,
    pub principal: String,
    pub device: String,
    pub service: String,
    pub connection: String,
}

impl ConnectionScope {
    #[must_use]
    pub fn id_scope(&self, direction: Direction) -> IdScope {
        IdScope::new(
            &self.tenant,
            &self.principal,
            &self.device,
            &self.service,
            &self.connection,
            direction,
        )
    }
}

/// Supervisor configuration. Bounds default to `docs/acp.md`'s table; the
/// deadlines are shortened by tests so a timeout can actually elapse.
#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    pub child: ChildConfig,
    pub scope: ConnectionScope,
    /// `docs/acp.md`: 60 seconds, then cancel the prompt and the pending
    /// permission.
    pub permission_timeout: Duration,
    /// How often the supervisor reads its clock and observes the table.
    pub deadline_tick: Duration,
    pub session_limit: usize,
    pub pending_limit: usize,
}

impl SupervisorConfig {
    /// The documented bounds, with a child configuration supplied.
    #[must_use]
    pub fn new(child: ChildConfig, scope: ConnectionScope) -> Self {
        Self {
            child,
            scope,
            permission_timeout: Duration::from_secs(60),
            deadline_tick: Duration::from_millis(20),
            session_limit: MAX_SESSIONS_PER_CONNECTION,
            pending_limit: MAX_PENDING_PER_DIRECTION,
        }
    }
}

/// What the supervisor refused, or what went wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// The pure lifecycle refused, and named its rule.
    Lifecycle(LifecycleRejection),
    /// The child's output was refused by the profile, and named its rule.
    Protocol(AcpRule),
    /// The child is gone, so the outcome of anything already dispatched is
    /// unknown.
    ChildGone,
}

impl SupervisorError {
    /// The lifecycle rule, when one refused.
    #[must_use]
    pub const fn rule(self) -> Option<LifecycleRule> {
        match self {
            Self::Lifecycle(rejection) => Some(rejection.rule),
            Self::Protocol(_) | Self::ChildGone => None,
        }
    }
}

impl From<LifecycleRejection> for SupervisorError {
    fn from(rejection: LifecycleRejection) -> Self {
        Self::Lifecycle(rejection)
    }
}

impl core::fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lifecycle(rejection) => write!(formatter, "{rejection}"),
            Self::Protocol(rule) => write!(formatter, "ACP_PROTOCOL: {}", rule.code()),
            Self::ChildGone => formatter.write_str("ACP_CHILD_GONE"),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// What the host learns from the agent while a prompt is pending.
///
/// Carries identifiers, phases and counters. Never a prompt, a thought chunk,
/// a permission body or a credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEvent {
    /// A `session/update` notification arrived.
    Update { session: Option<String> },
    /// The agent is asking the host for permission.
    Permission { id: RequestId, session: String },
    /// The agent asked, and the bounded callback table refused before the
    /// host ever saw it.
    PermissionRefused { id: RequestId, rule: LifecycleRule },
    /// The permission deadline elapsed. `outcome` is always
    /// [`PermissionOutcome::Cancelled`].
    PermissionExpired {
        id: RequestId,
        session: Option<String>,
        /// Measured supervisor-clock milliseconds the permission was
        /// outstanding. Strictly greater than `bound_ms`.
        elapsed_ms: u64,
        bound_ms: u64,
        outcome: PermissionOutcome,
    },
    /// The child's message stream ended, for this reason.
    Ended(ChildEnd),
}

/// One agent→host message on its way to an SSE stream.
///
/// **This is the transport path, and it is deliberately separate from
/// [`AgentEvent`].** `AgentEvent` is diagnostics — identifiers, phases and
/// counters, never a payload — and widening it to carry bytes would have made
/// every existing consumer of it a payload consumer. This carries the exact
/// compact bytes the child wrote, already validated by the profile, and
/// nothing else: it is read only by the bridge that frames it as an SSE event.
///
/// Ordering is the reason it is one channel from one task: the supervisor's
/// single stdout reader sends here in the order the agent wrote, so wire order
/// is the channel's order and not a property anything downstream has to
/// reconstruct.
#[derive(Clone)]
pub struct OutboundMessage {
    /// `params.sessionId`, when the message carries one.
    pub session: Option<String>,
    pub kind: MessageKind,
    /// The compact message bytes, exactly as the child wrote them.
    pub compact: Vec<u8>,
}

impl core::fmt::Debug for OutboundMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OutboundMessage")
            .field("kind", &self.kind)
            .field("session", &self.session)
            .field("bytes", &self.compact.len())
            .finish()
    }
}

/// A dispatched prompt. Awaiting it does not stop the reader.
#[derive(Debug)]
pub struct PromptTicket {
    session: String,
    id: RequestId,
    reply: oneshot::Receiver<Result<Value, SupervisorError>>,
}

impl PromptTicket {
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    #[must_use]
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// Await the turn's `stopReason`.
    ///
    /// # Errors
    /// [`SupervisorError::Protocol`] when the result is not a v1 turn
    /// completion — notably a v2 acknowledgement with no `stopReason`, which
    /// the pinned profile refuses by its own rule. [`SupervisorError::ChildGone`]
    /// when the child ended first.
    pub async fn stop_reason(self) -> Result<String, SupervisorError> {
        Ok(self.completion().await?.1)
    }

    /// The turn's terminal **and** its wire spelling.
    ///
    /// The [`AcpTerminal`] is built here, where the pinned `StopReason` is
    /// already in scope, so the classification runs on the schema's own type
    /// rather than on a string anybody could have retyped.  The bridge records
    /// it; that is what makes `tunnel_acp::terminal` a rule the product
    /// applies rather than a table only a test reads.
    pub async fn completion(self) -> Result<(AcpTerminal, String), SupervisorError> {
        let value = self.reply.await.map_err(|_| SupervisorError::ChildGone)??;
        let stop = read_turn_completion(&value)
            .map_err(|rejection| SupervisorError::Protocol(rejection.rule))?;
        // The pinned crate's own serialization, so the vocabulary is the
        // schema's rather than a string retyped here.
        let spelling = serde_json::to_value(stop)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or(SupervisorError::Protocol(AcpRule::UnknownStopReason))?;
        Ok((AcpTerminal::Turn(stop), spelling))
    }
}

/// Payload-free diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    pub lifecycle_is_terminal: bool,
    pub spawned: u64,
    pub killed: u64,
    pub exited: u64,
    pub invalid_output: u64,
    pub oversized_output: u64,
    pub batch_output: u64,
    pub stderr_bytes: u64,
    pub stderr_over_cap: u64,
    pub group_kills: u64,
    /// Holders of the child handle other than this `Supervisor`, read from
    /// `Arc::strong_count`.
    ///
    /// **This is the quantity that actually gates cleanup.** The synchronous
    /// process-group kill lives in `ChildHandle::drop`, which runs when the
    /// last `Arc` goes; anything still holding one keeps it from running. It
    /// must reach 0 once the child has been reaped.
    ///
    /// It is deliberately preferred to `background_tasks` below for that
    /// assertion: a future task that clones the `Arc` without taking a
    /// `TaskGuard` would be invisible to the counter and would recreate the
    /// M8-C07 defect **with the test still green**. `strong_count` needs no
    /// instrumentation and cannot be forgotten.
    pub child_handle_holders: u64,
    /// Supervisor background tasks still alive, by explicit instrumentation.
    ///
    /// Kept alongside `child_handle_holders` because it names *what* is still
    /// running rather than only that something is; it is the more readable of
    /// the two and the weaker of the two.
    pub background_tasks: u64,
    /// Children for which a parent-death sentinel was armed.
    ///
    /// **This is what lets a measurement tell "the mechanism ran and contained
    /// this" from "the mechanism was never there".** A `SIGKILL` test that
    /// only observed a dead helper could not say which of the two it had
    /// found, and that difference is the whole of M8-C07's trigger half.
    pub deadman_armed: u64,
    /// Sentinels that reported standing down, read from the sentinel's own
    /// exit status rather than from the supervisor having asked.
    pub deadman_stood_down: u64,
    pub resolutions: u64,
    pub permission_expirations: u64,
}

type Reply = oneshot::Receiver<Result<Value, SupervisorError>>;
type Waiters = HashMap<RequestId, oneshot::Sender<Result<Value, SupervisorError>>>;

/// What must hold before a host request is registered and written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Gate {
    /// `initialize`: admitted before the connection is ready.
    Open,
    /// `session/new`: admission open and a session slot free.
    NewSession,
    /// `session/prompt`: the session's one prompt slot is taken first, and
    /// given back if the request is then refused.
    Prompt,
}

/// A host request the owner registered: its id, its line, and where its
/// response will arrive.
struct Dispatched {
    id: RequestId,
    body: Vec<u8>,
    reply: Reply,
}

/// Everything that can be asked of the state owner. One command is one
/// indivisible change.
enum Command {
    /// Allocate the next request id, register it and hand back its line.
    Dispatch {
        method: &'static str,
        params: Value,
        kind: PendingKind,
        session: Option<String>,
        gate: Gate,
        reply: oneshot::Sender<Result<Dispatched, SupervisorError>>,
    },
    /// The line of a dispatched request could not be written.
    SendFailed {
        id: RequestId,
    },
    /// Drive the child lifecycle's own transition table.
    Advance {
        event: LifecycleEvent,
        reply: oneshot::Sender<Result<(), LifecycleRejection>>,
    },
    OpenSession {
        session: String,
        reply: oneshot::Sender<Result<(), LifecycleRejection>>,
    },
    SubscriberReady {
        session: String,
        reply: oneshot::Sender<Result<(), LifecycleRejection>>,
    },
    AnswerPermission {
        id: RequestId,
        outcome: PermissionOutcome,
        reply: oneshot::Sender<Result<(), LifecycleRejection>>,
    },
    /// Cancel one session's outstanding permissions, or every open session's.
    CancelPermissions {
        session: Option<String>,
        reply: oneshot::Sender<Vec<RequestId>>,
    },
    HasSession {
        session: String,
        reply: oneshot::Sender<bool>,
    },
    OpenSessions {
        reply: oneshot::Sender<Vec<String>>,
    },
    /// Stop admission and cancel every outstanding permission.
    Drain {
        reply: oneshot::Sender<()>,
    },
    /// The agent asked the host for permission.
    RegisterPermission {
        id: RequestId,
        session: String,
        offered: Vec<String>,
        reply: oneshot::Sender<Result<(), LifecycleRejection>>,
    },
    /// The agent answered a host request. `result` is `None` for an error.
    Response {
        id: RequestId,
        result: Option<Value>,
        reply: oneshot::Sender<()>,
    },
    /// The child's message stream ended.
    ChildEnded {
        end: ChildEnd,
        reply: oneshot::Sender<()>,
    },
    /// The deadline ticker read the clock.
    Observe {
        reply: oneshot::Sender<Vec<ExpiredPermission>>,
    },
}

/// What the owner publishes after every command: the values the synchronous
/// accessors read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Published {
    lifecycle: ChildLifecycle,
    session_count: usize,
    pending_host_to_agent: usize,
    pending_agent_to_host: usize,
    resolutions: u64,
    permission_expirations: u64,
}

/// The single owner of one connection's state.
struct Owner {
    connection: AcpConnection,
    callbacks: CallbackTable,
    waiters: Waiters,
    next_id: u64,
    session_limit: usize,
    /// Session identifiers this connection has opened, so a drain can cancel
    /// each one's outstanding permissions.
    open_sessions: Vec<String>,
    host_scope: IdScope,
    agent_scope: IdScope,
    started: Instant,
    permission_timeout_ms: u64,
    published: watch::Sender<Published>,
}

impl Owner {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        // Ends when every sender is gone: the `Supervisor`, the reader and the
        // ticker. Waiters still held then are dropped, which a ticket reads
        // as `ChildGone`.
        while let Some(command) = commands.recv().await {
            self.handle(command);
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn snapshot(&self) -> Published {
        Published {
            lifecycle: self.connection.lifecycle(),
            session_count: self.connection.session_count(),
            pending_host_to_agent: self.callbacks.pending_in(&self.host_scope),
            pending_agent_to_host: self.callbacks.pending_in(&self.agent_scope),
            resolutions: self.callbacks.resolutions(),
            permission_expirations: self.callbacks.expirations(),
        }
    }

    /// Publish the state as it now is. Called after a command is applied and
    /// **before** its reply or any waiter is released, so whoever is woken by
    /// a change reads a snapshot that already contains it.
    fn publish(&self) {
        let next = self.snapshot();
        self.published.send_if_modified(|current| {
            if *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Dispatch {
                method,
                params,
                kind,
                session,
                gate,
                reply,
            } => {
                let dispatched = self.dispatch(method, params, kind, session.as_deref(), gate);
                self.publish();
                if let Err(Ok(dispatched)) = reply.send(dispatched) {
                    // The caller went away before it could write the line, so
                    // the request was never sent and nobody is waiting.
                    self.forget(&dispatched.id, kind, session.as_deref());
                    self.publish();
                }
            }
            Command::SendFailed { id } => {
                let waiter = self.waiters.remove(&id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Err(SupervisorError::ChildGone));
                }
            }
            Command::Advance { event, reply } => {
                let advanced = self.connection.advance(event).map(|_| ());
                self.publish();
                let _ = reply.send(advanced);
            }
            Command::OpenSession { session, reply } => {
                let now = self.now();
                let opened = self.connection.open_session(&session, now);
                if opened.is_ok() {
                    self.open_sessions.push(session);
                }
                self.publish();
                let _ = reply.send(opened);
            }
            Command::SubscriberReady { session, reply } => {
                let ready = self.connection.subscriber_ready(&session);
                self.publish();
                let _ = reply.send(ready);
            }
            Command::AnswerPermission { id, outcome, reply } => {
                let now = self.now();
                let resolved = self
                    .callbacks
                    .resolve(&self.agent_scope, &id, Outcome::Permission(outcome), now)
                    .map(|_| ());
                self.publish();
                let _ = reply.send(resolved);
            }
            Command::CancelPermissions { session, reply } => {
                let now = self.now();
                let sessions = session.map_or_else(|| self.open_sessions.clone(), |one| vec![one]);
                let mut cancelled = Vec::new();
                for session in sessions {
                    cancelled.extend(
                        self.callbacks
                            .cancel_session_permissions(&session, now)
                            .into_iter()
                            .map(|(_, id)| id),
                    );
                }
                self.publish();
                let _ = reply.send(cancelled);
            }
            Command::HasSession { session, reply } => {
                let _ = reply.send(self.open_sessions.contains(&session));
            }
            Command::OpenSessions { reply } => {
                let _ = reply.send(self.open_sessions.clone());
            }
            Command::Drain { reply } => {
                let now = self.now();
                let _ = self.connection.advance(LifecycleEvent::DrainRequested);
                // Every outstanding permission is cancelled, never approved.
                for session in self.open_sessions.clone() {
                    self.callbacks.cancel_session_permissions(&session, now);
                }
                self.publish();
                let _ = reply.send(());
            }
            Command::RegisterPermission {
                id,
                session,
                offered,
                reply,
            } => {
                let now = self.now();
                // The options the agent offered are recorded with the
                // callback, so the host's answer can be checked against them
                // (`docs/acp.md`: "Validate the response against ... the
                // offered option").
                let registered = self.callbacks.register_permission(
                    &self.agent_scope,
                    id,
                    Some(&session),
                    now,
                    self.permission_timeout_ms,
                    offered,
                );
                self.publish();
                let _ = reply.send(registered);
            }
            Command::Response { id, result, reply } => {
                self.response(id, result);
                let _ = reply.send(());
            }
            Command::ChildEnded { end, reply } => {
                let event = match end {
                    ChildEnd::Closed => LifecycleEvent::Reaped,
                    ChildEnd::OversizedLine | ChildEnd::InvalidLine(_) | ChildEnd::ReadFailed => {
                        LifecycleEvent::Failed
                    }
                };
                let _ = self.connection.advance(event);
                let waiters: Vec<_> = self.waiters.drain().map(|(_, sender)| sender).collect();
                self.publish();
                // Every request still outstanding learns that its outcome is
                // unknown. None is answered as if it had completed, and none
                // is sent again.
                for waiter in waiters {
                    let _ = waiter.send(Err(SupervisorError::ChildGone));
                }
                let _ = reply.send(());
            }
            Command::Observe { reply } => {
                let now = self.now();
                let expired = self.callbacks.observe(now);
                self.publish();
                let _ = reply.send(expired);
            }
        }
    }

    /// Register a host request and compose its line.
    fn dispatch(
        &mut self,
        method: &str,
        params: Value,
        kind: PendingKind,
        session: Option<&str>,
        gate: Gate,
    ) -> Result<Dispatched, SupervisorError> {
        match gate {
            Gate::Open => {}
            // The bound is checked before dispatch, so a ninth session is
            // never asked for.
            Gate::NewSession => {
                if !self.connection.lifecycle().admits() {
                    return Err(LifecycleRejection::new(
                        LifecycleRule::ConnectionNotReady,
                        "the connection is not admitting new sessions",
                    )
                    .into());
                }
                if self.connection.session_count() >= self.session_limit {
                    return Err(LifecycleRejection::new(
                        LifecycleRule::SessionLimit,
                        "too many sessions on this connection",
                    )
                    .into());
                }
            }
            Gate::Prompt => {
                self.connection.begin_prompt(session.unwrap_or_default())?;
            }
        }
        let registered = self.register(method, params, kind, session, gate != Gate::Open);
        if registered.is_err() && gate == Gate::Prompt {
            // The turn never started; put the session back.
            let _ = self.connection.end_prompt(session.unwrap_or_default());
        }
        registered
    }

    fn register(
        &mut self,
        method: &str,
        params: Value,
        kind: PendingKind,
        session: Option<&str>,
        require_ready: bool,
    ) -> Result<Dispatched, SupervisorError> {
        if require_ready && !self.connection.lifecycle().admits() {
            return Err(LifecycleRejection::new(
                LifecycleRule::ConnectionNotReady,
                "the connection is not admitting requests",
            )
            .into());
        }
        let now = self.now();
        self.next_id += 1;
        let id = RequestId::Number(i64::try_from(self.next_id).unwrap_or(i64::MAX));
        self.callbacks
            .register(&self.host_scope, id.clone(), kind, session, now, 0)?;
        let (sender, reply) = oneshot::channel();
        self.waiters.insert(id.clone(), sender);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id_value(&id),
            "method": method,
            "params": params,
        }))
        .unwrap_or_default();
        Ok(Dispatched { id, body, reply })
    }

    /// Undo a registration whose line was never written.
    fn forget(&mut self, id: &RequestId, kind: PendingKind, session: Option<&str>) {
        let now = self.now();
        self.waiters.remove(id);
        let _ = self.callbacks.resolve(
            &self.host_scope,
            id,
            Outcome::Failed("not_sent".to_owned()),
            now,
        );
        if kind == PendingKind::Prompt
            && let Some(session) = session
        {
            let _ = self.connection.end_prompt(session);
        }
    }

    fn response(&mut self, id: RequestId, result: Option<Value>) {
        let now = self.now();
        let outcome = result.as_ref().map_or_else(
            || Outcome::Failed("agent_error".to_owned()),
            |_| Outcome::Completed("ok".to_owned()),
        );
        let Ok(resolution) = self.callbacks.resolve(&self.host_scope, &id, outcome, now) else {
            // A duplicate, a late, or an unsolicited response. It cannot
            // repeat a decision, so it is dropped.
            return;
        };
        if resolution.kind == PendingKind::Prompt
            && let Some(session) = resolution.session.as_deref()
        {
            let _ = self.connection.end_prompt(session);
        }
        // The entry leaves the table and the waiter leaves the map in this one
        // step, so a response reaches its waiter exactly once.
        let waiter = self.waiters.remove(&id);
        self.publish();
        if let Some(waiter) = waiter {
            let _ = waiter.send(match result {
                Some(value) => Ok(value),
                None => Err(SupervisorError::Protocol(AcpRule::NotJsonRpcMessage)),
            });
        }
    }
}

/// One supervised ACP child and its connection state.
///
/// The state itself lives in the owner task; this is a handle to it. Methods
/// that change it are `async` and return once the owner has applied the
/// change. [`Supervisor::lifecycle`], [`Supervisor::pending`],
/// [`Supervisor::session_count`] and [`Supervisor::diagnostics`] stay
/// synchronous by reading the owner's **last published snapshot**; the owner
/// publishes before it releases any reply, waiter or agent event, so a caller
/// that has awaited a method, a ticket or an [`AgentEvent`] reads a snapshot
/// that already includes it.
pub struct Supervisor {
    commands: mpsc::Sender<Command>,
    published: watch::Receiver<Published>,
    child: Arc<ChildHandle>,
    counters: Arc<ChildCounters>,
    started: Instant,
}

impl Supervisor {
    /// Spawn the child and start the owner, reader and deadline tasks.
    ///
    /// # Errors
    /// [`SpawnError`] when the process cannot be started.
    pub fn start(
        config: SupervisorConfig,
    ) -> Result<(Self, mpsc::Receiver<AgentEvent>), SpawnError> {
        Self::start_forwarding(config, None)
    }

    /// Spawn the child with an additional **transport** sink for agent→host
    /// messages.
    ///
    /// `forward` receives every notification and every agent-originated
    /// request, in the order the child wrote them, carrying the compact bytes
    /// the HTTP bridge frames as SSE events. Responses to the supervisor's own
    /// dispatched requests are not forwarded: those resolve a waiter here, and
    /// the bridge composes its answer with the *host's* JSON-RPC id, which is
    /// a different id in a different scope.
    ///
    /// # Errors
    /// [`SpawnError`] when the process cannot be started.
    pub fn start_forwarding(
        config: SupervisorConfig,
        forward: Option<mpsc::Sender<OutboundMessage>>,
    ) -> Result<(Self, mpsc::Receiver<AgentEvent>), SpawnError> {
        let counters = Arc::new(ChildCounters::default());
        let (child, events) = crate::child::spawn(&config.child, &counters)?;
        let child = Arc::new(child);
        let started = Instant::now();
        let connection = AcpConnection::new(config.session_limit);
        let callbacks = CallbackTable::new(config.pending_limit);
        let (published, snapshots) = watch::channel(Published {
            lifecycle: connection.lifecycle(),
            session_count: 0,
            pending_host_to_agent: 0,
            pending_agent_to_host: 0,
            resolutions: callbacks.resolutions(),
            permission_expirations: callbacks.expirations(),
        });
        let owner = Owner {
            connection,
            callbacks,
            waiters: HashMap::new(),
            next_id: 0,
            session_limit: config.session_limit,
            open_sessions: Vec::new(),
            host_scope: config.scope.id_scope(Direction::HostToAgent),
            agent_scope: config.scope.id_scope(Direction::AgentToHost),
            started,
            permission_timeout_ms: u64::try_from(config.permission_timeout.as_millis())
                .unwrap_or(u64::MAX),
            published,
        };
        let (commands, queue) = mpsc::channel(COMMAND_QUEUE);
        // The owner holds no child handle, so it never delays the synchronous
        // cleanup in `ChildHandle::drop`.
        tokio::spawn(owner.run(queue));
        let (to_host, from_agent) = mpsc::channel(crate::child::STDOUT_QUEUE);
        tokio::spawn(read_agent(
            events,
            ReaderContext {
                commands: commands.clone(),
                child: Arc::clone(&child),
                to_host: to_host.clone(),
                counters: Arc::clone(&counters),
                forward,
            },
        ));
        tokio::spawn(observe_deadlines(
            commands.clone(),
            Arc::clone(&child),
            to_host,
            config.deadline_tick,
            Arc::clone(&counters),
        ));
        let supervisor = Self {
            commands,
            published: snapshots,
            child,
            counters,
            started,
        };
        Ok((supervisor, from_agent))
    }

    /// The supervisor's own clock, in milliseconds since it started. This is
    /// the only clock in the ACP path, and it is on the impure side of the
    /// boundary on purpose.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The child lifecycle in the owner's last published snapshot.
    #[must_use]
    pub fn lifecycle(&self) -> ChildLifecycle {
        self.published.borrow().lifecycle
    }

    /// The child's process id, which is its process-group id.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.pid()
    }

    /// `initialize` the agent and open admission.
    ///
    /// # Errors
    /// [`SupervisorError::ChildGone`], or the lifecycle's refusal of a second
    /// `initialize`.
    pub async fn initialize(&self) -> Result<Value, SupervisorError> {
        self.initialize_with(json!({
            "protocolVersion": 1,
            "clientCapabilities": {},
            "clientInfo": {"name": "tunnel-acp-export", "version": "0.1.0"},
        }))
        .await
    }

    /// `initialize` the agent with the caller's own params.
    ///
    /// The HTTP bridge forwards the **host's** `initialize` params verbatim
    /// rather than substituting its own: capability negotiation is between the
    /// host's ACP client and the agent, and a bridge that rewrote it would be
    /// negotiating on the host's behalf.
    ///
    /// # Errors
    /// [`SupervisorError::ChildGone`], or the lifecycle's refusal of a second
    /// `initialize`.
    pub async fn initialize_with(&self, params: Value) -> Result<Value, SupervisorError> {
        let (_, reply) = self
            .dispatch("initialize", params, PendingKind::Call, None, Gate::Open)
            .await?;
        let value = reply.await.map_err(|_| SupervisorError::ChildGone)??;
        self.lifecycle_command(|reply| Command::Advance {
            event: LifecycleEvent::Initialized,
            reply,
        })
        .await?;
        Ok(value)
    }

    /// Create a session.
    ///
    /// # Errors
    /// [`LifecycleRule::SessionLimit`] at one session beyond the bound, and
    /// [`LifecycleRule::ConnectionNotReady`] before `initialize`.
    pub async fn new_session(&self, cwd: &str) -> Result<String, SupervisorError> {
        self.new_session_with(json!({"cwd": cwd, "mcpServers": []}))
            .await
    }

    /// Create a session from the caller's own params.
    ///
    /// # Errors
    /// As [`Supervisor::new_session`].
    pub async fn new_session_with(&self, params: Value) -> Result<String, SupervisorError> {
        let (_, reply) = self
            .dispatch(
                "session/new",
                params,
                PendingKind::Call,
                None,
                Gate::NewSession,
            )
            .await?;
        let value = reply.await.map_err(|_| SupervisorError::ChildGone)??;
        let session = value
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or(SupervisorError::Protocol(AcpRule::NotJsonRpcMessage))?
            .to_owned();
        let opened = session.clone();
        self.lifecycle_command(|reply| Command::OpenSession {
            session: opened,
            reply,
        })
        .await?;
        Ok(session)
    }

    /// The session's scoped subscriber arrived.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownSession`] or [`LifecycleRule::SessionNotReady`].
    pub async fn subscriber_ready(&self, session: &str) -> Result<(), SupervisorError> {
        let session = session.to_owned();
        self.lifecycle_command(|reply| Command::SubscriberReady { session, reply })
            .await
    }

    /// Start the session's one active prompt.
    ///
    /// Returns a [`PromptTicket`] as soon as the owner has registered the
    /// turn — it does not wait for the agent — and the reader keeps handling
    /// agent callbacks while the ticket is outstanding.
    ///
    /// # Errors
    /// [`LifecycleRule::PromptAlreadyActive`] for a second concurrent prompt,
    /// [`LifecycleRule::SessionNotReady`] before the subscriber arrives, and
    /// [`LifecycleRule::ConnectionNotReady`] once admission has stopped.
    pub async fn prompt(&self, session: &str, text: &str) -> Result<PromptTicket, SupervisorError> {
        self.prompt_with(
            session,
            json!({"sessionId": session, "prompt": [{"type": "text", "text": text}]}),
        )
        .await
    }

    /// Start the session's one active prompt from the caller's own params.
    ///
    /// The HTTP bridge forwards the host's `session/prompt` params verbatim:
    /// a v1 prompt is a list of content blocks, and a bridge that rebuilt it
    /// from the first text block would silently drop the rest.
    ///
    /// Taking the session's prompt slot, registering the request and — when
    /// the request is refused — giving the slot back are one owner command,
    /// so no other caller can observe the session between those steps.
    ///
    /// # Errors
    /// As [`Supervisor::prompt`].
    pub async fn prompt_with(
        &self,
        session: &str,
        params: Value,
    ) -> Result<PromptTicket, SupervisorError> {
        let (id, reply) = self
            .dispatch(
                "session/prompt",
                params,
                PendingKind::Prompt,
                Some(session),
                Gate::Prompt,
            )
            .await?;
        Ok(PromptTicket {
            session: session.to_owned(),
            id,
            reply,
        })
    }

    /// Answer an outstanding permission request.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownRequestId`] when that permission is not
    /// outstanding — which is exactly what a duplicate answer, and an answer
    /// that lost the race with the deadline, both are.
    pub async fn answer_permission(
        &self,
        id: &RequestId,
        outcome: PermissionOutcome,
    ) -> Result<(), SupervisorError> {
        let body = permission_response(id, &outcome);
        let id = id.clone();
        self.lifecycle_command(|reply| Command::AnswerPermission { id, outcome, reply })
            .await?;
        self.child
            .send(&body)
            .await
            .map_err(|_| SupervisorError::ChildGone)
    }

    /// Forward a `session/cancel` notification.
    ///
    /// `docs/acp.md`: the bridge resolves pending permission callbacks with
    /// `cancelled`, forwards cancellation, and then **waits for the original
    /// prompt response**. It does not synthesize one: a confirmed cancelled
    /// turn has `stopReason: "cancelled"` and only the agent can say so.
    ///
    /// # Errors
    /// [`SupervisorError::ChildGone`].
    pub async fn cancel_session(
        &self,
        session: &str,
        params: Value,
    ) -> Result<(), SupervisorError> {
        let cancelled = self.cancel_permissions(Some(session.to_owned())).await;
        for id in cancelled {
            // Tell the agent on the wire, exactly as the deadline path does.
            let _ = self
                .child
                .send(&permission_response(&id, &PermissionOutcome::Cancelled))
                .await;
        }
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "session/cancel",
            "params": params,
        }))
        .unwrap_or_default();
        self.child
            .send(&body)
            .await
            .map_err(|_| SupervisorError::ChildGone)
    }

    /// Whether this connection opened `session`, asked of the owner.
    pub async fn has_session(&self, session: &str) -> bool {
        let session = session.to_owned();
        self.ask(|reply| Command::HasSession { session, reply })
            .await
            .unwrap_or(false)
    }

    /// Every session this connection has open, asked of the owner.
    pub async fn open_sessions(&self) -> Vec<String> {
        self.ask(|reply| Command::OpenSessions { reply })
            .await
            .unwrap_or_default()
    }

    /// Resolve every outstanding permission on every open session as
    /// **cancelled**, tell the agent on the wire, and report how many there
    /// were.
    ///
    /// This is the "resolve pending permissions as cancelled" half of
    /// `docs/acp.md`'s subscriber-loss policy.  [`Supervisor::drain`] cancels
    /// them too, but discards the count and never tells the agent; the
    /// termination path needs both, because "how many permissions were
    /// cancelled" is the observation a test reads instead of trusting that
    /// cancellation happened.
    ///
    /// A timeout and a lost subscriber therefore resolve a callback the same
    /// way, which is the point: `docs/acp.md` says timeout and disconnect never
    /// mean permission.
    pub async fn cancel_all_permissions(&self) -> usize {
        let cancelled = self.cancel_permissions(None).await;
        for id in &cancelled {
            // The agent learns on the wire, exactly as the deadline path and
            // `session/cancel` do.  A supervisor's belief about what it
            // resolved is not evidence that the agent was told.
            let _ = self
                .child
                .send(&permission_response(id, &PermissionOutcome::Cancelled))
                .await;
        }
        cancelled.len()
    }

    /// Stop admission, cancel outstanding permissions, and end the child's
    /// life — which signals its process group.
    ///
    /// **This is not a graceful shutdown.** It does not close stdin, and it
    /// does not give the child a grace period to finish and exit by itself;
    /// `docs/acp.md`'s bounded grace period is not implemented. It cancels and
    /// kills. The [`ChildLifecycle::Stopped`] that results therefore records
    /// *who ended the child* — the supervisor, deliberately — and not *how the
    /// process died.
    pub async fn drain(&self) {
        let _ = self.ask(|reply| Command::Drain { reply }).await;
        self.child.kill();
        self.child.wait_exited().await;
        // Draining then reaped is what reaches `Stopped`; the transition
        // table decides, not this line.
        let _ = self
            .ask(|reply| Command::Advance {
                event: LifecycleEvent::Reaped,
                reply,
            })
            .await;
    }

    /// End the child's life without awaiting anything.
    ///
    /// The synchronous form of the kill half of [`Supervisor::drain`], for a
    /// connector whose own teardown is not async — `HttpHandlers::drop` is
    /// exactly that. It signals the child's process group; it does not wait
    /// for the reap, and it is idempotent.
    pub fn kill(&self) {
        self.child.kill();
    }

    /// Wait for the child to be reaped, however its life ended.
    pub async fn wait_exited(&self) {
        self.child.wait_exited().await;
    }

    /// Payload-free counters. The lifecycle, resolution and expiry values are
    /// the owner's last published snapshot; the rest are the child's atomics.
    #[must_use]
    pub fn diagnostics(&self) -> Diagnostics {
        let published = *self.published.borrow();
        Diagnostics {
            lifecycle_is_terminal: published.lifecycle.is_terminal(),
            spawned: self.counters.spawned.load(Ordering::Relaxed),
            killed: self.counters.killed.load(Ordering::Relaxed),
            exited: self.counters.exited.load(Ordering::Relaxed),
            invalid_output: self.counters.invalid_output.load(Ordering::Relaxed),
            oversized_output: self.counters.oversized_output.load(Ordering::Relaxed),
            batch_output: self.counters.batch_output.load(Ordering::Relaxed),
            stderr_bytes: self.counters.stderr_bytes.load(Ordering::Relaxed),
            stderr_over_cap: self.counters.stderr_over_cap.load(Ordering::Relaxed),
            group_kills: self.counters.group_kills.load(Ordering::Relaxed),
            // Minus one for this `Supervisor`'s own handle.
            child_handle_holders: (Arc::strong_count(&self.child) as u64).saturating_sub(1),
            background_tasks: self.counters.background_tasks.load(Ordering::Relaxed),
            deadman_armed: self.counters.deadman_armed.load(Ordering::Relaxed),
            deadman_stood_down: self.counters.deadman_stood_down.load(Ordering::Relaxed),
            resolutions: published.resolutions,
            permission_expirations: published.permission_expirations,
        }
    }

    /// Outstanding requests in one direction, for the bound tests, in the
    /// owner's last published snapshot.
    #[must_use]
    pub fn pending(&self, direction: Direction) -> usize {
        let published = self.published.borrow();
        match direction {
            Direction::HostToAgent => published.pending_host_to_agent,
            Direction::AgentToHost => published.pending_agent_to_host,
        }
    }

    /// Open sessions in the owner's last published snapshot.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.published.borrow().session_count
    }

    /// Send one command and await its reply. `None` when the owner is gone,
    /// which only a runtime being torn down can cause.
    async fn ask<R>(&self, command: impl FnOnce(oneshot::Sender<R>) -> Command) -> Option<R> {
        ask_owner(&self.commands, command).await
    }

    async fn lifecycle_command(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<(), LifecycleRejection>>) -> Command,
    ) -> Result<(), SupervisorError> {
        self.ask(command)
            .await
            .ok_or(SupervisorError::ChildGone)?
            .map_err(SupervisorError::from)
    }

    async fn cancel_permissions(&self, session: Option<String>) -> Vec<RequestId> {
        self.ask(|reply| Command::CancelPermissions { session, reply })
            .await
            .unwrap_or_default()
    }

    /// Have the owner register a host request, then write its line.
    ///
    /// The id is allocated by the owner, in the order commands reach it. The
    /// line is written by a task of its own so that a full stdin queue cannot
    /// hold the caller.
    async fn dispatch(
        &self,
        method: &'static str,
        params: Value,
        kind: PendingKind,
        session: Option<&str>,
        gate: Gate,
    ) -> Result<(RequestId, Reply), SupervisorError> {
        let session = session.map(ToOwned::to_owned);
        let Dispatched { id, body, reply } = self
            .ask(|reply| Command::Dispatch {
                method,
                params,
                kind,
                session,
                gate,
                reply,
            })
            .await
            .ok_or(SupervisorError::ChildGone)??;
        let child = Arc::clone(&self.child);
        let commands = self.commands.clone();
        let failed = id.clone();
        tokio::spawn(async move {
            if child.send(&body).await.is_err() {
                let _ = commands.send(Command::SendFailed { id: failed }).await;
            }
        });
        Ok((id, reply))
    }
}

/// Counts one live supervisor background task for as long as it exists.
///
/// The count is what makes "this task ended with its child" observable. A task
/// that loops forever holds an `Arc<ChildHandle>` and silently disables the
/// synchronous cleanup in `ChildHandle::drop`; before the M8-C07 review there
/// was nothing a test could read to notice.
struct TaskGuard(Arc<ChildCounters>);

impl TaskGuard {
    fn new(counters: &Arc<ChildCounters>) -> Self {
        counters.background_tasks.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counters))
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.background_tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Supervisor {
    /// A supervisor that goes away ends its child, whether or not anyone
    /// called [`Supervisor::drain`].
    ///
    /// Connection loss in a later chunk is exactly "the owner went away
    /// without draining", so a cleanup path that only ran on the happy path
    /// would leak the agent's whole process tree at the moment it matters
    /// most. Cancelling here makes the supervisor task send the group signal
    /// while the leader is still unreaped; if the runtime is being torn down
    /// and that task never runs, [`crate::child::ChildHandle::drop`] sends it
    /// synchronously instead.
    fn drop(&mut self) {
        self.child.kill();
    }
}

fn id_value(id: &RequestId) -> Value {
    match id {
        RequestId::Text(text) => Value::String(text.clone()),
        RequestId::Number(number) => Value::from(*number),
    }
}

/// The `optionId`s a `session/request_permission` offered, in the order the
/// agent listed them.
///
/// An agent that offers none yields an empty list, which admits no selection
/// at all — which is right: there was nothing to select.
fn offered_options(message: &serde_json::Value) -> Vec<String> {
    message
        .pointer("/params/options")
        .and_then(serde_json::Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(|option| {
                    option
                        .get("optionId")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn id_from_value(value: &Value) -> Option<RequestId> {
    match value {
        Value::String(text) => Some(RequestId::Text(text.clone())),
        Value::Number(number) => number.as_i64().map(RequestId::Number),
        _ => None,
    }
}

fn permission_response(id: &RequestId, outcome: &PermissionOutcome) -> Vec<u8> {
    let outcome = match outcome {
        PermissionOutcome::Selected(option) => {
            json!({"outcome": "selected", "optionId": option})
        }
        PermissionOutcome::Cancelled => json!({"outcome": "cancelled"}),
    };
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id_value(id),
        "result": {"outcome": outcome},
    }))
    .unwrap_or_default()
}

/// Everything the reader task needs. A struct rather than five arguments.
struct ReaderContext {
    commands: mpsc::Sender<Command>,
    child: Arc<ChildHandle>,
    to_host: mpsc::Sender<AgentEvent>,
    counters: Arc<ChildCounters>,
    /// The transport sink, when a bridge asked for one.
    forward: Option<mpsc::Sender<OutboundMessage>>,
}

/// Send the owner one command and await its reply. `None` when the owner is
/// gone.
async fn ask_owner<R>(
    commands: &mpsc::Sender<Command>,
    command: impl FnOnce(oneshot::Sender<R>) -> Command,
) -> Option<R> {
    let (reply, answer) = oneshot::channel();
    commands.send(command(reply)).await.ok()?;
    answer.await.ok()
}

/// The separate reader: it keeps handling agent callbacks while a prompt is
/// pending, because it is not the task awaiting the prompt.
///
/// It owns no connection state. Each message becomes one owner command, and
/// the reader waits for the owner to have applied it before it tells the host
/// or reads the next line, so the owner sees the agent's messages in the order
/// the agent wrote them.
async fn read_agent(mut events: mpsc::Receiver<ChildEvent>, context: ReaderContext) {
    let ReaderContext {
        commands,
        child,
        to_host,
        counters,
        forward,
    } = context;
    let _alive = TaskGuard::new(&counters);
    while let Some(event) = events.recv().await {
        match event {
            ChildEvent::Message(message) => {
                let message = message.message;
                match message.kind {
                    MessageKind::Notification => {
                        let session = message.session_id().map(ToOwned::to_owned);
                        // The transport copy goes first, and from this one
                        // task, so the order an SSE stream sees is the order
                        // the agent wrote.
                        if let Some(forward) = &forward
                            && forward
                                .send(OutboundMessage {
                                    session: session.clone(),
                                    kind: MessageKind::Notification,
                                    compact: message.compact.clone(),
                                })
                                .await
                                .is_err()
                        {
                            return;
                        }
                        if to_host.send(AgentEvent::Update { session }).await.is_err() {
                            return;
                        }
                    }
                    MessageKind::Request => {
                        let Some(id) = message.id.as_ref().and_then(id_from_value) else {
                            continue;
                        };
                        let session = message.session_id().unwrap_or_default().to_owned();
                        let offered = offered_options(&message.value);
                        let Some(registered) =
                            ask_owner(&commands, |reply| Command::RegisterPermission {
                                id: id.clone(),
                                session: session.clone(),
                                offered,
                                reply,
                            })
                            .await
                        else {
                            return;
                        };
                        let event = match registered {
                            Ok(()) => {
                                // Only an admitted callback reaches the host.
                                // One the bounded table refused was answered
                                // `cancelled` below and must never appear on a
                                // stream as if it were outstanding.
                                if let Some(forward) = &forward
                                    && forward
                                        .send(OutboundMessage {
                                            session: Some(session.clone()),
                                            kind: MessageKind::Request,
                                            compact: message.compact.clone(),
                                        })
                                        .await
                                        .is_err()
                                {
                                    return;
                                }
                                AgentEvent::Permission {
                                    id: id.clone(),
                                    session,
                                }
                            }
                            Err(rejection) => {
                                // Refused before the host ever saw it; tell the
                                // agent so its own wait ends.
                                let _ = child
                                    .send(&permission_response(&id, &PermissionOutcome::Cancelled))
                                    .await;
                                AgentEvent::PermissionRefused {
                                    id: id.clone(),
                                    rule: rejection.rule,
                                }
                            }
                        };
                        if to_host.send(event).await.is_err() {
                            return;
                        }
                    }
                    MessageKind::Response => {
                        let Some(id) = message.id.as_ref().and_then(id_from_value) else {
                            continue;
                        };
                        let result = message.value.get("result").cloned();
                        if ask_owner(&commands, |reply| Command::Response { id, result, reply })
                            .await
                            .is_none()
                        {
                            return;
                        }
                    }
                }
            }
            ChildEvent::Ended(end) => {
                // The owner fails every outstanding waiter before the host is
                // told the stream ended.
                let _ = ask_owner(&commands, |reply| Command::ChildEnded { end, reply }).await;
                let _ = to_host.send(AgentEvent::Ended(end)).await;
                return;
            }
        }
    }
}

/// Wake on the tick, have the owner read the clock and hand the reading to
/// the pure table, and act on what it decided. A permission that ran out of
/// time is **cancelled**; there is no path here that approves one.
async fn observe_deadlines(
    commands: mpsc::Sender<Command>,
    child: Arc<ChildHandle>,
    to_host: mpsc::Sender<AgentEvent>,
    tick: Duration,
    counters: Arc<ChildCounters>,
) {
    let _alive = TaskGuard::new(&counters);
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // **This task must end when the child does.** It holds an
        // `Arc<ChildHandle>`, and a ticker that loops forever keeps that
        // strong count above zero, so `ChildHandle::drop` — which is where the
        // synchronous process-group kill lives — would never run for a
        // supervisor that was dropped rather than drained. That was the
        // M8-C07 review's first finding, and it left real `sleep` grandchildren
        // behind with their leaders already reaped.
        tokio::select! {
            () = child.wait_exited() => return,
            _ = ticker.tick() => {}
        }
        let Some(expired) = ask_owner(&commands, |reply| Command::Observe { reply }).await else {
            return;
        };
        for permission in expired {
            // Tell the agent, on the wire, that its request was cancelled.
            let _ = child
                .send(&permission_response(
                    &permission.id,
                    &PermissionOutcome::Cancelled,
                ))
                .await;
            let event = AgentEvent::PermissionExpired {
                id: permission.id,
                session: permission.session,
                elapsed_ms: permission.elapsed,
                bound_ms: permission.bound,
                outcome: permission.outcome,
            };
            if to_host.send(event).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ConnectionScope {
        ConnectionScope {
            tenant: "tenant-a".to_owned(),
            principal: "principal-a".to_owned(),
            device: "device-a".to_owned(),
            service: "agent".to_owned(),
            connection: "connection-1".to_owned(),
        }
    }

    /// An owner with no child behind it: `handle` is synchronous, so a test
    /// can place a command exactly between two others.
    fn owner() -> (Owner, watch::Receiver<Published>) {
        let connection = AcpConnection::new(MAX_SESSIONS_PER_CONNECTION);
        let callbacks = CallbackTable::new(MAX_PENDING_PER_DIRECTION);
        let (published, snapshots) = watch::channel(Published {
            lifecycle: connection.lifecycle(),
            session_count: 0,
            pending_host_to_agent: 0,
            pending_agent_to_host: 0,
            resolutions: 0,
            permission_expirations: 0,
        });
        let owner = Owner {
            connection,
            callbacks,
            waiters: HashMap::new(),
            next_id: 0,
            session_limit: MAX_SESSIONS_PER_CONNECTION,
            open_sessions: Vec::new(),
            host_scope: scope().id_scope(Direction::HostToAgent),
            agent_scope: scope().id_scope(Direction::AgentToHost),
            started: Instant::now(),
            permission_timeout_ms: 60_000,
            published,
        };
        (owner, snapshots)
    }

    fn ready_session(owner: &mut Owner, session: &str) {
        let (reply, mut answer) = oneshot::channel();
        owner.handle(Command::Advance {
            event: LifecycleEvent::Initialized,
            reply,
        });
        answer.try_recv().expect("replied").expect("initialized");
        let (reply, mut answer) = oneshot::channel();
        owner.handle(Command::OpenSession {
            session: session.to_owned(),
            reply,
        });
        answer.try_recv().expect("replied").expect("opened");
        let (reply, mut answer) = oneshot::channel();
        owner.handle(Command::SubscriberReady {
            session: session.to_owned(),
            reply,
        });
        answer.try_recv().expect("replied").expect("subscriber");
    }

    fn prompt(
        owner: &mut Owner,
        session: &str,
    ) -> oneshot::Receiver<Result<Dispatched, SupervisorError>> {
        let (reply, answer) = oneshot::channel();
        owner.handle(Command::Dispatch {
            method: "session/prompt",
            params: json!({"sessionId": session}),
            kind: PendingKind::Prompt,
            session: Some(session.to_owned()),
            gate: Gate::Prompt,
            reply,
        });
        answer
    }

    fn respond(owner: &mut Owner, id: i64) {
        let (reply, _answer) = oneshot::channel();
        owner.handle(Command::Response {
            id: RequestId::Number(id),
            result: Some(json!({"stopReason": "end_turn"})),
            reply,
        });
    }

    /// A caller that drops `prompt()` after its command was queued has a
    /// closed reply channel by the time the owner registers the request. The
    /// registration must be undone in that same command: the line was never
    /// written, so nothing may stay outstanding for it.
    #[test]
    fn a_prompt_whose_caller_went_away_is_undone_and_its_late_response_is_ignored() {
        let (mut owner, snapshots) = owner();
        ready_session(&mut owner, "s1");

        // The caller is gone before the owner applies the command.
        let (reply, answer) = oneshot::channel();
        drop(answer);
        owner.handle(Command::Dispatch {
            method: "session/prompt",
            params: json!({"sessionId": "s1"}),
            kind: PendingKind::Prompt,
            session: Some("s1".to_owned()),
            gate: Gate::Prompt,
            reply,
        });

        // The id was allocated, and then everything about it was undone.
        assert_eq!(owner.next_id, 1);
        assert!(owner.waiters.is_empty(), "no waiter is left behind");
        assert_eq!(owner.callbacks.pending_in(&owner.host_scope), 0);
        assert_eq!(owner.callbacks.resolutions(), 1);
        let published = *snapshots.borrow();
        assert_eq!(published.pending_host_to_agent, 0);
        assert_eq!(published.resolutions, 1, "exactly one resolution");

        // The prompt slot is free: the next prompt is admitted, under a new id.
        let mut second = prompt(&mut owner, "s1");
        let Dispatched {
            id,
            reply: mut ticket,
            ..
        } = second
            .try_recv()
            .expect("replied")
            .expect("the slot was given back");
        assert_eq!(id, RequestId::Number(2));
        assert_eq!(owner.waiters.len(), 1);

        // A late response for the forgotten id resolves nothing and reaches
        // nobody — in particular not the request that came after it.
        respond(&mut owner, 1);
        assert!(ticket.try_recv().is_err(), "the later request is untouched");
        assert_eq!(owner.callbacks.resolutions(), 1);
        assert_eq!(owner.callbacks.pending_in(&owner.host_scope), 1);
        assert_eq!(owner.waiters.len(), 1);
        // The slot is still held by the second prompt, not freed by the stray.
        let refused = prompt(&mut owner, "s1")
            .try_recv()
            .expect("replied")
            .err()
            .expect("the second prompt still holds the slot");
        assert_eq!(refused.rule(), Some(LifecycleRule::PromptAlreadyActive));

        // Its own response is delivered to it, once.
        respond(&mut owner, 2);
        let value = ticket.try_recv().expect("delivered").expect("a result");
        assert_eq!(value["stopReason"], "end_turn");
        assert!(owner.waiters.is_empty());
        assert_eq!(owner.callbacks.pending_in(&owner.host_scope), 0);
        assert_eq!(snapshots.borrow().resolutions, 2);
    }
}
