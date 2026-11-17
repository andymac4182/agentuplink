//! The Streamable HTTP export: transparent forwarding to one fixed,
//! operator-configured loopback MCP server.
//!
//! * The target address, `Host`, path and backend credential come only from
//!   configuration.  The consumer's request contributes a method that its
//!   profile routes allow, the validated profile headers and the validated
//!   body; nothing in it can select a host, port, proxy or path.
//! * The complete bounded body is validated ([`tunnel_mcp::message`]) before
//!   the backend is dialled.
//! * `Accept-Encoding: identity` is always sent and any other response
//!   `Content-Encoding` is refused, so byte limits count real bytes.
//! * Redirects are never followed: a 3xx is a local 502.  A backend 401, 403
//!   or 407 is a local 502 as well, so a private `WWW-Authenticate`
//!   challenge never reaches the consumer as if it were relay login.
//! * Response headers are reduced to the profile's response allowlist; the
//!   body streams with the JSON or SSE cumulative limit by content type.
//! * Dropping the response body closes the backend connection, which is the
//!   2026-07-28 cancellation signal; for 2025-11-25 it is a plain disconnect,
//!   exactly what the consumer did.
//! * A failure before the request is written is a sanitized 502 JSON-RPC
//!   error (the backend was not invoked); a failure after it was written is
//!   an interruption with no fabricated JSON-RPC result.
//! * M3-04: the backend owns `mcp-2025-11-25` session identifiers, but the
//!   device owns who may use one.  This export remembers the opaque
//!   `tunnel-principal-binding` each session was issued to and refuses any
//!   other principal — and any session it did not see issued — as an unknown
//!   session, before the backend is dialled.  The binding itself is
//!   relay-to-device metadata and is never forwarded upstream.  Capacity is
//!   refused at the door and capped per principal, so opening sessions can
//!   never evict anybody else's, and an entry unused for
//!   `session_idle_seconds` is forgotten, so a client that vanishes without a
//!   DELETE cannot hold a slot for ever.

use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tunnel_http_bridge::ChannelBody;
use tunnel_mcp::message::{McpRejection, codes, validate_delete, validate_get, validate_post};
use tunnel_mcp::{McpLimits, McpProfile};

use crate::body::{
    BodyEffect, BodyEvent, BodyOver, BodyPhase, BoxError, CollectError, ExportBody, StreamFailure,
    capacity_refusal, collect_limited, local_error, rejection,
};
use crate::config::{HttpBackend, McpConfigError};
use crate::{ExportCounters, ExportError};

/// Bound on dialling the fixed backend.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest accepted bearer token file.
pub const MAX_TOKEN_BYTES: usize = 8192;
/// Backend-issued `mcp-2025-11-25` sessions whose principal binding this
/// export tracks at once.
pub const MAX_TRACKED_SESSIONS: usize = 256;
/// Sessions one principal may hold at once.  One principal therefore cannot
/// fill the table, and a new `initialize` is refused before the backend is
/// dialled instead of evicting somebody else's live session.
pub const MAX_SESSIONS_PER_BINDING: usize = MAX_TRACKED_SESSIONS / 8;
/// Decisions queued towards the task that owns the session table.  An
/// exchange waits for room; the task never waits on anything else, so the
/// queue always drains.
pub const BINDING_QUEUE: usize = 64;

/// Session-less requests that may be in flight towards the backend with a
/// reservation at once.  One past it is forwarded without a reservation, and
/// a session the backend issues to it is refused instead of recorded.
pub const MAX_PENDING_OPENS: usize = MAX_TRACKED_SESSIONS * 4;

/// A reservation: the request was admitted and may yet be issued a session.
const RESERVED: u8 = 0;
/// A recorded session its binding may use.
const LIVE: u8 = 1;
/// Ended: revoked, or a reservation whose exchange finished without a
/// session.  Terminal.
const ENDED: u8 = 2;

/// Who a session -- or a request that may open one -- belongs to, and whether
/// it has ended.  This is the part of an entry the revocation path can see.
///
/// It is published when the request is **admitted**, before the backend is
/// dialled, and the session that request opens keeps the same value.  A
/// revocation therefore always finds it, whether it lands before the session
/// is recorded (the record is then refused) or after (the entry is dropped
/// before the next decision).
#[derive(Debug)]
struct Bound {
    binding: Option<String>,
    /// `RESERVED`, then `LIVE` (set only by the table's task), or `ENDED`.
    state: AtomicU8,
}

impl Bound {
    fn is_ended(&self) -> bool {
        self.state.load(Ordering::SeqCst) == ENDED
    }

    /// End it, whatever it was.  Returns whether this call ended a recorded
    /// session.
    fn end(&self) -> bool {
        self.state.swap(ENDED, Ordering::SeqCst) == LIVE
    }

    /// Turn a reservation into a recorded session.  Refused when a
    /// revocation ended it first.
    fn go_live(&self) -> bool {
        self.state
            .compare_exchange(RESERVED, LIVE, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// End a reservation that was never recorded.  Returns whether it was
    /// still one.
    fn abandon(&self) -> bool {
        self.state
            .compare_exchange(RESERVED, ENDED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

/// One remembered session: who may use it, and when it was last used.
#[derive(Debug)]
struct SessionEntry {
    bound: Arc<Bound>,
    last_used: Instant,
}

/// What became of a session the backend issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Recorded {
    /// The session is bound to the principal that opened it.
    Bound,
    /// The backend reissued an identifier that is already bound to another
    /// principal.  Nothing was recorded, and the session is not this
    /// caller's to end.
    Foreign,
    /// Not recorded: the principal's authorization was revoked while the
    /// request was in flight, there is no room, or the table is gone.
    Refused,
}

/// Principal bindings for the sessions a Streamable HTTP backend issued
/// through this export (M3-04).  The backend owns the session identifiers;
/// the device owns which principal may use them.
///
/// Nothing here ever evicts another principal's entry.  An earlier revision
/// dropped the oldest binding when the table filled, which let any authorized
/// principal evict every other principal's live session — a cross-principal
/// denial channel — by opening 257 sessions.  Capacity is refused at the door
/// instead.
///
/// An entry leaves when its own session does — a successful DELETE, or a
/// backend that answers 404 for it — or when it has gone unused for
/// `session_idle_seconds`.  The expiry is what keeps a client that crashes
/// and restarts without a DELETE from leaking one slot per restart: without
/// it, thirty-two restarts would refuse that principal every `initialize`
/// until the device process restarted, and 256 abandoned sessions would lock
/// the export for everyone.  Expiry fails closed: a forgotten session is
/// answered 404 and its own holder re-initializes; nobody else is affected.
#[derive(Debug, Default)]
struct SessionBindings {
    bindings: std::collections::HashMap<String, SessionEntry>,
    /// Admitted session-less requests whose exchange has not finished.
    reserved: Vec<Arc<Bound>>,
}

impl SessionBindings {
    /// Drop every entry a revocation ended and every reservation that ended.
    /// Called before each decision, so a revoked session is never permitted
    /// and never holds a slot.  Returns whether anything left.
    fn prune(&mut self) -> bool {
        let before = self.bindings.len() + self.reserved.len();
        self.bindings.retain(|_, entry| !entry.bound.is_ended());
        self.reserved.retain(|bound| !bound.is_ended());
        self.bindings.len() + self.reserved.len() != before
    }

    /// Forget every entry unused for `idle`.  Called before each capacity or
    /// permission decision, so the table is never consulted while stale.
    fn expire(&mut self, now: Instant, idle: Duration) {
        self.bindings
            .retain(|_, entry| now.saturating_duration_since(entry.last_used) < idle);
    }

    /// What the revocation path may see: who each remembered session, and
    /// each request that may yet open one, belongs to.
    fn published(&self) -> Published {
        self.bindings
            .values()
            .map(|entry| &entry.bound)
            .chain(&self.reserved)
            .cloned()
            .collect()
    }

    /// Whether `binding` may use `session`, marking it used if so.  An
    /// unknown session is refused.
    fn permits(&mut self, session: &str, binding: Option<&String>, now: Instant) -> bool {
        match self.bindings.get_mut(session) {
            Some(entry) if entry.bound.binding.as_ref() == binding => {
                entry.last_used = now;
                true
            }
            _ => false,
        }
    }

    fn held_by(&self, binding: Option<&String>) -> usize {
        self.bindings
            .values()
            .filter(|entry| entry.bound.binding.as_ref() == binding)
            .count()
    }

    /// Whether one more session may be opened for `binding`.
    fn has_room_for(&self, binding: Option<&String>) -> bool {
        self.bindings.len() < MAX_TRACKED_SESSIONS
            && self.held_by(binding) < MAX_SESSIONS_PER_BINDING
    }

    /// Reserve for a session-less request of `binding`, so a revocation can
    /// see it before the backend answers.  `None` past
    /// [`MAX_PENDING_OPENS`].
    fn reserve(&mut self, binding: Option<String>) -> Option<Arc<Bound>> {
        if self.reserved.len() >= MAX_PENDING_OPENS {
            return None;
        }
        let bound = Arc::new(Bound {
            binding,
            state: AtomicU8::new(RESERVED),
        });
        self.reserved.push(Arc::clone(&bound));
        Some(bound)
    }

    /// Record a session the backend issued to the request that holds the
    /// reservation `bound`.  Refuses when the reservation has ended (its
    /// binding was revoked), or the table or the principal's share is full;
    /// the caller fails the exchange closed.
    fn remember(&mut self, session: String, bound: &Arc<Bound>, now: Instant) -> Recorded {
        let Some(index) = self
            .reserved
            .iter()
            .position(|reserved| Arc::ptr_eq(reserved, bound))
        else {
            return Recorded::Refused;
        };
        let bound = self.reserved.swap_remove(index);
        if let Some(existing) = self.bindings.get(&session) {
            // The first binding of an identifier stands.
            // The reissued identifier is usable by this caller exactly when
            // it already was; a reservation a revocation ended is refused.
            let same = existing.bound.binding == bound.binding;
            let unrevoked = bound.abandon();
            return match (same, unrevoked) {
                (true, true) => Recorded::Bound,
                (true, false) => Recorded::Refused,
                (false, _) => Recorded::Foreign,
            };
        }
        if !self.has_room_for(bound.binding.as_ref()) || !bound.go_live() {
            let _ = bound.abandon();
            return Recorded::Refused;
        }
        self.bindings.insert(
            session,
            SessionEntry {
                bound,
                last_used: now,
            },
        );
        Recorded::Bound
    }

    fn forget(&mut self, session: &str) {
        self.bindings.remove(session);
    }

    fn len(&self) -> usize {
        self.bindings.len()
    }
}

/// The remembered sessions' owners, as last published by the table's task.
type Published = Arc<[Arc<Bound>]>;

/// An admitted session-less request's claim on the session it may open.
///
/// Dropping it without recording a session ends the reservation, so an
/// exchange that fails, is cancelled, or is answered without a session leaves
/// nothing behind.
#[derive(Debug)]
struct Reservation {
    bound: Arc<Bound>,
    prune: Arc<Notify>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.bound.abandon() {
            self.prune.notify_one();
        }
    }
}

/// What the session table decided about one request.
#[derive(Debug)]
enum Admission {
    /// Forward it.  A request naming no session carries the reservation a
    /// session issued to it must be recorded under.
    Admitted(Option<Reservation>),
    /// The request names a session this principal may not use.
    UnknownSession,
    /// The request would open a session and there is no room for one.
    AtCapacity,
}

/// What an exchange asks of the task that owns the session table.
enum BindingCommand {
    /// Decide whether a request may be forwarded.  Expiry, the permission
    /// check and the capacity check are one decision.
    Admit {
        session: Option<String>,
        binding: Option<String>,
        /// Whether the request would open a session (a POST naming none).
        opens: bool,
        now: Instant,
        idle: Duration,
        decided: oneshot::Sender<Admission>,
    },
    /// Record a session the backend issued, and say whether it was.
    Remember {
        session: String,
        bound: Arc<Bound>,
        now: Instant,
        recorded: oneshot::Sender<Recorded>,
    },
    /// The named session is gone.
    Forget { session: String },
}

/// The export's handle on the task that owns its session table.
///
/// **One task owns the table.**  Exchanges ask it for decisions in order, so
/// expiry, permission and capacity are decided against one consistent table.
/// A revocation is synchronous and cannot wait for that task, so it works on
/// what the task last published: it ends each of the binding's entries -- one
/// atomic swap per entry, so each session is counted once -- and the task
/// drops ended entries before every decision it takes.
///
/// **A revocation cannot miss a session.**  The value a revocation ends is
/// published when the opening request is admitted, not when its session is
/// recorded, and the exchange does not answer until the task has said the
/// session was recorded.  So a revocation that lands while the request is in
/// flight ends the reservation and the record is refused; one that lands
/// after the record ends the session.  There is no window in which the
/// consumer holds a session identifier the revocation path could not see.
struct BindingTable {
    commands: mpsc::Sender<BindingCommand>,
    published: watch::Receiver<Published>,
    /// Nudges the owning task to drop entries that ended.
    prune: Arc<Notify>,
}

impl BindingTable {
    /// Start the owning task.  Called from an exchange, so a runtime is
    /// running.
    fn start() -> Self {
        let (commands, inbox) = mpsc::channel(BINDING_QUEUE);
        let (publish, published) = watch::channel(Published::from(Vec::new()));
        let prune = Arc::new(Notify::new());
        tokio::spawn(own_bindings(inbox, publish, Arc::clone(&prune)));
        Self {
            commands,
            published,
            prune,
        }
    }

    /// Ask for a decision.  A table whose task is gone admits nothing.
    async fn admit(
        &self,
        session: Option<String>,
        binding: Option<String>,
        opens: bool,
        idle: Duration,
    ) -> Admission {
        let (decided, decision) = oneshot::channel();
        let command = BindingCommand::Admit {
            session,
            binding,
            opens,
            now: Instant::now(),
            idle,
            decided,
        };
        if self.commands.send(command).await.is_err() {
            return Admission::UnknownSession;
        }
        decision.await.unwrap_or(Admission::UnknownSession)
    }

    /// Record `session` under `reservation` and wait for the table's task to
    /// say it did.  No reservation, a task that is gone, and a refusal are
    /// all [`Recorded::Refused`]: the caller must not hand the session out.
    async fn remember(&self, reservation: Option<Reservation>, session: String) -> Recorded {
        let Some(reservation) = reservation else {
            return Recorded::Refused;
        };
        let (recorded, answer) = oneshot::channel();
        let command = BindingCommand::Remember {
            session,
            bound: Arc::clone(&reservation.bound),
            now: Instant::now(),
            recorded,
        };
        if self.commands.send(command).await.is_err() {
            return Recorded::Refused;
        }
        // The reservation is held until the answer, so an exchange dropped
        // here before the task acted leaves a reservation that ends.
        let answer = answer.await.unwrap_or(Recorded::Refused);
        drop(reservation);
        answer
    }

    /// End every session issued to `binding`, and every reservation one of
    /// its requests holds; returns how many sessions this call ended.
    fn forget_binding(&self, binding: &str) -> u64 {
        let published = Arc::clone(&self.published.borrow());
        let mut forgotten = 0;
        for bound in published.iter() {
            if bound.binding.as_deref() == Some(binding) && bound.end() {
                forgotten += 1;
            }
        }
        self.prune.notify_one();
        forgotten
    }
}

/// The session table's task: its only owner and only writer.
///
/// It ends when the export that holds the sending half is dropped.
async fn own_bindings(
    mut commands: mpsc::Receiver<BindingCommand>,
    publish: watch::Sender<Published>,
    prune: Arc<Notify>,
) {
    let mut sessions = SessionBindings::default();
    loop {
        let command = tokio::select! {
            command = commands.recv() => match command {
                Some(command) => Some(command),
                None => return,
            },
            () = prune.notified() => None,
        };
        let mut changed = sessions.prune();
        match command {
            Some(BindingCommand::Admit {
                session,
                binding,
                opens,
                now,
                idle,
                decided,
            }) => {
                let before = sessions.len();
                sessions.expire(now, idle);
                changed |= sessions.len() != before;
                let admission = match &session {
                    Some(session) if !sessions.permits(session, binding.as_ref(), now) => {
                        Admission::UnknownSession
                    }
                    Some(_) => Admission::Admitted(None),
                    None if opens && !sessions.has_room_for(binding.as_ref()) => {
                        Admission::AtCapacity
                    }
                    None => Admission::Admitted(sessions.reserve(binding).map(|bound| {
                        changed = true;
                        Reservation {
                            bound,
                            prune: Arc::clone(&prune),
                        }
                    })),
                };
                // Published before the decision is answered: a revocation
                // that follows the answer finds the reservation.
                if changed {
                    publish.send_replace(sessions.published());
                    changed = false;
                }
                let _ = decided.send(admission);
            }
            Some(BindingCommand::Remember {
                session,
                bound,
                now,
                recorded,
            }) => {
                let answer = sessions.remember(session, &bound, now);
                // The reservation left the table whatever the answer; when
                // it was recorded the same value is published as a session.
                publish.send_replace(sessions.published());
                let _ = recorded.send(answer);
            }
            Some(BindingCommand::Forget { session }) => {
                let before = sessions.len();
                sessions.forget(&session);
                changed |= sessions.len() != before;
            }
            None => {}
        }
        if changed {
            publish.send_replace(sessions.published());
        }
    }
}

/// A validated Streamable HTTP export.
pub struct HttpBackendExport {
    profile: McpProfile,
    limits: McpLimits,
    backend: HttpBackend,
    authorization: Option<HeaderValue>,
    counters: Arc<ExportCounters>,
    /// The session table.  Started by the first exchange, because an export
    /// may be built where no runtime is running yet.
    sessions: OnceLock<BindingTable>,
}

impl std::fmt::Debug for HttpBackendExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpBackendExport")
            .field("profile", &self.profile)
            .field("credential", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The backend response body: counted, limited, and owning the connection.
struct BackendBody {
    inner: Incoming,
    limit: u64,
    phase: BodyPhase,
    counter: Arc<AtomicU64>,
    _connection: AbortOnDrop,
}

impl BackendBody {
    /// Apply one event and report what to yield for it.
    fn advance(&mut self, event: BodyEvent) -> BodyEffect {
        match self.phase.on_event(event, self.limit) {
            Ok((next, effect)) => {
                self.phase = next;
                effect
            }
            Err(BodyOver) => BodyEffect::Finish,
        }
    }
}

impl Body for BackendBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if !self.phase.is_streaming() {
            return Poll::Ready(None);
        }
        let frame = match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                let _ = self.advance(BodyEvent::End);
                return Poll::Ready(None);
            }
            Poll::Ready(Some(Err(_))) => {
                let _ = self.advance(BodyEvent::Failure(StreamFailure::Interrupted));
                return Poll::Ready(Some(Err(Box::new(StreamFailure::Interrupted))));
            }
            Poll::Ready(Some(Ok(frame))) => frame,
        };
        let event = frame
            .data_ref()
            .map_or(BodyEvent::Other, |data| BodyEvent::Data(data.len() as u64));
        match self.advance(event) {
            BodyEffect::Fail(failure) => Poll::Ready(Some(Err(Box::new(failure)))),
            BodyEffect::Forward | BodyEffect::Finish => {
                if let Some(data) = frame.data_ref() {
                    self.counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                // Non-empty trailers are refused by the bridge; the frame is
                // passed on so it decides.
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl HttpBackendExport {
    /// Forget the backend sessions bound to `binding` (M3-16).
    pub(crate) fn forget_binding_sessions(&self, binding: &str) -> u64 {
        self.sessions
            .get()
            .map_or(0, |sessions| sessions.forget_binding(binding))
    }

    pub(crate) fn new(
        profile: McpProfile,
        limits: McpLimits,
        backend: HttpBackend,
        counters: Arc<ExportCounters>,
    ) -> Result<Self, McpConfigError> {
        const TOKEN_RULE: &str =
            "mcp.backend.bearer_token_file must hold one visible-ASCII token of at most 8192 bytes";
        let authorization = match &backend.bearer_token_file {
            None => None,
            Some(path) => {
                let text = std::fs::read(path).map_err(|_| McpConfigError(TOKEN_RULE))?;
                let token = std::str::from_utf8(&text)
                    .map_err(|_| McpConfigError(TOKEN_RULE))?
                    .trim_end_matches(['\n', '\r']);
                if token.is_empty()
                    || token.len() > MAX_TOKEN_BYTES
                    || !token.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(McpConfigError(TOKEN_RULE));
                }
                let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| McpConfigError(TOKEN_RULE))?;
                value.set_sensitive(true);
                Some(value)
            }
        };
        Ok(Self {
            profile,
            limits,
            backend,
            authorization,
            counters,
            sessions: OnceLock::new(),
        })
    }

    fn sessions(&self) -> &BindingTable {
        self.sessions.get_or_init(BindingTable::start)
    }

    fn reject(&self, value: &McpRejection) -> Response<ExportBody> {
        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
        rejection(value)
    }

    fn backend_error(&self, status: StatusCode, message: &'static str) -> Response<ExportBody> {
        self.counters.backend_errors.fetch_add(1, Ordering::Relaxed);
        local_error(status, message, None)
    }

    /// Best effort: ask the backend to end a session it issued that this
    /// export refused to record.  Bounded by [`CONNECT_TIMEOUT`]; the
    /// backend's own idle expiry covers a failure.
    async fn end_backend_session(&self, session: &str) {
        let mut request = Request::builder()
            .method(Method::DELETE)
            .uri(self.backend.path.as_str())
            .header(http::header::HOST, self.backend.authority.as_str())
            .header(http::header::ACCEPT_ENCODING, "identity")
            .header(tunnel_mcp::headers::MCP_SESSION_ID, session)
            .header(
                tunnel_mcp::headers::MCP_PROTOCOL_VERSION,
                tunnel_mcp::PROTOCOL_2025_11_25,
            );
        if let Some(authorization) = &self.authorization {
            request = request.header(http::header::AUTHORIZATION, authorization.clone());
        }
        let Ok(request) = request.body(http_body_util::Full::new(Bytes::new())) else {
            return;
        };
        let address = self.backend.address;
        let _ = tokio::time::timeout(CONNECT_TIMEOUT, async move {
            let stream = TcpStream::connect(address).await.ok()?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .ok()?;
            let _connection = AbortOnDrop(tokio::spawn(async move {
                let _ = connection.await;
            }));
            sender.send_request(request).await.ok().map(drop)
        })
        .await;
    }

    /// Serve one exchange.
    ///
    /// # Errors
    /// [`ExportError`] when the backend may have received the request but no
    /// response head was obtained, or the request body failed.
    pub async fn handle(
        self: Arc<Self>,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let (parts, body) = request.into_parts();
        let limit = if parts.method == Method::POST {
            self.limits.request_body()
        } else {
            0
        };
        let checked = match parts.method {
            Method::POST => Ok(()),
            Method::GET => validate_get(self.profile, &parts.headers),
            Method::DELETE => validate_delete(self.profile, &parts.headers),
            _ => Err(McpRejection {
                status: 405,
                code: codes::INVALID_REQUEST,
                message: "method not allowed",
                id: None,
                supported: None,
            }),
        };
        if let Err(error) = checked {
            return Ok(self.reject(&error));
        }
        let body = match collect_limited(body, limit).await {
            Ok(body) => body,
            Err(CollectError::TooLarge) => {
                return Ok(self.reject(&McpRejection {
                    status: if limit == 0 { 400 } else { 413 },
                    code: codes::INVALID_REQUEST,
                    message: "the request body exceeds the export limit",
                    id: None,
                    supported: None,
                }));
            }
            Err(CollectError::Interrupted) => return Err(ExportError),
        };
        // The consumer's body is forwarded as received, except an
        // `initialize` whose offered revision was rewritten (M3-38).
        let body = if parts.method == Method::POST {
            match validate_post(self.profile, &parts.headers, &body) {
                Ok(message) if message.protocol_version_rewritten => Bytes::from(message.compact),
                Ok(_) => body,
                Err(error) => return Ok(self.reject(&error)),
            }
        } else {
            body
        };

        // M3-04.  This revision's sessions belong to the backend, but which
        // principal may use one is the device's decision: a request naming a
        // session this export did not see opened for exactly this principal
        // binding is answered as an unknown session, before the backend is
        // dialled, so nothing is dispatched and nothing distinguishes a
        // foreign session from a nonexistent one.
        let binding = crate::request_principal_binding(&parts.headers);
        let named_session = parts
            .headers
            .get(tunnel_mcp::headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut reservation = None;
        if self.profile.is_legacy() {
            let admission = self
                .sessions()
                .admit(
                    named_session.clone(),
                    binding.clone(),
                    parts.method == Method::POST,
                    self.backend.session_idle,
                )
                .await;
            match admission {
                Admission::Admitted(reserved) => reservation = reserved,
                Admission::UnknownSession => {
                    return Ok(self.reject(&McpRejection {
                        status: 404,
                        code: codes::INVALID_REQUEST,
                        message: "session not found",
                        id: None,
                        supported: None,
                    }));
                }
                // A POST naming no session opens one.  Capacity is decided
                // here, before the backend is dialled, so a full table
                // refuses the newcomer instead of evicting somebody else's
                // live session, and so the backend never creates a session
                // this export could not track.
                Admission::AtCapacity => {
                    // Counted like any other refusal, so diagnostics and the
                    // gate can see an export that is at its session limit.
                    self.counters.rejected.fetch_add(1, Ordering::Relaxed);
                    return Ok(capacity_refusal(
                        "the export is at its session limit",
                        // The request ID is not parsed here; JSON-RPC sends
                        // an unknown ID as `null` (review of #187).
                        Some(serde_json::Value::Null),
                    ));
                }
            }
        }

        let mut upstream = Request::builder()
            .method(parts.method.clone())
            .uri(self.backend.path.as_str());
        for (name, value) in &parts.headers {
            // The codec already reduced the head to the profile allowlist;
            // copy exactly those fields and nothing the export sets itself.
            // The principal binding is relay-to-device metadata and is never
            // forwarded: the backend authenticates nobody.
            if name.as_str() == tunnel_mcp::headers::TUNNEL_PRINCIPAL_BINDING
                || name == http::header::HOST
                || name == http::header::ACCEPT_ENCODING
                || name == http::header::AUTHORIZATION
                || name == http::header::CONTENT_LENGTH
            {
                continue;
            }
            upstream = upstream.header(name, value);
        }
        upstream = upstream
            .header(http::header::HOST, self.backend.authority.as_str())
            .header(http::header::ACCEPT_ENCODING, "identity");
        if let Some(authorization) = &self.authorization {
            upstream = upstream.header(http::header::AUTHORIZATION, authorization.clone());
        }
        let Ok(upstream) = upstream.body(http_body_util::Full::new(body)) else {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend request could not be built",
            ));
        };

        let Ok(Ok(stream)) =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.backend.address)).await
        else {
            return Ok(
                self.backend_error(StatusCode::BAD_GATEWAY, "the MCP backend is unavailable")
            );
        };
        let Ok((mut sender, connection)) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
        else {
            return Ok(
                self.backend_error(StatusCode::BAD_GATEWAY, "the MCP backend is unavailable")
            );
        };
        let connection = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        self.counters.dispatched.fetch_add(1, Ordering::Relaxed);
        let Ok(response) = sender.send_request(upstream).await else {
            self.counters.interrupted.fetch_add(1, Ordering::Relaxed);
            return Err(ExportError);
        };
        let status = response.status();
        if status.is_redirection() {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend redirected; redirects are not followed",
            ));
        }
        if matches!(
            status,
            StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::PROXY_AUTHENTICATION_REQUIRED
        ) {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend refused the device credential",
            ));
        }
        if status.is_informational() || status == StatusCode::SWITCHING_PROTOCOLS {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend switched protocols",
            ));
        }
        let upstream_headers = response.headers();
        if upstream_headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend used an unsupported content encoding",
            ));
        }
        let is_sse = upstream_headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/event-stream"))
            });
        let body_limit = if is_sse {
            self.limits.sse_response_body()
        } else {
            self.limits.json_response_body()
        };
        let declared = upstream_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > body_limit) {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend response exceeds the export limit",
            ));
        }
        if self.profile.is_legacy() {
            // A session the backend issues on a successful exchange belongs
            // to the principal that opened it, and a successful DELETE ends
            // it.  Nothing is recorded for a failed exchange.
            let issued = upstream_headers
                .get(tunnel_mcp::headers::MCP_SESSION_ID)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            match (&named_session, status) {
                // Only the exchange that opened a session binds it.  A
                // backend that echoes some other identifier on a later
                // request cannot bind it to this caller.
                (None, status) if status.is_success() => {
                    if let Some(session) = issued {
                        // The table's task has recorded the session before
                        // the consumer can learn its identifier, under the
                        // reservation a revocation has been able to see
                        // since this request was admitted.  Anything else
                        // fails closed: the identifier is not handed out.
                        let recorded = self
                            .sessions()
                            .remember(reservation.take(), session.clone())
                            .await;
                        if recorded != Recorded::Bound {
                            drop(response);
                            drop(connection);
                            if recorded == Recorded::Refused {
                                // Nobody can use the session through this
                                // export; do not leave it open upstream.
                                self.end_backend_session(&session).await;
                            }
                            return Ok(self.backend_error(
                                StatusCode::BAD_GATEWAY,
                                "the MCP session could not be opened",
                            ));
                        }
                    }
                }
                // The session this request named is gone: a successful
                // DELETE ended it, and a 404 says the backend expired it.
                // Forgetting it is what keeps the table from filling with
                // sessions no one can use.
                (Some(session), status)
                    if (status.is_success() && parts.method == Method::DELETE)
                        || status == StatusCode::NOT_FOUND =>
                {
                    let _ = self
                        .sessions()
                        .commands
                        .send(BindingCommand::Forget {
                            session: session.clone(),
                        })
                        .await;
                }
                _ => {}
            }
        }
        let mut out = Response::builder().status(status);
        for (name, _) in self.profile.response_headers() {
            let mut values = upstream_headers.get_all(*name).iter();
            if let Some(value) = values.next() {
                if values.next().is_some() {
                    return Ok(self.backend_error(
                        StatusCode::BAD_GATEWAY,
                        "the MCP backend repeated a singleton response header",
                    ));
                }
                if !value
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == b'\t' || (0x20..0x7f).contains(byte))
                {
                    return Ok(self.backend_error(
                        StatusCode::BAD_GATEWAY,
                        "the MCP backend sent an invalid response header",
                    ));
                }
                out = out.header(*name, value.clone());
            }
        }
        let zero_body = matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        );
        let body: ExportBody = if zero_body {
            drop(response);
            drop(connection);
            crate::body::empty()
        } else {
            BackendBody {
                inner: response.into_body(),
                limit: body_limit,
                phase: BodyPhase::START,
                counter: Arc::clone(&self.counters.streamed_bytes),
                _connection: connection,
            }
            .boxed()
        };
        out.body(body).map_err(|_| ExportError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(label: &str) -> Option<String> {
        Some(label.to_owned())
    }

    /// A fixed origin, so every test states its own clock explicitly instead
    /// of waiting for one.
    fn origin() -> Instant {
        Instant::now()
    }

    const IDLE: Duration = Duration::from_secs(600);

    /// Reserve for `binding` and record `session` under the reservation, as
    /// an admitted exchange does.
    fn remember(
        sessions: &mut SessionBindings,
        session: String,
        binding: Option<String>,
        now: Instant,
    ) -> Recorded {
        let bound = sessions.reserve(binding).expect("room for a reservation");
        sessions.remember(session, &bound, now)
    }

    /// M3-04 review: opening sessions must never cost another principal its
    /// own.  An earlier revision evicted the oldest entry when the table
    /// filled, so any authorized principal could drop every other
    /// principal's live session by opening `MAX_TRACKED_SESSIONS + 1`.
    #[test]
    fn one_principal_cannot_evict_another_by_opening_sessions() {
        let now = origin();
        let mut sessions = SessionBindings::default();
        let victim = binding("victim");
        remember(&mut sessions, "victim-session".into(), victim.clone(), now);
        assert!(sessions.permits("victim-session", victim.as_ref(), now));

        // The attacker exhausts its own share, then the whole table.
        let attacker = binding("attacker");
        for index in 0..MAX_TRACKED_SESSIONS * 2 {
            remember(
                &mut sessions,
                format!("attacker-{index}"),
                attacker.clone(),
                now,
            );
        }
        assert_eq!(
            sessions.held_by(attacker.as_ref()),
            MAX_SESSIONS_PER_BINDING
        );
        assert!(!sessions.has_room_for(attacker.as_ref()));
        // The victim's session is untouched, and the victim can still open
        // one: a principal's own share is not consumed by anybody else.
        assert!(sessions.permits("victim-session", victim.as_ref(), now));
        assert!(sessions.has_room_for(victim.as_ref()));
        assert!(sessions.len() <= MAX_TRACKED_SESSIONS);
    }

    /// The table is bounded, and a full table refuses the newcomer.
    #[test]
    fn a_full_table_refuses_instead_of_evicting() {
        let now = origin();
        let mut sessions = SessionBindings::default();
        let principals = MAX_TRACKED_SESSIONS / MAX_SESSIONS_PER_BINDING;
        for principal in 0..principals {
            let holder = binding(&format!("principal-{principal}"));
            for index in 0..MAX_SESSIONS_PER_BINDING {
                remember(
                    &mut sessions,
                    format!("s-{principal}-{index}"),
                    holder.clone(),
                    now,
                );
            }
        }
        assert_eq!(sessions.len(), MAX_TRACKED_SESSIONS);
        let newcomer = binding("newcomer");
        assert!(!sessions.has_room_for(newcomer.as_ref()));
        remember(
            &mut sessions,
            "newcomer-session".into(),
            newcomer.clone(),
            now,
        );
        assert!(!sessions.permits("newcomer-session", newcomer.as_ref(), now));
        assert_eq!(sessions.len(), MAX_TRACKED_SESSIONS);
        // The first principal's sessions all survived.
        let first = binding("principal-0");
        assert_eq!(sessions.held_by(first.as_ref()), MAX_SESSIONS_PER_BINDING);
        // Ending one frees exactly one slot, for its own holder.
        sessions.forget("s-0-0");
        assert!(sessions.has_room_for(first.as_ref()));
        assert!(sessions.has_room_for(newcomer.as_ref()));
    }

    /// A binding is compared exactly: no principal inherits another's
    /// session, and "no principal" is its own holder.
    #[test]
    fn a_session_permits_only_its_own_binding() {
        let now = origin();
        let mut sessions = SessionBindings::default();
        remember(&mut sessions, "bound".into(), binding("alice"), now);
        remember(&mut sessions, "unbound".into(), None, now);
        assert!(sessions.permits("bound", binding("alice").as_ref(), now));
        assert!(!sessions.permits("bound", binding("bob").as_ref(), now));
        assert!(!sessions.permits("bound", None, now));
        assert!(sessions.permits("unbound", None, now));
        assert!(!sessions.permits("unbound", binding("alice").as_ref(), now));
        assert!(!sessions.permits("never-issued", binding("alice").as_ref(), now));
    }

    /// M3-04 review round 2: without an expiry, a client that crashes and
    /// restarts without a DELETE leaks one slot per restart, and after
    /// `MAX_SESSIONS_PER_BINDING` restarts its own principal is refused every
    /// `initialize` until the device process restarts.
    #[test]
    fn abandoned_sessions_expire_and_do_not_leak_a_principals_share() {
        let start = origin();
        let mut sessions = SessionBindings::default();
        let holder = binding("restarts");
        // Every restart abandons its session without a DELETE.
        for index in 0..MAX_SESSIONS_PER_BINDING {
            let now = start + Duration::from_secs(index as u64);
            sessions.expire(now, IDLE);
            assert!(sessions.has_room_for(holder.as_ref()), "restart {index}");
            remember(
                &mut sessions,
                format!("abandoned-{index}"),
                holder.clone(),
                now,
            );
        }
        // Without an expiry this principal is now locked out for good.
        let full = start + Duration::from_secs(MAX_SESSIONS_PER_BINDING as u64);
        sessions.expire(full, IDLE);
        assert!(!sessions.has_room_for(holder.as_ref()));
        // One idle period after the last use, every abandoned entry is gone
        // and the principal can open a session again.
        let later = full + IDLE;
        sessions.expire(later, IDLE);
        assert_eq!(sessions.len(), 0);
        assert!(sessions.has_room_for(holder.as_ref()));
        // A forgotten session is refused, not silently adopted: its holder
        // re-initializes and nobody else is affected.
        assert!(!sessions.permits("abandoned-0", holder.as_ref(), later));
    }

    /// The review's interleaving: the backend issued a session, the record
    /// is queued, and the principal's authorization is revoked before the
    /// table's task acts on it.  The earlier revision answered the consumer
    /// while the record was only queued, the revocation found nothing
    /// published, and the task then inserted a session nothing had ended.
    #[tokio::test]
    async fn a_revocation_ahead_of_a_queued_record_refuses_it() {
        let table = BindingTable::start();
        let who = binding("revoked");
        let Admission::Admitted(Some(reservation)) =
            table.admit(None, who.clone(), true, IDLE).await
        else {
            panic!("an opening request is admitted with a reservation");
        };
        // Queue the record without letting the task run (this test's runtime
        // has one thread and nothing here yields before the revocation).
        let (recorded, answer) = oneshot::channel();
        table
            .commands
            .send(BindingCommand::Remember {
                session: "issued".into(),
                bound: Arc::clone(&reservation.bound),
                now: Instant::now(),
                recorded,
            })
            .await
            .unwrap();
        // Nothing was a session yet, so nothing is counted ended.
        assert_eq!(table.forget_binding("revoked"), 0);
        assert_eq!(answer.await, Ok(Recorded::Refused));
        assert!(matches!(
            table.admit(Some("issued".into()), who, false, IDLE).await,
            Admission::UnknownSession
        ));
    }

    /// A revocation while the request is at the backend refuses the record.
    #[tokio::test]
    async fn a_revocation_while_the_request_is_in_flight_refuses_the_record() {
        let table = BindingTable::start();
        let who = binding("revoked");
        let Admission::Admitted(reservation) = table.admit(None, who.clone(), true, IDLE).await
        else {
            panic!("admitted");
        };
        assert_eq!(table.forget_binding("revoked"), 0);
        assert_eq!(
            table.remember(reservation, "issued".into()).await,
            Recorded::Refused
        );
        assert!(matches!(
            table.admit(Some("issued".into()), who, false, IDLE).await,
            Admission::UnknownSession
        ));
    }

    /// A revocation after the record was acknowledged ends the session, and
    /// only that binding's.
    #[tokio::test]
    async fn a_revocation_after_the_record_ends_the_session() {
        let table = BindingTable::start();
        for who in ["revoked", "bystander"] {
            let Admission::Admitted(reservation) =
                table.admit(None, binding(who), true, IDLE).await
            else {
                panic!("admitted");
            };
            assert_eq!(
                table.remember(reservation, format!("{who}-session")).await,
                Recorded::Bound
            );
        }
        assert_eq!(table.forget_binding("revoked"), 1);
        assert_eq!(table.forget_binding("revoked"), 0);
        assert!(matches!(
            table
                .admit(
                    Some("revoked-session".into()),
                    binding("revoked"),
                    false,
                    IDLE
                )
                .await,
            Admission::UnknownSession
        ));
        assert!(matches!(
            table
                .admit(
                    Some("bystander-session".into()),
                    binding("bystander"),
                    false,
                    IDLE
                )
                .await,
            Admission::Admitted(None)
        ));
    }

    /// A session is never recorded without a reservation, and a reservation
    /// whose exchange ends without a session leaves nothing published.
    #[tokio::test]
    async fn a_reservation_ends_with_its_exchange() {
        let table = BindingTable::start();
        assert_eq!(
            table.remember(None, "unreserved".into()).await,
            Recorded::Refused
        );
        let Admission::Admitted(Some(reservation)) =
            table.admit(None, binding("gone"), true, IDLE).await
        else {
            panic!("admitted with a reservation");
        };
        assert_eq!(table.published.borrow().len(), 1);
        drop(reservation);
        // The next decision is taken against a pruned table.
        assert!(matches!(
            table.admit(Some("none".into()), None, false, IDLE).await,
            Admission::UnknownSession
        ));
        assert_eq!(table.published.borrow().len(), 0);
    }

    /// A reissued identifier stays with the principal it was first bound to.
    #[test]
    fn a_reissued_identifier_is_not_rebound() {
        let now = origin();
        let mut sessions = SessionBindings::default();
        assert_eq!(
            remember(&mut sessions, "s".into(), binding("alice"), now),
            Recorded::Bound
        );
        assert_eq!(
            remember(&mut sessions, "s".into(), binding("alice"), now),
            Recorded::Bound
        );
        assert_eq!(
            remember(&mut sessions, "s".into(), binding("bob"), now),
            Recorded::Foreign
        );
        assert!(sessions.permits("s", binding("alice").as_ref(), now));
        assert!(!sessions.permits("s", binding("bob").as_ref(), now));
        assert_eq!(sessions.len(), 1);
        assert!(sessions.reserved.is_empty());
    }

    /// Use keeps a session alive, and expiry is per entry.
    #[test]
    fn use_keeps_a_session_alive_and_expiry_is_per_entry() {
        let start = origin();
        let mut sessions = SessionBindings::default();
        let alice = binding("alice");
        let bob = binding("bob");
        remember(&mut sessions, "alice-session".into(), alice.clone(), start);
        remember(&mut sessions, "bob-session".into(), bob.clone(), start);
        // Alice keeps using hers; Bob never touches his again.
        let mut now = start;
        for _ in 0..4 {
            now += IDLE / 2;
            sessions.expire(now, IDLE);
            assert!(sessions.permits("alice-session", alice.as_ref(), now));
        }
        // Bob's has been idle for longer than the deadline and is gone;
        // Alice's, used within it, is not.
        assert_eq!(sessions.len(), 1);
        assert!(!sessions.permits("bob-session", bob.as_ref(), now));
        assert!(sessions.permits("alice-session", alice.as_ref(), now));
        // Expiry frees the slot for its own holder.
        assert!(sessions.has_room_for(bob.as_ref()));
    }
}
