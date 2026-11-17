//! The stdio export: an in-process Streamable HTTP handler bridging to a
//! supervised MCP child process.
//!
//! The bridge forwards raw JSON-RPC messages.  A request's compact bytes are
//! written to the child exactly (IDs, `_meta` and unknown fields intact), and
//! each child stdout line is forwarded as one SSE `data` event or as the
//! complete `application/json` body, never re-serialized.
//!
//! **2026-07-28** (no protocol sessions).  Every POSTed JSON-RPC request gets
//! its own child process, so request IDs, notifications and progress of
//! different requests or consumers can never cross.  If the child's first
//! message is the final response it is returned as `application/json`;
//! otherwise the response is an SSE stream of the child's notifications
//! followed by the final response.  A child request on that stream, a
//! response for another ID, a crash, invalid output or an oversized message
//! interrupts the exchange (never a fabricated JSON-RPC result, never a
//! replay).  Closing the response stream is cancellation: the bridge writes
//! `notifications/cancelled` with the request ID to the child, allows
//! [`CANCEL_GRACE`] and kills it.  A client notification has no addressee (no
//! per-request child exists for it) and is accepted with 202 and dropped.
//!
//! **2025-11-25** (sessions).  `initialize` without `Mcp-Session-Id` starts
//! one child and one session, identified by a random 128-bit ID returned in
//! `Mcp-Session-Id`.  Requests are routed back to their POST by ID;
//! notifications carrying the request's `progressToken` follow it; every
//! other server message (logging, list changes, server requests) goes to the
//! single standalone GET stream, or waits in a bounded backlog until one
//! opens.  A disconnect is not cancellation in this revision: the client
//! POSTs `notifications/cancelled`, which is forwarded unchanged; the
//! cancelled request's own POST, which the server need not answer, then ends
//! at once as an empty event stream (M3-48) instead of waiting for the
//! session to end.  DELETE
//! kills the child.  A session idle for the configured `session_idle_seconds`
//! (no POST, no newly opened GET, no request in flight; an open GET stream
//! alone does not count) ends the same way, and a request whose consumer
//! lets its stream queue fill has only that stream interrupted.  A child crash ends the session: open streams are
//! interrupted and later requests get 404.
//!
//! **Principal binding (M3-04).**  A session also remembers the opaque
//! `tunnel-principal-binding` the relay ingress derived for the consumer that
//! opened it, and POST, GET and DELETE all require exactly that value.  A
//! different value — including none, when this export is reached without an
//! ingress — is answered as an unknown session, byte for byte, so a session
//! ID learned by another authorized consumer neither works nor reveals that
//! the session exists.  The device never derives or interprets the value.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tunnel_http_bridge::{ChannelBody, HandlerCancellation};
use tunnel_mcp::message::{
    McpMessage, McpRejection, MessageKind, codes, validate_delete, validate_get, validate_post,
};
use tunnel_mcp::{McpLimits, McpProfile, headers};

use crate::body::{
    ChannelResponseBody, CollectError, ExportBody, StreamFailure, capacity_refusal,
    collect_limited, json_response, local_error, no_body, rejection, sse_event, sse_head,
};
use crate::child::{self, ChildCounters, ChildEvent, ChildHandle};
use crate::config::StdioBackend;
use crate::{ExportCounters, ExportError};

/// How long a cancelled 2026 child may keep running after
/// `notifications/cancelled` before it is killed.
pub const CANCEL_GRACE: Duration = Duration::from_secs(1);
/// Server messages kept for a legacy session without a GET stream.
pub const MAX_BACKLOG_MESSAGES: usize = 64;
/// Messages queued towards one legacy request's response stream.  The
/// session pump never waits on a stream: a consumer that lets this queue fill
/// has only its own stream interrupted.
pub const SESSION_STREAM_QUEUE: usize = 64;
/// Commands queued towards one legacy session's pump, which owns the
/// session's routing state.  A sender waits for room: the pump never waits on
/// a stream or on the child, so the queue always drains.
pub const SESSION_COMMAND_QUEUE: usize = 32;
/// Sessions queued for listing by the export's registry task.  An
/// `initialize` waits for room, and for the listing to be published, before
/// it answers.
pub const REGISTRY_QUEUE: usize = 32;

/// What a request's response stream receives.
#[derive(Debug)]
enum Routed {
    Interim(Bytes),
    Final(Bytes),
    Ended,
    /// The client cancelled this legacy request (`notifications/cancelled`,
    /// M3-48).  The server need not answer it, so the bridge ends the
    /// response cleanly with no JSON-RPC response instead of holding the
    /// POST open until the session ends.
    Cancelled,
}

fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

/// The routing key of the request a client `notifications/cancelled` names.
fn cancelled_request(message: &McpMessage) -> Option<String> {
    if message.kind != MessageKind::Notification
        || message.method.as_deref() != Some("notifications/cancelled")
    {
        return None;
    }
    message
        .value
        .get("params")?
        .get("requestId")
        .filter(|id| id.is_string() || id.is_i64() || id.is_u64())
        .map(id_key)
}

fn cancelled_notification(id: &Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": { "requestId": id, "reason": "the consumer closed the response stream" }
    }))
    .unwrap_or_default()
}

/// Runs its action exactly once: `true` when the request completed (or the
/// child already ended), `false` when it was abandoned.
struct RequestGuard {
    action: Option<Box<dyn FnOnce(bool) + Send>>,
}

impl RequestGuard {
    fn new(action: impl FnOnce(bool) + Send + 'static) -> Self {
        Self {
            action: Some(Box::new(action)),
        }
    }

    /// A guard with nothing to do.  A legacy request needs none: its routing
    /// entry ends with its response stream, whose receiving half the session
    /// pump sees closed.
    const fn detached() -> Self {
        Self { action: None }
    }

    fn complete(&mut self) {
        if let Some(action) = self.action.take() {
            action(true);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(action) = self.action.take() {
            action(false);
        }
    }
}

/// A validated stdio export.
pub struct StdioExport {
    profile: McpProfile,
    limits: McpLimits,
    backend: StdioBackend,
    counters: Arc<ExportCounters>,
    slots: Arc<Semaphore>,
    /// The open legacy sessions.  Started by the first `initialize`, because
    /// an export may be built where no runtime is running yet.
    registry: OnceLock<Registry>,
    /// Cancelled when the export is dropped or [`StdioExport::shutdown`] is
    /// called.  A legacy session's pump is a detached task that owns the
    /// child and its `max_children` permit, so without this the children of
    /// sessions nobody ended would outlive the export, the connector and the
    /// device session they were opened on.
    shutdown: CancellationToken,
}

impl Drop for StdioExport {
    fn drop(&mut self) {
        self.shutdown_sessions();
    }
}

impl std::fmt::Debug for StdioExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioExport")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

fn cancellation(request: &Request<ChannelBody>) -> CancellationToken {
    request
        .extensions()
        .get::<HandlerCancellation>()
        .map(|cancel| cancel.0.clone())
        .unwrap_or_default()
}

impl StdioExport {
    pub(crate) fn new(
        profile: McpProfile,
        limits: McpLimits,
        backend: StdioBackend,
        counters: Arc<ExportCounters>,
    ) -> Self {
        let slots = Arc::new(Semaphore::new(backend.max_children));
        Self {
            profile,
            limits,
            backend,
            counters,
            slots,
            registry: OnceLock::new(),
            shutdown: CancellationToken::new(),
        }
    }

    /// End every open legacy session and kill its child's process group.
    ///
    /// Idempotent, and safe to call from `Drop`: the session pumps observe
    /// the cancellation and their children are killed here as well, so a
    /// child cannot survive the export whatever the task scheduler does
    /// afterwards.
    pub fn shutdown_sessions(&self) {
        // Cancelled first: a session's pump stops routing, and refuses every
        // later registration, as soon as it observes this.
        self.shutdown.cancel();
        let Some(registry) = self.registry.get() else {
            return;
        };
        for session in registry.listing().values() {
            if session.unlist() {
                session.child.kill();
            }
        }
        registry.prune.notify_one();
    }

    fn child_counters(&self) -> &Arc<ChildCounters> {
        &self.counters.children
    }

    fn reject(&self, rejection_value: &McpRejection) -> Response<ExportBody> {
        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
        rejection(rejection_value)
    }

    /// Serve one exchange.
    ///
    /// # Errors
    /// [`ExportError`] when the exchange must be interrupted rather than
    /// answered (a child that ended after the request was written, a request
    /// body failure).
    pub async fn handle(
        self: Arc<Self>,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let cancel = cancellation(&request);
        let (parts, body) = request.into_parts();
        match parts.method {
            Method::POST => {
                let body = match collect_limited(body, self.limits.request_body()).await {
                    Ok(body) => body,
                    Err(CollectError::TooLarge) => {
                        return Ok(self.reject(&McpRejection {
                            status: 413,
                            code: codes::INVALID_REQUEST,
                            message: "the request body exceeds the export limit",
                            id: None,
                            supported: None,
                        }));
                    }
                    Err(CollectError::Interrupted) => return Err(ExportError),
                };
                let message = match validate_post(self.profile, &parts.headers, &body) {
                    Ok(message) => message,
                    Err(error) => return Ok(self.reject(&error)),
                };
                match self.profile {
                    McpProfile::V2026_07_28 => self.post_current(message, cancel).await,
                    McpProfile::V2025_11_25 => {
                        self.post_legacy(&parts.headers, message, cancel).await
                    }
                }
            }
            Method::GET | Method::DELETE => {
                let checked = if parts.method == Method::GET {
                    validate_get(self.profile, &parts.headers)
                } else {
                    validate_delete(self.profile, &parts.headers)
                };
                if let Err(error) = checked {
                    return Ok(self.reject(&error));
                }
                match collect_limited(body, 0).await {
                    Ok(_) => {}
                    Err(CollectError::TooLarge) => {
                        return Ok(self.reject(&McpRejection {
                            status: 400,
                            code: codes::INVALID_REQUEST,
                            message: "GET and DELETE carry no body",
                            id: None,
                            supported: None,
                        }));
                    }
                    Err(CollectError::Interrupted) => return Err(ExportError),
                }
                if parts.method == Method::GET {
                    self.get_legacy(&parts.headers, cancel).await
                } else {
                    Ok(self.delete_legacy(&parts.headers))
                }
            }
            _ => Ok(self.reject(&McpRejection {
                status: 405,
                code: codes::INVALID_REQUEST,
                message: "method not allowed",
                id: None,
                supported: None,
            })),
        }
    }

    // ---- 2026-07-28 ---------------------------------------------------------

    async fn post_current(
        self: &Arc<Self>,
        message: McpMessage,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        if message.kind == MessageKind::Notification {
            // A 2026 client notification has no addressee: every request has
            // its own child, which exists only for that request's lifetime,
            // and this revision defines no client notification over HTTP
            // (cancellation is closing the response stream).  Accept it as the
            // transport requires (202, no body) and drop it.
            self.counters
                .notifications_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Ok(no_body(StatusCode::ACCEPTED));
        }
        let (MessageKind::Request, Some(id)) = (message.kind, message.id.clone()) else {
            return Ok(self.reject(&McpRejection {
                status: 400,
                code: codes::INVALID_REQUEST,
                message: "this stdio export accepts JSON-RPC requests only",
                id: None,
                supported: None,
            }));
        };
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Ok(capacity_refusal(
                "the export is at its child process limit",
                Some(id),
            ));
        };
        let Ok((child, events)) = child::spawn(
            &self.backend,
            self.limits.json_response_body(),
            self.child_counters(),
        ) else {
            // Nothing was started, so nothing can have run.
            return Ok(local_error(
                StatusCode::BAD_GATEWAY,
                "the MCP server process could not be started",
                Some(id),
            ));
        };
        if child.send(&message.compact).await.is_err() {
            return Err(ExportError);
        }
        let (routed_tx, routed_rx) = mpsc::channel(crate::body::STREAM_QUEUE);
        tokio::spawn(route_single(
            events,
            id_key(&id),
            routed_tx,
            child.kill_switch(),
        ));
        let counters = Arc::clone(&self.counters);
        let guard = RequestGuard::new(move |completed| {
            finish_current_child(child, permit, id, completed, counters);
        });
        self.respond(routed_rx, cancel, guard, None).await
    }

    // ---- shared response streaming -------------------------------------------

    async fn respond(
        &self,
        mut routed: mpsc::Receiver<Routed>,
        cancel: CancellationToken,
        guard: RequestGuard,
        session: Option<HeaderValue>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let first = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(ExportError),
            first = routed.recv() => first,
        };
        self.respond_with_first(first, routed, cancel, guard, session)
    }

    fn respond_with_first(
        &self,
        first: Option<Routed>,
        mut routed: mpsc::Receiver<Routed>,
        cancel: CancellationToken,
        mut guard: RequestGuard,
        session: Option<HeaderValue>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let with_session = |mut response: Response<ExportBody>| {
            if let Some(session) = &session {
                response
                    .headers_mut()
                    .insert(headers::MCP_SESSION_ID, session.clone());
            }
            response
        };
        match first {
            None | Some(Routed::Ended) => {
                guard.complete();
                self.counters.interrupted.fetch_add(1, Ordering::Relaxed);
                Err(ExportError)
            }
            Some(Routed::Cancelled) => {
                // An empty event stream that ends cleanly: what rmcp's own
                // Streamable HTTP server answers for a cancelled request.
                guard.complete();
                let mut response = Response::new(crate::body::empty());
                sse_head(&mut response);
                Ok(with_session(response))
            }
            Some(Routed::Final(bytes)) => {
                guard.complete();
                self.counters.json_responses.fetch_add(1, Ordering::Relaxed);
                Ok(with_session(json_response(StatusCode::OK, bytes)))
            }
            Some(Routed::Interim(bytes)) => {
                let (sender, body) = ChannelResponseBody::channel(
                    self.limits.sse_response_body(),
                    Arc::clone(&self.counters.streamed_bytes),
                );
                let mut response = Response::new(body.boxed());
                sse_head(&mut response);
                self.counters.sse_responses.fetch_add(1, Ordering::Relaxed);
                let counters = Arc::clone(&self.counters);
                tokio::spawn(async move {
                    let mut guard = guard;
                    if sender.send(sse_event(&bytes)).await.is_err() {
                        return;
                    }
                    loop {
                        tokio::select! {
                            biased;
                            () = sender.closed() => return,
                            () = cancel.cancelled() => return,
                            next = routed.recv() => match next {
                                Some(Routed::Interim(bytes)) => {
                                    if sender.send(sse_event(&bytes)).await.is_err() {
                                        return;
                                    }
                                }
                                Some(Routed::Final(bytes)) => {
                                    if sender.send(sse_event(&bytes)).await.is_ok() {
                                        guard.complete();
                                    }
                                    return;
                                }
                                // Dropping the sender ends the body cleanly.
                                Some(Routed::Cancelled) => {
                                    guard.complete();
                                    return;
                                }
                                None | Some(Routed::Ended) => {
                                    guard.complete();
                                    counters.interrupted.fetch_add(1, Ordering::Relaxed);
                                    sender.fail(StreamFailure::Interrupted).await;
                                    return;
                                }
                            },
                        }
                    }
                });
                Ok(with_session(response))
            }
        }
    }

    // ---- 2025-11-25 ---------------------------------------------------------

    async fn post_legacy(
        self: &Arc<Self>,
        headers_map: &HeaderMap,
        message: McpMessage,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let binding = crate::request_principal_binding(headers_map);
        let session_header = headers_map
            .get(headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok());
        if message.is_initialize() {
            if session_header.is_some() {
                return Ok(self.reject(&McpRejection {
                    status: 400,
                    code: codes::INVALID_REQUEST,
                    message: "initialize must not carry Mcp-Session-Id",
                    id: message.id.clone(),
                    supported: None,
                }));
            }
            return self.initialize_legacy(binding, message, cancel).await;
        }
        let Some(session_id) = session_header else {
            return Ok(self.reject(&McpRejection {
                status: 400,
                code: codes::INVALID_REQUEST,
                message: "Mcp-Session-Id is required",
                id: message.id.clone(),
                supported: None,
            }));
        };
        // An unknown session and a session bound to another principal are the
        // same answer, so a valid session ID leaked to another consumer
        // proves nothing about whether it exists.
        let Some(session) = self
            .session(session_id)
            .filter(|session| session.binding == binding)
        else {
            return Ok(self.reject(&McpRejection {
                status: 404,
                code: codes::INVALID_REQUEST,
                message: "session not found",
                id: message.id.clone(),
                supported: None,
            }));
        };
        session.touch();
        match (message.kind, message.id.clone()) {
            (MessageKind::Request, Some(id)) => {
                let routed = match session.register(&id, message.progress_token()).await {
                    Ok(routed) => routed,
                    Err(RegisterError::Ended) => {
                        return Ok(self.reject(&McpRejection {
                            status: 404,
                            code: codes::INVALID_REQUEST,
                            message: "session not found",
                            id: Some(id),
                            supported: None,
                        }));
                    }
                    Err(RegisterError::DuplicateId) => {
                        return Ok(self.reject(&McpRejection {
                            status: 400,
                            code: codes::INVALID_REQUEST,
                            message: "a request with this id is already in flight",
                            id: Some(id),
                            supported: None,
                        }));
                    }
                    Err(RegisterError::DuplicateProgressToken) => {
                        return Ok(self.reject(&McpRejection {
                            status: 400,
                            code: codes::INVALID_REQUEST,
                            message: "a request with this progress token is already in flight",
                            id: Some(id),
                            supported: None,
                        }));
                    }
                };
                if session.child.send(&message.compact).await.is_err() {
                    // `routed` is dropped here, which is what takes the
                    // request out of the session's routing table.
                    return Err(ExportError);
                }
                let header = HeaderValue::from_str(&session.id).ok();
                self.respond(routed, cancel, RequestGuard::detached(), header)
                    .await
            }
            _ => {
                if session.child.send(&message.compact).await.is_err() {
                    return Err(ExportError);
                }
                // M3-48: once the cancellation has reached the child, close
                // the cancelled request's POST.  Only a request of this
                // session, still in flight, is affected.  Its routing entry
                // stays until that POST's own response stream is dropped, so
                // the ID stays in flight until then: a request reusing it
                // meanwhile
                // is refused as a duplicate rather than registered, where it
                // could receive the cancelled request's late response or be
                // removed by the old POST's cleanup.  A late response that
                // arrives after the cleanup is undeliverable.
                if let Some(key) = cancelled_request(&message) {
                    // A full queue is a consumer that is not reading: that
                    // stream is left to the stall detector, as before.
                    if session.close_cancelled(key).await {
                        self.counters
                            .cancelled_requests_closed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(no_body(StatusCode::ACCEPTED))
            }
        }
    }

    async fn initialize_legacy(
        self: &Arc<Self>,
        binding: Option<String>,
        message: McpMessage,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let id = message.id.clone().unwrap_or(Value::Null);
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Ok(capacity_refusal(
                "the export is at its session limit",
                Some(id),
            ));
        };
        let Ok((child, events)) = child::spawn(
            &self.backend,
            self.limits.json_response_body(),
            self.child_counters(),
        ) else {
            return Ok(local_error(
                StatusCode::BAD_GATEWAY,
                "the MCP server process could not be started",
                Some(id),
            ));
        };
        let session_id = uuid::Uuid::new_v4().simple().to_string();
        let (commands, inbox) = mpsc::channel(SESSION_COMMAND_QUEUE);
        let session = Arc::new(Session {
            id: session_id.clone(),
            binding,
            child,
            commands,
            _slot: permit,
            listed: AtomicBool::new(true),
            epoch: tokio::time::Instant::now(),
            last_activity_nanos: AtomicU64::new(0),
        });
        // The pump does not exist yet, so the router is still this task's own
        // and the `initialize` request is registered on it directly.
        let mut router =
            Router::new(usize::try_from(self.limits.json_response_body()).unwrap_or(usize::MAX));
        let RouterEffect::Registered(routed) = router.on_event(RouterEvent::Register {
            key: id_key(&id),
            token: message.progress_token().map(id_key),
        }) else {
            return Err(ExportError);
        };
        let registry = self.registry.get_or_init(Registry::start);
        self.counters
            .sessions_opened
            .fetch_add(1, Ordering::Relaxed);
        tokio::spawn(run_session(
            SessionPump {
                session: Arc::clone(&session),
                router,
                inbox,
                idle: self.backend.session_idle,
                prune: Arc::clone(&registry.prune),
                counters: Arc::clone(&self.counters),
                shutdown: self.shutdown.child_token(),
            },
            events,
        ));
        // Listed after its pump exists: an exchange dropped while it waits
        // here leaves a session that still expires, not a listed child
        // nothing watches.  No request can name the session before this
        // returns, because its identifier has not been sent yet.
        registry.list(Arc::clone(&session)).await;
        if session.child.send(&message.compact).await.is_err() {
            self.remove_session(&session_id);
            return Err(ExportError);
        }
        let guard = RequestGuard::detached();
        let mut routed = routed;
        let first = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                self.remove_session(&session_id);
                return Err(ExportError);
            }
            first = routed.recv() => first,
        };
        // A failed initialize creates no session: its error is returned
        // without Mcp-Session-Id and the child is killed.
        let failed = match &first {
            Some(Routed::Final(bytes)) => serde_json::from_slice::<Value>(bytes)
                .map_or(true, |value| value.get("result").is_none()),
            // `initialize` must not be cancelled; if it is, no session.
            None | Some(Routed::Ended | Routed::Cancelled) => true,
            Some(Routed::Interim(_)) => false,
        };
        let header = if failed {
            self.remove_session(&session_id);
            None
        } else {
            HeaderValue::from_str(&session_id).ok()
        };
        self.respond_with_first(first, routed, cancel, guard, header)
    }

    async fn get_legacy(
        &self,
        headers_map: &HeaderMap,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let binding = crate::request_principal_binding(headers_map);
        let Some(session) = headers_map
            .get(headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .and_then(|id| self.session(id))
            .filter(|session| session.binding == binding)
        else {
            return Ok(self.reject(&McpRejection {
                status: 404,
                code: codes::INVALID_REQUEST,
                message: "session not found",
                id: None,
                supported: None,
            }));
        };
        // Opening the stream is activity; holding it open is not, so an idle
        // client cannot pin a child and its slot with one open GET.
        session.touch();
        let (stream_tx, mut stream_rx) = mpsc::channel(MAX_BACKLOG_MESSAGES + 1);
        if !session.open_standalone(stream_tx).await {
            return Ok(self.reject(&McpRejection {
                status: 409,
                code: codes::INVALID_REQUEST,
                message: "a standalone stream is already open for this session",
                id: None,
                supported: None,
            }));
        }
        let (sender, body) = ChannelResponseBody::channel(
            self.limits.sse_response_body(),
            Arc::clone(&self.counters.streamed_bytes),
        );
        let mut response = Response::new(body.boxed());
        sse_head(&mut response);
        if let Ok(value) = HeaderValue::from_str(&session.id) {
            response
                .headers_mut()
                .insert(headers::MCP_SESSION_ID, value);
        }
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = sender.closed() => break,
                    () = cancel.cancelled() => break,
                    next = stream_rx.recv() => match next {
                        Some(Routed::Interim(bytes) | Routed::Final(bytes)) => {
                            if sender.send(sse_event(&bytes)).await.is_err() {
                                break;
                            }
                        }
                        // The standalone stream is never a cancelled request.
                        None | Some(Routed::Ended | Routed::Cancelled) => {
                            sender.fail(StreamFailure::Interrupted).await;
                            break;
                        }
                    },
                }
            }
            // Dropping `stream_rx` here is what frees the session's one
            // standalone slot: its pump sees the stream closed.
        });
        Ok(response)
    }

    fn delete_legacy(&self, headers_map: &HeaderMap) -> Response<ExportBody> {
        let binding = crate::request_principal_binding(headers_map);
        // The binding is checked before the session is removed, so another
        // principal's DELETE cannot end a session it could not use.
        let removed = headers_map
            .get(headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .filter(|id| {
                self.session(id)
                    .is_some_and(|session| session.binding == binding)
            })
            .and_then(|id| self.remove_session(id));
        match removed {
            Some(session) => {
                session.child.kill();
                no_body(StatusCode::NO_CONTENT)
            }
            None => self.reject(&McpRejection {
                status: 404,
                code: codes::INVALID_REQUEST,
                message: "session not found",
                id: None,
                supported: None,
            }),
        }
    }

    fn session(&self, id: &str) -> Option<Arc<Session>> {
        self.registry
            .get()?
            .listing()
            .get(id)
            .filter(|session| session.is_listed())
            .cloned()
    }

    /// Take a session out of the export and kill its child.
    ///
    /// `Some` for exactly one caller per session: the one whose call ended
    /// its listing.
    fn remove_session(&self, id: &str) -> Option<Arc<Session>> {
        let registry = self.registry.get()?;
        let session = registry.listing().get(id).cloned()?;
        if !session.unlist() {
            return None;
        }
        session.child.kill();
        registry.prune.notify_one();
        Some(session)
    }

    /// Remove and kill every legacy session opened with `binding` (M3-16).
    pub fn end_binding_sessions(&self, binding: &str) -> u64 {
        let Some(registry) = self.registry.get() else {
            return 0;
        };
        let mut ended = 0;
        for session in registry.listing().values() {
            if session.binding.as_deref() == Some(binding) && session.unlist() {
                session.child.kill();
                ended += 1;
            }
        }
        registry.prune.notify_one();
        ended
    }

    /// Open legacy sessions.
    #[must_use]
    pub fn open_sessions(&self) -> usize {
        self.registry.get().map_or(0, |registry| {
            registry
                .listing()
                .values()
                .filter(|session| session.is_listed())
                .count()
        })
    }
}

fn finish_current_child(
    child: ChildHandle,
    permit: OwnedSemaphorePermit,
    id: Value,
    completed: bool,
    counters: Arc<ExportCounters>,
) {
    if completed {
        drop(child);
        drop(permit);
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn(async move {
        if child.send(&cancelled_notification(&id)).await.is_ok() {
            counters
                .cancel_notifications_sent
                .fetch_add(1, Ordering::Relaxed);
        }
        let _ = tokio::time::timeout(CANCEL_GRACE, child.wait_exited()).await;
        drop(child);
        drop(permit);
    });
}

/// Classify one 2026 child's messages relative to its single request.
async fn route_single(
    mut events: mpsc::Receiver<ChildEvent>,
    key: String,
    routed: mpsc::Sender<Routed>,
    kill: child::PhaseCell,
) {
    while let Some(event) = events.recv().await {
        let next = match event {
            ChildEvent::Ended(_) => Routed::Ended,
            ChildEvent::Message(message) => {
                let has_method = message.value.get("method").is_some();
                let response_id = message.value.get("id");
                match (has_method, response_id) {
                    (true, None) => Routed::Interim(message.compact),
                    (false, Some(id)) if id_key(id) == key => Routed::Final(message.compact),
                    // A server request or a response for another ID is not
                    // allowed on a 2026 request stream.
                    _ => {
                        kill.request_kill();
                        Routed::Ended
                    }
                }
            }
        };
        let last = !matches!(next, Routed::Interim(_));
        if routed.send(next).await.is_err() || last {
            return;
        }
    }
    let _ = routed.send(Routed::Ended).await;
}

// ---- legacy sessions -------------------------------------------------------

/// The sessions an export has open, as last published by its registry task.
type Listing = Arc<HashMap<String, Arc<Session>>>;

/// One session to list, and where to say it is visible.
struct List {
    session: Arc<Session>,
    listed: oneshot::Sender<()>,
}

/// The export's handle on the task that owns its session map.
///
/// **One task owns the map; everyone else reads what it published.**  A
/// session enters by being sent to that task, which publishes a new immutable
/// listing before it answers.  A session *leaves* by its own
/// [`Session::unlist`] latch, which is one atomic swap and so can be taken by
/// a synchronous caller -- `Drop`, a revocation, a `DELETE` -- and by exactly
/// one of them; the task is then nudged to drop the entry.  A reader therefore
/// treats a listed-but-unlisted session as absent, and every reader does.
struct Registry {
    additions: mpsc::Sender<List>,
    published: watch::Receiver<Listing>,
    /// Nudges the owning task to drop sessions that were unlisted.
    prune: Arc<Notify>,
}

impl Registry {
    /// Start the owning task.  Called from an `initialize`, so a runtime is
    /// running.
    fn start() -> Self {
        let (additions, inbox) = mpsc::channel(REGISTRY_QUEUE);
        let (publish, published) = watch::channel(Listing::default());
        let prune = Arc::new(Notify::new());
        tokio::spawn(own_sessions(inbox, publish, Arc::clone(&prune)));
        Self {
            additions,
            published,
            prune,
        }
    }

    /// The sessions as last published.  Entries may have been unlisted since.
    fn listing(&self) -> Listing {
        Arc::clone(&self.published.borrow())
    }

    /// List a session, returning once a lookup can find it.
    async fn list(&self, session: Arc<Session>) {
        let (listed, visible) = oneshot::channel();
        if self.additions.send(List { session, listed }).await.is_ok() {
            let _ = visible.await;
        }
    }
}

/// The registry task: the only writer of the session map.
///
/// It ends when the export that holds the sending half is dropped, which
/// drops every session it still listed.
async fn own_sessions(
    mut additions: mpsc::Receiver<List>,
    publish: watch::Sender<Listing>,
    prune: Arc<Notify>,
) {
    let mut sessions: HashMap<String, Arc<Session>> = HashMap::new();
    loop {
        let addition = tokio::select! {
            addition = additions.recv() => match addition {
                Some(addition) => Some(addition),
                None => return,
            },
            () = prune.notified() => None,
        };
        sessions.retain(|_, session| session.is_listed());
        let listed = addition.map(|List { session, listed }| {
            // A session that ended before it could be listed is dropped here
            // rather than kept: nothing would ever nudge it out, and it would
            // hold its child slot.
            if session.is_listed() {
                sessions.insert(session.id.clone(), session);
            }
            listed
        });
        publish.send_replace(Arc::new(sessions.clone()));
        if let Some(listed) = listed {
            let _ = listed.send(());
        }
    }
}

/// Where a session's server-initiated messages go.
enum Standalone {
    /// No standalone GET stream is open: messages wait, bounded.
    Backlog {
        messages: VecDeque<Bytes>,
        bytes: usize,
    },
    /// The session's one standalone GET stream.
    Open(mpsc::Sender<Routed>),
}

impl Standalone {
    const fn empty() -> Self {
        Self::Backlog {
            messages: VecDeque::new(),
            bytes: 0,
        }
    }
}

/// A legacy session's routing state.
///
/// Owned by the session's pump and by nothing else.  The request table, the
/// progress table and the standalone stream exist only while the session is
/// live; an ended session has none of them, so nothing can be registered on
/// one.
enum Router {
    Live {
        /// In-flight requests by routing key.
        pending: HashMap<String, mpsc::Sender<Routed>>,
        /// Progress tokens of in-flight requests, to their routing keys.
        progress: HashMap<String, String>,
        standalone: Standalone,
        /// Bytes the backlog may hold.
        backlog_limit: usize,
    },
    Ended,
}

/// Everything that can happen to a [`Router`].
enum RouterEvent {
    /// A POSTed request asks to be routed its response.
    Register { key: String, token: Option<String> },
    /// A request's stream stalled: stop routing to it.
    Unregister { key: String },
    /// A GET asks to be the standalone stream.
    OpenStandalone(mpsc::Sender<Routed>),
    /// The standalone stream stalled: stop routing to it.
    StandaloneStalled,
    /// The child wrote a message.
    Message {
        /// The routing key of the request this is the response to.
        response_to: Option<String>,
        /// The progress token of a notification.
        token: Option<String>,
        compact: Bytes,
    },
    /// The idle deadline passed.
    IdleElapsed,
    /// The child ended, the backlog overflowed or the export shut down.
    End,
}

/// What a [`RouterEvent`] produced.
enum RouterEffect {
    Registered(mpsc::Receiver<Routed>),
    RegisterRefused(RegisterError),
    StandaloneOpened,
    StandaloneRefused,
    Route(Destination),
    /// The idle deadline passed with a request in flight, which is activity.
    StillActive,
    /// The session ended.  These are the streams to interrupt.
    Closed(Vec<mpsc::Sender<Routed>>),
    /// The event changed nothing that anyone needs to hear about.
    Done,
    /// The session had already ended, so the event was refused.
    SessionOver,
}

impl Router {
    fn new(backlog_limit: usize) -> Self {
        Self::Live {
            pending: HashMap::new(),
            progress: HashMap::new(),
            standalone: Standalone::empty(),
            backlog_limit,
        }
    }

    /// The only place a session's routing state changes.
    ///
    /// A request whose response stream was dropped is no longer in flight,
    /// and a standalone stream whose GET went away is no longer open: both
    /// are forgotten before the event is looked at, so every decision below
    /// sees only streams somebody is still reading.
    fn on_event(&mut self, event: RouterEvent) -> RouterEffect {
        let Self::Live {
            pending,
            progress,
            standalone,
            backlog_limit,
        } = self
        else {
            return RouterEffect::SessionOver;
        };
        pending.retain(|_, stream| !stream.is_closed());
        progress.retain(|_, request| pending.contains_key(request));
        if matches!(standalone, Standalone::Open(stream) if stream.is_closed()) {
            *standalone = Standalone::empty();
        }
        match event {
            RouterEvent::Register { key, token } => {
                if pending.contains_key(&key) {
                    return RouterEffect::RegisterRefused(RegisterError::DuplicateId);
                }
                if token
                    .as_ref()
                    .is_some_and(|token| progress.contains_key(token))
                {
                    return RouterEffect::RegisterRefused(RegisterError::DuplicateProgressToken);
                }
                let (tx, rx) = mpsc::channel(SESSION_STREAM_QUEUE);
                pending.insert(key.clone(), tx);
                if let Some(token) = token {
                    progress.insert(token, key);
                }
                RouterEffect::Registered(rx)
            }
            RouterEvent::Unregister { key } => {
                pending.remove(&key);
                progress.retain(|_, request| *request != key);
                RouterEffect::Done
            }
            RouterEvent::OpenStandalone(stream) => match standalone {
                Standalone::Open(_) => RouterEffect::StandaloneRefused,
                Standalone::Backlog { messages, .. } => {
                    // The stream is created with room for the whole backlog,
                    // so this hands every waiting message over.
                    for bytes in messages.drain(..) {
                        if stream.try_send(Routed::Interim(bytes)).is_err() {
                            break;
                        }
                    }
                    *standalone = Standalone::Open(stream);
                    RouterEffect::StandaloneOpened
                }
            },
            RouterEvent::StandaloneStalled => {
                *standalone = Standalone::empty();
                RouterEffect::Done
            }
            RouterEvent::Message {
                response_to: Some(key),
                ..
            } => {
                progress.retain(|_, request| *request != key);
                RouterEffect::Route(match pending.remove(&key) {
                    Some(stream) => Destination::Request(stream, true, key),
                    None => Destination::Dropped,
                })
            }
            RouterEvent::Message {
                response_to: None,
                token,
                compact,
            } => {
                let request = token
                    .as_ref()
                    .and_then(|token| progress.get(token))
                    .and_then(|key| pending.get(key).map(|stream| (stream.clone(), key.clone())));
                RouterEffect::Route(match (request, standalone) {
                    (Some((stream, key)), _) => Destination::Request(stream, false, key),
                    (None, Standalone::Open(stream)) => Destination::Standalone(stream.clone()),
                    (None, Standalone::Backlog { messages, bytes })
                        if messages.len() < MAX_BACKLOG_MESSAGES
                            && bytes.saturating_add(compact.len()) <= *backlog_limit =>
                    {
                        *bytes += compact.len();
                        messages.push_back(compact);
                        Destination::Backlogged
                    }
                    (None, Standalone::Backlog { .. }) => Destination::Overflow,
                })
            }
            RouterEvent::IdleElapsed if !pending.is_empty() => RouterEffect::StillActive,
            RouterEvent::IdleElapsed | RouterEvent::End => {
                let Self::Live {
                    pending,
                    standalone,
                    ..
                } = std::mem::replace(self, Self::Ended)
                else {
                    return RouterEffect::SessionOver;
                };
                let mut streams: Vec<_> = pending.into_values().collect();
                if let Standalone::Open(stream) = standalone {
                    streams.push(stream);
                }
                RouterEffect::Closed(streams)
            }
        }
    }

    /// The stream of an in-flight request, left registered.
    fn pending_stream(&self, key: &str) -> Option<&mpsc::Sender<Routed>> {
        match self {
            Self::Live { pending, .. } => pending.get(key),
            Self::Ended => None,
        }
    }
}

/// What a request handler asks of the session's pump.
enum SessionCommand {
    Register {
        key: String,
        token: Option<String>,
        reply: oneshot::Sender<Result<mpsc::Receiver<Routed>, RegisterError>>,
    },
    /// Close the POST of the request the client cancelled (M3-48).
    CloseCancelled {
        key: String,
        closed: oneshot::Sender<bool>,
    },
    OpenStandalone {
        stream: mpsc::Sender<Routed>,
        opened: oneshot::Sender<bool>,
    },
}

struct Session {
    id: String,
    /// The principal binding the session was opened with (M3-04).  Every
    /// later request on the session must present exactly this value; any
    /// other one is answered as an unknown session, so a consumer who learns
    /// a session ID cannot tell a bound session from a nonexistent one.
    binding: Option<String>,
    child: ChildHandle,
    /// To the pump, which owns this session's routing state.  A send that
    /// fails means the pump is gone, which is the session having ended.
    commands: mpsc::Sender<SessionCommand>,
    _slot: OwnedSemaphorePermit,
    /// Whether the export still lists this session.  Cleared exactly once, by
    /// whichever caller ends it.
    listed: AtomicBool,
    /// The origin `last_activity_nanos` counts from.
    epoch: tokio::time::Instant,
    /// When the session last saw a POST, a newly opened GET or an in-flight
    /// request at its idle deadline: nanoseconds after `epoch`.
    last_activity_nanos: AtomicU64,
}

/// Why a legacy request could not be registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegisterError {
    Ended,
    DuplicateId,
    DuplicateProgressToken,
}

impl Session {
    /// End this session's listing.  `true` for exactly one caller.
    fn unlist(&self) -> bool {
        self.listed.swap(false, Ordering::SeqCst)
    }

    fn is_listed(&self) -> bool {
        self.listed.load(Ordering::SeqCst)
    }

    fn touch(&self) {
        let now = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_activity_nanos.fetch_max(now, Ordering::Relaxed);
    }

    fn idle_deadline(&self, idle: Duration) -> tokio::time::Instant {
        self.epoch + Duration::from_nanos(self.last_activity_nanos.load(Ordering::Relaxed)) + idle
    }

    async fn register(
        &self,
        id: &Value,
        progress: Option<&Value>,
    ) -> Result<mpsc::Receiver<Routed>, RegisterError> {
        let (reply, registered) = oneshot::channel();
        let command = SessionCommand::Register {
            key: id_key(id),
            token: progress.map(id_key),
            reply,
        };
        if self.commands.send(command).await.is_err() {
            return Err(RegisterError::Ended);
        }
        registered.await.unwrap_or(Err(RegisterError::Ended))
    }

    /// End the POST of an in-flight request the client cancelled.  `true`
    /// when that stream was told.
    async fn close_cancelled(&self, key: String) -> bool {
        let (closed, answer) = oneshot::channel();
        if self
            .commands
            .send(SessionCommand::CloseCancelled { key, closed })
            .await
            .is_err()
        {
            return false;
        }
        answer.await.unwrap_or(false)
    }

    async fn open_standalone(&self, stream: mpsc::Sender<Routed>) -> bool {
        let (opened, answer) = oneshot::channel();
        if self
            .commands
            .send(SessionCommand::OpenStandalone { stream, opened })
            .await
            .is_err()
        {
            return false;
        }
        answer.await.unwrap_or(false)
    }
}

enum Destination {
    Request(mpsc::Sender<Routed>, bool, String),
    Standalone(mpsc::Sender<Routed>),
    Backlogged,
    Overflow,
    Dropped,
}

/// Everything a session's pump owns.
struct SessionPump {
    session: Arc<Session>,
    router: Router,
    inbox: mpsc::Receiver<SessionCommand>,
    idle: Duration,
    prune: Arc<Notify>,
    counters: Arc<ExportCounters>,
    shutdown: CancellationToken,
}

impl SessionPump {
    fn serve(&mut self, command: SessionCommand) {
        match command {
            SessionCommand::Register { key, token, reply } => {
                let _ = reply.send(
                    match self.router.on_event(RouterEvent::Register { key, token }) {
                        RouterEffect::Registered(routed) => Ok(routed),
                        RouterEffect::RegisterRefused(error) => Err(error),
                        _ => Err(RegisterError::Ended),
                    },
                );
            }
            SessionCommand::CloseCancelled { key, closed } => {
                let told = self
                    .router
                    .pending_stream(&key)
                    .is_some_and(|stream| stream.try_send(Routed::Cancelled).is_ok());
                let _ = closed.send(told);
            }
            SessionCommand::OpenStandalone { stream, opened } => {
                let _ = opened.send(matches!(
                    self.router.on_event(RouterEvent::OpenStandalone(stream)),
                    RouterEffect::StandaloneOpened
                ));
            }
        }
    }

    /// Route one child message.  `false` when the backlog overflowed, which
    /// ends the session.
    fn route(&mut self, message: child::ChildMessage) -> bool {
        let has_method = message.value.get("method").is_some();
        let id = message.value.get("id");
        let response_to = id.filter(|_| !has_method).map(id_key);
        let token = message
            .value
            .get("params")
            .and_then(|params| params.get("progressToken"))
            .filter(|_| id.is_none())
            .map(id_key);
        let RouterEffect::Route(destination) = self.router.on_event(RouterEvent::Message {
            response_to,
            token,
            compact: message.compact.clone(),
        }) else {
            return true;
        };
        match destination {
            Destination::Request(sender, is_final, key) => {
                let routed = if is_final {
                    Routed::Final(message.compact)
                } else {
                    Routed::Interim(message.compact)
                };
                match sender.try_send(routed) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Fail fast: interrupt only this request's stream (its
                        // queue closes once every sender is gone).
                        drop(sender);
                        self.router.on_event(RouterEvent::Unregister { key });
                        self.counters
                            .stalled_streams
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.counters.undeliverable.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Destination::Standalone(sender) => {
                match sender.try_send(Routed::Interim(message.compact)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.router.on_event(RouterEvent::StandaloneStalled);
                        self.counters
                            .stalled_streams
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.counters.undeliverable.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Destination::Backlogged => {}
            Destination::Dropped => {
                self.counters.undeliverable.fetch_add(1, Ordering::Relaxed);
            }
            Destination::Overflow => {
                self.counters.undeliverable.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    }
}

/// One legacy session's pump: the owner of its routing state.
///
/// Request handlers reach that state only by sending this task a command, so
/// every decision about it -- a registration against a duplicate, the idle
/// expiry against a request arriving -- is taken in one place, in order.
async fn run_session(mut pump: SessionPump, mut events: mpsc::Receiver<ChildEvent>) {
    // Why the loop ended, announced only once the session has left the
    // listing (M3-27; the same ordering M8-C31 fixed in the ACP export).
    let mut expired = false;
    let mut interrupted = Vec::new();
    loop {
        let event = tokio::select! {
            biased;
            () = pump.shutdown.cancelled() => break,
            command = pump.inbox.recv() => {
                // Never `None`: this task holds the session, which holds a
                // sender.
                if let Some(command) = command {
                    pump.serve(command);
                }
                continue;
            }
            event = events.recv() => event,
            () = tokio::time::sleep_until(pump.session.idle_deadline(pump.idle)) => {
                if tokio::time::Instant::now() < pump.session.idle_deadline(pump.idle) {
                    continue;
                }
                // An in-flight request is activity (it is bounded by its own
                // exchange deadline); otherwise the session has expired.  The
                // decision and the ending are one transition, so a request
                // cannot register between them.
                if let RouterEffect::Closed(streams) = pump.router.on_event(RouterEvent::IdleElapsed) {
                    interrupted = streams;
                    expired = true;
                    break;
                }
                pump.session.touch();
                continue;
            }
        };
        let Some(ChildEvent::Message(message)) = event else {
            break;
        };
        if !pump.route(message) {
            break;
        }
    }
    // The child ended (or overflowed): interrupt every stream, end the
    // session and kill the process.
    if let RouterEffect::Closed(streams) = pump.router.on_event(RouterEvent::End) {
        interrupted = streams;
    }
    // Nothing registers from here on: a command still queued, or sent later,
    // finds its reply dropped and reads that as an ended session.
    pump.inbox.close();
    for sender in interrupted {
        // A full queue closes when this last sender drops, which interrupts
        // that stream just the same.
        let _ = sender.try_send(Routed::Ended);
    }
    pump.session.unlist();
    pump.prune.notify_one();
    pump.session.child.kill();
    // **Unlisted before either counter is released.** A reader waits on
    // `sessions_expired` or `sessions_ended` with an `Acquire` load (see
    // `ExportCounters::snapshot`) and then reads `open_sessions()`, which
    // counts only sessions still listed, so the unlisting above, sequenced
    // before this `Release`, is visible to it. Counted first, as this loop
    // once did, the announcement named a session still listed open (M3-27).
    if expired {
        pump.counters
            .sessions_expired
            .fetch_add(1, Ordering::Release);
    }
    pump.counters.sessions_ended.fetch_add(1, Ordering::Release);
}

#[cfg(test)]
mod router_tests {
    use super::{
        Bytes, Destination, MAX_BACKLOG_MESSAGES, RegisterError, Routed, Router, RouterEffect,
        RouterEvent, mpsc,
    };

    fn register(router: &mut Router, key: &str, token: Option<&str>) -> RouterEffect {
        router.on_event(RouterEvent::Register {
            key: key.to_owned(),
            token: token.map(ToOwned::to_owned),
        })
    }

    fn notification(router: &mut Router, token: Option<&str>) -> RouterEffect {
        router.on_event(RouterEvent::Message {
            response_to: None,
            token: token.map(ToOwned::to_owned),
            compact: Bytes::from_static(b"{}"),
        })
    }

    fn response(router: &mut Router, key: &str) -> RouterEffect {
        router.on_event(RouterEvent::Message {
            response_to: Some(key.to_owned()),
            token: None,
            compact: Bytes::from_static(b"{}"),
        })
    }

    #[test]
    fn a_request_registers_once_and_its_id_and_token_stay_in_flight() {
        let mut router = Router::new(1024);
        let RouterEffect::Registered(_stream) = register(&mut router, "1", Some("t")) else {
            panic!("a first request registers");
        };
        assert!(matches!(
            register(&mut router, "1", None),
            RouterEffect::RegisterRefused(RegisterError::DuplicateId)
        ));
        assert!(matches!(
            register(&mut router, "2", Some("t")),
            RouterEffect::RegisterRefused(RegisterError::DuplicateProgressToken)
        ));
    }

    #[test]
    fn a_dropped_response_stream_takes_its_request_out_of_flight() {
        let mut router = Router::new(1024);
        let RouterEffect::Registered(stream) = register(&mut router, "1", Some("t")) else {
            panic!("a first request registers");
        };
        drop(stream);
        // The id and the token are both free again.
        assert!(matches!(
            register(&mut router, "1", Some("t")),
            RouterEffect::Registered(_)
        ));
    }

    #[test]
    fn a_response_goes_to_its_request_and_ends_the_registration() {
        let mut router = Router::new(1024);
        let RouterEffect::Registered(_stream) = register(&mut router, "1", Some("t")) else {
            panic!("a first request registers");
        };
        assert!(matches!(
            notification(&mut router, Some("t")),
            RouterEffect::Route(Destination::Request(_, false, key)) if key == "1"
        ));
        assert!(matches!(
            response(&mut router, "1"),
            RouterEffect::Route(Destination::Request(_, true, key)) if key == "1"
        ));
        // A second response for the same id has no addressee.
        assert!(matches!(
            response(&mut router, "1"),
            RouterEffect::Route(Destination::Dropped)
        ));
        // And its progress token went with it.
        assert!(matches!(
            notification(&mut router, Some("t")),
            RouterEffect::Route(Destination::Backlogged)
        ));
    }

    #[test]
    fn unregistering_a_stalled_request_frees_its_id_and_token() {
        let mut router = Router::new(1024);
        let RouterEffect::Registered(_stream) = register(&mut router, "1", Some("t")) else {
            panic!("a first request registers");
        };
        assert!(matches!(
            router.on_event(RouterEvent::Unregister {
                key: "1".to_owned()
            }),
            RouterEffect::Done
        ));
        assert!(matches!(
            response(&mut router, "1"),
            RouterEffect::Route(Destination::Dropped)
        ));
        assert!(matches!(
            register(&mut router, "1", Some("t")),
            RouterEffect::Registered(_)
        ));
    }

    #[test]
    fn server_messages_wait_in_a_bounded_backlog_until_one_stream_opens() {
        let mut router = Router::new(1024);
        for _ in 0..MAX_BACKLOG_MESSAGES {
            assert!(matches!(
                notification(&mut router, None),
                RouterEffect::Route(Destination::Backlogged)
            ));
        }
        assert!(matches!(
            notification(&mut router, None),
            RouterEffect::Route(Destination::Overflow)
        ));
        let (stream, mut opened) = mpsc::channel(MAX_BACKLOG_MESSAGES + 1);
        assert!(matches!(
            router.on_event(RouterEvent::OpenStandalone(stream)),
            RouterEffect::StandaloneOpened
        ));
        let mut delivered = 0;
        while let Ok(Routed::Interim(_)) = opened.try_recv() {
            delivered += 1;
        }
        assert_eq!(delivered, MAX_BACKLOG_MESSAGES);
        // One standalone stream at a time.
        let (second, _second_rx) = mpsc::channel(1);
        assert!(matches!(
            router.on_event(RouterEvent::OpenStandalone(second)),
            RouterEffect::StandaloneRefused
        ));
        assert!(matches!(
            notification(&mut router, None),
            RouterEffect::Route(Destination::Standalone(_))
        ));
        // A stream whose GET went away is no longer open, and the backlog
        // starts again from empty.
        drop(opened);
        assert!(matches!(
            notification(&mut router, None),
            RouterEffect::Route(Destination::Backlogged)
        ));
    }

    #[test]
    fn the_backlog_is_bounded_in_bytes_as_well() {
        let mut router = Router::new(3);
        assert!(matches!(
            notification(&mut router, None),
            RouterEffect::Route(Destination::Backlogged)
        ));
        assert!(matches!(
            notification(&mut router, None),
            RouterEffect::Route(Destination::Overflow)
        ));
    }

    #[test]
    fn a_stalled_standalone_stream_is_closed_and_another_may_open() {
        let mut router = Router::new(1024);
        let (stream, _opened) = mpsc::channel(1);
        assert!(matches!(
            router.on_event(RouterEvent::OpenStandalone(stream)),
            RouterEffect::StandaloneOpened
        ));
        assert!(matches!(
            router.on_event(RouterEvent::StandaloneStalled),
            RouterEffect::Done
        ));
        let (next, _next_rx) = mpsc::channel(1);
        assert!(matches!(
            router.on_event(RouterEvent::OpenStandalone(next)),
            RouterEffect::StandaloneOpened
        ));
    }

    #[test]
    fn the_idle_deadline_ends_a_session_only_when_nothing_is_in_flight() {
        let mut router = Router::new(1024);
        let RouterEffect::Registered(stream) = register(&mut router, "1", None) else {
            panic!("a first request registers");
        };
        assert!(matches!(
            router.on_event(RouterEvent::IdleElapsed),
            RouterEffect::StillActive
        ));
        drop(stream);
        let (standalone, _opened) = mpsc::channel(1);
        assert!(matches!(
            router.on_event(RouterEvent::OpenStandalone(standalone)),
            RouterEffect::StandaloneOpened
        ));
        // An open standalone stream alone is not activity, and it is handed
        // back to be interrupted.
        let RouterEffect::Closed(streams) = router.on_event(RouterEvent::IdleElapsed) else {
            panic!("an idle session with nothing in flight ends");
        };
        assert_eq!(streams.len(), 1);
        assert!(matches!(router, Router::Ended));
    }

    #[test]
    fn ending_hands_back_every_stream_and_an_ended_session_refuses_everything() {
        let mut router = Router::new(1024);
        let RouterEffect::Registered(_first) = register(&mut router, "1", None) else {
            panic!("a first request registers");
        };
        let RouterEffect::Registered(_second) = register(&mut router, "2", None) else {
            panic!("a second request registers");
        };
        let (standalone, _opened) = mpsc::channel(1);
        assert!(matches!(
            router.on_event(RouterEvent::OpenStandalone(standalone)),
            RouterEffect::StandaloneOpened
        ));
        let RouterEffect::Closed(streams) = router.on_event(RouterEvent::End) else {
            panic!("a live session ends");
        };
        assert_eq!(streams.len(), 3);
        assert!(router.pending_stream("1").is_none());

        let (late, _late_rx) = mpsc::channel(1);
        for event in [
            RouterEvent::Register {
                key: "3".to_owned(),
                token: None,
            },
            RouterEvent::Unregister {
                key: "1".to_owned(),
            },
            RouterEvent::OpenStandalone(late),
            RouterEvent::StandaloneStalled,
            RouterEvent::Message {
                response_to: Some("1".to_owned()),
                token: None,
                compact: Bytes::from_static(b"{}"),
            },
            RouterEvent::IdleElapsed,
            RouterEvent::End,
        ] {
            assert!(matches!(router.on_event(event), RouterEffect::SessionOver));
        }
    }
}
