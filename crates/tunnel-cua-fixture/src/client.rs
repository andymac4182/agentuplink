//! The Lane A dispatch path: validate, negotiate, check the endpoint, then —
//! and only then — send one `/cmd` exchange and classify the answer.
//!
//! **Where this lives, and why.** The *policy* — the ordering of the checks,
//! the lease, the capture carry-forward — lives in `tunnel-cua`, which is pure.
//! What lives here is the part that is genuinely transport, plus [`SessionFacade`]:
//! the device-side state one tunnel session's operations are planned against,
//! and the one place a lease is taken and a capture identity is issued. It
//! lives beside the fixture because the fixture is the only backend it is
//! allowed to talk to.
//!
//! **Supervision arrived in chunk 4 and is still not *here*.** The lifecycle,
//! the health probe and the deadman are `tunnel-cua-export`; what this file
//! gained is the one place they meet this state: [`DeviceState`] implements
//! [`tunnel_cua_export::supervisor::InputAuthority`], so a supervised restart
//! drops every lease and forgets every capture identity through
//! [`tunnel_cua::supervision::invalidate`].
//!
//! A restarted backend is a **new endpoint**, so a session driving it needs a
//! new [`SessionFacade`] built on the same [`DeviceState`]. There is
//! deliberately no `retarget`: a facade that could be pointed at a different
//! backend in place would be a facade whose outstanding operations changed
//! meaning underneath them, and "which backend was this dispatched to" is
//! exactly the question a restart makes load-bearing.
//!
//! **The ordering is the contract.** Every check below the comment marked
//! `dispatch boundary` may produce a [`Completion`]; every check above it may
//! only produce a [`NotDispatched`]. A test reads the fixture's ledger to
//! check that claim rather than taking this module's word for it.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tunnel_cua::capability::{CallerGrant, LocalConfiguration, UpstreamSupport};
use tunnel_cua::capture::PointSpace;
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::lease::{GrantRevision, LeaseGrant, LeaseRefusal, SessionId, TargetSession};
use tunnel_cua::operation::Operation;
use tunnel_cua::outcome::{
    Completion, Dispatch, NotDispatched, UnknownReason, classify_backend_response,
};
use tunnel_cua::plan::{Planned, SessionContext, discovery_payload, plan};
use tunnel_cua::schema::Request;

use crate::CMD_PATH;
use crate::registries::{CaptureRecord, PlanRequest, Registries};

/// Everything the dispatcher needs that is not the request.
pub struct Dispatcher {
    endpoint: BackendEndpoint,
    /// Shared so a plan request can carry the set to the registries' owner
    /// without copying it. Never changed after construction.
    permitted: Arc<BTreeSet<Operation>>,
    deadline: Duration,
    /// The supervisor's lifecycle epoch, if this dispatcher was given one.
    ///
    /// Detached by default, so a dispatcher talking to a backend nobody
    /// supervises attributes nothing and the transport's own reason survives.
    epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle,
}

/// The default per-exchange deadline. Finite; there is no unlimited value.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

impl Dispatcher {
    /// Build a dispatcher for a negotiated capability set.
    ///
    /// The capability set is computed by the caller through
    /// [`tunnel_cua::capability::negotiate`], so the dispatcher cannot widen
    /// it: it has no access to the three inputs, only to their intersection.
    #[must_use]
    pub fn new(endpoint: BackendEndpoint, permitted: BTreeSet<Operation>) -> Self {
        Self {
            endpoint,
            permitted: Arc::new(permitted),
            deadline: DEFAULT_DEADLINE,
            epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle::detached(),
        }
    }

    /// Watch a supervisor's lifecycle epoch, so an exchange that fails across
    /// a supervised restart is reported as a restart rather than as a lost
    /// connection.
    ///
    /// **This is the production caller `docs/tasks.md` M5-C10 says
    /// [`tunnel_cua::supervision::restart_outcome`] lacked.** Without it the
    /// contract still held -- `TransportLost` is equally `Dispatched`, equally
    /// `Unknown` and equally non-retryable -- but the named reason never
    /// reached a consumer, so a diagnostic could not tell "the backend was
    /// replaced under you" from "the network went away".
    #[must_use]
    pub fn watching(mut self, epoch: tunnel_cua_export::supervisor::LifecycleEpochHandle) -> Self {
        self.epoch = epoch;
        self
    }

    /// Build one from the three negotiation inputs.
    #[must_use]
    pub fn negotiated(
        endpoint: BackendEndpoint,
        local: &LocalConfiguration,
        upstream: &UpstreamSupport,
        grant: &CallerGrant,
    ) -> Self {
        Self::new(
            endpoint,
            tunnel_cua::capability::negotiate(local, upstream, grant),
        )
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    #[must_use]
    pub fn permits(&self, operation: Operation) -> bool {
        self.permitted.contains(&operation)
    }

    /// The negotiated set this dispatcher was built with.
    #[must_use]
    pub fn permitted(&self) -> &BTreeSet<Operation> {
        &self.permitted
    }

    /// Validate a consumer request body and dispatch it if everything allows.
    ///
    /// **The ordering is not written here.** It lives in
    /// [`tunnel_cua::plan::plan`], in the production crate, so a future
    /// device-side facade inherits it rather than re-deriving it. This
    /// function is the part that is genuinely transport: take the plan, and
    /// either send it or answer it locally.
    pub async fn handle(&self, body: &[u8], limit: u64, context: &SessionContext<'_>) -> Dispatch {
        self.dispatch_planned(plan(body, limit, &self.permitted, context))
            .await
            .1
    }

    /// Plan, then dispatch, returning the plan alongside the outcome.
    ///
    /// [`SessionFacade`] needs both: the outcome to return, and the plan to
    /// know whether a capture identity should be issued and for which display.
    /// Splitting them out here keeps the facade from re-deriving either.
    async fn dispatch_planned(
        &self,
        planned: Result<Planned, Dispatch>,
    ) -> (Option<Planned>, Dispatch) {
        self.dispatch_planned_until(planned, core::future::pending())
            .await
    }

    /// [`Dispatcher::dispatch_planned`], abandoned if `cancel` completes first.
    async fn dispatch_planned_until(
        &self,
        planned: Result<Planned, Dispatch>,
        cancel: impl core::future::Future<Output = ()>,
    ) -> (Option<Planned>, Dispatch) {
        // ---- above the dispatch boundary: nothing has been sent -------------
        let planned = match planned {
            Ok(planned) => planned,
            Err(refused) => return (None, refused),
        };
        let payload = match &planned {
            // `describe` is answered from the negotiated set -- the only
            // honest thing it could be answered from, since a config echo
            // would be the trap. It is **not** a dispatch, and reporting it as
            // one made `reached_the_backend()` true for an operation that sent
            // no bytes.
            Planned::AnswerLocally { .. } => {
                return (Some(planned), Dispatch::AnsweredLocally(self.describe()));
            }
            Planned::Dispatch { payload, .. } => payload.clone(),
        };

        // ---- the dispatch boundary -----------------------------------------
        // Past this line the backend may have seen the command, so no failure
        // may be reported as `NotDispatched` unless we know the request was
        // never fully written.
        let dispatch = self.send_until(&payload, cancel).await;
        (Some(planned), dispatch)
    }

    /// Read the backend's `version` response, which is where
    /// `desktop_capture_authorized` lives.
    ///
    /// Separate from [`Dispatcher::handle`] because `version` is not a
    /// `computer.v1` operation: it is issued during capability discovery, on
    /// nobody's behalf, and it goes through
    /// [`tunnel_cua::plan::discovery_payload`] which admits only the commands
    /// `describe` reads.
    pub async fn read_version(&self) -> Dispatch {
        match discovery_payload(tunnel_cua::capability::CAPTURE_AUTHORITY_COMMAND) {
            Err(refusal) => Dispatch::NotDispatched(refusal),
            Ok(payload) => self.send(&payload).await,
        }
    }

    /// The `describe` answer: the negotiated set, and facts this dispatcher
    /// can actually observe.
    ///
    /// `endpoint_is_loopback` is **derived from the endpoint**, not written as
    /// a literal. It is tautologically true given that
    /// [`BackendEndpoint`] cannot hold anything else -- but a hardcoded `true`
    /// asserting a safety property is the config-echo shape this chunk spends
    /// its length policing, and a derived one costs nothing.
    fn describe(&self) -> Value {
        json!({
            "operations": self
                .permitted
                .iter()
                .map(|operation| operation.name())
                .collect::<Vec<_>>(),
            "endpoint_is_loopback": self.endpoint.address().ip().is_loopback(),
        })
    }

    async fn send(&self, payload: &Value) -> Dispatch {
        self.send_until(payload, core::future::pending()).await
    }

    /// One exchange, abandoned if `cancel` completes first (M5-04).
    ///
    /// **What a cancellation reports is decided by how far the request got,
    /// never by the fact of cancelling.** `began` is set immediately before
    /// the first byte of the request is handed to the socket, so:
    ///
    /// * cancelled with `began` unset -- the connection may be open, but not
    ///   a byte of the command left this process: [`NotDispatched::Cancelled`],
    ///   retryable;
    /// * cancelled with `began` set -- the backend may have the whole request
    ///   and may have acted, and the answer that would have said so is being
    ///   thrown away: [`UnknownReason::Cancelled`], **not** retryable.
    ///
    /// The second rule is deliberately conservative about a *partial* write.
    /// The transport's own `FailureStage::Writing` may call a failed write
    /// `NotReached`, because a write that *errored* did not complete; a write
    /// that was merely *abandoned* may have completed in the kernel before the
    /// future was dropped, and nothing here can tell.
    ///
    /// `cancel` is polled first (`biased`), so a cancellation that is already
    /// complete wins before the exchange is polled at all. **That ordering is
    /// not what makes an early cancellation safe, and it was measured not to
    /// be:** with `biased` removed (review follow-up, log nonce
    /// `e9a087a00d8d`) the cancellation test stays green, because the exchange
    /// cannot complete on its first poll (the connect is pending) and `began`
    /// is set only after the connect -- so whichever branch is polled first,
    /// an already-complete cancellation still finds `began` unset. `began` is
    /// the guarantee; `biased` only saves a pointless connect attempt. No
    /// guard case is kept for it, since one could only report `still green`.
    async fn send_until(
        &self,
        payload: &Value,
        cancel: impl core::future::Future<Output = ()>,
    ) -> Dispatch {
        // **Read before a single byte is written**, so the comparison below
        // spans the whole exchange. Reading it after the write would leave the
        // request-writing window unwatched, which is exactly the window a
        // restart-killed click occupies.
        let before = self.epoch.read();
        let began = std::sync::atomic::AtomicBool::new(false);
        let exchange = async {
            match tokio::time::timeout(self.deadline, self.exchange(payload, &began)).await {
                // The deadline expired. We had already begun writing, so the
                // outcome is unknown rather than not dispatched.
                Err(_) => Dispatch::Dispatched(Completion::Unknown(UnknownReason::DeadlineExpired)),
                Ok(Err(stage)) => stage.into_dispatch(),
                Ok(Ok((status, body))) => classify_backend_response(status, &body),
            }
        };
        let transport = tokio::select! {
            biased;
            () = cancel => {
                // The consumer abandoned the exchange. The restart attribution
                // below is not applied: the cancellation is the cause the
                // consumer needs to hear, and both arms keep their
                // retryability either way.
                return if began.load(std::sync::atomic::Ordering::SeqCst) {
                    Dispatch::Dispatched(Completion::Unknown(UnknownReason::Cancelled))
                } else {
                    Dispatch::NotDispatched(NotDispatched::Cancelled)
                };
            }
            transport = exchange => transport,
        };
        // The attribution is a pure function of the two readings and the
        // transport's own answer; this line owns none of the policy. It cannot
        // widen retryability -- `attribution_never_changes_what_a_retry_is_
        // allowed_to_do` measures that over the full cross-product.
        tunnel_cua::supervision::attribute_restart(before, self.epoch.read(), transport)
    }

    /// One HTTP/1.1 exchange against the fixture.
    ///
    /// The error type is the **stage** the failure happened at, because that
    /// is precisely what decides `NotDispatched` versus `Unknown`. An error
    /// that merely said "I/O error" would have thrown the distinction away at
    /// the only point where it is recoverable.
    async fn exchange(
        &self,
        payload: &Value,
        began: &std::sync::atomic::AtomicBool,
    ) -> Result<(u16, Vec<u8>), FailureStage> {
        let mut stream = TcpStream::connect(self.endpoint.address())
            .await
            .map_err(|_| FailureStage::Connecting)?;
        let body = payload.to_string();
        let request = format!(
            "POST {CMD_PATH} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.endpoint.address(),
            body.len()
        );
        // Written and flushed as one unit. Until this returns Ok, nothing was
        // fully delivered and the request is safely `NotReached`.
        //
        // **The assumption this rests on, stated rather than left implicit.**
        // Treating a partial write as `NotDispatched` is only sound because
        // the backend will not act on a truncated request: the pinned server
        // reads a `Content-Length`-framed body and dispatches to the command
        // registry **after** the body is complete, so bytes that never arrived
        // cannot have been parsed into a command. A backend that dispatched
        // incrementally -- a chunked or streaming command surface -- would
        // break this, and `/ws` is exactly such a surface. It is deferred
        // (`cua_pin::WEBSOCKET_DEFERRAL_RECORDED_AS`), and a chunk that takes
        // it up must revisit this mapping rather than inherit it.
        //
        // `began` is set **before** the write, not after: from here on an
        // abandoned exchange may have delivered the whole command. See
        // `send_until`.
        began.store(true, std::sync::atomic::Ordering::SeqCst);
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| FailureStage::Writing)?;
        stream.flush().await.map_err(|_| FailureStage::Writing)?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|_| FailureStage::Reading)?;
        if response.is_empty() {
            // The connection closed with no answer at all, after we had
            // written the whole request. Dispatched; outcome unknown.
            return Err(FailureStage::Reading);
        }
        parse_response(&response).ok_or(FailureStage::Reading)
    }
}

/// Where in the exchange a failure happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureStage {
    /// The connection was never established. Nothing was sent.
    Connecting,
    /// The request was not fully written. Partial HTTP is not a command: the
    /// backend cannot have parsed a body it did not receive.
    Writing,
    /// The request was fully written and the answer was lost.
    Reading,
}

impl FailureStage {
    const fn into_dispatch(self) -> Dispatch {
        match self {
            Self::Connecting | Self::Writing => Dispatch::NotDispatched(NotDispatched::NotReached),
            Self::Reading => {
                Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost))
            }
        }
    }
}

/// Split an HTTP/1.1 response into its status and body.
///
/// **A chunked body is de-chunked, and a malformed one is not a body.** The
/// released server answers `/cmd` with a Starlette `StreamingResponse`, which
/// has no `Content-Length`, so uvicorn frames it with
/// `Transfer-Encoding: chunked` on an HTTP/1.1 request -- observed in the
/// Linux guest on 2026-09-26 (task row M5-C22; the raw answer is
/// `tests/cua-fixture/evidence/2026-09-26-linux-aarch64-tunnel-demo/wire-cmd-http11.txt`).
/// The fixture writes an
/// identity-framed body, which is why the Lane A tests never needed this.
/// A chunked body that does not end in its terminating zero-size chunk was
/// cut off after the request was written, so it returns `None` and the
/// exchange is reported as dispatched with an unknown outcome, never
/// classified from a prefix.
fn parse_response(bytes: &[u8]) -> Option<(u16, Vec<u8>)> {
    let separator = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&bytes[..separator]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = &bytes[separator + 4..];
    if chunked {
        return Some((status, dechunk(body)?));
    }
    Some((status, body.to_vec()))
}

/// Decode an HTTP/1.1 chunked body; `None` unless it is complete and
/// well-formed. Chunk extensions are ignored; trailers are not accepted.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|window| window == b"\r\n")?;
        let size_text = core::str::from_utf8(&body[..line_end]).ok()?;
        let size_text = size_text.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return (body == b"\r\n").then_some(out);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Read the backend's `/commands` listing.
///
/// Separate from [`Dispatcher`] because it is part of building an
/// [`UpstreamSupport`], not part of dispatching an operation — and because a
/// `/commands` reading is **not** on its own evidence that a backend can act.
///
/// # Errors
/// Any I/O failure, or a response this function cannot parse.
pub async fn read_commands(endpoint: BackendEndpoint) -> std::io::Result<Vec<String>> {
    let mut stream = TcpStream::connect(endpoint.address()).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        crate::COMMANDS_PATH,
        endpoint.address()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let (_, body) = parse_response(&response).ok_or(std::io::ErrorKind::InvalidData)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| std::io::ErrorKind::InvalidData)?;
    // The released server's `commands` is an object keyed by command name
    // (M5-C27); the names are its keys. Anything else is not a listing this
    // profile understands, and is refused rather than read as "no commands".
    let listing = value
        .get("commands")
        .and_then(Value::as_object)
        .ok_or(std::io::ErrorKind::InvalidData)?;
    Ok(listing.keys().cloned().collect())
}

/// Build a `computer.v1` request body, the way a consumer would.
#[must_use]
pub fn request_body(operation: &str, params: Value) -> Vec<u8> {
    json!({
        "version": tunnel_cua::SCHEMA_VERSION,
        "operation": operation,
        "params": params,
    })
    .to_string()
    .into_bytes()
}

/// A convenience for a validated request's operation, for tests that need to
/// name what they sent.
#[must_use]
pub fn operation_of(request: &Request) -> Operation {
    request.operation()
}

/// The device-side state shared by every tunnel session on one device.
///
/// One lease registry and one capture registry, because both are properties of
/// the **device**, not of a session: a lease that was per-session could not
/// exclude anybody, and a capture registry that was per-session could not
/// notice that another session's capture superseded yours.
///
/// **Neither registry is reachable from here.** Both are owned by one task
/// (`crate::registries`), and every accessor below is a request to it. That
/// task applies one request at a time, whole, in the order they were made,
/// which is what keeps the two registries consistent with each other and
/// what puts an invalidation into effect ahead of every plan not yet made. The
/// accessors are `async` for that reason; none of them does I/O.
#[derive(Debug)]
pub struct DeviceState {
    registries: Registries,
    /// The display scale this device has been **told**, as a percentage, or
    /// `None`. There is no default (M5-C14).
    ///
    /// One independent word: [`SCALE_UNDECLARED`], or the percentage.
    declared_scale_percent: AtomicU64,
    /// The display's size in input point space, if an operator declared one
    /// (M5-C19 option (b)). When set, each capture's scale is **derived**
    /// from it rather than read from [`DeviceState::declare_scale_percent`].
    ///
    /// One independent word: [`POINT_SPACE_UNDECLARED`], or the width in the
    /// high half and the height in the low half. Both dimensions are stored
    /// and read as that one word, so a reader never sees the width of one
    /// declaration with the height of another.
    declared_point_space: AtomicU64,
}

/// No scale declared. Outside the range of any `u32` percentage.
const SCALE_UNDECLARED: u64 = u64::MAX;
/// No point space declared. A declared one never has a zero dimension.
const POINT_SPACE_UNDECLARED: u64 = 0;

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            registries: Registries::default(),
            declared_scale_percent: AtomicU64::new(SCALE_UNDECLARED),
            declared_point_space: AtomicU64::new(POINT_SPACE_UNDECLARED),
        }
    }
}

impl DeviceState {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Which session holds the input lease for a target, if any. For tests
    /// that need to read the registry rather than infer it from a refusal.
    pub async fn holder(&self, target: &TargetSession) -> Option<SessionId> {
        self.registries.holder(target).await
    }

    /// Declare the display scale of the captures this device will record, as
    /// a percentage (100 is 1x), or clear it with `None`.
    ///
    /// **The only source of a scale, because the pinned server has none**
    /// (M5-C14). A capture recorded while this is `None` still gets an
    /// identity, and every coordinate that refers to it is refused with
    /// `CaptureRefusal::ScaleUndeclared` rather than defaulted to 1x. It
    /// applies to captures recorded *after* the call: an identity keeps the
    /// scale it was recorded under, so changing the declaration cannot move a
    /// coordinate on an image the consumer already looked at.
    ///
    /// Where a real device gets this from is an operator decision recorded in
    /// `docs/tasks.md` M5-C14: only a probe of a real backend (M5-C02) can say
    /// whether any server output could replace it.
    pub fn declare_scale_percent(&self, percent: Option<u32>) {
        self.declared_scale_percent.store(
            percent.map_or(SCALE_UNDECLARED, u64::from),
            Ordering::SeqCst,
        );
    }

    /// Declare the target display's size in input point space, or clear it.
    ///
    /// **M5-C19 option (b), applied by default pending owner confirmation
    /// (2026-09-25).** While a point space is declared, every capture's scale
    /// is derived from it and from that capture's own PNG dimensions
    /// ([`PointSpace::scale_percent_for`]); a capture the declaration
    /// contradicts is recorded with **no** scale, so every coordinate on it is
    /// refused with `CaptureRefusal::ScaleUndeclared` rather than placed
    /// somewhere else. A declared point space takes precedence over a
    /// declared percentage. Like the percentage, it applies to captures
    /// recorded after the call.
    pub fn declare_point_space(&self, space: Option<PointSpace>) {
        let word = space.map_or(POINT_SPACE_UNDECLARED, |space| {
            (u64::from(space.width()) << 32) | u64::from(space.height())
        });
        self.declared_point_space.store(word, Ordering::SeqCst);
    }

    fn declared_scale_percent(&self) -> Option<u32> {
        u32::try_from(self.declared_scale_percent.load(Ordering::SeqCst)).ok()
    }

    fn declared_point_space(&self) -> Option<PointSpace> {
        let word = self.declared_point_space.load(Ordering::SeqCst);
        if word == POINT_SPACE_UNDECLARED {
            return None;
        }
        let width = u32::try_from(word >> 32).ok()?;
        let height = u32::try_from(word & u64::from(u32::MAX)).ok()?;
        // Only a `PointSpace` that already passed `new` is ever stored.
        PointSpace::new(width, height).ok()
    }

    /// Drop the leases of a session whose grant revision has advanced.
    ///
    /// **The M3-16 mechanism, with no production caller.** See
    /// `tunnel_cua::lease` and `docs/tasks.md` M5-C05.
    pub async fn reconcile_grant(
        &self,
        session: SessionId,
        revision: GrantRevision,
    ) -> Vec<TargetSession> {
        self.registries.reconcile_grant(session, revision).await
    }

    /// End a device-side session: drop every input lease it holds, whatever
    /// its revision, and report which targets were freed.
    ///
    /// **The device-local half of M3-16 option (c)**, which is the only
    /// option that closes M5-C05 for a *revoked* grant rather than a changed
    /// one. That option is a connector control message naming an opaque
    /// principal binding whose sessions must end; the relay already derives
    /// the binding, and a device that received the message would map it to
    /// its sessions and call this for each. The message itself is a protocol
    /// addition and is queued as an owner decision, so this has no production
    /// caller -- but the effect is pinned here, so the decision is about the
    /// delivery and not about what a device does on receipt.
    pub async fn end_session(&self, session: SessionId) -> Vec<TargetSession> {
        self.registries.end_session(session).await
    }

    /// How many capture identities this device is holding.
    ///
    /// For a test that must read the registry rather than infer its size from
    /// a refusal.
    pub async fn capture_count(&self) -> usize {
        self.registries.capture_count().await
    }
}

/// **The restart contract, wired to the device's own registries.**
///
/// This is the whole production shape of the M5-C08 decision: a supervised
/// restart hands the device state to
/// [`tunnel_cua::supervision::invalidate`], which drops every input lease and
/// forgets every capture identity in one call. There is no implementation of
/// this trait that keeps a lease, and
/// [`tunnel_cua_export::Supervisor::restart`] takes it as a required argument,
/// so a restart cannot happen without one.
///
/// **Ordering.** No input can be planned between the invalidation being
/// requested and it being applied. The request is recorded synchronously by
/// the first poll of the returned future; plans are computed only by the
/// registries' owner, which honours an outstanding request -- emptying both
/// registries -- before it applies any command at all. Once requested it is
/// applied even if the caller stops waiting, and the future resolves after it
/// has taken effect. `crate::registries` has the full argument, and
/// `an_invalidation_takes_effect_before_any_plan_not_yet_computed` drives it
/// with a full queue and a caller that gives up.
impl tunnel_cua_export::supervisor::InputAuthority for DeviceState {
    async fn invalidate(
        &self,
        generation: tunnel_cua::supervision::BackendGeneration,
    ) -> tunnel_cua::supervision::Invalidation {
        self.registries.invalidate(generation).await
    }
}

/// One tunnel session's view of a device: its lease, its captures, its
/// dispatcher.
///
/// This is the shape D3 describes — cross-exchange state keyed by tunnel
/// session, device-side, never in the codec — reduced to what Lane A needs.
pub struct SessionFacade {
    state: Arc<DeviceState>,
    dispatcher: Dispatcher,
    session: SessionId,
    target: TargetSession,
    grant_revision: GrantRevision,
    carrier_generation: u64,
}

impl SessionFacade {
    #[must_use]
    pub fn new(
        state: Arc<DeviceState>,
        dispatcher: Dispatcher,
        session: SessionId,
        target: TargetSession,
    ) -> Self {
        Self {
            state,
            dispatcher,
            session,
            target,
            grant_revision: GrantRevision::new(0),
            carrier_generation: 0,
        }
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub fn target(&self) -> &TargetSession {
        &self.target
    }

    /// Take the exclusive input lease for this session's target.
    ///
    /// **Explicit, never implicit.** An input operation does not take the
    /// lease as a side effect: a lease taken by a click is a lease nobody
    /// releases, and the second agent would then be excluded by an accident.
    ///
    /// # Errors
    /// [`LeaseRefusal::HeldByAnotherSession`].
    pub async fn acquire_input_lease(&self) -> Result<LeaseGrant, LeaseRefusal> {
        self.state
            .registries
            .acquire(&self.target, self.session, self.grant_revision)
            .await
    }

    /// Release a lease this session holds.
    ///
    /// # Errors
    /// Any [`LeaseRefusal`].
    pub async fn release_input_lease(&self, grant: &LeaseGrant) -> Result<(), LeaseRefusal> {
        self.state.registries.release(grant).await
    }

    /// The carrier rotated underneath this session.
    ///
    /// **It does nothing to the lease, and that is the contract.** The holder
    /// is the tunnel session, not the carrier, so there is no code path by
    /// which a rotation could drop a lease — and
    /// `tests/input_lease.rs::a_rotation_leaves_the_lease_held_and_never_repeats_a_click`
    /// drives one across a held lease and a lost click to check it. The
    /// generation is tracked only so a test can show the rotation happened.
    pub const fn rotate_carrier(&mut self) {
        self.carrier_generation += 1;
    }

    #[must_use]
    pub const fn carrier_generation(&self) -> u64 {
        self.carrier_generation
    }

    /// Tell this session what revision the device believes its grant carries,
    /// and **stop honouring every lease it holds under an older one in the
    /// same step**. Returns the targets that were freed.
    ///
    /// # Why learning the revision now frees the target (M5-C05)
    ///
    /// This used to record the revision and nothing else. The holder was then
    /// refused at the point of use -- but the lease entry stayed, so every
    /// other agent was refused with `HeldByAnotherSession` by a lease nobody
    /// could use, until something called `reconcile_grant`. Nothing did. So
    /// the moment the device learned that a grant had moved, the input lease
    /// it had authorized became a lock with no key, held on behalf of a
    /// consumer the relay had already fenced.
    ///
    /// The reconcile is now **requested in the same step** that records the
    /// revision -- the revision is recorded at the instant the reconcile is
    /// queued for the registries' owner, with no await between the two, and
    /// this session cannot plan in between because it is borrowed mutably
    /// until the owner has answered. So there is no window in which the
    /// device knows a holding is superseded and still honours it for
    /// exclusion, and a caller that stops waiting leaves either neither done
    /// or both. A superseded holder's next input is refused with
    /// [`LeaseRefusal::NotHeld`] rather than `GrantRevoked`, because there is
    /// no holding left to be revoked -- and nothing is dispatched either way.
    ///
    /// **A revision is not a revocation**, and this does not pretend to tell
    /// them apart: the session may take the lease again under the revision
    /// it now carries, exactly as `release` then `acquire` always allowed.
    /// A *revoked* principal is expected not to, because the relay fences a
    /// revoked principal's `http-forward/1` traffic (M3-16 measured ~10 ms for
    /// MCP) -- **not measured for CUA**, which is not relay-routed yet. Ending
    /// the device-side session of a revoked grant is
    /// [`DeviceState::end_session`], and delivering that signal to a device is
    /// the M3-16 option (c) protocol decision.
    ///
    /// **The cost of releasing on a non-revoking change**, stated because it is
    /// real: if the revision moved because the grant was *changed* rather than
    /// revoked, the holder loses the lease between two of its operations, and
    /// another agent may take the target before the holder re-acquires --
    /// mid-sequence, for example between the `move` and the `click` of a
    /// composed gesture. Nothing is dispatched on the old holder's behalf once
    /// it is released, so this is an interleaving hazard, not a
    /// double-dispatch; `docs/tasks.md` M5-C05 records it.
    ///
    /// **A stale revision changes nothing.** Revisions are monotonic, so a
    /// value at or below the one already recorded is an out-of-order delivery
    /// and is ignored rather than moving the session's belief backwards.
    ///
    /// Nothing calls this in production yet, because nothing tells a device
    /// that a grant moved. See `docs/tasks.md` M5-C05.
    pub async fn note_grant_revision(&mut self, revision: GrantRevision) -> Vec<TargetSession> {
        if revision <= self.grant_revision {
            return Vec::new();
        }
        let recorded = &mut self.grant_revision;
        self.state
            .registries
            .reconcile_grant_with(self.session, revision, || *recorded = revision)
            .await
    }

    #[must_use]
    pub const fn grant_revision(&self) -> GrantRevision {
        self.grant_revision
    }

    /// The dispatcher underneath, for the discovery reads that are not
    /// `computer.v1` operations and therefore have no session context.
    #[must_use]
    pub const fn dispatcher(&self) -> &Dispatcher {
        &self.dispatcher
    }

    /// Validate and dispatch one `computer.v1` request for this session.
    ///
    /// The registries' owner is asked **only** for the [`plan`], which is
    /// pure and cannot block, and has answered before anything is sent. An
    /// owner busy across the exchange would make the lease exclusion over the
    /// network rather than over input.
    pub async fn handle(&self, body: &[u8], limit: u64) -> Dispatch {
        let planned = self.plan(body, limit).await;
        let (planned, dispatch) = self.dispatcher.dispatch_planned(planned).await;
        self.issue_capture_identity(planned.as_ref(), dispatch)
            .await
    }

    /// Have the registries' owner run the pure planner against both
    /// registries as they stand when it reaches this request.
    async fn plan(&self, body: &[u8], limit: u64) -> Result<Planned, Dispatch> {
        self.state
            .registries
            .plan(PlanRequest {
                body: body.to_vec(),
                limit,
                permitted: Arc::clone(&self.dispatcher.permitted),
                session: self.session,
                target: self.target.clone(),
                grant_revision: self.grant_revision,
            })
            .await
    }

    /// [`SessionFacade::handle`], abandoned if `cancel` completes first
    /// (M5-04).
    ///
    /// The consumer-facing half of cancellation. What comes back is decided by
    /// how far the exchange got, never by the fact of cancelling:
    /// [`NotDispatched::Cancelled`] (retryable) only if not a byte of the
    /// command was written, and [`UnknownReason::Cancelled`] (never retryable)
    /// otherwise. The obvious composition -- racing [`SessionFacade::handle`]
    /// against `cancel` and calling the loser "not dispatched" -- reports a
    /// click that has already landed as safe to send again, and
    /// `a_cancelled_click_reports_what_is_known_and_is_never_repeated` was
    /// red against exactly that.
    ///
    /// Nothing is retried here, automatically or otherwise.
    pub async fn handle_until(
        &self,
        body: &[u8],
        limit: u64,
        cancel: impl core::future::Future<Output = ()>,
    ) -> Dispatch {
        let planned = self.plan(body, limit).await;
        let (planned, dispatch) = self
            .dispatcher
            .dispatch_planned_until(planned, cancel)
            .await;
        self.issue_capture_identity(planned.as_ref(), dispatch)
            .await
    }

    /// Record a successful capture and hand its identity back to the consumer.
    ///
    /// **Only on [`Completion::Ok`].** A capture that failed, or whose outcome
    /// is unknown, issues no identity: there is no image the consumer could
    /// have looked at, so there is nothing for a later click to refer to.
    async fn issue_capture_identity(
        &self,
        planned: Option<&Planned>,
        dispatch: Dispatch,
    ) -> Dispatch {
        let Some(Planned::Dispatch {
            operation: Operation::Capture,
            payload,
            ..
        }) = planned
        else {
            return dispatch;
        };
        let Dispatch::Dispatched(Completion::Ok(result)) = &dispatch else {
            return dispatch;
        };
        let display = payload
            .pointer("/params/display")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        // **Dimensions from the image the released server actually sends**
        // (M5-C14). Every pinned `screenshot` answers
        // `{success, image_data, format}` (VNC omits `format`) and none sends
        // `width`, `height` or a scale. This used to read those three members,
        // which only this fixture emitted -- so against a released backend it
        // took the early return below and issued no identity at all. The PNG
        // states its own dimensions in its `IHDR`, and that is what is read.
        let Ok((width, height)) = tunnel_cua::image::capture_dimensions(result) else {
            // A capture whose dimensions we cannot read is not one a later
            // coordinate may refer to. The capture itself still succeeded, so
            // the outcome is unchanged; what is withheld is the identity.
            return dispatch;
        };
        // **The scale is never read from the response, and never defaulted.**
        // No pinned backend reports one, and a 1x default on a 2x display is a
        // click at twice the intended position with no error anywhere -- the
        // exact failure M5-C06 predicted, which the red run for M5-C14
        // reproduced once the dimensions became readable. Nor can the scale be
        // derived from the server: the pinned macOS handler resizes any
        // capture wider than 1,920 px before encoding it, and its
        // `get_screen_size` reports the `ImageGrab` pixel size, so "decoded
        // width over screen width" measures that resize, not the point scale.
        //
        // So the scale is what the device was told
        // ([`DeviceState::declare_scale_percent`]) or nothing, and with nothing
        // every coordinate on this capture is refused with
        // `CaptureRefusal::ScaleUndeclared`.
        let declared = match self.state.declared_point_space() {
            // M5-C19 option (b): the ratio is derived per capture, and a
            // capture the declaration contradicts gets no scale at all.
            Some(space) => space.scale_percent_for(width, height).ok(),
            None => self.state.declared_scale_percent(),
        };
        let recorded = self
            .state
            .registries
            .record(CaptureRecord {
                target: self.target.clone(),
                display,
                width,
                height,
                scale_percent: declared,
            })
            .await;
        let Some(identity) = recorded else {
            return dispatch;
        };

        let mut annotated = result.clone();
        if let Some(object) = annotated.as_object_mut() {
            object.insert("capture".to_owned(), json!(identity.id().value()));
            object.insert("display".to_owned(), json!(display));
        }
        Dispatch::Dispatched(Completion::Ok(annotated))
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::Poll;
    use std::collections::BTreeSet;

    use serde_json::json;
    use tunnel_cua::endpoint::BackendEndpoint;
    use tunnel_cua::lease::{LeaseRefusal, SessionId, TargetSession};
    use tunnel_cua::operation::Operation;
    use tunnel_cua::outcome::{Dispatch, InputRefusal, NotDispatched};
    use tunnel_cua::supervision::BackendGeneration;
    use tunnel_cua_export::supervisor::InputAuthority;

    use super::{DeviceState, Dispatcher, SessionFacade, parse_response, request_body};
    use crate::registries::QUEUE;

    const LIMIT: u64 = tunnel_cua::DEFAULT_REQUEST_BODY_LIMIT;

    /// Poll a future exactly once, without yielding to the runtime, and say
    /// whether it is still pending.
    async fn poll_once<T>(future: &mut Pin<Box<dyn Future<Output = T> + '_>>) -> bool {
        core::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending()))
            .await
    }

    /// A loopback endpoint nothing is listening on, so an operation that
    /// passes planning is reported `NotReached` and one that planning refuses
    /// is reported as refused: the two cannot be confused.
    async fn dead_endpoint() -> BackendEndpoint {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback");
        let address = listener.local_addr().expect("bound");
        drop(listener);
        BackendEndpoint::new(address).expect("loopback")
    }

    fn lease_not_held() -> Dispatch {
        Dispatch::NotDispatched(NotDispatched::InputAuthority(InputRefusal::Lease(
            LeaseRefusal::NotHeld,
        )))
    }

    /// The computer-use ordering: once an invalidation has been requested, no
    /// input operation is planned against the authority it revokes.
    ///
    /// Single-threaded on purpose, so the registries' owner runs only when
    /// this test yields and every interleaving below is the one written.
    #[tokio::test]
    async fn an_invalidation_takes_effect_before_any_plan_not_yet_computed() {
        let state = DeviceState::new();
        let target = TargetSession::new("console:1");
        let facade = SessionFacade::new(
            std::sync::Arc::clone(&state),
            Dispatcher::new(dead_endpoint().await, BTreeSet::from(Operation::ALL)),
            SessionId::new(1),
            target.clone(),
        );
        let key = request_body("press_key", json!({"key": "a"}));
        facade.acquire_input_lease().await.expect("an idle target");
        // The control: holding the lease, the key press passes planning.
        assert_eq!(
            facade.handle(&key, LIMIT).await,
            Dispatch::NotDispatched(NotDispatched::NotReached)
        );

        // Fill the owner's queue with key presses it has not looked at yet.
        let mut queued: Vec<Pin<Box<dyn Future<Output = Dispatch> + '_>>> = Vec::new();
        for _ in 0..QUEUE {
            let mut press: Pin<Box<dyn Future<Output = Dispatch> + '_>> =
                Box::pin(facade.handle(&key, LIMIT));
            assert!(poll_once(&mut press).await);
            queued.push(press);
        }
        assert_eq!(state.registries.room(), 0, "the queue is full");

        // Request the invalidation. Its command cannot be queued: there is no
        // room. Then ask for one more key press, behind it.
        let mut invalidation: Pin<Box<dyn Future<Output = _> + '_>> =
            Box::pin(state.invalidate(BackendGeneration::INITIAL));
        assert!(poll_once(&mut invalidation).await);
        let mut later: Pin<Box<dyn Future<Output = Dispatch> + '_>> =
            Box::pin(facade.handle(&key, LIMIT));
        assert!(poll_once(&mut later).await);

        // The caller gives up before its command was ever queued. The request
        // was made, so it must still take effect.
        drop(invalidation);

        // Every key press the owner had not yet planned is refused -- those
        // queued ahead of the request as much as the one behind it.
        for press in queued {
            assert_eq!(press.await, lease_not_held());
        }
        assert_eq!(later.await, lease_not_held());
        assert_eq!(state.holder(&target).await, None);
        assert_eq!(facade.handle(&key, LIMIT).await, lease_not_held());

        // What the abandoned request freed is reported by the next one.
        let reported = state.invalidate(BackendGeneration::INITIAL).await;
        assert_eq!(reported.leases_released, vec![target]);
    }

    /// The plain case: an invalidation that was awaited has been applied.
    #[tokio::test]
    async fn an_awaited_invalidation_has_dropped_the_lease_and_the_captures() {
        let state = DeviceState::new();
        let target = TargetSession::new("console:1");
        let facade = SessionFacade::new(
            std::sync::Arc::clone(&state),
            Dispatcher::new(dead_endpoint().await, BTreeSet::from(Operation::ALL)),
            SessionId::new(1),
            target.clone(),
        );
        facade.acquire_input_lease().await.expect("an idle target");
        let freed = state.invalidate(BackendGeneration::INITIAL).await;
        assert_eq!(freed.leases_released, vec![target.clone()]);
        assert_eq!(state.holder(&target).await, None);
        assert_eq!(state.capture_count().await, 0);
        let key = request_body("press_key", json!({"key": "a"}));
        assert_eq!(facade.handle(&key, LIMIT).await, lease_not_held());
        // Nothing was left over for a second invalidation to report.
        assert!(
            !state
                .invalidate(BackendGeneration::INITIAL)
                .await
                .freed_anything()
        );
    }

    /// The shape uvicorn gives the released server's `StreamingResponse`.
    #[test]
    fn a_chunked_response_is_dechunked() {
        let body = b"data: {\"success\": true}\n\n";
        let mut response =
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        response.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        response.extend_from_slice(body);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(parse_response(&response), Some((200, body.to_vec())));
    }

    /// Cut off before the terminating chunk: the answer was lost, so there is
    /// no body to classify, and the caller reports an unknown outcome.
    #[test]
    fn a_truncated_chunked_response_is_not_a_body() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ndata:\r\n";
        assert_eq!(parse_response(response), None);
        let short = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata:\r\n0\r\n\r\n";
        assert_eq!(parse_response(short), None);
    }

    /// An identity-framed body, as the fixture writes, is unchanged.
    #[test]
    fn an_identity_body_is_returned_as_is() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
            Some((200, b"ok".to_vec()))
        );
    }
}
