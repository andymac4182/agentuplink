//! The owner-side ingress adapter.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, header};
use http_body::Body;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tunnel_http_forward::{
    HttpErrorCode, Method, ResponseEvent, ResponseHead, ResponseReader, requires_zero_body,
};

use crate::body::{BodySender, ChannelBody};
use crate::exchange::{Dir, Exchange};
use crate::normalize;
use crate::progress::{
    self, BudgetClock, PauseSignal, ProgressKind, WaitMark, track_partial_record,
};
use crate::pump::{self, Delivery, DeliveryEffect, DeliveryEvent, Exit, PumpError};
use crate::status::{
    ExchangeReport, Execution, Origin, Outcome, ResetDetail, gateway_response, gateway_status,
};
use crate::stream::{Frame, FrameReceiver, FrameSender};
use crate::{BridgeConfig, Profile};

/// Observes and controls a forwarded exchange after `forward` returns.
pub struct ExchangeHandle {
    task: JoinHandle<ExchangeReport>,
    consumer: CancellationToken,
}

impl ExchangeHandle {
    /// Cancel the exchange as a consumer disconnect would.
    pub fn cancel(&self) {
        self.consumer.cancel();
    }

    /// Wait for both directions to reach a terminal state.
    pub async fn report(self) -> ExchangeReport {
        self.task.await.unwrap_or(ExchangeReport {
            request: Outcome::Pending,
            response: Outcome::Pending,
            execution: Execution::Unknown,
            error: Some(HttpErrorCode::StreamInterrupted),
            progress_expired: None,
        })
    }
}

enum HeadOutcome {
    Committed(Response<ChannelBody>),
    Failed(Origin, ResetDetail),
}

/// Who answered the consumer's pending head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeadPhase {
    /// Nothing was sent to the consumer yet.
    Pending,
    /// A gateway failure answered it.
    Failed,
    /// The response head was handed to the consumer.  A consumer that leaves
    /// after this released a response body (M3-32).
    Committed,
    /// The response head was decided, but the consumer had already dropped
    /// the pending head: it was never handed a body, so leaving is an
    /// ordinary pre-head cancellation, not a release (M3-32 review).
    Unclaimed,
}

impl HeadPhase {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Failed => 1,
            Self::Committed => 2,
            Self::Unclaimed => 3,
        }
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Failed,
            2 => Self::Committed,
            _ => Self::Unclaimed,
        }
    }
}

/// The take-once answer to the consumer's pending head.
///
/// The phase is the claim: exactly one caller moves it out of `Pending`, and
/// only that caller sends.  The queue therefore carries at most one message
/// ever, and its single slot is never full.
struct HeadSlot {
    phase: AtomicU8,
    tx: mpsc::Sender<HeadOutcome>,
}

impl HeadSlot {
    fn new() -> (Self, mpsc::Receiver<HeadOutcome>) {
        let (tx, rx) = mpsc::channel(1);
        let slot = Self {
            phase: AtomicU8::new(HeadPhase::Pending.to_u8()),
            tx,
        };
        (slot, rx)
    }

    fn phase(&self) -> HeadPhase {
        HeadPhase::from_u8(self.phase.load(Ordering::SeqCst))
    }

    /// The only way out of `Pending`: true for the one caller that may send.
    fn claim(&self, phase: HeadPhase) -> bool {
        self.phase
            .compare_exchange(
                HeadPhase::Pending.to_u8(),
                phase.to_u8(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Answer a still-pending head with a gateway failure.
    fn fail(&self, origin: Origin, detail: ResetDetail) {
        if self.claim(HeadPhase::Failed) {
            let _ = self.tx.try_send(HeadOutcome::Failed(origin, detail));
        }
    }

    /// Hand the response head to the consumer.  False if the head was
    /// already answered.
    fn commit(&self, response: Response<ChannelBody>) -> bool {
        // Claimed as `Committed` before the send, because a consumer that
        // takes the head can release its body at once.  Every `Owner` method
        // runs on the exchange's one `run` task and nothing here awaits, so
        // no observer runs between the claim and the correction below.
        if !self.claim(HeadPhase::Committed) {
            return false;
        }
        if let Err(unsent) = self.tx.try_send(HeadOutcome::Committed(response)) {
            self.phase
                .store(HeadPhase::Unclaimed.to_u8(), Ordering::SeqCst);
            // Dropped after the phase is corrected: an unsent body's drop
            // cancels the exchange, and that path reads the phase.
            drop(unsent);
        }
        true
    }
}

struct Owner {
    exchange: Exchange,
    head: HeadSlot,
    consumer: CancellationToken,
}

impl Owner {
    /// Abort the exchange; before headers commit, answer with a gateway
    /// response carrying the first failure.
    fn fail(&self, origin: Origin, code: HttpErrorCode) {
        if let Some(detail) = self.exchange.abort(code) {
            self.head.fail(origin, detail);
        }
    }

    /// The device reset: its dispatch record is authoritative.
    fn peer_reset(&self, detail: ResetDetail) {
        if !self.exchange.is_complete(Dir::Response) {
            self.exchange.set_execution(detail.execution);
        }
        self.fail(Origin::Upstream, detail.code);
    }

    /// The consumer went away: before the response head it abandoned the
    /// request, which is an ordinary consumer cancellation; after it, it
    /// released the response body, which is recorded as
    /// [`Outcome::Released`] (M3-32).  Both send the same RESET.
    fn consumer_left(&self) {
        if self.head.phase() == HeadPhase::Committed {
            // No gateway response can follow a committed head, so there is
            // no pending head to answer.
            let _ = self.exchange.release(HttpErrorCode::Cancelled);
        } else {
            self.fail(Origin::Consumer, HttpErrorCode::Cancelled);
        }
    }

    fn progress_expired(&self, kind: ProgressKind) {
        self.exchange.note_progress_expired(kind);
        self.fail(Origin::Upstream, HttpErrorCode::DeadlineExceeded);
    }

    fn pump_failed(&self, error: PumpError) {
        match error {
            PumpError::Stopped => {}
            PumpError::Source(code) => self.fail(Origin::Consumer, code),
            PumpError::Sink(code) => self.fail(Origin::Upstream, code),
            PumpError::Progress(kind) => self.progress_expired(kind),
        }
    }

    fn commit(&self, response: Response<ChannelBody>) -> bool {
        self.head.commit(response)
    }
}

fn rejected(
    status: StatusCode,
    code: HttpErrorCode,
    execution: Execution,
) -> (Response<ChannelBody>, ExchangeHandle) {
    let report = ExchangeReport {
        request: Outcome::Aborted,
        response: Outcome::Aborted,
        execution,
        error: Some(code),
        progress_expired: None,
    };
    (
        gateway_response(status, code, execution),
        ExchangeHandle {
            task: tokio::spawn(async move { report }),
            consumer: CancellationToken::new(),
        },
    )
}

/// The consumer-facing rejection for a request head that fails
/// normalization: the same status and sanitized `{code, execution}` body
/// [`forward`] would return, with `not_dispatched` execution.  An ingress
/// uses it to refuse such a request before it opens any tunnel stream.
#[must_use]
pub fn rejection_response(error: normalize::NormalizeError) -> Response<ChannelBody> {
    gateway_response(error.status(), error.code(), Execution::NotDispatched)
}

/// Forward one consumer request over one logical stream.
///
/// Returns once the device's response head arrives (early responses are
/// returned while the upload continues) or a failure is decided before
/// headers.  Nothing is written to `to_device` unless the request passes
/// normalization and policy validation.  Dropping the returned future, or
/// the response body before it ends, cancels the exchange with RESET.
pub async fn forward<B>(
    request: Request<B>,
    profile: Arc<Profile>,
    config: BridgeConfig,
    to_device: FrameSender,
    from_device: FrameReceiver,
) -> (Response<ChannelBody>, ExchangeHandle)
where
    B: Body<Data = Bytes> + Send + 'static,
{
    forward_paused(
        request,
        profile,
        config,
        to_device,
        from_device,
        PauseSignal::never(),
    )
    .await
}

/// [`forward`] whose progress clocks stop while `pause` reports this
/// endpoint's (or its owner's relayed) recorded rotation freeze.
pub async fn forward_paused<B>(
    request: Request<B>,
    profile: Arc<Profile>,
    config: BridgeConfig,
    to_device: FrameSender,
    from_device: FrameReceiver,
    pause: PauseSignal,
) -> (Response<ChannelBody>, ExchangeHandle)
where
    B: Body<Data = Bytes> + Send + 'static,
{
    let (handle, head) = begin_paused(request, profile, config, to_device, from_device, pause);
    (head.await, handle)
}

/// The consumer-facing half of an exchange started by [`begin_paused`]: it
/// resolves to the response (or the gateway failure) once the head is
/// decided.  Dropping it before then — even unpolled — is the consumer going
/// away, and cancels the exchange exactly as dropping [`forward`] does.
pub type PendingHead = Pin<Box<dyn Future<Output = Response<ChannelBody>> + Send>>;

/// [`forward_paused`] split in two, so a caller can observe the exchange's
/// terminal report **whether or not the consumer waits for the head**.
///
/// With [`forward_paused`] the [`ExchangeHandle`] only exists once the head
/// has been decided, so a consumer that leaves before any response head drops
/// the handle with the future and nobody records the exchange (M3-14).  Here
/// the handle is returned immediately: the exchange is already running, and
/// its report is available however the [`PendingHead`] ends.
pub fn begin_paused<B>(
    request: Request<B>,
    profile: Arc<Profile>,
    config: BridgeConfig,
    to_device: FrameSender,
    from_device: FrameReceiver,
    pause: PauseSignal,
) -> (ExchangeHandle, PendingHead)
where
    B: Body<Data = Bytes> + Send + 'static,
{
    let (parts, body) = request.into_parts();
    let ingress = match normalize::request_head(&parts, &profile.request) {
        Ok(ingress) => ingress,
        Err(error) => {
            let (response, handle) =
                rejected(error.status(), error.code(), Execution::NotDispatched);
            return (handle, Box::pin(std::future::ready(response)));
        }
    };
    let method = ingress.head.method;
    let declared = ingress.head.body_length;
    let (head, mut head_rx) = HeadSlot::new();
    let consumer = CancellationToken::new();
    let owner = Arc::new(Owner {
        exchange: Exchange::new(
            to_device,
            Execution::NotDispatched,
            pause,
            config.progress(),
        ),
        head,
        consumer: consumer.clone(),
    });
    let task = tokio::spawn(run(
        Arc::clone(&owner),
        ingress.record,
        body,
        declared,
        method,
        profile,
        config,
        from_device,
    ));
    let handle = ExchangeHandle {
        task,
        consumer: consumer.clone(),
    };
    // Created here, not inside the future, so that dropping a head future
    // that was never polled still cancels the exchange.
    let guard = consumer.drop_guard();
    let head = async move {
        let outcome = head_rx.recv().await;
        drop(guard.disarm());
        match outcome {
            Some(HeadOutcome::Committed(response)) => response,
            Some(HeadOutcome::Failed(origin, detail)) => gateway_response(
                gateway_status(origin, detail.code, detail.execution),
                detail.code,
                detail.execution,
            ),
            None => {
                let execution = owner.exchange.execution();
                gateway_response(
                    gateway_status(
                        Origin::Upstream,
                        HttpErrorCode::StreamInterrupted,
                        execution,
                    ),
                    HttpErrorCode::StreamInterrupted,
                    execution,
                )
            }
        }
    };
    (handle, Box::pin(head))
}

#[allow(clippy::too_many_arguments)]
async fn run<B>(
    owner: Arc<Owner>,
    head_record: Bytes,
    body: B,
    declared: Option<u64>,
    method: Method,
    profile: Arc<Profile>,
    config: BridgeConfig,
    from_device: FrameReceiver,
) -> ExchangeReport
where
    B: Body<Data = Bytes> + Send + 'static,
{
    let exchange = &owner.exchange;
    let started = Instant::now();
    let deadline_at = started + config.deadline();
    let head_at = config.response_head_deadline().map(|bound| started + bound);
    let discard_until = started + config.discard_bound();
    let request = async {
        // A head no larger than the credit capacity is one queue item: it is
        // either wholly queued or not queued at all.  Only once it is queued
        // can the request reach the device.  A larger head could be partly
        // queued before a failure, so it is `unknown` from the start.
        if head_record.len() > exchange.peer.capacity() {
            exchange.set_execution(Execution::Unknown);
        }
        if let Err(error) = pump::send(exchange, head_record).await {
            owner.pump_failed(error);
            return;
        }
        exchange.set_execution(Execution::Unknown);
        let body = std::pin::pin!(body);
        match pump::pump_body(exchange, body, declared, profile.request.body_limit()).await {
            Ok(()) => exchange.complete(Dir::Request),
            Err(error) => owner.pump_failed(error),
        }
    };
    let response = response_pump(
        &owner,
        from_device,
        ResponseReader::new(profile.response.clone(), method),
        method,
        config.body_queue(),
        discard_until,
    );
    let pumps = async {
        tokio::join!(request, response);
    };
    let watchdog = async {
        let deadline = tokio::time::sleep_until(deadline_at);
        let finished = async {
            exchange.terminal(Dir::Request).await;
            exchange.terminal(Dir::Response).await;
        };
        tokio::select! {
            biased;
            () = finished => {}
            () = owner.consumer.cancelled() => owner.consumer_left(),
            () = deadline => owner.fail(Origin::Upstream, HttpErrorCode::DeadlineExceeded),
            () = exchange.response_head_missed(head_at) => {
                owner.fail(Origin::Upstream, HttpErrorCode::DeadlineExceeded);
            }
        }
    };
    tokio::join!(pumps, watchdog);
    exchange.report()
}

fn build_response(
    head: ResponseHead,
    method: Method,
    queue: usize,
    consumer: &CancellationToken,
) -> Result<(Response<ChannelBody>, BodySender), HttpErrorCode> {
    let status = StatusCode::from_u16(head.status).map_err(|_| HttpErrorCode::InvalidHead)?;
    let mut headers = HeaderMap::new();
    for field in &head.headers {
        let name = HeaderName::from_bytes(field.name.as_bytes())
            .map_err(|_| HttpErrorCode::InvalidHead)?;
        let value = HeaderValue::from_str(&field.value).map_err(|_| HttpErrorCode::InvalidHead)?;
        headers.append(name, value);
    }
    let zero_body = requires_zero_body(method, head.status);
    if !zero_body && let Some(length) = head.body_length {
        // Generated from the checked typed length, never copied framing.
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    let (sender, body) = ChannelBody::channel(queue, head.body_length, Some(consumer.clone()));
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok((response, sender))
}

async fn response_pump(
    owner: &Owner,
    mut from_device: FrameReceiver,
    mut reader: ResponseReader,
    method: Method,
    queue: usize,
    discard_until: Instant,
) {
    let exchange = &owner.exchange;
    let mut signal = from_device.reset_signal();
    let mut delivery = Delivery::AwaitHead;
    let pause = exchange.pause.clone();
    let mut record = BudgetClock::new(ProgressKind::Record, &exchange.budgets);
    let mut fin = BudgetClock::new(ProgressKind::FinAfterEnd, &exchange.budgets);
    let mut record_ordinal = None;
    let exit = 'frames: loop {
        let listen_only = exchange.is_complete(Dir::Response);
        let mark = WaitMark::now(&pause);
        let clocks = [record, fin];
        let frame = tokio::select! {
            biased;
            () = exchange.stopped() => break Exit::Local,
            _ = exchange.terminal(Dir::Request), if listen_only => return,
            frame = from_device.recv() => frame,
            kind = progress::expired(clocks, mark, pause.clone()), if !listen_only => {
                owner.progress_expired(kind);
                break Exit::Local;
            }
        };
        progress::end_wait(&mut [&mut record, &mut fin], mark, &pause);
        match frame {
            None => {
                if !listen_only {
                    owner.fail(Origin::Upstream, HttpErrorCode::StreamInterrupted);
                }
                break Exit::PeerTerminated;
            }
            Some(Frame::Reset(detail)) => {
                owner.peer_reset(detail);
                break Exit::PeerTerminated;
            }
            Some(Frame::Fin) => match reader.fin() {
                Ok(()) => {
                    fin.disarm();
                    // The reader accepts FIN only after END, where the
                    // delivery awaits it; the body ends cleanly here.
                    delivery.transition(DeliveryEvent::Fin);
                    exchange.complete(Dir::Response);
                }
                Err(error) => {
                    owner.fail(Origin::Upstream, error.code());
                    break Exit::Local;
                }
            },
            Some(Frame::Data(bytes)) => {
                let mut input: &[u8] = &bytes;
                loop {
                    let event = match reader.read(&mut input) {
                        Ok(Some(event)) => event,
                        Ok(None) => break,
                        Err(error) => {
                            owner.fail(Origin::Upstream, error.code());
                            break 'frames Exit::Local;
                        }
                    };
                    match event {
                        ResponseEvent::Head(head) => {
                            exchange.note_response_head();
                            let declared = head.body_length;
                            match build_response(head, method, queue, &owner.consumer) {
                                Ok((response, sender)) => {
                                    // A response head is only sent after the
                                    // handler returned.
                                    exchange.set_execution(Execution::Dispatched);
                                    let event = DeliveryEvent::Head { sender, declared };
                                    if delivery.transition(event) == DeliveryEffect::ArmFin {
                                        fin.arm();
                                    }
                                    if !owner.commit(response) {
                                        break 'frames Exit::Local;
                                    }
                                }
                                Err(code) => {
                                    owner.fail(Origin::Upstream, code);
                                    break 'frames Exit::Local;
                                }
                            }
                        }
                        ResponseEvent::Body(slice) => {
                            let chunk = bytes.slice_ref(slice);
                            let effect =
                                delivery.transition(DeliveryEvent::Body(chunk.len() as u64));
                            // After the last declared byte only END and FIN
                            // may follow, so the FIN-after-END budget covers
                            // them from here.  The consumer may already have
                            // released the body at its declared length,
                            // which is not a cancellation (see `ChannelBody`).
                            if (effect
                                == DeliveryEffect::Deliver {
                                    last_declared: true,
                                })
                            {
                                fin.arm();
                            }
                            // No body is being fed outside the body phase:
                            // the bytes are dropped.
                            let Some(sender) = delivery.sender() else {
                                continue;
                            };
                            tokio::select! {
                                biased;
                                () = exchange.stopped() => break 'frames Exit::Local,
                                sent = sender.send(chunk) => if sent.is_err() {
                                    owner.consumer_left();
                                    break 'frames Exit::Local;
                                },
                                // Only a RESET before the device's FIN: bytes
                                // of a response the device completed are
                                // delivered, and a later RESET is seen in
                                // order (it then aborts only the upload).
                                detail = signal.wait_before_fin() => {
                                    owner.peer_reset(detail);
                                    break 'frames Exit::Local;
                                }
                            }
                        }
                        ResponseEvent::End => {
                            delivery.transition(DeliveryEvent::End);
                            fin.arm();
                        }
                    }
                }
                track_partial_record(reader.partial_record(), &mut record, &mut record_ordinal);
            }
        }
    };
    delivery.transition(DeliveryEvent::Stop(exchange.error_code()));
    if exit == Exit::Local {
        // Bounded by the deadline plus a short grace: a peer that never
        // finishes cannot hold the exchange open, but a deadline abort still
        // gives the peer time to see the RESET instead of a lost receiver.
        let _ = tokio::time::timeout_at(discard_until, from_device.discard_until_terminal()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> (Owner, mpsc::Receiver<HeadOutcome>) {
        let (to_device, _device_rx, _) = crate::stream::channel(64 * 1024);
        let (head, head_rx) = HeadSlot::new();
        let owner = Owner {
            exchange: Exchange::new(
                to_device,
                Execution::Dispatched,
                PauseSignal::never(),
                BridgeConfig::default().progress(),
            ),
            head,
            consumer: CancellationToken::new(),
        };
        (owner, head_rx)
    }

    fn response() -> Response<ChannelBody> {
        let (_sender, body) = ChannelBody::channel(1, None, None);
        Response::new(body)
    }

    /// M3-32 review: a head the consumer never received is not a release.
    /// The consumer dropped the pending head just as the response head was
    /// committed, so the send fails; leaving then is a pre-head cancellation.
    #[tokio::test]
    async fn a_head_the_consumer_never_took_is_not_a_release() {
        let (owner, head_rx) = owner();
        drop(head_rx);
        assert!(owner.commit(response()));
        owner.consumer_left();
        let report = owner.exchange.report();
        assert_eq!(report.response, Outcome::Aborted);
        assert_eq!(report.error, Some(HttpErrorCode::Cancelled));
    }

    /// The other side of the same rule: a head the consumer did take makes a
    /// later departure a release.
    #[tokio::test]
    async fn a_head_the_consumer_took_makes_leaving_a_release() {
        let (owner, _head_rx) = owner();
        assert!(owner.commit(response()));
        owner.consumer_left();
        assert_eq!(owner.exchange.report().response, Outcome::Released);
    }
}
