//! The device-side handler adapter.
//!
//! [`serve`] takes no address and opens no listener: the decoded request is
//! passed to the handler by a direct call on a spawned task.

use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, Uri, Version};
use http_body::Body;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tunnel_http_forward::{
    HttpErrorCode, HttpVersion, Method, RequestEvent, RequestHead, RequestReader,
};

use crate::body::{BodySender, ChannelBody};
use crate::exchange::{Dir, Exchange};
use crate::normalize;
use crate::progress::{
    self, BudgetClock, PauseSignal, ProgressKind, WaitMark, track_partial_record,
};
use crate::pump::{self, Delivery, DeliveryEvent, Exit, PumpError, next_frame};
use crate::status::{ExchangeReport, Execution};
use crate::stream::{Frame, FrameReceiver, FrameSender};
use crate::{BridgeConfig, Profile};

/// Request extension: cancelled when the exchange is reset, cancelled, or
/// fails before the response completes.
#[derive(Clone, Debug)]
pub struct HandlerCancellation(pub CancellationToken);

fn build_request(
    head: &RequestHead,
    queue: usize,
    cancel: &CancellationToken,
) -> Result<(Request<ChannelBody>, BodySender), HttpErrorCode> {
    let target = if head.query.is_empty() {
        head.path.clone()
    } else {
        format!("{}?{}", head.path, head.query)
    };
    let uri = Uri::try_from(target).map_err(|_| HttpErrorCode::InvalidHead)?;
    let method = match head.method {
        Method::Get => http::Method::GET,
        Method::Head => http::Method::HEAD,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Patch => http::Method::PATCH,
        Method::Delete => http::Method::DELETE,
        Method::Options => http::Method::OPTIONS,
    };
    let (sender, body) = ChannelBody::channel(queue, head.body_length, None);
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = match head.http_version {
        HttpVersion::Http11 => Version::HTTP_11,
        HttpVersion::Http2 => Version::HTTP_2,
    };
    let headers = request.headers_mut();
    for field in &head.headers {
        let name = HeaderName::from_bytes(field.name.as_bytes())
            .map_err(|_| HttpErrorCode::InvalidHead)?;
        let value = HeaderValue::from_str(&field.value).map_err(|_| HttpErrorCode::InvalidHead)?;
        headers.append(name, value);
    }
    request
        .extensions_mut()
        .insert(HandlerCancellation(cancel.clone()));
    Ok((request, sender))
}

/// Serve one exchange by calling `handler` in process.
///
/// The request head is fully validated before the handler is invoked; the
/// request body streams to the handler concurrently with the response.  If
/// the handler drops the request body, remaining upload bytes are still
/// validated and then discarded.
pub async fn serve<H, F, B, E>(
    profile: Arc<Profile>,
    config: BridgeConfig,
    from_owner: FrameReceiver,
    to_owner: FrameSender,
    handler: H,
) -> ExchangeReport
where
    H: FnOnce(Request<ChannelBody>) -> F + Send + 'static,
    F: Future<Output = Result<Response<B>, E>> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    E: Send + 'static,
{
    serve_paused(
        profile,
        config,
        from_owner,
        to_owner,
        PauseSignal::never(),
        handler,
    )
    .await
}

/// [`serve`] whose progress clocks stop while `pause` reports this
/// connector's recorded rotation freeze.
pub async fn serve_paused<H, F, B, E>(
    profile: Arc<Profile>,
    config: BridgeConfig,
    from_owner: FrameReceiver,
    to_owner: FrameSender,
    pause: PauseSignal,
    handler: H,
) -> ExchangeReport
where
    H: FnOnce(Request<ChannelBody>) -> F + Send + 'static,
    F: Future<Output = Result<Response<B>, E>> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    E: Send + 'static,
{
    let exchange = Exchange::new(to_owner, Execution::NotDispatched, pause, config.progress());
    let started = Instant::now();
    let deadline_at = started + config.deadline();
    let head_at = config.response_head_deadline().map(|bound| started + bound);
    let discard_until = started + config.discard_bound();
    let cancel = CancellationToken::new();
    let (dispatch_tx, dispatch_rx) = oneshot::channel();
    let request = request_pump(
        &exchange,
        from_owner,
        RequestReader::new(profile.request.clone()),
        dispatch_tx,
        config.body_queue(),
        &cancel,
        discard_until,
    );
    let response = response_pump(&exchange, &profile, dispatch_rx, handler);
    let watchdog = async {
        let deadline = tokio::time::sleep_until(deadline_at);
        let finished = async {
            exchange.terminal(Dir::Request).await;
            exchange.terminal(Dir::Response).await;
        };
        tokio::select! {
            biased;
            () = finished => {}
            () = exchange.stopped() => {}
            () = deadline => { exchange.abort(HttpErrorCode::DeadlineExceeded); }
            // M4-71: a handler that never answers is bounded by the head
            // bound; one that has answered streams to the absolute deadline.
            () = exchange.response_head_missed(head_at) => {
                exchange.abort(HttpErrorCode::DeadlineExceeded);
            }
        }
        if exchange.is_stopped() {
            cancel.cancel();
        }
    };
    tokio::join!(request, response, watchdog);
    exchange.report()
}

async fn request_pump(
    exchange: &Exchange,
    mut from_owner: FrameReceiver,
    mut reader: RequestReader,
    dispatch: oneshot::Sender<(Method, Request<ChannelBody>)>,
    queue: usize,
    cancel: &CancellationToken,
    discard_until: Instant,
) {
    let mut signal = from_owner.reset_signal();
    let mut dispatch = Some(dispatch);
    let mut delivery = Delivery::AwaitHead;
    let pause = exchange.pause.clone();
    let mut first_head = BudgetClock::new(ProgressKind::FirstHead, &exchange.budgets);
    let mut record = BudgetClock::new(ProgressKind::Record, &exchange.budgets);
    let mut fin = BudgetClock::new(ProgressKind::FinAfterEnd, &exchange.budgets);
    let mut record_ordinal = None;
    first_head.arm();
    let exit = 'frames: loop {
        let listen_only = exchange.is_complete(Dir::Request);
        let mark = WaitMark::now(&pause);
        let clocks = [first_head, record, fin];
        let frame = tokio::select! {
            biased;
            () = exchange.stopped() => break Exit::Local,
            _ = exchange.terminal(Dir::Response), if listen_only => return,
            frame = from_owner.recv() => frame,
            kind = progress::expired(clocks, mark, pause.clone()), if !listen_only => {
                exchange.note_progress_expired(kind);
                exchange.abort(HttpErrorCode::DeadlineExceeded);
                break Exit::Local;
            }
        };
        progress::end_wait(&mut [&mut first_head, &mut record, &mut fin], mark, &pause);
        match frame {
            None => {
                if !listen_only {
                    exchange.abort(HttpErrorCode::StreamInterrupted);
                }
                break Exit::PeerTerminated;
            }
            Some(Frame::Reset(detail)) => {
                exchange.abort(detail.code);
                break Exit::PeerTerminated;
            }
            Some(Frame::Fin) => match reader.fin() {
                Ok(()) => {
                    fin.disarm();
                    // The reader accepts FIN only after END, where the
                    // delivery awaits it; the body ends cleanly here.
                    delivery.transition(DeliveryEvent::Fin);
                    exchange.complete(Dir::Request);
                }
                Err(error) => {
                    exchange.abort(error.code());
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
                            exchange.abort(error.code());
                            break 'frames Exit::Local;
                        }
                    };
                    match event {
                        RequestEvent::Head(head) => match build_request(&head, queue, cancel) {
                            Ok((request, sender)) => {
                                first_head.disarm();
                                // The declared length is not tracked here:
                                // the handler's body starts no FIN-after-END
                                // budget before END.
                                delivery.transition(DeliveryEvent::Head {
                                    sender,
                                    declared: None,
                                });
                                if let Some(dispatch) = dispatch.take() {
                                    let _ = dispatch.send((head.method, request));
                                }
                            }
                            Err(code) => {
                                exchange.abort(code);
                                break 'frames Exit::Local;
                            }
                        },
                        RequestEvent::Body(slice) => {
                            let chunk = bytes.slice_ref(slice);
                            delivery.transition(DeliveryEvent::Body(chunk.len() as u64));
                            let Some(sender) = delivery.sender() else {
                                // The handler dropped the body: discard.
                                continue;
                            };
                            let sent = tokio::select! {
                                biased;
                                () = exchange.stopped() => break 'frames Exit::Local,
                                sent = sender.send(chunk) => sent,
                                // Any RESET, even one queued behind the
                                // owner's FIN: this pump cannot reach the
                                // queue while the handler is not reading.
                                reset = signal.wait() => {
                                    exchange.abort(reset.detail.code);
                                    break 'frames Exit::Local;
                                }
                            };
                            if sent.is_err() {
                                delivery.transition(DeliveryEvent::ReaderGone);
                            }
                        }
                        RequestEvent::End => {
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
        // Bounded by the deadline plus a short grace.
        let _ = tokio::time::timeout_at(discard_until, from_owner.discard_until_terminal()).await;
    }
}

async fn response_pump<H, F, B, E>(
    exchange: &Exchange,
    profile: &Profile,
    dispatch: oneshot::Receiver<(Method, Request<ChannelBody>)>,
    handler: H,
) where
    H: FnOnce(Request<ChannelBody>) -> F + Send + 'static,
    F: Future<Output = Result<Response<B>, E>> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    E: Send + 'static,
{
    let (method, request) = tokio::select! {
        biased;
        () = exchange.stopped() => return,
        received = dispatch => match received {
            Ok(received) => received,
            Err(_) => return,
        },
    };
    if !exchange.begin_dispatch() {
        return;
    }
    let mut task = tokio::spawn(async move { handler(request).await });
    let joined = tokio::select! {
        biased;
        () = exchange.stopped() => {
            // Wait until the handler future has actually been dropped, so the
            // terminal report never precedes the handler's cancellation.
            task.abort();
            let _ = task.await;
            return;
        }
        joined = &mut task => joined,
    };
    // A panic, a cancelled task and a handler error are indistinguishable to
    // the peer; none of their messages is carried.
    let Ok(Ok(response)) = joined else {
        exchange.abort(HttpErrorCode::StreamInterrupted);
        return;
    };
    exchange.note_response_head();
    let (parts, body) = response.into_parts();
    let mut body = std::pin::pin!(body);
    let prepared =
        match normalize::response_head(&parts, body.size_hint().exact(), method, &profile.response)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                exchange.abort(error.code());
                return;
            }
        };
    if prepared.zero_body
        && let Err(code) = drain_zero_body(exchange, body.as_mut()).await
    {
        exchange.abort(code);
        return;
    }
    let result = match pump::send(exchange, prepared.record).await {
        Ok(()) => {
            pump::pump_body(
                exchange,
                body,
                prepared.head.body_length,
                profile.response.body_limit(),
            )
            .await
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => exchange.complete(Dir::Response),
        Err(PumpError::Stopped) => {}
        Err(PumpError::Source(code) | PumpError::Sink(code)) => {
            exchange.abort(code);
        }
        Err(PumpError::Progress(kind)) => {
            exchange.note_progress_expired(kind);
            exchange.abort(HttpErrorCode::DeadlineExceeded);
        }
    }
}

/// A zero-body response is checked to be empty before its head is sent, so
/// a violation is still a clean pre-header failure.
async fn drain_zero_body<B>(
    exchange: &Exchange,
    mut body: std::pin::Pin<&mut B>,
) -> Result<(), HttpErrorCode>
where
    B: Body<Data = Bytes>,
{
    loop {
        let next = tokio::select! {
            biased;
            () = exchange.stopped() => return Err(exchange.error_code()),
            next = next_frame(body.as_mut()) => next,
        };
        match next {
            None => return Ok(()),
            Some(Err(_)) => return Err(HttpErrorCode::StreamInterrupted),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) if data.is_empty() => {}
                Ok(_) => return Err(HttpErrorCode::LengthMismatch),
                Err(frame) => {
                    if frame
                        .trailers_ref()
                        .is_some_and(|trailers| !trailers.is_empty())
                    {
                        return Err(HttpErrorCode::UnsupportedFeature);
                    }
                }
            },
        }
    }
}
