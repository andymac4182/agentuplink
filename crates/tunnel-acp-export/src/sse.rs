//! Response bodies for the ACP HTTP binding: complete JSON answers, bodyless
//! 202/204 answers, and the bounded `text/event-stream` body a connection- or
//! session-scoped `GET` holds open.
//!
//! **The event encoding is one line.**  An ACP message is compact JSON with no
//! line break in it, so one message is exactly `data: <compact>\n\n` — no
//! `event:` name, no `id:` field and therefore no `Last-Event-ID` replay,
//! which `docs/acp.md` says this profile does not have.  `tunnel-mcp-export`
//! frames its SSE the same way; the two encoders are deliberately identical
//! and each is asserted byte for byte in its own crate.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::mpsc;
use tunnel_acp::message::AcpRejection;

/// A boxed error carrying no payload.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// The response body every ACP export answer uses.
pub type ExportBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// A payload-free stream failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamFailure {
    /// The cumulative `text/event-stream` limit was exceeded.
    Limit,
    /// The connection ended while the stream was open.
    Interrupted,
}

impl std::fmt::Display for StreamFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "acp export stream failed: {self:?}")
    }
}

impl std::error::Error for StreamFailure {}

fn full(bytes: Bytes) -> ExportBody {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

/// An empty body.
#[must_use]
pub fn empty() -> ExportBody {
    full(Bytes::new())
}

/// A complete `application/json` response.
#[must_use]
pub fn json_response(status: StatusCode, body: Bytes) -> Response<ExportBody> {
    let mut response = Response::new(full(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// A local rejection as a JSON-RPC error response at its rule's status.
#[must_use]
pub fn rejection(rejection: &AcpRejection) -> Response<ExportBody> {
    let status = StatusCode::from_u16(rejection.status).unwrap_or(StatusCode::BAD_REQUEST);
    json_response(status, Bytes::from(rejection.body()))
}

/// A bodyless response (202 Accepted, 204 No Content, 409 Conflict).
#[must_use]
pub fn no_body(status: StatusCode) -> Response<ExportBody> {
    let mut response = Response::new(empty());
    *response.status_mut() = status;
    response
}

/// The headers of an SSE response.
///
/// **No `Acp-Session-Id` (task row M8-C05).**  The pinned SDK's own server
/// sets that header on every session-scoped SSE response it serves
/// (`agent-client-protocol-http` 2.1.0 `src/http_server.rs`, `handle_get`).
/// This bridge follows the RFD instead, which names only `Acp-Connection-Id`
/// on responses and returns a new session's identifier in the `session/new`
/// response body.  The consequence is recorded rather than hidden: **this
/// device's session-scoped SSE responses are not byte-identical to the pinned
/// server's.**  What the chunk proves is that they do not need to be — the
/// pinned *client* reads the session header on no response, and completes a
/// whole v1 conversation without it.
pub fn sse_head(response: &mut Response<ExportBody>, connection: &str) {
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        http::HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    if let Ok(value) = HeaderValue::from_str(connection) {
        headers.insert(
            http::HeaderName::from_static(tunnel_acp::headers::ACP_CONNECTION_ID),
            value,
        );
    }
}

/// Frame one compact ACP message as an SSE `data` event.
///
/// The compact form of a JSON-RPC message never contains a line break, so one
/// message is one `data:` line and the event terminates with a blank line.
#[must_use]
pub fn sse_event(compact: &[u8]) -> Bytes {
    let mut event = Vec::with_capacity(compact.len() + 8);
    event.extend_from_slice(b"data: ");
    event.extend_from_slice(compact);
    event.extend_from_slice(b"\n\n");
    Bytes::from(event)
}

/// Bytes queued towards one open SSE body.
pub const STREAM_QUEUE: usize = 8;

/// The sending half of a [`ChannelResponseBody`].
///
/// **Clone is what makes subscriber loss observable without a message to
/// send.**  A pump only learns its body is gone when it next tries to write,
/// so a connection whose agent has fallen silent would not notice a broken
/// stream at all.  A clone parked on the stream's [`Target`][t] lets the
/// connection's watchdog ask [`StreamSender::is_closed`] on its own schedule.
/// Cloning the sender does not keep the body alive: `is_closed` reports the
/// *receiving* half being dropped, which is exactly the event being watched.
///
/// [t]: crate::bridge
#[derive(Clone, Debug)]
pub struct StreamSender {
    tx: mpsc::Sender<Result<Bytes, StreamFailure>>,
}

impl StreamSender {
    /// Send bytes, waiting for queue room.  `Err` once the body was dropped.
    pub async fn send(&self, bytes: Bytes) -> Result<(), ()> {
        self.tx.send(Ok(bytes)).await.map_err(|_| ())
    }

    /// Fail the body.  Never a clean end: a broken ACP stream must not look
    /// like an orderly one.
    pub async fn fail(&self, failure: StreamFailure) {
        let _ = self.tx.send(Err(failure)).await;
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Where a streaming response body is in its life.
///
/// `sent` exists only while the body is streaming: once it failed or ended
/// there is no cumulative count left to compare against a limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyPhase {
    /// Frames are still being forwarded; `sent` data bytes have been.
    Streaming { sent: u64 },
    /// One error frame was yielded.  Every later poll is end of stream.
    Failed,
    /// The source ended cleanly.
    Done,
}

/// What the body's source produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyEvent {
    /// A data frame of this many bytes.
    Data(u64),
    /// The source failed.
    Failure(StreamFailure),
    /// The source ended.
    End,
}

/// What the body does with the frame that caused a transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyEffect {
    /// Yield the frame.
    Forward,
    /// Yield this failure instead of the frame.
    Fail(StreamFailure),
    /// Yield end of stream.
    Finish,
}

/// An event offered to a body that is no longer streaming.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BodyOver;

impl BodyPhase {
    pub(crate) const START: Self = Self::Streaming { sent: 0 };

    /// The only place a body's phase changes.  `limit` is the cumulative
    /// data-byte bound: a data frame that would pass it fails the body
    /// instead of being forwarded.
    ///
    /// # Errors
    /// [`BodyOver`] for any event once the body failed or ended.
    pub(crate) fn on_event(
        self,
        event: BodyEvent,
        limit: u64,
    ) -> Result<(Self, BodyEffect), BodyOver> {
        let Self::Streaming { sent } = self else {
            return Err(BodyOver);
        };
        Ok(match event {
            BodyEvent::Data(len) => {
                let total = sent.saturating_add(len);
                if total > limit {
                    (Self::Failed, BodyEffect::Fail(StreamFailure::Limit))
                } else {
                    (Self::Streaming { sent: total }, BodyEffect::Forward)
                }
            }
            BodyEvent::Failure(failure) => (Self::Failed, BodyEffect::Fail(failure)),
            BodyEvent::End => (Self::Done, BodyEffect::Finish),
        })
    }

    pub(crate) const fn is_streaming(self) -> bool {
        matches!(self, Self::Streaming { .. })
    }
}

/// A response body fed by a bounded queue, failing once its cumulative limit
/// is exceeded.
#[derive(Debug)]
pub struct ChannelResponseBody {
    rx: mpsc::Receiver<Result<Bytes, StreamFailure>>,
    limit: u64,
    phase: BodyPhase,
    bytes: Arc<AtomicU64>,
}

impl ChannelResponseBody {
    /// A body limited to `limit` cumulative bytes, and its sender.
    #[must_use]
    pub fn channel(limit: u64, bytes: Arc<AtomicU64>) -> (StreamSender, Self) {
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        (
            StreamSender { tx },
            Self {
                rx,
                limit,
                phase: BodyPhase::START,
                bytes,
            },
        )
    }

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

impl Body for ChannelResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if !self.phase.is_streaming() {
            return Poll::Ready(None);
        }
        let (event, bytes) = match self.rx.poll_recv(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => (BodyEvent::End, None),
            Poll::Ready(Some(Err(failure))) => (BodyEvent::Failure(failure), None),
            Poll::Ready(Some(Ok(bytes))) => (BodyEvent::Data(bytes.len() as u64), Some(bytes)),
        };
        match (self.advance(event), bytes) {
            (BodyEffect::Forward, Some(bytes)) => {
                self.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            (BodyEffect::Fail(failure), bytes) => {
                if bytes.is_some() {
                    // The limit refused a frame the queue delivered: nothing
                    // further is read from it.
                    self.rx.close();
                }
                Poll::Ready(Some(Err(Box::new(failure))))
            }
            (BodyEffect::Finish | BodyEffect::Forward, _) => Poll::Ready(None),
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Box a streaming body.
#[must_use]
pub fn stream_body(body: ChannelResponseBody) -> ExportBody {
    body.boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_message_is_one_data_line_and_a_blank_line() {
        assert_eq!(sse_event(br#"{"a":1}"#), &b"data: {\"a\":1}\n\n"[..]);
    }

    #[test]
    fn an_sse_response_never_carries_the_session_header() {
        let mut response = Response::new(empty());
        sse_head(&mut response, "connection-1");
        assert!(
            response
                .headers()
                .get(tunnel_acp::headers::ACP_SESSION_ID)
                .is_none(),
            "M8-C05: this profile follows the RFD, which names no session header on a response"
        );
        assert_eq!(
            response
                .headers()
                .get(tunnel_acp::headers::ACP_CONNECTION_ID)
                .and_then(|value| value.to_str().ok()),
            Some("connection-1")
        );
    }

    #[test]
    fn a_streaming_body_counts_data_and_stays_streaming() {
        let phase = BodyPhase::START;
        let (phase, effect) = phase.on_event(BodyEvent::Data(6), 10).unwrap();
        assert_eq!(phase, BodyPhase::Streaming { sent: 6 });
        assert_eq!(effect, BodyEffect::Forward);
        // Exactly the limit is accepted.
        let (phase, effect) = phase.on_event(BodyEvent::Data(4), 10).unwrap();
        assert_eq!(phase, BodyPhase::Streaming { sent: 10 });
        assert_eq!(effect, BodyEffect::Forward);
    }

    #[test]
    fn a_streaming_body_fails_on_the_limit_or_a_failure_and_ends_on_end() {
        let streaming = BodyPhase::Streaming { sent: 10 };
        assert_eq!(
            streaming.on_event(BodyEvent::Data(1), 10),
            Ok((BodyPhase::Failed, BodyEffect::Fail(StreamFailure::Limit)))
        );
        assert_eq!(
            streaming.on_event(BodyEvent::Failure(StreamFailure::Interrupted), 10),
            Ok((
                BodyPhase::Failed,
                BodyEffect::Fail(StreamFailure::Interrupted)
            ))
        );
        assert_eq!(
            streaming.on_event(BodyEvent::End, 10),
            Ok((BodyPhase::Done, BodyEffect::Finish))
        );
    }

    #[test]
    fn a_body_that_failed_or_ended_refuses_every_event() {
        for over in [BodyPhase::Failed, BodyPhase::Done] {
            assert!(!over.is_streaming());
            for event in [
                BodyEvent::Data(1),
                BodyEvent::Failure(StreamFailure::Interrupted),
                BodyEvent::End,
            ] {
                assert_eq!(over.on_event(event, u64::MAX), Err(BodyOver));
            }
        }
    }
}
