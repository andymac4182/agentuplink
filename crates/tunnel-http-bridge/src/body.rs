//! A bounded streaming HTTP body fed by a pump.
//!
//! The body ends cleanly only when the pump calls [`BodySender::finish`],
//! which it does after the direction's END and FIN.  A dropped sender or a
//! [`BodySender::fail`] yields an error frame, so truncation can never look
//! like a successful end.

use core::fmt;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tunnel_http_forward::HttpErrorCode;

use crate::stream::QueueStats;

/// A body stream error.  It carries only the sanitized code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BodyError {
    code: HttpErrorCode,
}

impl BodyError {
    #[must_use]
    pub const fn code(&self) -> HttpErrorCode {
        self.code
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "http-forward body failed: {}", self.code)
    }
}

impl std::error::Error for BodyError {}

#[derive(Clone, Copy, Debug)]
enum Terminal {
    End,
    Error(HttpErrorCode),
}

#[derive(Debug, Default)]
struct Shared {
    terminal: OnceLock<Terminal>,
    stats: Arc<QueueStats>,
}

/// The pump's half.
pub struct BodySender {
    tx: mpsc::Sender<Bytes>,
    shared: Arc<Shared>,
}

/// The receiver dropped the body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyClosed;

impl BodySender {
    /// Deliver one chunk, waiting for queue capacity.
    ///
    /// # Errors
    /// [`BodyClosed`] when the body was dropped.
    pub async fn send(&self, data: Bytes) -> Result<(), BodyClosed> {
        let len = data.len();
        // Charged before the send so the reader never releases bytes that
        // were not yet counted.
        self.shared.stats.add(len);
        self.tx.send(data).await.map_err(|_| {
            self.shared.stats.sub(len);
            BodyClosed
        })
    }

    /// End the body successfully after already queued chunks.
    pub fn finish(self) {
        let _ = self.shared.terminal.set(Terminal::End);
    }

    /// Fail the body; the error is visible on the next poll.
    pub fn fail(self, code: HttpErrorCode) {
        let _ = self.shared.terminal.set(Terminal::Error(code));
    }
}

impl fmt::Debug for BodySender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BodySender")
            .field(
                "queued_chunks",
                &(self.tx.max_capacity() - self.tx.capacity()),
            )
            .finish()
    }
}

/// Whether a body can still yield frames.  The queue exists only while it
/// can.
enum Reading {
    Streaming(mpsc::Receiver<Bytes>),
    /// The terminal frame (a clean end or the error) was returned.
    Done,
}

/// What the pump left behind once its queue closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ending {
    Clean,
    Error(HttpErrorCode),
}

impl Reading {
    /// The only place a body's reading phase changes: the queue closed with
    /// `terminal` recorded by the pump.  A queue that closed with nothing
    /// recorded was dropped, which is never a successful end.
    fn close(&mut self, terminal: Option<Terminal>) -> Option<Ending> {
        match std::mem::replace(self, Self::Done) {
            Self::Done => None,
            Self::Streaming(_) => Some(match terminal {
                Some(Terminal::End) => Ending::Clean,
                Some(Terminal::Error(code)) => Ending::Error(code),
                None => Ending::Error(HttpErrorCode::StreamInterrupted),
            }),
        }
    }
}

/// A streaming body backed by a bounded queue.  `Debug` prints no bytes.
pub struct ChannelBody {
    reading: Reading,
    shared: Arc<Shared>,
    length: Option<u64>,
    /// Octets handed to the reader so far.
    delivered: u64,
    on_drop: Option<CancellationToken>,
}

impl ChannelBody {
    /// A body of `queue` chunks.  `length` is the checked exact length, if
    /// declared.  `on_drop` is cancelled if the body is dropped before the
    /// pump ends or fails it.
    #[must_use]
    pub fn channel(
        queue: usize,
        length: Option<u64>,
        on_drop: Option<CancellationToken>,
    ) -> (BodySender, Self) {
        let (tx, rx) = mpsc::channel(queue.max(1));
        let shared = Arc::new(Shared::default());
        let sender = BodySender {
            tx,
            shared: Arc::clone(&shared),
        };
        let body = Self {
            reading: Reading::Streaming(rx),
            shared,
            length,
            delivered: 0,
            on_drop,
        };
        (sender, body)
    }

    /// Byte accounting for chunks queued between the pump and this body's
    /// reader: the current occupancy and its high-water mark.
    #[must_use]
    pub fn stats(&self) -> Arc<QueueStats> {
        Arc::clone(&self.shared.stats)
    }

    /// A complete body of known bytes.
    #[must_use]
    pub fn full(data: Bytes) -> Self {
        let length = data.len() as u64;
        let (sender, body) = Self::channel(1, Some(length), None);
        if !data.is_empty() {
            // A fresh one-slot queue always has room.
            sender.shared.stats.add(data.len());
            let _ = sender.tx.try_send(data);
        }
        sender.finish();
        body
    }
}

impl fmt::Debug for ChannelBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelBody")
            .field(
                "queued_chunks",
                &match &self.reading {
                    Reading::Streaming(rx) => rx.len(),
                    Reading::Done => 0,
                },
            )
            .field("length", &self.length)
            .field("done", &self.is_end_stream())
            .finish()
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        // Chunks queued before a failure were received in order and are
        // delivered first; the queue is bounded, so the error follows
        // promptly.  `fail` drops the sender, which closes the queue.
        let Reading::Streaming(rx) = &mut this.reading else {
            return Poll::Ready(None);
        };
        match rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(data)) => {
                this.shared.stats.sub(data.len());
                this.delivered = this.delivered.saturating_add(data.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(None) => {
                let terminal = this.shared.terminal.get().copied();
                match this.reading.close(terminal) {
                    None | Some(Ending::Clean) => Poll::Ready(None),
                    Some(Ending::Error(code)) => Poll::Ready(Some(Err(BodyError { code }))),
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.reading, Reading::Done)
    }

    fn size_hint(&self) -> SizeHint {
        self.length
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

impl Drop for ChannelBody {
    /// Dropping an unfinished body cancels the exchange, except when the
    /// reader already took every octet of a declared length: an HTTP server
    /// stops polling at the declared length, before END and FIN arrive, and
    /// that is not the consumer going away.  The exchange then completes (or
    /// fails) on its own END and FIN, which the owner's response pump bounds
    /// with the FIN-after-END budget from the last declared byte.
    fn drop(&mut self) {
        let fully_delivered = self.length == Some(self.delivered);
        if self.shared.terminal.get().is_none()
            && !fully_delivered
            && let Some(token) = &self.on_drop
        {
            token.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn dropping_a_fully_delivered_declared_body_is_not_a_cancellation() {
        let token = CancellationToken::new();
        let (sender, mut body) = ChannelBody::channel(2, Some(3), Some(token.clone()));
        sender.send(Bytes::from_static(b"abc")).await.expect("send");
        let frame = body.frame().await.expect("frame").expect("data");
        assert_eq!(frame.into_data().expect("data").as_ref(), b"abc");
        // The server stops at the declared length before END and FIN.
        drop(body);
        assert!(!token.is_cancelled());
        drop(sender);

        let token = CancellationToken::new();
        let (sender, mut body) = ChannelBody::channel(2, Some(6), Some(token.clone()));
        sender.send(Bytes::from_static(b"abc")).await.expect("send");
        let _ = body.frame().await;
        drop(body);
        assert!(token.is_cancelled(), "a short read is a consumer departure");
        drop(sender);

        let token = CancellationToken::new();
        let (_sender, body) = ChannelBody::channel(2, None, Some(token.clone()));
        drop(body);
        assert!(token.is_cancelled(), "an unknown length ends only at FIN");
    }

    #[test]
    fn a_closed_queue_ends_reading_once_with_what_the_pump_recorded() {
        let code = HttpErrorCode::BodyLimit;
        for (terminal, ending) in [
            (Some(Terminal::End), Ending::Clean),
            (Some(Terminal::Error(code)), Ending::Error(code)),
            (None, Ending::Error(HttpErrorCode::StreamInterrupted)),
        ] {
            let (_tx, rx) = mpsc::channel(1);
            let mut reading = Reading::Streaming(rx);
            assert_eq!(reading.close(terminal), Some(ending));
            assert!(matches!(reading, Reading::Done));
            // Done is final: a second close reports nothing.
            assert_eq!(reading.close(terminal), None);
            assert!(matches!(reading, Reading::Done));
        }
    }

    #[tokio::test]
    async fn a_body_yields_its_terminal_frame_once() {
        let (sender, mut body) = ChannelBody::channel(2, None, None);
        sender.send(Bytes::from_static(b"abc")).await.expect("send");
        sender.fail(HttpErrorCode::Cancelled);
        assert!(body.frame().await.expect("frame").is_ok());
        assert!(!body.is_end_stream());
        let error = body.frame().await.expect("frame").expect_err("failure");
        assert_eq!(error.code(), HttpErrorCode::Cancelled);
        assert!(body.is_end_stream());
        assert!(body.frame().await.is_none());

        let (sender, mut body) = ChannelBody::channel(2, None, None);
        drop(sender);
        let error = body.frame().await.expect("frame").expect_err("dropped");
        assert_eq!(error.code(), HttpErrorCode::StreamInterrupted);
        assert!(body.frame().await.is_none());
    }
}
