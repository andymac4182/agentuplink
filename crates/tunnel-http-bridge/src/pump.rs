//! Streaming a local HTTP body into BODY records under byte credit, and the
//! explicit phase of the opposite hand-off: a receiving pump delivering a
//! decoded direction to its local body ([`Delivery`]).

use std::pin::Pin;

use bytes::Bytes;
use http_body::Body;
use tunnel_http_forward::{
    END_RECORD, HttpErrorCode, MAX_BODY_PAYLOAD_LEN, RecordHeader, RecordKind,
};

use crate::body::BodySender;
use crate::exchange::Exchange;
use crate::progress::{self, BudgetClock, ProgressKind, WaitMark};
use crate::stream::SendError;

/// Why a pump stopped early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PumpError {
    /// The exchange was already stopped by another failure.
    Stopped,
    /// The local body was invalid or failed.
    Source(HttpErrorCode),
    /// The outbound stream is gone.
    Sink(HttpErrorCode),
    /// A transport progress budget expired (`HTTP_DEADLINE_EXCEEDED`).
    Progress(ProgressKind),
}

/// Queue bytes on the exchange's outbound direction, abandoning the wait as
/// soon as the exchange stops.  A send blocked on output credit for longer
/// than the credit-stall budget (not counting this endpoint's recorded
/// freeze) fails; each completed send starts a fresh stall clock.
pub(crate) async fn send(exchange: &Exchange, data: Bytes) -> Result<(), PumpError> {
    let mut stall = BudgetClock::new(ProgressKind::CreditStall, &exchange.budgets);
    stall.arm();
    let mark = WaitMark::now(&exchange.pause);
    tokio::select! {
        biased;
        () = exchange.stopped() => Err(PumpError::Stopped),
        result = exchange.peer.send_data(data) => match result {
            Ok(()) => Ok(()),
            Err(SendError::Terminated) => Err(PumpError::Stopped),
            Err(SendError::Closed) => Err(PumpError::Sink(HttpErrorCode::StreamInterrupted)),
        },
        kind = progress::expired([stall], mark, exchange.pause.clone()) => {
            Err(PumpError::Progress(kind))
        }
    }
}

/// Encode `data` as consecutive BODY records without copying the payload.
async fn send_body_records(exchange: &Exchange, data: Bytes) -> Result<(), PumpError> {
    let mut rest = data;
    while !rest.is_empty() {
        let payload = rest.split_to(rest.len().min(MAX_BODY_PAYLOAD_LEN));
        // Invariant: 1..=MAX_BODY_PAYLOAD_LEN bytes is always a valid BODY.
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let header = RecordHeader::new(RecordKind::Body, len)
            .map_err(|_| PumpError::Source(HttpErrorCode::BadRecord))?;
        send(exchange, Bytes::copy_from_slice(&header.encode())).await?;
        send(exchange, payload).await?;
    }
    Ok(())
}

/// Pump a local body to END and FIN.  One body frame is held at a time, and
/// the next is polled only after the previous one fit the outbound credit.
/// The declared length is checked on every chunk (long) and at the end
/// (short); discovered non-empty trailers fail the direction.
pub(crate) async fn pump_body<B>(
    exchange: &Exchange,
    mut body: Pin<&mut B>,
    declared: Option<u64>,
    limit: u64,
) -> Result<(), PumpError>
where
    B: Body<Data = Bytes>,
{
    let mut sent = 0u64;
    loop {
        let next = tokio::select! {
            biased;
            () = exchange.stopped() => return Err(PumpError::Stopped),
            next = next_frame(body.as_mut()) => next,
        };
        let frame = match next {
            None => break,
            Some(Err(_)) => return Err(PumpError::Source(HttpErrorCode::StreamInterrupted)),
            Some(Ok(frame)) => frame,
        };
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if frame
                    .trailers_ref()
                    .is_some_and(|trailers| !trailers.is_empty())
                {
                    return Err(PumpError::Source(HttpErrorCode::UnsupportedFeature));
                }
                continue;
            }
        };
        if data.is_empty() {
            continue;
        }
        let total = sent
            .checked_add(data.len() as u64)
            .ok_or(PumpError::Source(HttpErrorCode::BodyLimit))?;
        if declared.is_some_and(|declared| total > declared) {
            return Err(PumpError::Source(HttpErrorCode::LengthMismatch));
        }
        if total > limit {
            return Err(PumpError::Source(HttpErrorCode::BodyLimit));
        }
        sent = total;
        send_body_records(exchange, data).await?;
    }
    if declared.is_some_and(|declared| declared != sent) {
        return Err(PumpError::Source(HttpErrorCode::LengthMismatch));
    }
    send(exchange, Bytes::from_static(&END_RECORD)).await?;
    exchange.peer.finish().map_err(|error| match error {
        SendError::Terminated => PumpError::Stopped,
        SendError::Closed => PumpError::Sink(HttpErrorCode::StreamInterrupted),
    })
}

/// Poll one frame, discarding the error value so no body error type (and no
/// message it might carry) is held or reported.
pub(crate) async fn next_frame<B>(
    mut body: Pin<&mut B>,
) -> Option<Result<http_body::Frame<Bytes>, ()>>
where
    B: Body<Data = Bytes>,
{
    std::future::poll_fn(|cx| {
        body.as_mut()
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(drop)))
    })
    .await
}

/// Where a receiving pump is in handing one decoded direction to its local
/// body.  The record reader is the grammar authority (it rejects a second
/// head, a body after END, a FIN before END); this is the hand-off state the
/// pump keeps beside it, and the [`BodySender`] exists only in the phases
/// that can still use it.
#[derive(Debug)]
pub(crate) enum Delivery {
    /// No head yet: there is no body to deliver to.
    AwaitHead,
    /// The head was handed over and body bytes are delivered.  `remaining`
    /// counts the declared octets not yet received, if a length was declared
    /// and this pump tracks it.
    Body {
        sender: BodySender,
        remaining: Option<u64>,
    },
    /// The local reader dropped the body: later body bytes are still
    /// validated by the record reader, then discarded.
    Discarding,
    /// END passed; only the outer FIN may follow.  The sender is kept so the
    /// body ends cleanly only at FIN.
    AwaitFin { sender: Option<BodySender> },
    /// FIN passed and the body, if still held, ended successfully.
    Complete,
    /// The pump stopped early and the body, if still held, was failed.
    Failed,
}

/// Everything that can change a [`Delivery`].
#[derive(Debug)]
pub(crate) enum DeliveryEvent {
    /// The direction's head was decoded and its body channel built.
    Head {
        sender: BodySender,
        declared: Option<u64>,
    },
    /// Body bytes of this length were decoded.
    Body(u64),
    /// The local reader dropped the body.
    ReaderGone,
    /// The END record.
    End,
    /// The outer FIN, accepted by the record reader.
    Fin,
    /// The pump is stopping without FIN.
    Stop(HttpErrorCode),
}

/// What a transition asks the pump to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeliveryEffect {
    /// Nothing further.
    Applied,
    /// Deliver the bytes to [`Delivery::sender`].  `last_declared` is true
    /// when they are (or follow) the last declared octet: only END and FIN
    /// may follow, so the FIN-after-END budget starts.
    Deliver { last_declared: bool },
    /// The bytes have no reader: drop them.
    Discard,
    /// Start the FIN-after-END budget.
    ArmFin,
    /// The event is not legal in this phase; nothing changed.
    Refused,
}

impl Delivery {
    /// The only place a delivery phase changes.
    pub(crate) fn transition(&mut self, event: DeliveryEvent) -> DeliveryEffect {
        let (next, effect) = match (std::mem::replace(self, Self::Failed), event) {
            (Self::AwaitHead, DeliveryEvent::Head { sender, declared }) => (
                Self::Body {
                    sender,
                    remaining: declared,
                },
                if declared == Some(0) {
                    DeliveryEffect::ArmFin
                } else {
                    DeliveryEffect::Applied
                },
            ),
            (Self::Body { sender, remaining }, DeliveryEvent::Body(len)) => {
                let remaining = remaining.map(|remaining| remaining.saturating_sub(len));
                (
                    Self::Body { sender, remaining },
                    DeliveryEffect::Deliver {
                        last_declared: remaining == Some(0),
                    },
                )
            }
            (Self::Discarding, DeliveryEvent::Body(_)) => {
                (Self::Discarding, DeliveryEffect::Discard)
            }
            (Self::Body { .. }, DeliveryEvent::ReaderGone) => {
                (Self::Discarding, DeliveryEffect::Applied)
            }
            (Self::Body { sender, .. }, DeliveryEvent::End) => (
                Self::AwaitFin {
                    sender: Some(sender),
                },
                DeliveryEffect::ArmFin,
            ),
            (Self::Discarding, DeliveryEvent::End) => {
                (Self::AwaitFin { sender: None }, DeliveryEffect::ArmFin)
            }
            (Self::AwaitFin { sender }, DeliveryEvent::Fin) => {
                if let Some(sender) = sender {
                    sender.finish();
                }
                (Self::Complete, DeliveryEffect::Applied)
            }
            // A completed delivery stays complete.
            (Self::Complete, DeliveryEvent::Stop(_)) => (Self::Complete, DeliveryEffect::Refused),
            (phase, DeliveryEvent::Stop(code)) => {
                let already = matches!(phase, Self::Failed);
                if let Self::Body { sender, .. }
                | Self::AwaitFin {
                    sender: Some(sender),
                } = phase
                {
                    sender.fail(code);
                }
                (
                    Self::Failed,
                    if already {
                        DeliveryEffect::Refused
                    } else {
                        DeliveryEffect::Applied
                    },
                )
            }
            // Dropping a refused head drops its body sender, which fails
            // that body.
            (phase, _) => (phase, DeliveryEffect::Refused),
        };
        *self = next;
        effect
    }

    /// The body to deliver to, while one is being fed.
    pub(crate) const fn sender(&self) -> Option<&BodySender> {
        match self {
            Self::Body { sender, .. } => Some(sender),
            _ => None,
        }
    }
}

/// Why a receiving pump left its frame loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Exit {
    /// The peer's RESET or the loss of its carrier was read: nothing more
    /// can arrive.
    PeerTerminated,
    /// This endpoint stopped first; the peer's remaining frames are
    /// discarded up to its own terminal frame.
    Local,
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;
    use crate::body::ChannelBody;

    fn head(declared: Option<u64>) -> (DeliveryEvent, ChannelBody) {
        let (sender, body) = ChannelBody::channel(4, declared, None);
        (DeliveryEvent::Head { sender, declared }, body)
    }

    fn name(phase: &Delivery) -> &'static str {
        match phase {
            Delivery::AwaitHead => "await_head",
            Delivery::Body { .. } => "body",
            Delivery::Discarding => "discarding",
            Delivery::AwaitFin { sender: Some(_) } => "await_fin",
            Delivery::AwaitFin { sender: None } => "await_fin_discarding",
            Delivery::Complete => "complete",
            Delivery::Failed => "failed",
        }
    }

    /// Build each phase by its legal path.
    fn built(target: &str) -> (Delivery, Option<ChannelBody>) {
        let mut phase = Delivery::AwaitHead;
        if target == "await_head" {
            return (phase, None);
        }
        let (event, body) = head(None);
        phase.transition(event);
        let events: &[fn() -> DeliveryEvent] = match target {
            "body" => &[],
            "discarding" => &[|| DeliveryEvent::ReaderGone],
            "await_fin" => &[|| DeliveryEvent::End],
            "await_fin_discarding" => &[|| DeliveryEvent::ReaderGone, || DeliveryEvent::End],
            "complete" => &[|| DeliveryEvent::End, || DeliveryEvent::Fin],
            "failed" => &[|| DeliveryEvent::Stop(HttpErrorCode::Cancelled)],
            other => panic!("unknown phase {other}"),
        };
        for event in events {
            assert_ne!(phase.transition(event()), DeliveryEffect::Refused);
        }
        assert_eq!(name(&phase), target);
        (phase, Some(body))
    }

    const PHASES: [&str; 7] = [
        "await_head",
        "body",
        "discarding",
        "await_fin",
        "await_fin_discarding",
        "complete",
        "failed",
    ];

    #[tokio::test]
    async fn the_legal_path_delivers_and_ends_the_body_at_fin() {
        let mut phase = Delivery::AwaitHead;
        assert!(phase.sender().is_none());
        let (event, body) = head(Some(3));
        assert_eq!(phase.transition(event), DeliveryEffect::Applied);
        assert_eq!(
            phase.transition(DeliveryEvent::Body(2)),
            DeliveryEffect::Deliver {
                last_declared: false
            }
        );
        assert_eq!(
            phase.transition(DeliveryEvent::Body(1)),
            DeliveryEffect::Deliver {
                last_declared: true
            }
        );
        let sender = phase.sender().expect("a body is being fed");
        sender.send(Bytes::from_static(b"abc")).await.expect("send");
        assert_eq!(phase.transition(DeliveryEvent::End), DeliveryEffect::ArmFin);
        assert!(phase.sender().is_none(), "nothing is delivered after END");
        assert_eq!(
            phase.transition(DeliveryEvent::Fin),
            DeliveryEffect::Applied
        );
        assert_eq!(name(&phase), "complete");
        let collected = body.collect().await.expect("a clean end").to_bytes();
        assert_eq!(collected.as_ref(), b"abc");
    }

    #[test]
    fn a_declared_empty_body_starts_the_fin_budget_at_its_head() {
        let mut phase = Delivery::AwaitHead;
        let (event, _body) = head(Some(0));
        assert_eq!(phase.transition(event), DeliveryEffect::ArmFin);
    }

    #[tokio::test]
    async fn a_dropped_reader_discards_and_still_completes() {
        let (mut phase, _body) = built("discarding");
        assert_eq!(
            phase.transition(DeliveryEvent::Body(9)),
            DeliveryEffect::Discard
        );
        assert!(phase.sender().is_none());
        assert_eq!(phase.transition(DeliveryEvent::End), DeliveryEffect::ArmFin);
        assert_eq!(
            phase.transition(DeliveryEvent::Fin),
            DeliveryEffect::Applied
        );
        assert_eq!(name(&phase), "complete");
    }

    #[tokio::test]
    async fn stopping_fails_a_held_body_and_never_a_completed_one() {
        for start in ["body", "await_fin"] {
            let (mut phase, body) = built(start);
            assert_eq!(
                phase.transition(DeliveryEvent::Stop(HttpErrorCode::BodyLimit)),
                DeliveryEffect::Applied
            );
            assert_eq!(name(&phase), "failed");
            let error = body.expect("body").collect().await.expect_err("failed");
            assert_eq!(error.code(), HttpErrorCode::BodyLimit);
        }
        let (mut phase, body) = built("complete");
        assert_eq!(
            phase.transition(DeliveryEvent::Stop(HttpErrorCode::BodyLimit)),
            DeliveryEffect::Refused
        );
        assert_eq!(name(&phase), "complete");
        assert!(body.expect("body").collect().await.is_ok());
        for start in ["await_head", "discarding", "await_fin_discarding"] {
            let (mut phase, _body) = built(start);
            assert_eq!(
                phase.transition(DeliveryEvent::Stop(HttpErrorCode::BodyLimit)),
                DeliveryEffect::Applied
            );
            assert_eq!(name(&phase), "failed");
        }
    }

    /// Every (phase, event) pair outside the table is refused and leaves the
    /// phase where it was.
    #[tokio::test]
    async fn every_other_event_is_refused() {
        let legal: &[(&str, &str)] = &[
            ("await_head", "head"),
            ("body", "body"),
            ("body", "reader_gone"),
            ("body", "end"),
            ("discarding", "body"),
            ("discarding", "end"),
            ("await_fin", "fin"),
            ("await_fin_discarding", "fin"),
            ("await_head", "stop"),
            ("body", "stop"),
            ("discarding", "stop"),
            ("await_fin", "stop"),
            ("await_fin_discarding", "stop"),
        ];
        for start in PHASES {
            for event in ["head", "body", "reader_gone", "end", "fin", "stop"] {
                let (mut phase, _body) = built(start);
                let (head_event, _head_body) = head(None);
                let effect = phase.transition(match event {
                    "head" => head_event,
                    "body" => DeliveryEvent::Body(1),
                    "reader_gone" => DeliveryEvent::ReaderGone,
                    "end" => DeliveryEvent::End,
                    "fin" => DeliveryEvent::Fin,
                    _ => DeliveryEvent::Stop(HttpErrorCode::Cancelled),
                });
                let refused = effect == DeliveryEffect::Refused;
                assert_eq!(
                    refused,
                    !legal.contains(&(start, event)),
                    "{start} + {event} gave {effect:?}"
                );
                if refused {
                    assert_eq!(name(&phase), start, "{start} + {event}");
                }
            }
        }
    }
}
