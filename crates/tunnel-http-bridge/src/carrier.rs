//! Carrying one exchange over a real logical tunnel stream (implementation
//! gate 3).
//!
//! [`owner::forward`](crate::owner::forward) and
//! [`device::serve`](crate::device::serve) are unchanged from gate 2: they
//! still talk to a bounded [`stream::channel`](crate::stream::channel).  A
//! real carrier (the relay's owner actor, a peer HTTP/3 request stream, or
//! the connector's device actor) implements [`CarrierWriter`] and
//! [`CarrierReader`], and [`pump_outbound`] / [`pump_inbound`] move frames
//! between that carrier and the channel.  The channel is then a *handoff*
//! of at most [`HANDOFF_CAPACITY`] bytes: one DATA frame.  Every hop keeps
//! its own credit authoritative; a pump holds at most one frame outside the
//! handoff.
//!
//! Resets cross the boundary with the protocol's shared numeric reason code
//! ([`reset_reason_for`]) plus bounded `RESULT_STATUS` detail
//! ([`result_outcome`], [`detail_from_status`]); there is no private numeric
//! extension to RESET.

use std::future::Future;

use bytes::Bytes;
use tunnel_http_forward::HttpErrorCode;
use tunnel_protocol::reset_reason;

use crate::status::{Execution, ResetDetail};
use crate::stream::{Frame, FrameReceiver, FrameSender, ResetSignal, SignaledReset};

/// The handoff capacity between a carrier pump and the bridge: one maximum
/// DATA payload, so a record head always fits one queue item.
pub const HANDOFF_CAPACITY: usize = 64 * 1024;

/// The carrier is gone (socket, peer stream, or actor registration lost).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CarrierClosed;

/// One ordered event read from a carrier.
#[derive(Clone, Eq, PartialEq)]
pub enum CarrierEvent {
    Data(Bytes),
    Fin,
    Reset(ResetDetail),
    /// The carrier ended without FIN or RESET.
    Closed,
}

impl core::fmt::Debug for CarrierEvent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Data(data) => formatter
                .debug_struct("Data")
                .field("payload_len", &data.len())
                .finish(),
            Self::Fin => formatter.write_str("Fin"),
            Self::Reset(detail) => formatter.debug_tuple("Reset").field(detail).finish(),
            Self::Closed => formatter.write_str("Closed"),
        }
    }
}

/// The sending half of a real carrier.
pub trait CarrierWriter: Send + 'static {
    /// Send DATA in order, resolving once the carrier accepted the whole
    /// chunk under its own credit.  The pump drops this future when the
    /// bridge resets before FIN; the writer must then still accept
    /// [`CarrierWriter::reset`] and must never emit a partial chunk.
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send;

    /// Send FIN after every accepted DATA chunk.
    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send;

    /// Send RESET (at most once) after every accepted DATA chunk.
    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send;
}

/// The receiving half of a real carrier.
pub trait CarrierReader: Send + 'static {
    /// The next ordered event.
    fn next(&mut self) -> impl Future<Output = CarrierEvent> + Send;

    /// A signal that resolves as soon as the carrier knows of a peer RESET,
    /// possibly before its ordered delivery (standing in for scoped control
    /// cancellation).  A carrier with no such knowledge returns a signal that
    /// never resolves.
    fn reset_signal(&self) -> ResetSignal;
}

/// The protocol RESET reason code for a bridge failure.  Cancellation has
/// its own code; every other HTTP forwarding failure is an adapter failure
/// whose detail travels in `RESULT_STATUS`.
#[must_use]
pub const fn reset_reason_for(detail: ResetDetail) -> u16 {
    match detail.code {
        HttpErrorCode::Cancelled => reset_reason::CANCELLED,
        _ => reset_reason::ADAPTER_FAILURE,
    }
}

/// The `RESULT_STATUS` outcome for a bridge failure: `cancelled`, or
/// `outcome_unknown` when the emitter cannot prove whether the handler ran,
/// otherwise `failed`.
#[must_use]
pub const fn result_outcome(detail: ResetDetail) -> &'static str {
    match (detail.code, detail.execution) {
        (HttpErrorCode::Cancelled, _) => "cancelled",
        (_, Execution::Unknown) => "outcome_unknown",
        _ => "failed",
    }
}

/// Rebuild the bridge detail from bounded `RESULT_STATUS` detail tokens.
/// Unknown tokens are rejected rather than guessed.
#[must_use]
pub fn detail_from_status(code: &str, execution: &str) -> Option<ResetDetail> {
    Some(ResetDetail {
        code: HttpErrorCode::parse(code)?,
        execution: Execution::parse(execution)?,
    })
}

/// The detail a receiver can infer from a RESET reason code alone, when no
/// matching `RESULT_STATUS` is available.  Execution is always `unknown`:
/// only the emitter's status can prove more.
#[must_use]
pub const fn detail_from_reason(reason: u16) -> ResetDetail {
    ResetDetail {
        code: if reason == reset_reason::CANCELLED {
            HttpErrorCode::Cancelled
        } else {
            HttpErrorCode::StreamInterrupted
        },
        execution: Execution::Unknown,
    }
}

/// How an outbound pump ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OutboundEnd {
    /// FIN was sent and the bridge released the direction.
    Finished,
    /// RESET was sent.
    Reset(ResetDetail),
    /// The bridge dropped the direction before FIN; RESET was sent.
    Abandoned,
    /// The carrier failed.
    CarrierClosed,
}

enum Step {
    Frame(Option<Frame>),
    ResetBeforeFin(ResetDetail),
}

enum Write {
    Done(Result<(), CarrierClosed>),
    ResetBeforeFin(ResetDetail),
}

/// Move the bridge's outbound frames onto a carrier until the direction is
/// terminal.  A RESET the bridge raises before its FIN preempts an
/// outstanding DATA write, so exhausted carrier credit cannot delay it; a
/// RESET after FIN is sent in order, so a completed direction is never
/// truncated.
pub async fn pump_outbound<W: CarrierWriter>(
    mut from_bridge: FrameReceiver,
    mut writer: W,
) -> OutboundEnd {
    let mut signal = from_bridge.reset_signal();
    let mut fin_sent = false;
    loop {
        let step = if fin_sent {
            Step::Frame(from_bridge.recv().await)
        } else {
            tokio::select! {
                biased;
                detail = signal.wait_before_fin() => Step::ResetBeforeFin(detail),
                frame = from_bridge.recv() => Step::Frame(frame),
            }
        };
        let frame = match step {
            Step::ResetBeforeFin(detail) => {
                writer.reset(detail).await;
                return OutboundEnd::Reset(detail);
            }
            Step::Frame(frame) => frame,
        };
        match frame {
            None if fin_sent => return OutboundEnd::Finished,
            None => {
                writer
                    .reset(ResetDetail {
                        code: HttpErrorCode::StreamInterrupted,
                        execution: Execution::Unknown,
                    })
                    .await;
                return OutboundEnd::Abandoned;
            }
            Some(Frame::Data(data)) => {
                let write = {
                    let pending = writer.data(data);
                    tokio::pin!(pending);
                    tokio::select! {
                        biased;
                        detail = signal.wait_before_fin() => Write::ResetBeforeFin(detail),
                        result = &mut pending => Write::Done(result),
                    }
                };
                match write {
                    Write::Done(Ok(())) => {}
                    Write::Done(Err(CarrierClosed)) => return OutboundEnd::CarrierClosed,
                    Write::ResetBeforeFin(detail) => {
                        writer.reset(detail).await;
                        return OutboundEnd::Reset(detail);
                    }
                }
            }
            Some(Frame::Fin) => {
                if writer.finish().await.is_err() {
                    return OutboundEnd::CarrierClosed;
                }
                fin_sent = true;
            }
            Some(Frame::Reset(detail)) => {
                writer.reset(detail).await;
                return OutboundEnd::Reset(detail);
            }
        }
    }
}

/// How an inbound pump ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InboundEnd {
    /// The peer's FIN was delivered and the bridge released the direction.
    Finished,
    /// The peer's RESET was delivered.
    Reset(ResetDetail),
    /// The carrier ended without FIN or RESET.
    CarrierClosed,
    /// The bridge stopped reading.
    BridgeClosed,
}

enum Delivery {
    Sent(bool),
    Ahead(CarrierEvent),
    Signal(SignaledReset),
}

/// Where an inbound pump is in one carrier direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Inbound {
    /// Neither the carrier's FIN nor an after-FIN RESET signal was seen.
    Streaming,
    /// The carrier's FIN was read (in order, or one event ahead).
    FinSeen,
    /// The carrier signalled a RESET that follows the peer's FIN, before
    /// the pump read that FIN.  The bridge's signal is raised; the signal is
    /// no longer watched.
    ResetSignalled,
    /// Both: the FIN was read and the RESET that follows it was signalled.
    FinSeenResetSignalled,
    /// The pump is over.
    Ended(InboundEnd),
}

/// Everything that can change an [`Inbound`] phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundEvent {
    /// The carrier's out-of-band RESET signal fired.
    Signal(SignaledReset),
    /// The carrier's FIN was read, in order or ahead.
    Fin,
    /// The carrier's RESET was read ahead of a DATA chunk still waiting for
    /// handoff credit.
    ResetAhead(ResetDetail),
    /// The carrier's RESET was reached in order.
    Reset(ResetDetail),
    /// The carrier ended without (further) FIN or RESET.
    Closed,
    /// The bridge stopped reading.
    BridgeClosed,
}

/// What a transition asks the pump to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundEffect {
    /// Carry on with ordered delivery.
    Continue,
    /// Raise the bridge's RESET signal without queuing anything: the RESET
    /// follows the peer's FIN, and the ordered frames still arrive in
    /// sequence.
    RaiseSignal(SignaledReset),
    /// Keep the RESET read ahead and deliver it in order: the direction it
    /// follows is complete and must not be truncated.
    Hold,
    /// Queue RESET to the bridge now; the pump ended with it.
    Reset(ResetDetail),
    /// The pump ended.
    End(InboundEnd),
    /// The event is not legal in this phase; nothing changed.
    Refused,
}

impl Inbound {
    const fn fin_seen(self) -> bool {
        matches!(self, Self::FinSeen | Self::FinSeenResetSignalled)
    }

    /// Whether the carrier's RESET signal is still to be watched.
    const fn watches_signal(self) -> bool {
        matches!(self, Self::Streaming | Self::FinSeen)
    }

    /// The only place an inbound phase changes.
    fn transition(&mut self, event: InboundEvent) -> InboundEffect {
        let (next, effect) = match (*self, event) {
            (Self::Ended(_), _)
            | (Self::ResetSignalled | Self::FinSeenResetSignalled, InboundEvent::Signal(_)) => {
                (*self, InboundEffect::Refused)
            }
            (Self::Streaming, InboundEvent::Signal(reset)) if reset.after_fin => {
                (Self::ResetSignalled, InboundEffect::RaiseSignal(reset))
            }
            (Self::FinSeen, InboundEvent::Signal(reset)) if reset.after_fin => (
                Self::FinSeenResetSignalled,
                InboundEffect::RaiseSignal(reset),
            ),
            // A RESET before the peer's FIN is terminal at once.
            (Self::Streaming | Self::FinSeen, InboundEvent::Signal(reset)) => (
                Self::Ended(InboundEnd::Reset(reset.detail)),
                InboundEffect::Reset(reset.detail),
            ),
            (Self::Streaming | Self::FinSeen, InboundEvent::Fin) => {
                (Self::FinSeen, InboundEffect::Continue)
            }
            (Self::ResetSignalled | Self::FinSeenResetSignalled, InboundEvent::Fin) => {
                (Self::FinSeenResetSignalled, InboundEffect::Continue)
            }
            (Self::FinSeen | Self::FinSeenResetSignalled, InboundEvent::ResetAhead(_)) => {
                (*self, InboundEffect::Hold)
            }
            (Self::Streaming | Self::ResetSignalled, InboundEvent::ResetAhead(detail))
            | (_, InboundEvent::Reset(detail)) => (
                Self::Ended(InboundEnd::Reset(detail)),
                InboundEffect::Reset(detail),
            ),
            (phase, InboundEvent::Closed) => {
                // Dropping the only sender without FIN or RESET is a carrier
                // failure to the bridge.
                let end = if phase.fin_seen() {
                    InboundEnd::Finished
                } else {
                    InboundEnd::CarrierClosed
                };
                (Self::Ended(end), InboundEffect::End(end))
            }
            (_, InboundEvent::BridgeClosed) => (
                Self::Ended(InboundEnd::BridgeClosed),
                InboundEffect::End(InboundEnd::BridgeClosed),
            ),
        };
        *self = next;
        effect
    }
}

/// Move a carrier's ordered events into the bridge.  While one DATA chunk
/// waits for handoff credit, the pump reads at most one further event
/// ahead, and it also watches the carrier's out-of-band RESET signal, so a
/// peer RESET reaches a stalled bridge promptly.  A RESET known to follow
/// the peer's FIN only raises the bridge's signal; the ordered DATA, FIN and
/// RESET are still delivered in sequence.
pub async fn pump_inbound<R: CarrierReader>(mut reader: R, to_bridge: FrameSender) -> InboundEnd {
    let mut signal = reader.reset_signal();
    let mut phase = Inbound::Streaming;
    // The one event read ahead of a DATA chunk waiting for handoff credit.
    let mut ahead: Option<CarrierEvent> = None;
    loop {
        let event = if let Some(event) = ahead.take() {
            event
        } else {
            let step = tokio::select! {
                biased;
                () = to_bridge.closed() => Wake::Event(InboundEvent::BridgeClosed),
                reset = signal.wait(), if phase.watches_signal() => {
                    Wake::Event(InboundEvent::Signal(reset))
                }
                event = reader.next() => Wake::Read(event),
            };
            match step {
                Wake::Read(event) => event,
                Wake::Event(event) => {
                    if let Some(end) = act(&mut phase, event, &to_bridge) {
                        return end;
                    }
                    continue;
                }
            }
        };
        let ordered = match event {
            CarrierEvent::Data(data) => {
                let send = to_bridge.send_data(data);
                tokio::pin!(send);
                loop {
                    let outcome = tokio::select! {
                        biased;
                        result = &mut send => Delivery::Sent(result.is_ok()),
                        reset = signal.wait(), if phase.watches_signal() => {
                            Delivery::Signal(reset)
                        }
                        event = reader.next(), if ahead.is_none() => Delivery::Ahead(event),
                    };
                    let event = match outcome {
                        Delivery::Sent(true) => break,
                        Delivery::Sent(false) => InboundEvent::BridgeClosed,
                        Delivery::Signal(reset) => InboundEvent::Signal(reset),
                        Delivery::Ahead(CarrierEvent::Reset(detail)) => {
                            match phase.transition(InboundEvent::ResetAhead(detail)) {
                                InboundEffect::Hold => {
                                    ahead = Some(CarrierEvent::Reset(detail));
                                    continue;
                                }
                                effect => {
                                    if let Some(end) = perform(effect, &to_bridge) {
                                        return end;
                                    }
                                    continue;
                                }
                            }
                        }
                        Delivery::Ahead(event) => {
                            if event == CarrierEvent::Fin {
                                phase.transition(InboundEvent::Fin);
                            }
                            ahead = Some(event);
                            continue;
                        }
                    };
                    if let Some(end) = act(&mut phase, event, &to_bridge) {
                        return end;
                    }
                }
                continue;
            }
            CarrierEvent::Fin => {
                phase.transition(InboundEvent::Fin);
                if to_bridge.finish().is_err() {
                    InboundEvent::BridgeClosed
                } else {
                    continue;
                }
            }
            CarrierEvent::Reset(detail) => InboundEvent::Reset(detail),
            CarrierEvent::Closed => InboundEvent::Closed,
        };
        if let Some(end) = act(&mut phase, ordered, &to_bridge) {
            return end;
        }
    }
}

/// One wake-up of the idle pump: a carrier event to deliver in order, or an
/// event that only changes the phase.
enum Wake {
    Read(CarrierEvent),
    Event(InboundEvent),
}

/// Apply `event` and carry out its effect; the pump's end, if it ended.
fn act(phase: &mut Inbound, event: InboundEvent, to_bridge: &FrameSender) -> Option<InboundEnd> {
    perform(phase.transition(event), to_bridge)
}

fn perform(effect: InboundEffect, to_bridge: &FrameSender) -> Option<InboundEnd> {
    match effect {
        InboundEffect::Continue | InboundEffect::Hold | InboundEffect::Refused => None,
        InboundEffect::RaiseSignal(reset) => {
            to_bridge.signal_reset(reset);
            None
        }
        InboundEffect::Reset(detail) => {
            to_bridge.reset(detail);
            Some(InboundEnd::Reset(detail))
        }
        InboundEffect::End(end) => Some(end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DETAIL: ResetDetail = ResetDetail {
        code: HttpErrorCode::Cancelled,
        execution: Execution::Unknown,
    };
    const BEFORE_FIN: SignaledReset = SignaledReset {
        detail: DETAIL,
        after_fin: false,
    };
    const AFTER_FIN: SignaledReset = SignaledReset {
        detail: DETAIL,
        after_fin: true,
    };
    const LIVE: [Inbound; 4] = [
        Inbound::Streaming,
        Inbound::FinSeen,
        Inbound::ResetSignalled,
        Inbound::FinSeenResetSignalled,
    ];
    const RESET: (Inbound, InboundEffect) = (
        Inbound::Ended(InboundEnd::Reset(DETAIL)),
        InboundEffect::Reset(DETAIL),
    );

    fn step(mut phase: Inbound, event: InboundEvent) -> (Inbound, InboundEffect) {
        let effect = phase.transition(event);
        (phase, effect)
    }

    #[test]
    fn a_signal_before_fin_is_terminal_and_one_after_fin_is_only_raised() {
        for phase in [Inbound::Streaming, Inbound::FinSeen] {
            assert!(phase.watches_signal());
            assert_eq!(step(phase, InboundEvent::Signal(BEFORE_FIN)), RESET);
        }
        assert_eq!(
            step(Inbound::Streaming, InboundEvent::Signal(AFTER_FIN)),
            (
                Inbound::ResetSignalled,
                InboundEffect::RaiseSignal(AFTER_FIN)
            )
        );
        assert_eq!(
            step(Inbound::FinSeen, InboundEvent::Signal(AFTER_FIN)),
            (
                Inbound::FinSeenResetSignalled,
                InboundEffect::RaiseSignal(AFTER_FIN)
            )
        );
        // Once signalled, the signal is no longer watched and a second one
        // is refused.
        for phase in [Inbound::ResetSignalled, Inbound::FinSeenResetSignalled] {
            assert!(!phase.watches_signal());
            for reset in [BEFORE_FIN, AFTER_FIN] {
                assert_eq!(
                    step(phase, InboundEvent::Signal(reset)),
                    (phase, InboundEffect::Refused)
                );
            }
        }
    }

    #[test]
    fn fin_is_remembered_in_every_live_phase() {
        for (phase, next) in [
            (Inbound::Streaming, Inbound::FinSeen),
            (Inbound::FinSeen, Inbound::FinSeen),
            (Inbound::ResetSignalled, Inbound::FinSeenResetSignalled),
            (
                Inbound::FinSeenResetSignalled,
                Inbound::FinSeenResetSignalled,
            ),
        ] {
            assert_eq!(
                step(phase, InboundEvent::Fin),
                (next, InboundEffect::Continue)
            );
            assert!(next.fin_seen());
        }
    }

    #[test]
    fn a_reset_read_ahead_truncates_only_an_unfinished_direction() {
        for phase in [Inbound::Streaming, Inbound::ResetSignalled] {
            assert_eq!(step(phase, InboundEvent::ResetAhead(DETAIL)), RESET);
        }
        for phase in [Inbound::FinSeen, Inbound::FinSeenResetSignalled] {
            assert_eq!(
                step(phase, InboundEvent::ResetAhead(DETAIL)),
                (phase, InboundEffect::Hold)
            );
        }
        // Reached in order it always ends the pump.
        for phase in LIVE {
            assert_eq!(step(phase, InboundEvent::Reset(DETAIL)), RESET);
        }
    }

    #[test]
    fn the_carrier_closing_is_a_finish_only_after_fin() {
        for phase in LIVE {
            let end = if phase.fin_seen() {
                InboundEnd::Finished
            } else {
                InboundEnd::CarrierClosed
            };
            assert_eq!(
                step(phase, InboundEvent::Closed),
                (Inbound::Ended(end), InboundEffect::End(end))
            );
            assert_eq!(
                step(phase, InboundEvent::BridgeClosed),
                (
                    Inbound::Ended(InboundEnd::BridgeClosed),
                    InboundEffect::End(InboundEnd::BridgeClosed)
                )
            );
        }
    }

    #[test]
    fn an_ended_pump_refuses_every_event() {
        let ended = Inbound::Ended(InboundEnd::Finished);
        for event in [
            InboundEvent::Signal(BEFORE_FIN),
            InboundEvent::Signal(AFTER_FIN),
            InboundEvent::Fin,
            InboundEvent::ResetAhead(DETAIL),
            InboundEvent::Reset(DETAIL),
            InboundEvent::Closed,
            InboundEvent::BridgeClosed,
        ] {
            assert_eq!(step(ended, event), (ended, InboundEffect::Refused));
        }
    }
}
