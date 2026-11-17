//! The two explicit state machines of a raw bidirectional stream's
//! connector-side state (`DeviceHttpState` in `m2_http`).
//!
//! ```text
//! request side (owner -> handler)
//!   Receiving --Fin--> FinReady --DeliverFin--> FinDelivered
//!   Receiving | FinReady | FinDelivered --Reset(code)--> Reset{code, fin}
//!   Reset{code, fin: NotReceived} --Fin--> Reset{code, fin: Received}
//!
//! response writer
//!   Idle --Park(write)--> Parked(write)
//!   Parked(write) --QueueFinish(finish)--> ParkedFinishQueued(write, finish)
//!   Parked(write) --TakeParked--> Idle                       (yields write)
//!   ParkedFinishQueued(write, finish) --TakeParked--> FinishPending(finish)
//!   FinishPending(finish) --TakeFinish--> Idle               (yields finish)
//!   any --Abort--> Idle                        (yields whatever was held)
//! ```
//!
//! A reset keeps what was known about the request FIN (`fin`), because the
//! exchange record and the failed-exchange log report it after a reset too,
//! and a FIN dispatched after a local reset is still recorded as received.
//! It is never *delivered* after a reset.
//!
//! `FinishPending` is the short interval in which the parked write has been
//! taken for emission and its queued FIN follows it; the stream accepts no
//! new write until that FIN is taken.

use tokio::sync::oneshot;

/// What was known about the request FIN when the stream was reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FinAtReset {
    NotReceived,
    /// Received (before or after the reset) and never delivered.
    Received,
    /// Delivered to the reader before the reset.
    Delivered,
}

/// The request side of one raw stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestState {
    /// Request bytes may still arrive.
    Receiving,
    /// The request FIN arrived; the reader gets it after every buffered chunk.
    FinReady,
    /// The reader was given the request FIN.
    FinDelivered,
    /// A peer or local RESET with this reason code ended the stream.
    Reset { reason: u16, fin: FinAtReset },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestEvent {
    /// The ordered request FIN was dispatched to this stream.
    Fin,
    /// The reader takes the FIN (every buffered chunk was read).
    DeliverFin,
    /// A peer or local RESET with this reason code.
    Reset(u16),
}

/// The request-side event does not apply in the current state; the state is
/// unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalRequestTransition {
    pub(super) from: RequestState,
    pub(super) event: RequestEvent,
}

impl RequestState {
    /// The only writer of the request-side state.
    ///
    /// Refused: a repeated `Fin`, `DeliverFin` unless the FIN is ready and
    /// undelivered, and a second `Reset` (the first reason stays).
    pub(super) fn transition(
        &mut self,
        event: RequestEvent,
    ) -> Result<(), IllegalRequestTransition> {
        let next = match (*self, event) {
            (Self::Receiving, RequestEvent::Fin) => Self::FinReady,
            (
                Self::Reset {
                    reason,
                    fin: FinAtReset::NotReceived,
                },
                RequestEvent::Fin,
            ) => Self::Reset {
                reason,
                fin: FinAtReset::Received,
            },
            (Self::FinReady, RequestEvent::DeliverFin) => Self::FinDelivered,
            (Self::Receiving, RequestEvent::Reset(reason)) => Self::Reset {
                reason,
                fin: FinAtReset::NotReceived,
            },
            (Self::FinReady, RequestEvent::Reset(reason)) => Self::Reset {
                reason,
                fin: FinAtReset::Received,
            },
            (Self::FinDelivered, RequestEvent::Reset(reason)) => Self::Reset {
                reason,
                fin: FinAtReset::Delivered,
            },
            (from, event) => return Err(IllegalRequestTransition { from, event }),
        };
        *self = next;
        Ok(())
    }

    /// The request FIN was received (reported as `request_fin_received` and
    /// `request_fin_ready`).
    pub(super) const fn fin_received(self) -> bool {
        !matches!(
            self,
            Self::Receiving
                | Self::Reset {
                    fin: FinAtReset::NotReceived,
                    ..
                }
        )
    }

    /// The request FIN was delivered to the reader.
    pub(super) const fn fin_delivered(self) -> bool {
        matches!(
            self,
            Self::FinDelivered
                | Self::Reset {
                    fin: FinAtReset::Delivered,
                    ..
                }
        )
    }

    /// The reason code of the RESET that ended the stream.
    pub(super) const fn reset_reason(self) -> Option<u16> {
        match self {
            Self::Reset { reason, .. } => Some(reason),
            Self::Receiving | Self::FinReady | Self::FinDelivered => None,
        }
    }
}

/// One write the actor could not sequence yet, and the handler's reply slot.
pub(super) type ParkedWrite = (Vec<u8>, oneshot::Sender<bool>);

/// The response writer of one raw stream.
#[derive(Debug)]
pub(super) enum WriterState {
    /// Nothing is parked.
    Idle,
    /// One write waits for credit, replay room or a writer thaw.
    Parked(ParkedWrite),
    /// The response FIN waits behind the parked write.
    ParkedFinishQueued(ParkedWrite, oneshot::Sender<bool>),
    /// The parked write was taken for emission; its queued FIN follows.
    FinishPending(oneshot::Sender<bool>),
}

#[derive(Debug)]
pub(super) enum WriterEvent {
    /// Park a write that does not fit now.
    Park(ParkedWrite),
    /// Queue the response FIN behind the parked write.  A FIN already queued
    /// is replaced, and its reply slot dropped.
    QueueFinish(oneshot::Sender<bool>),
    /// The parked write now fits: take it for emission.
    TakeParked,
    /// The taken write was emitted: take the FIN queued behind it.
    TakeFinish,
    /// The stream was reset: give up everything held.
    Abort,
}

/// What a legal writer transition hands back to the actor.
#[derive(Debug)]
pub(super) enum WriterEffect {
    None,
    /// The write to emit.
    Write(ParkedWrite),
    /// The FIN reply to answer once the FIN is emitted.
    Finish(oneshot::Sender<bool>),
    /// The reply slots to fail.
    Aborted {
        write: Option<oneshot::Sender<bool>>,
        finish: Option<oneshot::Sender<bool>>,
    },
}

impl WriterState {
    /// The only writer of the response-writer state.  A refused event is
    /// handed back unchanged (with the reply slot it carries) and the state
    /// is unchanged.
    pub(super) fn transition(&mut self, event: WriterEvent) -> Result<WriterEffect, WriterEvent> {
        let (next, effect) = match (std::mem::replace(self, Self::Idle), event) {
            (Self::Idle, WriterEvent::Park(write)) => (Self::Parked(write), WriterEffect::None),
            (Self::Parked(write), WriterEvent::QueueFinish(finish))
            | (Self::ParkedFinishQueued(write, _), WriterEvent::QueueFinish(finish)) => {
                (Self::ParkedFinishQueued(write, finish), WriterEffect::None)
            }
            (Self::Parked(write), WriterEvent::TakeParked) => {
                (Self::Idle, WriterEffect::Write(write))
            }
            (Self::ParkedFinishQueued(write, finish), WriterEvent::TakeParked) => {
                (Self::FinishPending(finish), WriterEffect::Write(write))
            }
            (Self::FinishPending(finish), WriterEvent::TakeFinish) => {
                (Self::Idle, WriterEffect::Finish(finish))
            }
            (from, WriterEvent::Abort) => {
                let (write, finish) = match from {
                    Self::Idle => (None, None),
                    Self::Parked((_, write)) => (Some(write), None),
                    Self::ParkedFinishQueued((_, write), finish) => (Some(write), Some(finish)),
                    Self::FinishPending(finish) => (None, Some(finish)),
                };
                (Self::Idle, WriterEffect::Aborted { write, finish })
            }
            (from, event) => {
                *self = from;
                return Err(event);
            }
        };
        *self = next;
        Ok(effect)
    }

    /// The parked write's length.
    pub(super) fn parked_len(&self) -> Option<usize> {
        match self {
            Self::Parked((data, _)) | Self::ParkedFinishQueued((data, _), _) => Some(data.len()),
            Self::Idle | Self::FinishPending(_) => None,
        }
    }

    /// A response FIN is queued behind a parked (or just taken) write.
    pub(super) const fn finish_queued(&self) -> bool {
        matches!(self, Self::ParkedFinishQueued(..) | Self::FinishPending(_))
    }

    pub(super) const fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_STATES: [RequestState; 6] = [
        RequestState::Receiving,
        RequestState::FinReady,
        RequestState::FinDelivered,
        RequestState::Reset {
            reason: 7,
            fin: FinAtReset::NotReceived,
        },
        RequestState::Reset {
            reason: 7,
            fin: FinAtReset::Received,
        },
        RequestState::Reset {
            reason: 7,
            fin: FinAtReset::Delivered,
        },
    ];

    #[test]
    fn request_transition_table_is_exact() {
        use RequestEvent::{DeliverFin, Fin, Reset};
        use RequestState::{FinDelivered, FinReady, Receiving};
        let reset = |reason, fin| RequestState::Reset { reason, fin };
        let legal = [
            (Receiving, Fin, FinReady),
            (FinReady, DeliverFin, FinDelivered),
            (Receiving, Reset(9), reset(9, FinAtReset::NotReceived)),
            (FinReady, Reset(9), reset(9, FinAtReset::Received)),
            (FinDelivered, Reset(9), reset(9, FinAtReset::Delivered)),
            (
                reset(7, FinAtReset::NotReceived),
                Fin,
                reset(7, FinAtReset::Received),
            ),
        ];
        for from in REQUEST_STATES {
            for event in [Fin, DeliverFin, Reset(9)] {
                let mut state = from;
                let result = state.transition(event);
                match legal.iter().find(|(legal_from, legal_event, _)| {
                    *legal_from == from && *legal_event == event
                }) {
                    Some((_, _, to)) => {
                        assert_eq!(result, Ok(()), "{from:?} {event:?}");
                        assert_eq!(state, *to, "{from:?} {event:?}");
                    }
                    None => {
                        assert_eq!(
                            result,
                            Err(IllegalRequestTransition { from, event }),
                            "{from:?} {event:?}"
                        );
                        assert_eq!(state, from, "a refused event changes nothing");
                    }
                }
            }
        }
    }

    #[test]
    fn request_flags_are_exact_per_state() {
        let flags = REQUEST_STATES.map(|state| {
            (
                state.fin_received(),
                state.fin_delivered(),
                state.reset_reason(),
            )
        });
        assert_eq!(
            flags,
            [
                (false, false, None),
                (true, false, None),
                (true, true, None),
                (false, false, Some(7)),
                (true, false, Some(7)),
                (true, true, Some(7)),
            ]
        );
    }

    #[test]
    fn request_keeps_the_first_reset_and_never_delivers_a_fin_after_it() {
        let mut state = RequestState::FinReady;
        assert!(state.transition(RequestEvent::Reset(1)).is_ok());
        assert!(state.transition(RequestEvent::Reset(2)).is_err());
        assert_eq!(state.reset_reason(), Some(1));
        assert!(state.transition(RequestEvent::DeliverFin).is_err());
        assert!(!state.fin_delivered());
        // A FIN is delivered once, and only once it is ready.
        let mut state = RequestState::Receiving;
        assert!(state.transition(RequestEvent::DeliverFin).is_err());
        assert!(state.transition(RequestEvent::Fin).is_ok());
        assert!(state.transition(RequestEvent::Fin).is_err());
        assert!(state.transition(RequestEvent::DeliverFin).is_ok());
        assert!(state.transition(RequestEvent::DeliverFin).is_err());
    }

    fn write(len: usize) -> (ParkedWrite, oneshot::Receiver<bool>) {
        let (reply, receiver) = oneshot::channel();
        ((vec![0; len], reply), receiver)
    }

    /// 0 idle, 1 parked, 2 parked with a queued finish, 3 finish pending.
    fn writer(kind: u8) -> WriterState {
        match kind {
            0 => WriterState::Idle,
            1 => WriterState::Parked(write(3).0),
            2 => WriterState::ParkedFinishQueued(write(3).0, oneshot::channel().0),
            _ => WriterState::FinishPending(oneshot::channel().0),
        }
    }

    fn kind(state: &WriterState) -> u8 {
        match state {
            WriterState::Idle => 0,
            WriterState::Parked(_) => 1,
            WriterState::ParkedFinishQueued(..) => 2,
            WriterState::FinishPending(_) => 3,
        }
    }

    /// 0 park, 1 queue finish, 2 take parked, 3 take finish, 4 abort.
    fn event(kind: u8) -> WriterEvent {
        match kind {
            0 => WriterEvent::Park(write(5).0),
            1 => WriterEvent::QueueFinish(oneshot::channel().0),
            2 => WriterEvent::TakeParked,
            3 => WriterEvent::TakeFinish,
            _ => WriterEvent::Abort,
        }
    }

    #[test]
    fn writer_transition_table_is_exact() {
        // (from, event) -> to; every pair not listed is refused.
        let legal: [(u8, u8, u8); 10] = [
            (0, 0, 1),
            (1, 1, 2),
            (2, 1, 2),
            (1, 2, 0),
            (2, 2, 3),
            (3, 3, 0),
            (0, 4, 0),
            (1, 4, 0),
            (2, 4, 0),
            (3, 4, 0),
        ];
        for from in 0..4 {
            for event_kind in 0..5 {
                let mut state = writer(from);
                let result = state.transition(event(event_kind));
                match legal.iter().find(|(legal_from, legal_event, _)| {
                    *legal_from == from && *legal_event == event_kind
                }) {
                    Some((_, _, to)) => {
                        assert!(result.is_ok(), "{from} {event_kind}");
                        assert_eq!(kind(&state), *to, "{from} {event_kind}");
                    }
                    None => {
                        assert!(result.is_err(), "{from} {event_kind}");
                        assert_eq!(kind(&state), from, "a refused event changes nothing");
                    }
                }
            }
        }
    }

    #[test]
    fn writer_effects_carry_exactly_what_the_state_held() {
        let (parked, mut write_rx) = write(4);
        let mut state = WriterState::Idle;
        assert!(matches!(
            state.transition(WriterEvent::Park(parked)),
            Ok(WriterEffect::None)
        ));
        assert_eq!(state.parked_len(), Some(4));
        assert!(!state.finish_queued() && !state.is_idle());
        // A second write is refused and handed back with its reply slot.
        let (second, mut second_rx) = write(9);
        let Err(WriterEvent::Park((data, reply))) = state.transition(WriterEvent::Park(second))
        else {
            panic!("a second parked write is refused");
        };
        assert_eq!(data.len(), 9);
        let _ = reply.send(false);
        assert!(matches!(second_rx.try_recv(), Ok(false)));
        assert_eq!(state.parked_len(), Some(4));

        let (finish, mut finish_rx) = oneshot::channel();
        assert!(matches!(
            state.transition(WriterEvent::QueueFinish(finish)),
            Ok(WriterEffect::None)
        ));
        assert!(state.finish_queued());
        // The FIN cannot be taken ahead of the write.
        assert!(matches!(
            state.transition(WriterEvent::TakeFinish),
            Err(WriterEvent::TakeFinish)
        ));
        let Ok(WriterEffect::Write((data, reply))) = state.transition(WriterEvent::TakeParked)
        else {
            panic!("the parked write is released first");
        };
        assert_eq!(data.len(), 4);
        let _ = reply.send(true);
        assert!(matches!(write_rx.try_recv(), Ok(true)));
        assert_eq!(state.parked_len(), None);
        assert!(state.finish_queued() && !state.is_idle());
        let Ok(WriterEffect::Finish(reply)) = state.transition(WriterEvent::TakeFinish) else {
            panic!("the queued FIN follows the write");
        };
        let _ = reply.send(true);
        assert!(matches!(finish_rx.try_recv(), Ok(true)));
        assert!(state.is_idle());

        // With nothing parked a FIN is not queued: the caller emits it now.
        let (finish, _finish_rx) = oneshot::channel();
        assert!(matches!(
            state.transition(WriterEvent::QueueFinish(finish)),
            Err(WriterEvent::QueueFinish(_))
        ));
        assert!(matches!(
            state.transition(WriterEvent::TakeParked),
            Err(WriterEvent::TakeParked)
        ));
    }

    #[test]
    fn writer_abort_yields_every_held_reply_slot() {
        let held = |kind| match writer(kind).transition(WriterEvent::Abort) {
            Ok(WriterEffect::Aborted { write, finish }) => (write.is_some(), finish.is_some()),
            other => panic!("abort is always legal: {other:?}"),
        };
        assert_eq!(held(0), (false, false));
        assert_eq!(held(1), (true, false));
        assert_eq!(held(2), (true, true));
        assert_eq!(held(3), (false, true));
    }
}
