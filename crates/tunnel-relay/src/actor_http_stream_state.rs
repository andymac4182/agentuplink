//! The explicit half-close state of one owner HTTP stream.
//!
//! An `http-forward/1` stream is two independent half-closes plus a few
//! once-only latches.  Each is an enum here with one transition function, and
//! that function is the only writer; `actor_http_stream.rs` reads the state
//! through the accessors and never assigns it.
//!
//! * [`ReceiveHalf`]: the connector→owner direction as the reader sees it.
//! * [`SendHalf`]: the owner→connector direction, which is two tracks that the
//!   code really does move independently -- what the owner *asked for*
//!   ([`SendIntent`]) and what actually *reached the sequence*
//!   ([`SendWire`]) -- plus the sticky "a RESET waited behind a rotation
//!   freeze" latch.  They are not one linear machine: a terminal reply to the
//!   peer is sequenced without any local request, a close of an already
//!   completed stream can sequence a FIN after a local RESET was requested,
//!   and the freeze latch stays set after the deferred RESET is sequenced
//!   (the owner-stream record reports both).
//! * [`OnceLatch`]: a flag that is set at most once and never cleared.

use tunnel_protocol::Terminal;

/// A flag that is set once and never cleared.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct OnceLatch(bool);

impl OnceLatch {
    /// Set the latch.  Returns whether this call set it.
    pub(super) const fn set(&mut self) -> bool {
        let first = !self.0;
        self.0 = true;
        first
    }

    pub(super) const fn is_set(self) -> bool {
        self.0
    }
}

/// The connector→owner direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum ReceiveHalf {
    /// Neither FIN nor RESET arrived.
    #[default]
    Open,
    /// The connector's FIN arrived; the reader has not been told yet (bytes
    /// buffered ahead of it are delivered first).
    FinBuffered,
    /// The reader was told of the FIN, once.
    FinDelivered,
    /// A RESET ended the direction.  The first reason is kept.
    /// `fin_received` records whether the connector's FIN was also seen: a
    /// RESET may follow a FIN in sequence order, and a RESET the owner
    /// synthesised for an authorization failure does not stop a FIN that was
    /// already in flight from being accepted afterwards.
    Reset { reason: u16, fin_received: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReceiveEvent {
    /// The connector's FIN was accepted in order.
    Fin,
    /// A RESET with this reason was accepted.
    Reset(u16),
    /// The buffered FIN is being handed to the reader.
    DeliverFin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalReceiveTransition {
    pub(super) state: ReceiveHalf,
    pub(super) event: ReceiveEvent,
}

impl ReceiveHalf {
    /// The only place the receive half changes.  A refused event leaves the
    /// state exactly as it was.
    pub(super) const fn on_event(
        self,
        event: ReceiveEvent,
    ) -> Result<Self, IllegalReceiveTransition> {
        match (self, event) {
            (Self::Open, ReceiveEvent::Fin) => Ok(Self::FinBuffered),
            (
                Self::Reset {
                    reason,
                    fin_received: false,
                },
                ReceiveEvent::Fin,
            ) => Ok(Self::Reset {
                reason,
                fin_received: true,
            }),
            (Self::Open, ReceiveEvent::Reset(reason)) => Ok(Self::Reset {
                reason,
                fin_received: false,
            }),
            (Self::FinBuffered | Self::FinDelivered, ReceiveEvent::Reset(reason)) => {
                Ok(Self::Reset {
                    reason,
                    fin_received: true,
                })
            }
            (Self::FinBuffered, ReceiveEvent::DeliverFin) => Ok(Self::FinDelivered),
            // A repeated FIN, a second RESET (the first reason wins) and a FIN
            // delivery with no undelivered FIN change nothing.
            (state, event) => Err(IllegalReceiveTransition { state, event }),
        }
    }

    /// Apply `event`; returns whether the state changed.
    pub(super) fn apply(&mut self, event: ReceiveEvent) -> bool {
        match self.on_event(event) {
            Ok(next) => {
                *self = next;
                true
            }
            Err(_) => false,
        }
    }

    /// The connector's FIN was received (whether or not a RESET also was).
    pub(super) const fn fin_received(self) -> bool {
        matches!(
            self,
            Self::FinBuffered
                | Self::FinDelivered
                | Self::Reset {
                    fin_received: true,
                    ..
                }
        )
    }

    /// The reason of the RESET that ended this direction.
    pub(super) const fn reset(self) -> Option<u16> {
        match self {
            Self::Reset { reason, .. } => Some(reason),
            Self::Open | Self::FinBuffered | Self::FinDelivered => None,
        }
    }

    /// The connector finished or reset its direction.
    pub(super) const fn ended(self) -> bool {
        !matches!(self, Self::Open)
    }
}

/// What the owner asked for on its own direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum SendIntent {
    #[default]
    Open,
    /// The owner requested its FIN.
    FinRequested,
    /// The owner reset the stream locally.  The first reason is kept;
    /// `after_fin` records that a FIN had been requested before it.
    ResetRequested { reason: u16, after_fin: bool },
}

/// Which owner terminal actually entered the relay→connector sequence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum SendWire {
    #[default]
    Unsequenced,
    FinSequenced,
    /// The first sequenced RESET, with the generation it was sequenced on.
    /// `fin_sequenced` records that a FIN was sequenced as well.
    ResetSequenced {
        sequence: u64,
        generation: u64,
        fin_sequenced: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SendEvent {
    /// The owner requests its FIN.
    RequestFin,
    /// The owner resets the stream locally with this reason.
    RequestReset(u16),
    /// An owner terminal was sequenced on `generation`.
    TerminalSequenced {
        terminal: Terminal,
        sequence: u64,
        generation: u64,
    },
    /// A RESET was held behind the rotation freeze.
    ResetDeferredByFreeze,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalSendTransition {
    pub(super) state: SendHalf,
    pub(super) event: SendEvent,
}

/// The owner→connector direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct SendHalf {
    intent: SendIntent,
    wire: SendWire,
    reset_deferred_by_freeze: OnceLatch,
}

impl SendHalf {
    /// The only place the send half changes.  A refused event leaves the
    /// state exactly as it was.
    pub(super) const fn on_event(self, event: SendEvent) -> Result<Self, IllegalSendTransition> {
        let refused = Err(IllegalSendTransition { state: self, event });
        let mut next = self;
        match event {
            SendEvent::RequestFin => match self.intent {
                SendIntent::Open => next.intent = SendIntent::FinRequested,
                SendIntent::FinRequested | SendIntent::ResetRequested { .. } => return refused,
            },
            SendEvent::RequestReset(reason) => match self.intent {
                SendIntent::Open => {
                    next.intent = SendIntent::ResetRequested {
                        reason,
                        after_fin: false,
                    };
                }
                SendIntent::FinRequested => {
                    next.intent = SendIntent::ResetRequested {
                        reason,
                        after_fin: true,
                    };
                }
                // The first reason wins.
                SendIntent::ResetRequested { .. } => return refused,
            },
            SendEvent::TerminalSequenced {
                terminal: Terminal::Fin,
                ..
            } => match self.wire {
                SendWire::Unsequenced => next.wire = SendWire::FinSequenced,
                SendWire::ResetSequenced {
                    sequence,
                    generation,
                    fin_sequenced: false,
                } => {
                    next.wire = SendWire::ResetSequenced {
                        sequence,
                        generation,
                        fin_sequenced: true,
                    };
                }
                SendWire::FinSequenced
                | SendWire::ResetSequenced {
                    fin_sequenced: true,
                    ..
                } => return refused,
            },
            SendEvent::TerminalSequenced {
                terminal: Terminal::Reset(_),
                sequence,
                generation,
            } => match self.wire {
                SendWire::Unsequenced => {
                    next.wire = SendWire::ResetSequenced {
                        sequence,
                        generation,
                        fin_sequenced: false,
                    };
                }
                SendWire::FinSequenced => {
                    next.wire = SendWire::ResetSequenced {
                        sequence,
                        generation,
                        fin_sequenced: true,
                    };
                }
                // The first sequenced RESET keeps its position.
                SendWire::ResetSequenced { .. } => return refused,
            },
            SendEvent::ResetDeferredByFreeze => {
                if !next.reset_deferred_by_freeze.set() {
                    return refused;
                }
            }
        }
        Ok(next)
    }

    /// Apply `event`; returns whether the state changed.
    pub(super) fn apply(&mut self, event: SendEvent) -> bool {
        match self.on_event(event) {
            Ok(next) => {
                *self = next;
                true
            }
            Err(_) => false,
        }
    }

    /// The owner requested its FIN (a later local RESET does not undo that).
    pub(super) const fn fin_requested(self) -> bool {
        matches!(
            self.intent,
            SendIntent::FinRequested
                | SendIntent::ResetRequested {
                    after_fin: true,
                    ..
                }
        )
    }

    /// The reason the owner reset the stream locally with.
    pub(super) const fn reset_requested(self) -> Option<u16> {
        match self.intent {
            SendIntent::ResetRequested { reason, .. } => Some(reason),
            SendIntent::Open | SendIntent::FinRequested => None,
        }
    }

    /// The owner requested a FIN or a RESET.
    pub(super) const fn terminal_requested(self) -> bool {
        !matches!(self.intent, SendIntent::Open)
    }

    pub(super) const fn fin_sequenced(self) -> bool {
        matches!(
            self.wire,
            SendWire::FinSequenced
                | SendWire::ResetSequenced {
                    fin_sequenced: true,
                    ..
                }
        )
    }

    /// `(sequence, generation)` of the first sequenced RESET.
    pub(super) const fn reset_sequence(self) -> Option<(u64, u64)> {
        match self.wire {
            SendWire::ResetSequenced {
                sequence,
                generation,
                ..
            } => Some((sequence, generation)),
            SendWire::Unsequenced | SendWire::FinSequenced => None,
        }
    }

    pub(super) const fn reset_deferred_by_freeze(self) -> bool {
        self.reset_deferred_by_freeze.is_set()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESET_A: u16 = 3;
    const RESET_B: u16 = 4;

    fn receive_states() -> Vec<ReceiveHalf> {
        vec![
            ReceiveHalf::Open,
            ReceiveHalf::FinBuffered,
            ReceiveHalf::FinDelivered,
            ReceiveHalf::Reset {
                reason: RESET_A,
                fin_received: false,
            },
            ReceiveHalf::Reset {
                reason: RESET_A,
                fin_received: true,
            },
        ]
    }

    #[test]
    fn once_latch_sets_once_and_never_clears() {
        let mut latch = OnceLatch::default();
        assert!(!latch.is_set());
        assert!(latch.set(), "the first set is reported");
        assert!(latch.is_set());
        assert!(!latch.set(), "a repeat is not");
        assert!(latch.is_set());
    }

    #[test]
    fn receive_half_transition_table() {
        use ReceiveEvent::{DeliverFin, Fin, Reset};
        use ReceiveHalf::{FinBuffered, FinDelivered, Open};
        let reset = |reason, fin_received| ReceiveHalf::Reset {
            reason,
            fin_received,
        };
        // Every (state, event) pair: `Some(next)` is legal, `None` refused.
        let table: [(ReceiveHalf, ReceiveEvent, Option<ReceiveHalf>); 15] = [
            (Open, Fin, Some(FinBuffered)),
            (Open, Reset(RESET_B), Some(reset(RESET_B, false))),
            (Open, DeliverFin, None),
            (FinBuffered, Fin, None),
            (FinBuffered, Reset(RESET_B), Some(reset(RESET_B, true))),
            (FinBuffered, DeliverFin, Some(FinDelivered)),
            (FinDelivered, Fin, None),
            (FinDelivered, Reset(RESET_B), Some(reset(RESET_B, true))),
            (FinDelivered, DeliverFin, None),
            // A FIN already in flight is still recorded after a RESET.
            (reset(RESET_A, false), Fin, Some(reset(RESET_A, true))),
            // The first RESET reason wins.
            (reset(RESET_A, false), Reset(RESET_B), None),
            (reset(RESET_A, false), DeliverFin, None),
            (reset(RESET_A, true), Fin, None),
            (reset(RESET_A, true), Reset(RESET_B), None),
            (reset(RESET_A, true), DeliverFin, None),
        ];
        assert_eq!(table.len(), receive_states().len() * 3);
        for (state, event, expected) in table {
            let outcome = state.on_event(event);
            match expected {
                Some(next) => assert_eq!(outcome, Ok(next), "{state:?} on {event:?}"),
                None => assert_eq!(
                    outcome,
                    Err(IllegalReceiveTransition { state, event }),
                    "{state:?} on {event:?}"
                ),
            }
            let mut applied = state;
            assert_eq!(applied.apply(event), expected.is_some());
            assert_eq!(
                applied,
                expected.unwrap_or(state),
                "a refusal changes nothing"
            );
        }
    }

    #[test]
    fn receive_half_accessors_match_the_flags_they_replaced() {
        // (state, peer_fin, peer_reset)
        let expected = [
            (false, None),
            (true, None),
            (true, None),
            (false, Some(RESET_A)),
            (true, Some(RESET_A)),
        ];
        for (state, (fin, reset)) in receive_states().into_iter().zip(expected) {
            assert_eq!(state.fin_received(), fin, "{state:?}");
            assert_eq!(state.reset(), reset, "{state:?}");
            assert_eq!(state.ended(), fin || reset.is_some(), "{state:?}");
        }
    }

    fn sequenced(terminal: Terminal, sequence: u64, generation: u64) -> SendEvent {
        SendEvent::TerminalSequenced {
            terminal,
            sequence,
            generation,
        }
    }

    fn send_through(events: &[SendEvent]) -> SendHalf {
        let mut state = SendHalf::default();
        for event in events {
            assert!(state.apply(*event), "{event:?} refused in {state:?}");
        }
        state
    }

    #[test]
    fn send_intent_transition_table() {
        let open = SendHalf::default();
        let fin = send_through(&[SendEvent::RequestFin]);
        let reset = send_through(&[SendEvent::RequestReset(RESET_A)]);
        let reset_after_fin =
            send_through(&[SendEvent::RequestFin, SendEvent::RequestReset(RESET_A)]);
        assert_eq!(fin.intent, SendIntent::FinRequested);
        assert_eq!(
            reset.intent,
            SendIntent::ResetRequested {
                reason: RESET_A,
                after_fin: false
            }
        );
        assert_eq!(
            reset_after_fin.intent,
            SendIntent::ResetRequested {
                reason: RESET_A,
                after_fin: true
            }
        );
        // (state, fin_requested, reset_requested)
        for (state, fin_requested, reset_requested) in [
            (open, false, None),
            (fin, true, None),
            (reset, false, Some(RESET_A)),
            (reset_after_fin, true, Some(RESET_A)),
        ] {
            assert_eq!(state.fin_requested(), fin_requested, "{state:?}");
            assert_eq!(state.reset_requested(), reset_requested, "{state:?}");
            assert_eq!(
                state.terminal_requested(),
                fin_requested || reset_requested.is_some()
            );
            // The intent never touches the wire track or the latch.
            assert_eq!(state.wire, SendWire::Unsequenced);
            assert!(!state.reset_deferred_by_freeze());
        }
        // Refused: a second FIN request, a FIN after a RESET, a second RESET.
        for (state, event) in [
            (fin, SendEvent::RequestFin),
            (reset, SendEvent::RequestFin),
            (reset_after_fin, SendEvent::RequestFin),
            (reset, SendEvent::RequestReset(RESET_B)),
            (reset_after_fin, SendEvent::RequestReset(RESET_B)),
        ] {
            assert_eq!(
                state.on_event(event),
                Err(IllegalSendTransition { state, event }),
                "{state:?} on {event:?}"
            );
            let mut applied = state;
            assert!(!applied.apply(event));
            assert_eq!(applied, state, "a refusal changes nothing");
        }
    }

    #[test]
    fn send_wire_transition_table() {
        let fin_event = sequenced(Terminal::Fin, 4, 1);
        let reset_event = sequenced(Terminal::Reset(RESET_A), 5, 2);
        let later_reset = sequenced(Terminal::Reset(RESET_B), 6, 3);

        let unsequenced = SendHalf::default();
        let fin = send_through(&[fin_event]);
        let reset = send_through(&[reset_event]);
        let reset_after_fin = send_through(&[fin_event, reset_event]);
        let fin_after_reset = send_through(&[reset_event, fin_event]);
        assert_eq!(fin.wire, SendWire::FinSequenced);
        assert_eq!(
            reset.wire,
            SendWire::ResetSequenced {
                sequence: 5,
                generation: 2,
                fin_sequenced: false
            }
        );
        assert_eq!(
            reset_after_fin.wire,
            SendWire::ResetSequenced {
                sequence: 5,
                generation: 2,
                fin_sequenced: true
            }
        );
        assert_eq!(fin_after_reset, reset_after_fin);
        for (state, fin_sequenced, reset_sequence) in [
            (unsequenced, false, None),
            (fin, true, None),
            (reset, false, Some((5, 2))),
            (reset_after_fin, true, Some((5, 2))),
        ] {
            assert_eq!(state.fin_sequenced(), fin_sequenced, "{state:?}");
            assert_eq!(state.reset_sequence(), reset_sequence, "{state:?}");
            // Sequencing never invents a local request.
            assert_eq!(state.intent, SendIntent::Open);
            assert!(!state.terminal_requested());
        }
        // Refused: a repeated FIN, and any RESET after the first keeps the
        // first position.
        for (state, event) in [
            (fin, fin_event),
            (reset_after_fin, fin_event),
            (reset, later_reset),
            (reset_after_fin, later_reset),
        ] {
            assert_eq!(
                state.on_event(event),
                Err(IllegalSendTransition { state, event }),
                "{state:?} on {event:?}"
            );
        }
    }

    #[test]
    fn the_freeze_latch_is_independent_and_survives_sequencing() {
        let mut state = send_through(&[
            SendEvent::RequestReset(RESET_A),
            SendEvent::ResetDeferredByFreeze,
        ]);
        assert!(state.reset_deferred_by_freeze());
        assert_eq!(state.reset_sequence(), None);
        // The deferred RESET is sequenced after the freeze: both stay visible.
        assert!(state.apply(sequenced(Terminal::Reset(RESET_A), 9, 4)));
        assert!(state.reset_deferred_by_freeze());
        assert_eq!(state.reset_sequence(), Some((9, 4)));
        // Once only.
        let before = state;
        assert_eq!(
            state.on_event(SendEvent::ResetDeferredByFreeze),
            Err(IllegalSendTransition {
                state: before,
                event: SendEvent::ResetDeferredByFreeze
            })
        );
        assert!(!state.apply(SendEvent::ResetDeferredByFreeze));
        assert_eq!(state, before);
        // The latch can be set with no local request recorded (a deferred
        // RESET the close path chose): it changes nothing else.
        let bare = send_through(&[SendEvent::ResetDeferredByFreeze]);
        assert!(bare.reset_deferred_by_freeze());
        assert_eq!(bare.intent, SendIntent::Open);
        assert_eq!(bare.wire, SendWire::Unsequenced);
    }
}
