//! Terminal state of one M2 stream's two directions, as the connector actor
//! tracks it.
//!
//! These states are not a copy of `tunnel_protocol::sequence::DirectionState`'s
//! `send_terminal`/`receive_terminal`.  The sequence layer records what was
//! *sequenced* (and keeps only the last terminal: a RESET after a FIN replaces
//! it).  The actor additionally needs
//!
//! * for the request direction, whether the FIN was *dispatched to the
//!   adapter* (later than its receipt while authorization is unconfirmed) and
//!   whether the direction was reset by a peer RESET or an owner `CANCEL`,
//!   which is not a sequenced frame at all;
//! * for the response direction, that a RESET was admitted to the actor or
//!   its deferred queue but not yet sequenced, and that a FIN preceded the
//!   RESET.
//!
//! ```text
//! request (owner -> connector)
//!   Open --Fin--> Fin --Reset--> Reset{fin_dispatched: true}
//!   Open --Reset--> Reset{fin_dispatched: false} --Fin--> Reset{fin_dispatched: true}
//!
//! response (connector -> owner)
//!   Open --QueueReset--> ResetQueued{after_fin: false} --ResetSequenced--> Reset{after_fin: false}
//!   Open --FinSequenced--> Fin
//!   Fin --QueueReset (raw bidirectional stream only)--> ResetQueued{after_fin: true}
//!   ResetQueued{after_fin: false} --FinSequenced--> ResetQueued{after_fin: true}
//!   ResetQueued{after_fin} --ResetSequenced--> Reset{after_fin}
//!   ResetQueued{after_fin} --ResetUnqueued--> Open | Fin
//! ```
//!
//! A FIN followed by a RESET is legal in both directions (`docs/protocol.md`:
//! a RESET may follow a FIN solely to reset the stream), so "FIN and RESET"
//! is a real state, carried as data of the reset variants.  What cannot be
//! represented any more is a RESET that is at once queued and sequenced.

/// The request direction (owner to connector) as seen by the adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputState {
    /// Neither a dispatched FIN nor a reset.
    Open,
    /// The request FIN was dispatched to the adapter.
    Fin,
    /// A peer RESET or an owner `CANCEL` ended the direction.
    /// `fin_dispatched` records that the FIN was dispatched as well, before
    /// or (from the pre-authorization buffer) after the reset.
    Reset { fin_dispatched: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputEvent {
    /// The request FIN is dispatched to the adapter.
    Fin,
    /// A peer RESET was received in order, or an owner `CANCEL` matched.
    Reset,
}

impl InputState {
    /// The only writer of the request-direction state.  Both events latch:
    /// every transition is legal, and the return value says whether the state
    /// changed (a repeated event is a no-op).
    pub(super) fn transition(&mut self, event: InputEvent) -> bool {
        let next = match (*self, event) {
            (Self::Open, InputEvent::Fin) => Self::Fin,
            (Self::Open, InputEvent::Reset) => Self::Reset {
                fin_dispatched: false,
            },
            (Self::Fin, InputEvent::Fin) => Self::Fin,
            (Self::Fin, InputEvent::Reset) | (Self::Reset { .. }, InputEvent::Fin) => Self::Reset {
                fin_dispatched: true,
            },
            (Self::Reset { fin_dispatched }, InputEvent::Reset) => Self::Reset { fin_dispatched },
        };
        let changed = next != *self;
        *self = next;
        changed
    }

    /// The request FIN was dispatched to the adapter.
    pub(super) const fn fin(self) -> bool {
        matches!(
            self,
            Self::Fin
                | Self::Reset {
                    fin_dispatched: true
                }
        )
    }

    /// The request direction was reset.
    pub(super) const fn reset(self) -> bool {
        matches!(self, Self::Reset { .. })
    }
}

/// The response direction (connector to owner).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutputState {
    /// No terminal frame is sequenced or queued.
    Open,
    /// The connector's FIN is sequenced.
    Fin,
    /// A RESET is admitted to the actor or its deferred queue but has no
    /// sequence yet.  This makes repeated CANCEL/auth-expiry paths idempotent
    /// before the terminal frame reaches the active carrier.
    ResetQueued { after_fin: bool },
    /// The connector's RESET is sequenced.
    Reset { after_fin: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutputEvent {
    /// The connector's FIN was accepted by the sequence layer.
    FinSequenced,
    /// A RESET is about to be emitted or deferred.  `may_follow_fin` is true
    /// only for a raw bidirectional (HTTP or filesystem) stream, whose
    /// response may complete before its upload is aborted.
    QueueReset { may_follow_fin: bool },
    /// The queued RESET could be neither emitted nor deferred.
    ResetUnqueued,
    /// The queued RESET was accepted by the sequence layer.
    ResetSequenced,
}

/// The response-direction event does not apply in the current state; the
/// state is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalOutputTransition {
    pub(super) from: OutputState,
    pub(super) event: OutputEvent,
}

impl OutputState {
    /// The only writer of the response-direction state.
    pub(super) fn transition(&mut self, event: OutputEvent) -> Result<(), IllegalOutputTransition> {
        let next = match (*self, event) {
            (Self::Open, OutputEvent::FinSequenced) => Self::Fin,
            (Self::ResetQueued { after_fin: false }, OutputEvent::FinSequenced) => {
                Self::ResetQueued { after_fin: true }
            }
            (Self::Open, OutputEvent::QueueReset { .. }) => Self::ResetQueued { after_fin: false },
            (
                Self::Fin,
                OutputEvent::QueueReset {
                    may_follow_fin: true,
                },
            ) => Self::ResetQueued { after_fin: true },
            (Self::ResetQueued { after_fin: false }, OutputEvent::ResetUnqueued) => Self::Open,
            (Self::ResetQueued { after_fin: true }, OutputEvent::ResetUnqueued) => Self::Fin,
            (Self::ResetQueued { after_fin }, OutputEvent::ResetSequenced) => {
                Self::Reset { after_fin }
            }
            (from, event) => return Err(IllegalOutputTransition { from, event }),
        };
        *self = next;
        Ok(())
    }

    /// The connector's FIN is sequenced.
    pub(super) const fn fin(self) -> bool {
        matches!(
            self,
            Self::Fin | Self::ResetQueued { after_fin: true } | Self::Reset { after_fin: true }
        )
    }

    /// The connector's RESET is sequenced.
    pub(super) const fn reset(self) -> bool {
        matches!(self, Self::Reset { .. })
    }

    /// A RESET is queued and not yet sequenced.
    pub(super) const fn reset_queued(self) -> bool {
        matches!(self, Self::ResetQueued { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT_STATES: [InputState; 4] = [
        InputState::Open,
        InputState::Fin,
        InputState::Reset {
            fin_dispatched: false,
        },
        InputState::Reset {
            fin_dispatched: true,
        },
    ];

    const OUTPUT_STATES: [OutputState; 6] = [
        OutputState::Open,
        OutputState::Fin,
        OutputState::ResetQueued { after_fin: false },
        OutputState::ResetQueued { after_fin: true },
        OutputState::Reset { after_fin: false },
        OutputState::Reset { after_fin: true },
    ];

    const OUTPUT_EVENTS: [OutputEvent; 5] = [
        OutputEvent::FinSequenced,
        OutputEvent::QueueReset {
            may_follow_fin: false,
        },
        OutputEvent::QueueReset {
            may_follow_fin: true,
        },
        OutputEvent::ResetUnqueued,
        OutputEvent::ResetSequenced,
    ];

    #[test]
    fn input_transition_table_latches_exactly_like_two_flags() {
        // The previous representation was two independently latched flags.
        for from in INPUT_STATES {
            for event in [InputEvent::Fin, InputEvent::Reset] {
                let mut state = from;
                let changed = state.transition(event);
                let expected = (
                    from.fin() || event == InputEvent::Fin,
                    from.reset() || event == InputEvent::Reset,
                );
                assert_eq!((state.fin(), state.reset()), expected, "{from:?} {event:?}");
                assert_eq!(changed, state != from, "{from:?} {event:?}");
            }
        }
        let mut state = InputState::Open;
        assert!(state.transition(InputEvent::Fin));
        assert_eq!(state, InputState::Fin);
        assert!(!state.transition(InputEvent::Fin));
        assert!(state.transition(InputEvent::Reset));
        assert_eq!(
            state,
            InputState::Reset {
                fin_dispatched: true
            }
        );
        assert!(!state.transition(InputEvent::Reset));
        assert!(!state.transition(InputEvent::Fin));

        let mut state = InputState::Open;
        assert!(state.transition(InputEvent::Reset));
        assert_eq!(
            state,
            InputState::Reset {
                fin_dispatched: false
            }
        );
        assert!(state.transition(InputEvent::Fin));
        assert!(state.fin() && state.reset());
    }

    #[test]
    fn input_flags_are_exact_per_state() {
        let flags = INPUT_STATES.map(|state| (state.fin(), state.reset()));
        assert_eq!(
            flags,
            [(false, false), (true, false), (false, true), (true, true)]
        );
    }

    #[test]
    fn output_flags_are_exact_per_state() {
        let flags = OUTPUT_STATES.map(|state| (state.fin(), state.reset(), state.reset_queued()));
        assert_eq!(
            flags,
            [
                (false, false, false),
                (true, false, false),
                (false, false, true),
                (true, false, true),
                (false, true, false),
                (true, true, false),
            ]
        );
    }

    #[test]
    fn output_transition_table_is_exact() {
        use OutputEvent::{FinSequenced, QueueReset, ResetSequenced, ResetUnqueued};
        use OutputState::{Fin, Open, Reset, ResetQueued};
        let raw = QueueReset {
            may_follow_fin: true,
        };
        let finite = QueueReset {
            may_follow_fin: false,
        };
        let legal = [
            (Open, FinSequenced, Fin),
            (Open, finite, ResetQueued { after_fin: false }),
            (Open, raw, ResetQueued { after_fin: false }),
            (Fin, raw, ResetQueued { after_fin: true }),
            (
                ResetQueued { after_fin: false },
                FinSequenced,
                ResetQueued { after_fin: true },
            ),
            (ResetQueued { after_fin: false }, ResetUnqueued, Open),
            (ResetQueued { after_fin: true }, ResetUnqueued, Fin),
            (
                ResetQueued { after_fin: false },
                ResetSequenced,
                Reset { after_fin: false },
            ),
            (
                ResetQueued { after_fin: true },
                ResetSequenced,
                Reset { after_fin: true },
            ),
        ];
        for from in OUTPUT_STATES {
            for event in OUTPUT_EVENTS {
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
                            Err(IllegalOutputTransition { from, event }),
                            "{from:?} {event:?}"
                        );
                        assert_eq!(state, from, "a refused event changes nothing");
                    }
                }
            }
        }
    }

    #[test]
    fn output_refuses_the_named_illegal_moves() {
        // A finite stream's RESET never follows its FIN.
        let mut state = OutputState::Fin;
        assert!(
            state
                .transition(OutputEvent::QueueReset {
                    may_follow_fin: false
                })
                .is_err()
        );
        // A second RESET is never queued, before or after the first is sequenced.
        for mut state in [
            OutputState::ResetQueued { after_fin: false },
            OutputState::Reset { after_fin: false },
            OutputState::Reset { after_fin: true },
        ] {
            assert!(
                state
                    .transition(OutputEvent::QueueReset {
                        may_follow_fin: true
                    })
                    .is_err()
            );
        }
        // Nothing is sequenced after a RESET, and a FIN is sequenced once.
        for mut state in [OutputState::Fin, OutputState::Reset { after_fin: false }] {
            assert!(state.transition(OutputEvent::FinSequenced).is_err());
            assert!(state.transition(OutputEvent::ResetSequenced).is_err());
            assert!(state.transition(OutputEvent::ResetUnqueued).is_err());
        }
    }
}
