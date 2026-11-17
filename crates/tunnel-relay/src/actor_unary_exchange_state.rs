//! The explicit state of one unary echo exchange on the owner.
//!
//! Two machines, because the code moves them independently:
//!
//! * [`UnaryExchange`]: the relay's own side -- authorization, a result held
//!   across a rotation freeze, dispatch, and abandonment (task rows M6-C207,
//!   M7-C93, M7-C94).  `on_event` is the only place it changes.
//! * [`UnaryConnector`]: what the connector has proved about its side -- that
//!   it admitted the OPEN, and that its own terminal was received.  Those
//!   facts arrive in any relay state, before or after an abandonment.
//!
//! An exchange leaves the pending table (completed, or retired into a
//! tombstone) by being removed, so there is no terminal state here.
//!
//! The machine is generic over the held authorization result so that its
//! transition table can be tested with a plain value.

use std::time::Instant;

use super::FreezeAuthorization;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UnaryExchange<H> {
    /// No authorization challenge has been accepted for this OPEN.
    AwaitingChallenge,
    /// The connector's challenge was accepted and its authorization read is
    /// in flight.  The payload records whether a result was held by a freeze
    /// and, if so, whether it has been read again since.
    Authorizing(FreezeAuthorization),
    /// An authorization result arrived while the relay writer was frozen for
    /// a rotation and waits for the writer to resume.  `reread` is set when a
    /// fresh read was started while this result was still held.
    HeldByFreeze { held: H, reread: bool },
    /// DATA and FIN are queued: the device may have run the request.
    /// `abandoned_at` is set when the consumer was answered by another exit
    /// afterwards.
    Dispatched { abandoned_at: Option<Instant> },
    /// The consumer was answered before dispatch; nothing is delivered any
    /// more.  `relay_reset` records that the relay ended its own direction
    /// with RESET at sequence 1 instead of dispatching DATA and FIN.
    Abandoned { at: Instant, relay_reset: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UnaryEvent<H> {
    /// The connector's matching authorization challenge was accepted.
    ChallengeAccepted,
    /// The authorization result arrived while the writer was frozen.
    ResultHeldByFreeze(H),
    /// The writer resumed: the held result is taken to be applied again.
    HeldResultTaken,
    /// The held result went stale across the freeze; the catalog is read
    /// again.
    RereadStarted,
    /// DATA and FIN were queued.
    Dispatched,
    /// The consumer was answered by an exit other than completion.
    Abandoned { at: Instant },
    /// The relay's RESET for an abandoned, undispatched exchange was queued.
    RelayReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalUnaryTransition<H> {
    pub(super) state: UnaryExchange<H>,
    pub(super) event: UnaryEvent<H>,
}

impl<H> UnaryExchange<H> {
    /// The only place the exchange state changes.  Returns the next state
    /// and, for [`UnaryEvent::HeldResultTaken`], the result that was held.
    /// A refused event hands the state back unchanged.
    pub(super) fn on_event(
        self,
        event: UnaryEvent<H>,
    ) -> Result<(Self, Option<H>), IllegalUnaryTransition<H>> {
        match (self, event) {
            (Self::AwaitingChallenge, UnaryEvent::ChallengeAccepted) => {
                Ok((Self::Authorizing(FreezeAuthorization::NotHeld), None))
            }
            // Holding a result always records `Held`, also for a result that
            // was itself a re-read.
            (Self::Authorizing(_), UnaryEvent::ResultHeldByFreeze(held)) => Ok((
                Self::HeldByFreeze {
                    held,
                    reread: false,
                },
                None,
            )),
            (Self::HeldByFreeze { held, reread }, UnaryEvent::HeldResultTaken) => Ok((
                Self::Authorizing(if reread {
                    FreezeAuthorization::Reread
                } else {
                    FreezeAuthorization::Held
                }),
                Some(held),
            )),
            (Self::Authorizing(FreezeAuthorization::Held), UnaryEvent::RereadStarted) => {
                Ok((Self::Authorizing(FreezeAuthorization::Reread), None))
            }
            (
                Self::HeldByFreeze {
                    held,
                    reread: false,
                },
                UnaryEvent::RereadStarted,
            ) => Ok((Self::HeldByFreeze { held, reread: true }, None)),
            (Self::Authorizing(_) | Self::HeldByFreeze { .. }, UnaryEvent::Dispatched) => {
                Ok((Self::Dispatched { abandoned_at: None }, None))
            }
            // Abandoning drops a held result: nothing is delivered any more.
            (
                Self::AwaitingChallenge | Self::Authorizing(_) | Self::HeldByFreeze { .. },
                UnaryEvent::Abandoned { at },
            ) => Ok((
                Self::Abandoned {
                    at,
                    relay_reset: false,
                },
                None,
            )),
            (Self::Dispatched { abandoned_at: None }, UnaryEvent::Abandoned { at }) => Ok((
                Self::Dispatched {
                    abandoned_at: Some(at),
                },
                None,
            )),
            (
                Self::Abandoned {
                    at,
                    relay_reset: false,
                },
                UnaryEvent::RelayReset,
            ) => Ok((
                Self::Abandoned {
                    at,
                    relay_reset: true,
                },
                None,
            )),
            (state, event) => Err(IllegalUnaryTransition { state, event }),
        }
    }

    /// Apply `event` in place.  `Ok` carries the held result a
    /// [`UnaryEvent::HeldResultTaken`] released; `Err` means the event was
    /// refused and the state is exactly as it was.
    pub(super) fn apply(&mut self, event: UnaryEvent<H>) -> Result<Option<H>, UnaryEvent<H>> {
        let state = std::mem::replace(self, Self::AwaitingChallenge);
        match state.on_event(event) {
            Ok((next, released)) => {
                *self = next;
                Ok(released)
            }
            Err(IllegalUnaryTransition { state, event }) => {
                *self = state;
                Err(event)
            }
        }
    }

    /// DATA and FIN are queued.
    pub(super) const fn dispatched(&self) -> bool {
        matches!(self, Self::Dispatched { .. })
    }

    /// An accepted challenge's authorization has not been applied yet.
    pub(super) const fn authorization_in_flight(&self) -> bool {
        matches!(self, Self::Authorizing(_) | Self::HeldByFreeze { .. })
    }

    /// Whether this exchange's authorization result was held by a freeze.
    pub(super) const fn freeze_authorization(&self) -> FreezeAuthorization {
        match self {
            Self::Authorizing(freeze) => *freeze,
            Self::HeldByFreeze { reread: false, .. } => FreezeAuthorization::Held,
            Self::HeldByFreeze { reread: true, .. } => FreezeAuthorization::Reread,
            Self::AwaitingChallenge | Self::Dispatched { .. } | Self::Abandoned { .. } => {
                FreezeAuthorization::NotHeld
            }
        }
    }

    /// When the consumer was answered by an exit other than completion.
    pub(super) const fn abandoned_at(&self) -> Option<Instant> {
        match self {
            Self::Dispatched { abandoned_at } => *abandoned_at,
            Self::Abandoned { at, .. } => Some(*at),
            Self::AwaitingChallenge | Self::Authorizing(_) | Self::HeldByFreeze { .. } => None,
        }
    }

    /// The consumer has its outcome; nothing is delivered any more.
    pub(super) const fn abandoned(&self) -> bool {
        self.abandoned_at().is_some()
    }

    /// The relay ended its own direction with RESET instead of dispatching.
    pub(super) const fn relay_reset(&self) -> bool {
        matches!(
            self,
            Self::Abandoned {
                relay_reset: true,
                ..
            }
        )
    }

    /// Test fixtures only: the same abandoned state, abandoned at `at`.
    /// Returns whether the exchange was abandoned (and so re-dated).
    #[cfg(test)]
    pub(super) fn backdate_abandonment(&mut self, at: Instant) -> bool {
        match self {
            Self::Dispatched {
                abandoned_at: Some(abandoned_at),
            } => *abandoned_at = at,
            Self::Abandoned {
                at: abandoned_at, ..
            } => *abandoned_at = at,
            _ => return false,
        }
        true
    }
}

/// What the connector has proved about its side of a unary exchange.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum UnaryConnector {
    /// Nothing shows the connector admitted the OPEN.
    #[default]
    NotAdmitted,
    /// The connector admitted the OPEN (its OPENED or its authorization
    /// challenge was seen), so it holds a stream the relay must end.
    Admitted,
    /// The connector's own terminal (FIN or RESET) was received in sequence
    /// and acknowledged, which also proves admission.
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UnaryConnectorEvent {
    Admitted,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalUnaryConnectorTransition {
    pub(super) state: UnaryConnector,
    pub(super) event: UnaryConnectorEvent,
}

impl UnaryConnector {
    /// The only place the connector state changes.
    pub(super) const fn on_event(
        self,
        event: UnaryConnectorEvent,
    ) -> Result<Self, IllegalUnaryConnectorTransition> {
        match (self, event) {
            (Self::NotAdmitted, UnaryConnectorEvent::Admitted) => Ok(Self::Admitted),
            (Self::NotAdmitted | Self::Admitted, UnaryConnectorEvent::Terminal) => {
                Ok(Self::Terminal)
            }
            // A repeated proof changes nothing.
            (state, event) => Err(IllegalUnaryConnectorTransition { state, event }),
        }
    }

    /// Apply `event`; returns whether the state changed.
    pub(super) fn apply(&mut self, event: UnaryConnectorEvent) -> bool {
        match self.on_event(event) {
            Ok(next) => {
                *self = next;
                true
            }
            Err(_) => false,
        }
    }

    pub(super) const fn admitted(self) -> bool {
        matches!(self, Self::Admitted | Self::Terminal)
    }

    pub(super) const fn terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    type Exchange = UnaryExchange<u8>;
    type Event = UnaryEvent<u8>;

    const HELD: u8 = 7;
    const OTHER: u8 = 9;

    fn states(at: Instant) -> Vec<Exchange> {
        vec![
            Exchange::AwaitingChallenge,
            Exchange::Authorizing(FreezeAuthorization::NotHeld),
            Exchange::Authorizing(FreezeAuthorization::Held),
            Exchange::Authorizing(FreezeAuthorization::Reread),
            Exchange::HeldByFreeze {
                held: HELD,
                reread: false,
            },
            Exchange::HeldByFreeze {
                held: HELD,
                reread: true,
            },
            Exchange::Dispatched { abandoned_at: None },
            Exchange::Dispatched {
                abandoned_at: Some(at),
            },
            Exchange::Abandoned {
                at,
                relay_reset: false,
            },
            Exchange::Abandoned {
                at,
                relay_reset: true,
            },
        ]
    }

    fn events(later: Instant) -> Vec<Event> {
        vec![
            Event::ChallengeAccepted,
            Event::ResultHeldByFreeze(OTHER),
            Event::HeldResultTaken,
            Event::RereadStarted,
            Event::Dispatched,
            Event::Abandoned { at: later },
            Event::RelayReset,
        ]
    }

    /// The whole legal table; every pair not listed must be refused.
    fn expected(state: Exchange, event: Event) -> Option<(Exchange, Option<u8>)> {
        use FreezeAuthorization::{Held, NotHeld, Reread};
        Some(match (state, event) {
            (Exchange::AwaitingChallenge, Event::ChallengeAccepted) => {
                (Exchange::Authorizing(NotHeld), None)
            }
            (Exchange::Authorizing(_), Event::ResultHeldByFreeze(held)) => (
                Exchange::HeldByFreeze {
                    held,
                    reread: false,
                },
                None,
            ),
            (
                Exchange::HeldByFreeze {
                    held,
                    reread: false,
                },
                Event::HeldResultTaken,
            ) => (Exchange::Authorizing(Held), Some(held)),
            (Exchange::HeldByFreeze { held, reread: true }, Event::HeldResultTaken) => {
                (Exchange::Authorizing(Reread), Some(held))
            }
            (Exchange::Authorizing(Held), Event::RereadStarted) => {
                (Exchange::Authorizing(Reread), None)
            }
            (
                Exchange::HeldByFreeze {
                    held,
                    reread: false,
                },
                Event::RereadStarted,
            ) => (Exchange::HeldByFreeze { held, reread: true }, None),
            (Exchange::Authorizing(_) | Exchange::HeldByFreeze { .. }, Event::Dispatched) => {
                (Exchange::Dispatched { abandoned_at: None }, None)
            }
            (
                Exchange::AwaitingChallenge
                | Exchange::Authorizing(_)
                | Exchange::HeldByFreeze { .. },
                Event::Abandoned { at },
            ) => (
                Exchange::Abandoned {
                    at,
                    relay_reset: false,
                },
                None,
            ),
            (Exchange::Dispatched { abandoned_at: None }, Event::Abandoned { at }) => (
                Exchange::Dispatched {
                    abandoned_at: Some(at),
                },
                None,
            ),
            (
                Exchange::Abandoned {
                    at,
                    relay_reset: false,
                },
                Event::RelayReset,
            ) => (
                Exchange::Abandoned {
                    at,
                    relay_reset: true,
                },
                None,
            ),
            _ => return None,
        })
    }

    #[test]
    fn unary_exchange_transition_table() {
        let at = Instant::now();
        let later = at + Duration::from_secs(5);
        let mut legal = 0;
        let mut refused = 0;
        for state in states(at) {
            for event in events(later) {
                let outcome = state.on_event(event);
                let mut applied = state;
                let applied_outcome = applied.apply(event);
                if let Some((next, released)) = expected(state, event) {
                    legal += 1;
                    assert_eq!(outcome, Ok((next, released)), "{state:?} on {event:?}");
                    assert_eq!(applied_outcome, Ok(released));
                    assert_eq!(applied, next);
                } else {
                    refused += 1;
                    assert_eq!(
                        outcome,
                        Err(IllegalUnaryTransition { state, event }),
                        "{state:?} on {event:?}"
                    );
                    assert_eq!(applied_outcome, Err(event));
                    assert_eq!(applied, state, "a refusal changes nothing");
                }
            }
        }
        assert_eq!((legal, refused), (21, 49));
    }

    #[test]
    fn the_refusals_that_used_to_be_hand_kept_flag_pairs() {
        let at = Instant::now();
        let refused = |state: Exchange, event: Event| {
            assert_eq!(
                state.on_event(event),
                Err(IllegalUnaryTransition { state, event }),
                "{state:?} on {event:?}"
            );
        };
        // A second challenge is ignored while one is in flight or after
        // dispatch, and an abandoned exchange is never authorized.
        for state in states(at).into_iter().skip(1) {
            refused(state, Event::ChallengeAccepted);
        }
        // Dispatch needs an authorization in flight.
        refused(Exchange::AwaitingChallenge, Event::Dispatched);
        refused(
            Exchange::Abandoned {
                at,
                relay_reset: false,
            },
            Event::Dispatched,
        );
        // A relay RESET and a dispatch exclude each other.
        refused(
            Exchange::Abandoned {
                at,
                relay_reset: true,
            },
            Event::Dispatched,
        );
        refused(
            Exchange::Dispatched { abandoned_at: None },
            Event::RelayReset,
        );
        refused(
            Exchange::Dispatched {
                abandoned_at: Some(at),
            },
            Event::RelayReset,
        );
        // The first held result is kept; abandonment is recorded once.
        refused(
            Exchange::HeldByFreeze {
                held: HELD,
                reread: false,
            },
            Event::ResultHeldByFreeze(OTHER),
        );
        refused(
            Exchange::Abandoned {
                at,
                relay_reset: false,
            },
            Event::Abandoned { at },
        );
        refused(
            Exchange::Dispatched {
                abandoned_at: Some(at),
            },
            Event::Abandoned { at },
        );
    }

    #[test]
    fn accessors_match_the_flags_they_replaced() {
        use FreezeAuthorization::{Held, NotHeld, Reread};
        let at = Instant::now();
        // (dispatched, authorization_in_flight, freeze, abandoned, relay_reset)
        let expected = [
            (false, false, NotHeld, false, false),
            (false, true, NotHeld, false, false),
            (false, true, Held, false, false),
            (false, true, Reread, false, false),
            (false, true, Held, false, false),
            (false, true, Reread, false, false),
            (true, false, NotHeld, false, false),
            (true, false, NotHeld, true, false),
            (false, false, NotHeld, true, false),
            (false, false, NotHeld, true, true),
        ];
        for (state, (dispatched, in_flight, freeze, abandoned, relay_reset)) in
            states(at).into_iter().zip(expected)
        {
            assert_eq!(state.dispatched(), dispatched, "{state:?}");
            assert_eq!(state.authorization_in_flight(), in_flight, "{state:?}");
            assert_eq!(state.freeze_authorization(), freeze, "{state:?}");
            assert_eq!(state.abandoned(), abandoned, "{state:?}");
            assert_eq!(state.abandoned_at(), abandoned.then_some(at), "{state:?}");
            assert_eq!(state.relay_reset(), relay_reset, "{state:?}");
        }
    }

    #[test]
    fn backdating_only_re_dates_an_abandoned_exchange() {
        let at = Instant::now();
        let earlier = at.checked_sub(Duration::from_millis(1)).unwrap_or(at);
        for mut state in states(at) {
            let abandoned = state.abandoned();
            let before = state;
            assert_eq!(state.backdate_abandonment(earlier), abandoned);
            if abandoned {
                assert_eq!(state.abandoned_at(), Some(earlier));
                assert_eq!(state.relay_reset(), before.relay_reset());
                assert_eq!(state.dispatched(), before.dispatched());
            } else {
                assert_eq!(state, before);
            }
        }
    }

    #[test]
    fn unary_connector_transition_table() {
        use UnaryConnector::{Admitted, NotAdmitted, Terminal};
        use UnaryConnectorEvent as Event;
        let table = [
            (NotAdmitted, Event::Admitted, Some(Admitted)),
            (NotAdmitted, Event::Terminal, Some(Terminal)),
            (Admitted, Event::Admitted, None),
            (Admitted, Event::Terminal, Some(Terminal)),
            (Terminal, Event::Admitted, None),
            (Terminal, Event::Terminal, None),
        ];
        for (state, event, expected) in table {
            let outcome = state.on_event(event);
            match expected {
                Some(next) => assert_eq!(outcome, Ok(next), "{state:?} on {event:?}"),
                None => assert_eq!(
                    outcome,
                    Err(IllegalUnaryConnectorTransition { state, event }),
                    "{state:?} on {event:?}"
                ),
            }
            let mut applied = state;
            assert_eq!(applied.apply(event), expected.is_some());
            assert_eq!(applied, expected.unwrap_or(state));
        }
        // (admitted, connector_terminal)
        for (state, admitted, terminal) in [
            (NotAdmitted, false, false),
            (Admitted, true, false),
            (Terminal, true, true),
        ] {
            assert_eq!(state.admitted(), admitted);
            assert_eq!(state.terminal(), terminal);
        }
    }
}
