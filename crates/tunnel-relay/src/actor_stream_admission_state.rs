//! The explicit admission state of one owner M2 stream.
//!
//! A stream's OPEN stays pending until the connector acknowledges that exact
//! OPEN.  Independently the public registration can disappear while the OPEN
//! is still pending; the close that noticed it may supply a typed terminal
//! cause, which is held until the connector admits the stream and the real
//! terminal transition can carry it.
//!
//! [`StreamAdmission::on_event`] is the only place the state changes.  The
//! registration-dropped record is deliberately kept after admission: the
//! OPENED handler reads the deferred cause after it has admitted the stream,
//! and the record is how a detached-but-admitted stream is told apart.

use super::StreamTerminalCause;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StreamAdmission {
    /// The connector has not acknowledged this OPEN.
    OpenPending,
    /// The public registration disappeared while the OPEN was pending.  The
    /// OPEN stays live until the owner proves rejection or admission.
    OpenPendingRegistrationDropped { cause: Option<StreamTerminalCause> },
    /// The connector admitted the stream.
    Admitted,
    /// The connector admitted the stream after its registration was dropped;
    /// `cause` labels the terminal transition that admission makes possible.
    AdmittedRegistrationDropped { cause: Option<StreamTerminalCause> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdmissionEvent {
    /// The public registration was dropped, by a close that may name a cause.
    RegistrationDropped { cause: Option<StreamTerminalCause> },
    /// The connector admitted the OPEN (OPENED, or its first authorization
    /// challenge for the stream).
    Admitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalAdmissionTransition {
    pub(super) state: StreamAdmission,
    pub(super) event: AdmissionEvent,
}

impl StreamAdmission {
    /// The only place the admission state changes.  A refused event leaves
    /// the state exactly as it was.
    pub(super) const fn on_event(
        self,
        event: AdmissionEvent,
    ) -> Result<Self, IllegalAdmissionTransition> {
        match (self, event) {
            (Self::OpenPending, AdmissionEvent::RegistrationDropped { cause }) => {
                Ok(Self::OpenPendingRegistrationDropped { cause })
            }
            // A repeated close is idempotent, except that the first cause any
            // of them names is kept.
            (
                Self::OpenPendingRegistrationDropped { cause: None },
                AdmissionEvent::RegistrationDropped {
                    cause: cause @ Some(_),
                },
            ) => Ok(Self::OpenPendingRegistrationDropped { cause }),
            (Self::OpenPending, AdmissionEvent::Admitted) => Ok(Self::Admitted),
            (Self::OpenPendingRegistrationDropped { cause }, AdmissionEvent::Admitted) => {
                Ok(Self::AdmittedRegistrationDropped { cause })
            }
            // Refused: a registration cannot be dropped "while pending" once
            // the stream is admitted, a later cause never replaces the first,
            // and an admitted stream is never admitted again or un-admitted.
            (state, event) => Err(IllegalAdmissionTransition { state, event }),
        }
    }

    /// Apply `event`; returns whether the state changed.
    pub(super) fn apply(&mut self, event: AdmissionEvent) -> bool {
        match self.on_event(event) {
            Ok(next) => {
                *self = next;
                true
            }
            Err(_) => false,
        }
    }

    /// True only until the connector acknowledges this exact OPEN.
    pub(super) const fn open_pending(self) -> bool {
        matches!(
            self,
            Self::OpenPending | Self::OpenPendingRegistrationDropped { .. }
        )
    }

    /// The public registration disappeared before OPENED was observed.
    pub(super) const fn registration_dropped(self) -> bool {
        matches!(
            self,
            Self::OpenPendingRegistrationDropped { .. } | Self::AdmittedRegistrationDropped { .. }
        )
    }

    /// The cause a close supplied while the OPEN was still pending.
    pub(super) const fn deferred_terminal_cause(self) -> Option<StreamTerminalCause> {
        match self {
            Self::OpenPendingRegistrationDropped { cause }
            | Self::AdmittedRegistrationDropped { cause } => cause,
            Self::OpenPending | Self::Admitted => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAUSE: StreamTerminalCause = StreamTerminalCause::AdmissionLeaseExpired;
    const OTHER: StreamTerminalCause = StreamTerminalCause::QueueExhausted;

    const fn dropped(cause: Option<StreamTerminalCause>) -> AdmissionEvent {
        AdmissionEvent::RegistrationDropped { cause }
    }

    #[test]
    fn admission_transition_table() {
        use AdmissionEvent::Admitted as Admit;
        use StreamAdmission::{
            Admitted, AdmittedRegistrationDropped as AdmittedDropped, OpenPending,
            OpenPendingRegistrationDropped as PendingDropped,
        };
        // Every state against every event shape: `Some(next)` is legal,
        // `None` refused.
        let table = [
            (
                OpenPending,
                dropped(None),
                Some(PendingDropped { cause: None }),
            ),
            (
                OpenPending,
                dropped(Some(CAUSE)),
                Some(PendingDropped { cause: Some(CAUSE) }),
            ),
            (OpenPending, Admit, Some(Admitted)),
            (PendingDropped { cause: None }, dropped(None), None),
            (
                PendingDropped { cause: None },
                dropped(Some(CAUSE)),
                Some(PendingDropped { cause: Some(CAUSE) }),
            ),
            (
                PendingDropped { cause: None },
                Admit,
                Some(AdmittedDropped { cause: None }),
            ),
            (PendingDropped { cause: Some(CAUSE) }, dropped(None), None),
            // The first cause wins.
            (
                PendingDropped { cause: Some(CAUSE) },
                dropped(Some(OTHER)),
                None,
            ),
            (
                PendingDropped { cause: Some(CAUSE) },
                Admit,
                Some(AdmittedDropped { cause: Some(CAUSE) }),
            ),
            (Admitted, dropped(None), None),
            (Admitted, dropped(Some(CAUSE)), None),
            (Admitted, Admit, None),
            (AdmittedDropped { cause: None }, dropped(Some(CAUSE)), None),
            (AdmittedDropped { cause: None }, Admit, None),
            (AdmittedDropped { cause: Some(CAUSE) }, dropped(None), None),
            (
                AdmittedDropped { cause: Some(CAUSE) },
                dropped(Some(OTHER)),
                None,
            ),
            (AdmittedDropped { cause: Some(CAUSE) }, Admit, None),
        ];
        for (state, event, expected) in table {
            let outcome = state.on_event(event);
            match expected {
                Some(next) => assert_eq!(outcome, Ok(next), "{state:?} on {event:?}"),
                None => assert_eq!(
                    outcome,
                    Err(IllegalAdmissionTransition { state, event }),
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
    fn accessors_match_the_flags_they_replaced() {
        // (state, open_pending, registration_dropped, deferred_terminal_cause)
        let table = [
            (StreamAdmission::OpenPending, true, false, None),
            (
                StreamAdmission::OpenPendingRegistrationDropped { cause: None },
                true,
                true,
                None,
            ),
            (
                StreamAdmission::OpenPendingRegistrationDropped { cause: Some(CAUSE) },
                true,
                true,
                Some(CAUSE),
            ),
            (StreamAdmission::Admitted, false, false, None),
            (
                StreamAdmission::AdmittedRegistrationDropped { cause: None },
                false,
                true,
                None,
            ),
            (
                StreamAdmission::AdmittedRegistrationDropped { cause: Some(CAUSE) },
                false,
                true,
                Some(CAUSE),
            ),
        ];
        for (state, open_pending, registration_dropped, cause) in table {
            assert_eq!(state.open_pending(), open_pending, "{state:?}");
            assert_eq!(
                state.registration_dropped(),
                registration_dropped,
                "{state:?}"
            );
            assert_eq!(state.deferred_terminal_cause(), cause, "{state:?}");
        }
    }
}
