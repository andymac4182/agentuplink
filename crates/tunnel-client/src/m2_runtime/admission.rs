//! OPEN admission and the sequenced-writer freeze of one M2 session, as one
//! explicit state.
//!
//! The actor used to keep two booleans, `accepting` and `writes_frozen`, and
//! wrote them as an inverse pair at every rotation and recovery boundary.
//! Only three of their four combinations were ever reachable in production:
//!
//! | state     | accepting | writes frozen | entered by                         |
//! |-----------|-----------|---------------|------------------------------------|
//! | `Open`    | yes       | no            | start, COMMIT, COMPLETE, ABORTED,  |
//! |           |           |               | recovery activation                |
//! | `Frozen`  | no        | yes           | QUIESCE, ABORT, candidate loss,    |
//! |           |           |               | carrier loss, RECOVERY_BEGIN, an   |
//! |           |           |               | overlap deadline entering Aborting |
//! | `Closing` | no        | no            | GOAWAY while `Open`                |
//!
//! `accepting && writes_frozen` has no variant: a session that refuses to
//! sequence writes never admits a new stream.
//!
//! Transition table (`Admission::apply` is the only place the state changes):
//!
//! | from \ event | `Freeze` | `Resume` | `GoAway`  |
//! |--------------|----------|----------|-----------|
//! | `Open`       | `Frozen` | `Open`   | `Closing` |
//! | `Frozen`     | `Frozen` | `Open`   | `Frozen`  |
//! | `Closing`    | `Frozen` | `Open`   | `Closing` |
//!
//! Every cell is legal because every pre-existing write site was
//! unconditional; in particular a rotation or recovery that completes after a
//! GOAWAY re-opens admission exactly as the two booleans did.  GOAWAY never
//! thaws a frozen writer, because it only ever cleared `accepting`.

/// Whether the session admits new streams and whether it may sequence writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Admission {
    /// New streams are admitted and sequenced writes flow.
    Open,
    /// A rotation or recovery owns the data path: no new stream is admitted
    /// and sequenced writes are retained until the path is settled.
    Frozen,
    /// The owner sent GOAWAY: no new stream is admitted, existing streams
    /// keep writing.
    Closing,
}

/// What can change [`Admission`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdmissionEvent {
    /// A rotation or recovery boundary stops admission and sequenced writes.
    Freeze,
    /// The data path is settled: admission and sequenced writes resume.
    Resume,
    /// The owner announced it is draining this session.
    GoAway,
}

impl Admission {
    /// Whether a new OPEN may be admitted.
    pub(super) const fn accepting(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Whether sequenced writes are held back for a rotation or recovery.
    pub(super) const fn writes_frozen(self) -> bool {
        matches!(self, Self::Frozen)
    }

    /// The only place admission changes.
    pub(super) fn apply(&mut self, event: AdmissionEvent) {
        *self = match (*self, event) {
            (_, AdmissionEvent::Freeze) => Self::Frozen,
            (_, AdmissionEvent::Resume) => Self::Open,
            (Self::Open | Self::Closing, AdmissionEvent::GoAway) => Self::Closing,
            (Self::Frozen, AdmissionEvent::GoAway) => Self::Frozen,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{Admission, AdmissionEvent};

    const STATES: [Admission; 3] = [Admission::Open, Admission::Frozen, Admission::Closing];

    fn after(mut state: Admission, event: AdmissionEvent) -> Admission {
        state.apply(event);
        state
    }

    #[test]
    fn admission_states_expose_the_three_reachable_flag_pairs() {
        assert!(Admission::Open.accepting() && !Admission::Open.writes_frozen());
        assert!(!Admission::Frozen.accepting() && Admission::Frozen.writes_frozen());
        assert!(!Admission::Closing.accepting() && !Admission::Closing.writes_frozen());
        for state in STATES {
            assert!(
                !(state.accepting() && state.writes_frozen()),
                "{state:?} admits streams while the writer is frozen"
            );
        }
    }

    #[test]
    fn admission_freeze_and_resume_are_legal_from_every_state() {
        for state in STATES {
            assert_eq!(after(state, AdmissionEvent::Freeze), Admission::Frozen);
            assert_eq!(after(state, AdmissionEvent::Resume), Admission::Open);
        }
    }

    #[test]
    fn admission_goaway_stops_admission_without_touching_the_writer() {
        assert_eq!(
            after(Admission::Open, AdmissionEvent::GoAway),
            Admission::Closing
        );
        assert_eq!(
            after(Admission::Closing, AdmissionEvent::GoAway),
            Admission::Closing
        );
        // GOAWAY only ever cleared `accepting`: it is refused as a thaw.
        assert_eq!(
            after(Admission::Frozen, AdmissionEvent::GoAway),
            Admission::Frozen
        );
        for state in STATES {
            let next = after(state, AdmissionEvent::GoAway);
            assert!(!next.accepting());
            assert_eq!(next.writes_frozen(), state.writes_frozen());
        }
    }

    #[test]
    fn admission_matches_the_two_booleans_it_replaced() {
        // Replay every event sequence of length three against the old
        // inverse-pair writes; GOAWAY cleared only `accepting`.
        let events = [
            AdmissionEvent::Freeze,
            AdmissionEvent::Resume,
            AdmissionEvent::GoAway,
        ];
        for first in events {
            for second in events {
                for third in events {
                    let mut state = Admission::Open;
                    let mut flags = (true, false);
                    for event in [first, second, third] {
                        state.apply(event);
                        flags = match event {
                            AdmissionEvent::Freeze => (false, true),
                            AdmissionEvent::Resume => (true, false),
                            AdmissionEvent::GoAway => (false, flags.1),
                        };
                        assert_eq!((state.accepting(), state.writes_frozen()), flags);
                    }
                }
            }
        }
    }
}
