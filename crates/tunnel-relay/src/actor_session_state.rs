//! Small explicit state machines owned by one `DeviceSession`.
//!
//! * [`LeaseMaintenance`]: where the session's owner-lease maintenance is
//!   between maintenance rounds, including the explicit "the renewal's
//!   outcome is unknown" states.
//! * [`FailClosedDeadline`]: an armed-or-idle absolute deadline whose expiry
//!   closes the session.
//!
//! The session's `closed` flag is deliberately not modelled here: a session
//! is removed from the actor's table before the flag is set, so no session
//! the actor can still reach is ever in the closing state.

use std::time::Instant;

use super::UnknownOwnerWrite;

/// Owner-lease maintenance of one session.
///
/// At most one maintenance authority round is in flight per session.  A
/// round is either the ordinary one (an identity re-check, preceded by a
/// lease renewal when one is due) or, while the last renewal's outcome is
/// unknown, the authoritative owner read that reconciles it.
///
/// | state            | event                         | next state                  |
/// |------------------|-------------------------------|-----------------------------|
/// | `Idle`           | `RoundStarted`                | `RoundInFlight`             |
/// | `OutcomeUnknown` | `RoundStarted`                | `Reconciling`               |
/// | in flight        | `RoundStarted`                | refused                     |
/// | `RoundInFlight`  | `RoundFinished{None}`         | `Idle`                      |
/// | `RoundInFlight`  | `RoundFinished{Some(lost)}`   | `OutcomeUnknown(lost)`      |
/// | `Idle`           | `RoundFinished{..}`           | as `RoundInFlight`          |
/// | unknown states   | `RoundFinished{..}`           | `OutcomeUnknown` (first kept) |
/// | `Reconciling`    | `OwnerReadReturned`           | `OutcomeUnknown`            |
/// | `RoundInFlight`  | `OwnerReadReturned`           | `Idle`                      |
/// | not in flight    | `OwnerReadReturned`           | unchanged                   |
/// | `OutcomeUnknown` | `OwnerConfirmed`              | `Idle`                      |
/// | any other        | `OwnerConfirmed`              | refused                     |
///
/// A result is matched to its session by key, never by this state, so the
/// two "result returned" events are total: a result that finds no round in
/// flight settles nothing and still records a lost reply.  The first unknown
/// outcome is the one retained; the renewal is never replayed while one is
/// recorded.
#[derive(Clone, Copy, Debug)]
pub(super) enum LeaseMaintenance {
    /// No round in flight; the last renewal's outcome is known.
    Idle,
    /// An ordinary round (renewal and/or identity re-check) is in flight.
    RoundInFlight,
    /// The last renewal's reply was lost.  The session is unready for
    /// dispatch and admission until an authoritative owner read confirms it.
    OutcomeUnknown(UnknownOwnerWrite),
    /// As `OutcomeUnknown`, with the reconciling owner read in flight.
    Reconciling(UnknownOwnerWrite),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum LeaseEvent {
    /// The actor dispatched this session's maintenance round.
    RoundStarted,
    /// The ordinary round's result returned.  `lost_reply` is present when
    /// its renewal was dispatched and the reply was lost.
    RoundFinished {
        lost_reply: Option<UnknownOwnerWrite>,
    },
    /// The reconciling owner read's result returned, whatever it was.
    OwnerReadReturned,
    /// That read named this session's exact owner with lease remaining.
    OwnerConfirmed,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct IllegalLeaseTransition {
    #[allow(dead_code)]
    pub(super) state: LeaseMaintenance,
    #[allow(dead_code)]
    pub(super) event: LeaseEvent,
}

impl LeaseMaintenance {
    /// The only place lease maintenance changes state.
    pub(super) fn on_event(&mut self, event: LeaseEvent) -> Result<(), IllegalLeaseTransition> {
        let next = match (*self, event) {
            (Self::Idle, LeaseEvent::RoundStarted) => Self::RoundInFlight,
            (Self::OutcomeUnknown(unknown), LeaseEvent::RoundStarted) => Self::Reconciling(unknown),
            (Self::Idle | Self::RoundInFlight, LeaseEvent::RoundFinished { lost_reply }) => {
                lost_reply.map_or(Self::Idle, Self::OutcomeUnknown)
            }
            (
                Self::OutcomeUnknown(unknown) | Self::Reconciling(unknown),
                LeaseEvent::RoundFinished { .. } | LeaseEvent::OwnerReadReturned,
            ) => Self::OutcomeUnknown(unknown),
            (Self::Idle | Self::RoundInFlight, LeaseEvent::OwnerReadReturned) => Self::Idle,
            (Self::OutcomeUnknown(_), LeaseEvent::OwnerConfirmed) => Self::Idle,
            (state, event) => return Err(IllegalLeaseTransition { state, event }),
        };
        *self = next;
        Ok(())
    }

    /// A maintenance round for this session is in flight.
    pub(super) fn is_in_flight(&self) -> bool {
        matches!(self, Self::RoundInFlight | Self::Reconciling(_))
    }

    /// The unknown renewal outcome, while one is recorded.
    pub(super) fn unknown(&self) -> Option<UnknownOwnerWrite> {
        match self {
            Self::OutcomeUnknown(unknown) | Self::Reconciling(unknown) => Some(*unknown),
            Self::Idle | Self::RoundInFlight => None,
        }
    }

    /// The last renewal's outcome is unknown: the session is unready.
    pub(super) fn is_outcome_unknown(&self) -> bool {
        self.unknown().is_some()
    }
}

/// An absolute deadline whose expiry closes the session, armed only while
/// the debt it bounds is outstanding.
///
/// | state    | operation         | next state                         |
/// |----------|-------------------|------------------------------------|
/// | `Idle`   | `arm_once(d)`     | `Armed(d)`                         |
/// | `Armed`  | `arm_once(_)`     | unchanged: retries never extend it |
/// | any      | `set(Some(d))`    | `Armed(d)`                         |
/// | any      | `set(None)`/`clear` | `Idle`                           |
///
/// `set` is for the two deadlines that are re-derived rather than only armed
/// once: the owed-ACK window, moved forward when a retry makes progress, and
/// the terminal-FIN window, re-derived from the streams still refused.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum FailClosedDeadline {
    #[default]
    Idle,
    Armed(Instant),
}

impl FailClosedDeadline {
    /// Arm the deadline unless it is already armed.  `deadline` is evaluated
    /// only when it is used.
    pub(super) fn arm_once(&mut self, deadline: impl FnOnce() -> Instant) {
        if matches!(self, Self::Idle) {
            *self = Self::Armed(deadline());
        }
    }

    /// Replace the deadline with a re-derived one; `None` clears it.
    pub(super) fn set(&mut self, deadline: Option<Instant>) {
        *self = deadline.map_or(Self::Idle, Self::Armed);
    }

    pub(super) fn clear(&mut self) {
        *self = Self::Idle;
    }

    #[cfg(test)]
    pub(super) fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    pub(super) fn is_armed(&self) -> bool {
        matches!(self, Self::Armed(_))
    }

    /// The armed deadline, if any.
    #[cfg(test)]
    pub(super) fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Idle => None,
            Self::Armed(deadline) => Some(*deadline),
        }
    }

    /// Armed, and `now` is at or past the deadline.
    pub(super) fn expired(&self, now: Instant) -> bool {
        matches!(self, Self::Armed(deadline) if now >= *deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn unknown() -> UnknownOwnerWrite {
        UnknownOwnerWrite {
            since: Instant::now(),
            cause: None,
        }
    }

    fn after(mut state: LeaseMaintenance, event: LeaseEvent) -> LeaseMaintenance {
        state.on_event(event).expect("legal transition");
        state
    }

    fn refused(mut state: LeaseMaintenance, event: LeaseEvent) -> bool {
        let before = format!("{state:?}");
        let refused = state.on_event(event).is_err();
        assert_eq!(
            before,
            format!("{state:?}"),
            "a refusal leaves the state alone"
        );
        refused
    }

    #[test]
    fn a_round_starts_only_when_none_is_in_flight() {
        assert!(matches!(
            after(LeaseMaintenance::Idle, LeaseEvent::RoundStarted),
            LeaseMaintenance::RoundInFlight
        ));
        assert!(matches!(
            after(
                LeaseMaintenance::OutcomeUnknown(unknown()),
                LeaseEvent::RoundStarted
            ),
            LeaseMaintenance::Reconciling(_)
        ));
        assert!(refused(
            LeaseMaintenance::RoundInFlight,
            LeaseEvent::RoundStarted
        ));
        assert!(refused(
            LeaseMaintenance::Reconciling(unknown()),
            LeaseEvent::RoundStarted
        ));
    }

    #[test]
    fn a_finished_round_is_idle_or_records_the_lost_reply() {
        for start in [LeaseMaintenance::RoundInFlight, LeaseMaintenance::Idle] {
            assert!(matches!(
                after(start, LeaseEvent::RoundFinished { lost_reply: None }),
                LeaseMaintenance::Idle
            ));
            let next = after(
                start,
                LeaseEvent::RoundFinished {
                    lost_reply: Some(unknown()),
                },
            );
            assert!(matches!(next, LeaseMaintenance::OutcomeUnknown(_)));
            assert!(next.is_outcome_unknown() && !next.is_in_flight());
        }
    }

    #[test]
    fn the_first_unknown_outcome_is_retained() {
        let first = UnknownOwnerWrite {
            since: Instant::now() - Duration::from_millis(1),
            cause: None,
        };
        for start in [
            LeaseMaintenance::OutcomeUnknown(first),
            LeaseMaintenance::Reconciling(first),
        ] {
            for event in [
                LeaseEvent::RoundFinished { lost_reply: None },
                LeaseEvent::RoundFinished {
                    lost_reply: Some(unknown()),
                },
                LeaseEvent::OwnerReadReturned,
            ] {
                let next = after(start, event);
                assert!(matches!(next, LeaseMaintenance::OutcomeUnknown(_)));
                assert_eq!(
                    next.unknown().map(|unknown| unknown.since),
                    Some(first.since)
                );
            }
        }
    }

    #[test]
    fn an_owner_read_result_settles_the_round_without_confirming() {
        assert!(matches!(
            after(
                LeaseMaintenance::RoundInFlight,
                LeaseEvent::OwnerReadReturned
            ),
            LeaseMaintenance::Idle
        ));
        assert!(matches!(
            after(LeaseMaintenance::Idle, LeaseEvent::OwnerReadReturned),
            LeaseMaintenance::Idle
        ));
    }

    #[test]
    fn only_a_settled_unknown_outcome_is_confirmed() {
        assert!(matches!(
            after(
                LeaseMaintenance::OutcomeUnknown(unknown()),
                LeaseEvent::OwnerConfirmed
            ),
            LeaseMaintenance::Idle
        ));
        for state in [
            LeaseMaintenance::Idle,
            LeaseMaintenance::RoundInFlight,
            LeaseMaintenance::Reconciling(unknown()),
        ] {
            assert!(refused(state, LeaseEvent::OwnerConfirmed));
        }
    }

    #[test]
    fn a_fail_closed_deadline_is_armed_once_and_never_extended() {
        let first = Instant::now();
        let later = first + Duration::from_secs(5);
        let mut deadline = FailClosedDeadline::default();
        assert!(!deadline.is_armed() && !deadline.expired(later));
        assert_eq!(deadline.deadline(), None);

        deadline.arm_once(|| first);
        deadline.arm_once(|| unreachable!("an armed deadline is not re-derived"));
        assert_eq!(deadline, FailClosedDeadline::Armed(first));
        assert!(deadline.expired(first) && deadline.expired(later));
        assert!(!deadline.expired(first - Duration::from_nanos(1)));

        deadline.clear();
        assert_eq!(deadline, FailClosedDeadline::Idle);
        assert!(!deadline.expired(later));
    }

    #[test]
    fn a_fail_closed_deadline_is_re_derived_only_by_set() {
        let first = Instant::now();
        let later = first + Duration::from_secs(5);
        let mut deadline = FailClosedDeadline::Idle;
        deadline.set(Some(first));
        deadline.set(Some(later));
        assert_eq!(deadline.deadline(), Some(later));
        assert!(!deadline.expired(first));
        deadline.set(None);
        assert_eq!(deadline, FailClosedDeadline::Idle);
    }
}
