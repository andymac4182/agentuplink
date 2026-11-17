//! The connector's per-attempt rotation bookkeeping that shadows the pure
//! `RotationState` machine with finer sub-steps.
//!
//! Two groups live here:
//!
//! * [`RotationPhaseMessageIds`]: the phase message ids of the attempt in
//!   flight, which are always forgotten together;
//! * [`QuiesceStep`]: the explicit sub-steps between the owner's
//!   `ROTATE_QUIESCE` and this connector's `ROTATE_FROZEN`.

/// The phase message ids of the rotation attempt in flight.
///
/// Each id is recorded by the handler of its own phase and is only ever
/// forgotten together with the other eight, by [`Self::clear`].
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct RotationPhaseMessageIds {
    /// This connector's `ROTATE_FROZEN`; the owner's FROZEN and DRAINED
    /// reply to it.
    pub(super) local_frozen: Option<String>,
    /// This connector's `ROTATE_DRAINED`; the owner's COMMIT replies to it.
    pub(super) local_drained: Option<String>,
    /// This connector's `ROTATE_COMMITTED`; the owner's RETIRE replies to it.
    pub(super) local_committed: Option<String>,
    /// This connector's `ROTATE_RETIRED`; the owner's COMPLETE replies to it.
    pub(super) local_retired: Option<String>,
    /// The owner's `ROTATE_DRAINED`, kept to refuse a changed duplicate.
    pub(super) peer_drained: Option<String>,
    /// The owner's `ROTATE_COMMIT`, kept to refuse a changed duplicate.
    pub(super) peer_committed: Option<String>,
    /// The owner's `ROTATE_RETIRE`, kept to refuse a changed duplicate.
    pub(super) peer_retire: Option<String>,
    /// The owner's `ROTATE_ABORT`, kept to refuse a changed duplicate.
    pub(super) peer_abort: Option<String>,
    /// This connector's `ROTATE_ABORTED`; the owner's final ABORTED replies
    /// to it.
    pub(super) pending_abort_reply: Option<String>,
}

impl RotationPhaseMessageIds {
    /// Forget the phase message ids of the rotation attempt that just ended
    /// or is being replaced.
    ///
    /// This is the one copy of a block that used to be written out at three
    /// sites, which all cleared exactly these nine ids and differed only in
    /// what surrounds them:
    ///
    /// * `finish_rotation_tombstone` first moves `rotation_prepare_message_id`
    ///   into the tombstone and leaves the fences alone;
    /// * `handle_rotate_prepare` first records the new PREPARE id and then
    ///   also clears both fences, the peer fence id and the drain-proof flag;
    /// * `handle_rotate_complete` keeps `rotation_prepare_message_id` (the
    ///   tombstone taken right after it consumes it) and also clears the
    ///   fences, the drain-proof flag and the deferred QUIESCE/RETIRE.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The sub-steps between the owner's `ROTATE_QUIESCE` and this connector's
/// `ROTATE_FROZEN`.
///
/// ```text
/// Idle --Received--> Pending --BarrierQueued--> BarrierQueued
/// BarrierQueued --BarrierDrained--> Pending --Applied--> Idle
/// any --Clear--> Idle
/// ```
///
/// A QUIESCE waits in `Pending` until the candidate carrier is installed and
/// no pre-quiesce `STREAM_FORGET` is outstanding; the immutable fence barrier
/// is then queued on the active carrier (`BarrierQueued`).  When the barrier
/// drains the step returns to `Pending`: either a `STREAM_FORGET` that
/// arrived meanwhile must drain first (and the barrier is queued again), or
/// the QUIESCE is `Applied` and the fence snapshot is taken.  A queued
/// barrier without a QUIESCE has no variant.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum QuiesceStep<Q> {
    /// No QUIESCE is waiting.
    Idle,
    /// A QUIESCE is held; no fence barrier is queued on the active carrier.
    Pending(Q),
    /// A QUIESCE is held and its fence barrier is queued on the active
    /// carrier.
    BarrierQueued(Q),
}

/// What can change a [`QuiesceStep`].
#[derive(Debug, Eq, PartialEq)]
pub(super) enum QuiesceEvent<Q> {
    /// The owner's QUIESCE was validated (`handle_rotate_quiesce`).
    Received(Q),
    /// The fence barrier was queued on the active carrier
    /// (`apply_pending_quiesce`).
    BarrierQueued,
    /// The active carrier reported the fence barrier drained
    /// (`handle_barrier_complete`).
    BarrierDrained,
    /// The fence snapshot is being taken; yields the QUIESCE
    /// (`handle_barrier_complete`).
    Applied,
    /// COMMIT, COMPLETE or ABORT ended the sub-step, whatever it was.
    Clear,
}

/// A transition the sub-step does not have.  The step is unchanged.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct IllegalQuiesceTransition {
    pub(super) from: &'static str,
    pub(super) event: &'static str,
}

impl<Q> QuiesceStep<Q> {
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Pending(_) => "pending",
            Self::BarrierQueued(_) => "barrier_queued",
        }
    }

    /// The QUIESCE being held, if any.
    pub(super) fn pending(&self) -> Option<&Q> {
        match self {
            Self::Idle => None,
            Self::Pending(quiesce) | Self::BarrierQueued(quiesce) => Some(quiesce),
        }
    }

    /// Whether the rotation fence barrier is queued on the active carrier.
    pub(super) fn barrier_queued(&self) -> bool {
        matches!(self, Self::BarrierQueued(_))
    }

    /// The only place the sub-step changes.  `Applied` returns the QUIESCE;
    /// every other legal event returns `None`.
    pub(super) fn transition(
        &mut self,
        event: QuiesceEvent<Q>,
    ) -> Result<Option<Q>, IllegalQuiesceTransition> {
        let from = self.name();
        let (next, outcome) = match (std::mem::replace(self, Self::Idle), event) {
            (_, QuiesceEvent::Clear) => (Self::Idle, Ok(None)),
            (Self::Idle, QuiesceEvent::Received(quiesce)) => (Self::Pending(quiesce), Ok(None)),
            (Self::Pending(quiesce), QuiesceEvent::BarrierQueued) => {
                (Self::BarrierQueued(quiesce), Ok(None))
            }
            (Self::BarrierQueued(quiesce), QuiesceEvent::BarrierDrained) => {
                (Self::Pending(quiesce), Ok(None))
            }
            (Self::Pending(quiesce), QuiesceEvent::Applied) => (Self::Idle, Ok(Some(quiesce))),
            (unchanged, event) => {
                let event = match event {
                    QuiesceEvent::Received(_) => "received",
                    QuiesceEvent::BarrierQueued => "barrier_queued",
                    QuiesceEvent::BarrierDrained => "barrier_drained",
                    QuiesceEvent::Applied => "applied",
                    QuiesceEvent::Clear => "clear",
                };
                (unchanged, Err(IllegalQuiesceTransition { from, event }))
            }
        };
        *self = next;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::{IllegalQuiesceTransition, QuiesceEvent, QuiesceStep, RotationPhaseMessageIds};

    #[test]
    fn rotation_phase_message_ids_are_forgotten_together() {
        let id = |name: &str| Some(name.to_owned());
        let mut ids = RotationPhaseMessageIds {
            local_frozen: id("local-frozen"),
            local_drained: id("local-drained"),
            local_committed: id("local-committed"),
            local_retired: id("local-retired"),
            peer_drained: id("peer-drained"),
            peer_committed: id("peer-committed"),
            peer_retire: id("peer-retire"),
            peer_abort: id("peer-abort"),
            pending_abort_reply: id("abort-reply"),
        };
        ids.clear();
        let RotationPhaseMessageIds {
            local_frozen,
            local_drained,
            local_committed,
            local_retired,
            peer_drained,
            peer_committed,
            peer_retire,
            peer_abort,
            pending_abort_reply,
        } = ids;
        for cleared in [
            local_frozen,
            local_drained,
            local_committed,
            local_retired,
            peer_drained,
            peer_committed,
            peer_retire,
            peer_abort,
            pending_abort_reply,
        ] {
            assert_eq!(cleared, None);
        }
    }

    type Step = QuiesceStep<&'static str>;

    fn states() -> [Step; 3] {
        [Step::Idle, Step::Pending("q"), Step::BarrierQueued("q")]
    }

    fn events() -> [QuiesceEvent<&'static str>; 5] {
        [
            QuiesceEvent::Received("other"),
            QuiesceEvent::BarrierQueued,
            QuiesceEvent::BarrierDrained,
            QuiesceEvent::Applied,
            QuiesceEvent::Clear,
        ]
    }

    #[test]
    fn quiesce_step_walks_the_barrier_path_and_yields_the_quiesce_once() {
        let mut step = Step::Idle;
        assert_eq!(step.pending(), None);
        assert!(!step.barrier_queued());
        assert_eq!(step.transition(QuiesceEvent::Received("q")), Ok(None));
        assert_eq!(step, Step::Pending("q"));
        assert_eq!(step.pending(), Some(&"q"));
        assert!(!step.barrier_queued());
        assert_eq!(step.transition(QuiesceEvent::BarrierQueued), Ok(None));
        assert_eq!(step, Step::BarrierQueued("q"));
        assert_eq!(step.pending(), Some(&"q"));
        assert!(step.barrier_queued());
        // A STREAM_FORGET that arrived behind the barrier re-queues it.
        assert_eq!(step.transition(QuiesceEvent::BarrierDrained), Ok(None));
        assert_eq!(step, Step::Pending("q"));
        assert_eq!(step.transition(QuiesceEvent::BarrierQueued), Ok(None));
        assert_eq!(step.transition(QuiesceEvent::BarrierDrained), Ok(None));
        assert_eq!(step.transition(QuiesceEvent::Applied), Ok(Some("q")));
        assert_eq!(step, Step::Idle);
    }

    #[test]
    fn quiesce_step_clear_is_legal_from_every_state() {
        for mut step in states() {
            assert_eq!(step.transition(QuiesceEvent::Clear), Ok(None));
            assert_eq!(step, Step::Idle);
        }
    }

    #[test]
    fn quiesce_step_refuses_every_other_transition_unchanged() {
        let legal = |from: &Step, event: &QuiesceEvent<&'static str>| {
            matches!(
                (from, event),
                (_, QuiesceEvent::Clear)
                    | (Step::Idle, QuiesceEvent::Received(_))
                    | (Step::Pending(_), QuiesceEvent::BarrierQueued)
                    | (Step::BarrierQueued(_), QuiesceEvent::BarrierDrained)
                    | (Step::Pending(_), QuiesceEvent::Applied)
            )
        };
        let mut refused = 0;
        for (state_index, before) in states().into_iter().enumerate() {
            for (event_index, event) in events().into_iter().enumerate() {
                if legal(&before, &event) {
                    continue;
                }
                let mut step = states().into_iter().nth(state_index).expect("state exists");
                let outcome = step.transition(event);
                let event_name =
                    ["received", "barrier_queued", "barrier_drained", "applied"][event_index];
                assert_eq!(
                    outcome,
                    Err(IllegalQuiesceTransition {
                        from: before.name(),
                        event: event_name,
                    })
                );
                assert_eq!(step, before, "a refused event must not change the step");
                refused += 1;
            }
        }
        // 3 states x 5 events, minus the 3 `Clear` cells and the 4 other
        // legal cells.
        assert_eq!(refused, 8);
    }

    #[test]
    fn quiesce_step_never_queues_a_barrier_without_a_quiesce() {
        let mut step = Step::Idle;
        assert!(step.transition(QuiesceEvent::BarrierQueued).is_err());
        assert!(!step.barrier_queued());
        for step in states() {
            assert!(!step.barrier_queued() || step.pending().is_some());
        }
    }
}
