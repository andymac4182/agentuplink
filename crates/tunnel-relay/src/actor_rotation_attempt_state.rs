//! Attempt-scoped pieces of the relay's `RotationRuntime` that are always
//! reset together and that carry an invariant of their own.
//!
//! The pure `tunnel_protocol::RotationState` owns the rotation phase.  The
//! actor keeps, next to it, the wire-level evidence the phase transitions
//! are driven by.  This module holds the three groups of that evidence whose
//! rules are local:
//!
//! * [`RotationFences`]: the immutable per-direction sequence fences of one
//!   attempt.  A fence is recorded once, after the pure machine accepted it;
//!   recording a different fence for a direction that already has one is
//!   refused.
//! * [`PeerPhasePins`] / [`MessagePin`]: the first authenticated peer
//!   message for each phase.  A pin is set once and never overwritten.
//! * [`AbortExchange`]: the coordinated-abort exchange.  The connector's
//!   `ROTATE_ABORTED` can only be pinned and held pending against an abort
//!   this relay actually sent.
//!
//! Each is reset to its empty state wherever the actor begins or ends an
//! attempt.  What is *not* modelled here, and why, is recorded on
//! `RotationRuntime` itself.

use tunnel_protocol::rotation_control::{FenceSnapshot, RotateAborted};

/// The first authenticated peer message id for one phase of an attempt.
///
/// | state        | `pin(id)`            | result                    |
/// |--------------|----------------------|---------------------------|
/// | `Unpinned`   | non-empty `id`       | `Pinned(id)`, accepted    |
/// | `Pinned(p)`  | `id == p`            | unchanged, accepted       |
/// | `Pinned(p)`  | `id != p`            | unchanged, refused        |
/// | any          | empty `id`           | unchanged, refused        |
///
/// A fresh message id with the same attempt and reply target is not an
/// idempotent retry, and so never replaces the pin.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct MessagePin(Option<String>);

impl MessagePin {
    /// `incoming` would be accepted by [`Self::pin`].
    pub(super) fn is_acceptable(&self, incoming: &str) -> bool {
        !incoming.is_empty() && self.0.as_deref().is_none_or(|pinned| pinned == incoming)
    }

    /// The only place a pin is set.  Returns whether `incoming` is, or now
    /// became, the pinned message.
    #[must_use]
    pub(super) fn pin(&mut self, incoming: &str) -> bool {
        if !self.is_acceptable(incoming) {
            return false;
        }
        if self.0.is_none() {
            self.0 = Some(incoming.to_owned());
        }
        true
    }

    pub(super) fn get(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// The connector's phase messages pinned for the current attempt.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct PeerPhasePins {
    pub(super) frozen: MessagePin,
    pub(super) drained: MessagePin,
    pub(super) committed: MessagePin,
    pub(super) retired: MessagePin,
}

impl PeerPhasePins {
    /// Forget every pin: the attempt they belonged to began or ended.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }
}

/// A fence for a direction was already recorded and differs from this one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConflictingFence;

/// The sequence fences of the current attempt: the relay's own
/// relay-to-connector fence, and the connector's fences by direction index.
///
/// A fence is immutable once taken.  [`Self::record_own`] and
/// [`Self::record_remote`] are the only places one is set; both accept a
/// repeat of the identical fence and refuse a different one, exactly as the
/// pure machine's `frozen` does before the actor records it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct RotationFences {
    own: Option<FenceSnapshot>,
    remote: [Option<FenceSnapshot>; 2],
}

impl RotationFences {
    fn record(
        slot: &mut Option<FenceSnapshot>,
        fence: FenceSnapshot,
    ) -> Result<(), ConflictingFence> {
        match slot {
            Some(taken) if *taken != fence => Err(ConflictingFence),
            Some(_) => Ok(()),
            None => {
                *slot = Some(fence);
                Ok(())
            }
        }
    }

    /// Record the relay's own fence, taken when its writer froze.
    pub(super) fn record_own(&mut self, fence: FenceSnapshot) -> Result<(), ConflictingFence> {
        Self::record(&mut self.own, fence)
    }

    /// Record the connector's fence for one direction index.
    pub(super) fn record_remote(
        &mut self,
        direction_index: usize,
        fence: FenceSnapshot,
    ) -> Result<(), ConflictingFence> {
        let slot = self
            .remote
            .get_mut(direction_index)
            .ok_or(ConflictingFence)?;
        Self::record(slot, fence)
    }

    pub(super) fn own(&self) -> Option<&FenceSnapshot> {
        self.own.as_ref()
    }

    pub(super) fn remote(&self, direction_index: usize) -> Option<&FenceSnapshot> {
        self.remote.get(direction_index).and_then(Option::as_ref)
    }

    /// Drop every fence: the attempt they belonged to began or ended.
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The coordinated abort of the current attempt.
///
/// | state      | event                    | next state                              | guard site in `actor.rs` |
/// |------------|--------------------------|-----------------------------------------|--------------------------|
/// | `NotSent`  | `Queued(id)`             | `Sent{id, unpinned, no ack}`            | `emit_rotation_abort`, and the candidate-loss abort in `disconnect_data` |
/// | `Sent`     | `PeerAborted(aborted)`   | `Sent` with the pin set and ack pending | `handle_rotate_aborted`: `reply_to` is this abort and the pin accepts the message |
/// | any        | `Reset`                  | `NotSent`                               | every attempt start and end |
/// | `Sent`     | `Queued(_)`              | refused                                 | the abort is queued exactly once |
/// | `NotSent`  | `PeerAborted(_)`         | refused                                 | there is nothing to acknowledge |
/// | `Sent`     | `PeerAborted` (other id, or other `reply_to`) | refused            | not an idempotent retry |
///
/// The pending acknowledgement is not answered here: the owner's reply is
/// sent only once the pure machine has the owner-side closure proof too and
/// is back in `Active`, and the reset that follows ends the exchange.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) enum AbortExchange {
    /// The coordinator has not queued an `ROTATE_ABORT` for this attempt.
    #[default]
    NotSent,
    /// The coordinator's unsolicited `ROTATE_ABORT` was queued.
    Sent {
        /// Its message id.  An owner abort has an empty `reply_to`, so it is
        /// not a journal completion of any peer phase message and needs
        /// this marker of its own.
        message_id: String,
        /// The connector's first authenticated `ROTATE_ABORTED`.
        peer_message_id: MessagePin,
        /// That acknowledgement, held until the owner-side closure proof is
        /// present.
        pending_ack: Option<Box<RotateAborted>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AbortEvent {
    /// The coordinator queued its `ROTATE_ABORT` with this message id.
    Queued(String),
    /// The connector's authenticated `ROTATE_ABORTED` was accepted by the
    /// pure machine.
    PeerAborted(Box<RotateAborted>),
    /// The attempt began or ended.
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalAbortTransition;

impl AbortExchange {
    /// The only place the abort exchange changes state.
    pub(super) fn on_event(&mut self, event: AbortEvent) -> Result<(), IllegalAbortTransition> {
        match (&mut *self, event) {
            (_, AbortEvent::Reset) => *self = Self::NotSent,
            (Self::NotSent, AbortEvent::Queued(message_id)) => {
                *self = Self::Sent {
                    message_id,
                    peer_message_id: MessagePin::default(),
                    pending_ack: None,
                };
            }
            (
                Self::Sent {
                    message_id,
                    peer_message_id,
                    pending_ack,
                },
                AbortEvent::PeerAborted(aborted),
            ) => {
                if *message_id != aborted.reply_to || !peer_message_id.pin(&aborted.message_id) {
                    return Err(IllegalAbortTransition);
                }
                *pending_ack = Some(aborted);
            }
            (Self::Sent { .. }, AbortEvent::Queued(_))
            | (Self::NotSent, AbortEvent::PeerAborted(_)) => {
                return Err(IllegalAbortTransition);
            }
        }
        Ok(())
    }

    /// The attempt began or ended: forget the exchange.
    pub(super) fn reset(&mut self) {
        // `Reset` is accepted in every state.
        let _ = self.on_event(AbortEvent::Reset);
    }

    /// The coordinator's abort was queued for this attempt.
    pub(super) fn is_sent(&self) -> bool {
        matches!(self, Self::Sent { .. })
    }

    /// The queued abort's message id.
    pub(super) fn message_id(&self) -> Option<&str> {
        match self {
            Self::NotSent => None,
            Self::Sent { message_id, .. } => Some(message_id),
        }
    }

    /// `incoming` could be pinned as the connector's `ROTATE_ABORTED`.
    /// With no abort sent there is no pin yet, so only an empty id is
    /// refused here; the `reply_to` check refuses the message itself.
    pub(super) fn peer_message_id_is_acceptable(&self, incoming: &str) -> bool {
        match self {
            Self::NotSent => !incoming.is_empty(),
            Self::Sent {
                peer_message_id, ..
            } => peer_message_id.is_acceptable(incoming),
        }
    }

    /// The connector's acknowledgement awaiting the owner's reply.
    pub(super) fn pending_ack(&self) -> Option<&RotateAborted> {
        match self {
            Self::NotSent => None,
            Self::Sent { pending_ack, .. } => pending_ack.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tunnel_protocol::rotation_control::{RotationAttemptIdentity, StreamFence};
    use tunnel_protocol::sequence::Direction;

    use super::*;

    fn fence(snapshot_id: &str, last_emitted: u64) -> FenceSnapshot {
        FenceSnapshot::new(
            snapshot_id,
            vec![StreamFence {
                stream_id: 1,
                direction: Direction::RelayToConnector,
                last_emitted,
            }],
        )
    }

    fn aborted(message_id: &str, reply_to: &str) -> Box<RotateAborted> {
        Box::new(RotateAborted {
            message_id: message_id.to_owned(),
            reply_to: reply_to.to_owned(),
            attempt: RotationAttemptIdentity::new(
                "session", 1, "owner", "attempt", 1, 2, "old", "new",
            ),
            reason: "test".to_owned(),
            closed_connection_id: "new".to_owned(),
        })
    }

    #[test]
    fn a_pin_is_set_once_and_never_replaced() {
        let mut pin = MessagePin::default();
        assert!(!pin.is_acceptable(""));
        assert!(!pin.pin(""), "an empty id is never pinned");
        assert_eq!(pin.get(), None);

        assert!(pin.is_acceptable("first"));
        assert!(pin.pin("first"));
        assert_eq!(pin.get(), Some("first"));
        assert!(pin.pin("first"), "the pinned id is an idempotent retry");
        assert!(!pin.is_acceptable("second"));
        assert!(!pin.pin("second"), "a fresh id never replaces the pin");
        assert!(!pin.pin(""));
        assert_eq!(pin.get(), Some("first"));
    }

    #[test]
    fn phase_pins_are_independent_and_cleared_together() {
        let mut pins = PeerPhasePins::default();
        assert!(pins.frozen.pin("frozen"));
        assert!(pins.drained.pin("drained"));
        assert!(pins.committed.pin("committed"));
        assert!(pins.retired.pin("retired"));
        assert_eq!(pins.frozen.get(), Some("frozen"));
        assert_eq!(pins.retired.get(), Some("retired"));
        pins.clear();
        assert_eq!(pins, PeerPhasePins::default());
        assert!(pins.frozen.pin("next-attempt"));
    }

    #[test]
    fn a_fence_is_immutable_once_taken() {
        let mut fences = RotationFences::default();
        assert!(fences.own().is_none());
        assert!(fences.remote(0).is_none() && fences.remote(1).is_none());

        assert_eq!(fences.record_own(fence("snapshot", 7)), Ok(()));
        assert_eq!(
            fences.record_own(fence("snapshot", 7)),
            Ok(()),
            "the identical fence is an idempotent repeat"
        );
        assert_eq!(
            fences.record_own(fence("snapshot", 8)),
            Err(ConflictingFence),
            "a taken fence is never moved"
        );
        assert_eq!(fences.own(), Some(&fence("snapshot", 7)));

        assert_eq!(fences.record_remote(1, fence("snapshot", 3)), Ok(()));
        assert_eq!(fences.record_remote(1, fence("snapshot", 3)), Ok(()));
        assert_eq!(
            fences.record_remote(1, fence("other", 3)),
            Err(ConflictingFence)
        );
        assert_eq!(fences.remote(1), Some(&fence("snapshot", 3)));
        assert!(fences.remote(0).is_none(), "directions are independent");
        assert_eq!(
            fences.record_remote(2, fence("snapshot", 3)),
            Err(ConflictingFence),
            "there are only two directions"
        );
        assert!(fences.remote(2).is_none());
    }

    #[test]
    fn fences_are_dropped_only_with_their_attempt() {
        let mut fences = RotationFences::default();
        fences.record_own(fence("snapshot", 7)).expect("own fence");
        fences
            .record_remote(0, fence("snapshot", 1))
            .expect("remote fence");
        fences.clear();
        assert_eq!(fences, RotationFences::default());
        assert_eq!(
            fences.record_own(fence("next", 9)),
            Ok(()),
            "the next attempt takes its own fence"
        );
    }

    #[test]
    fn an_abort_is_queued_exactly_once() {
        let mut abort = AbortExchange::default();
        assert!(!abort.is_sent());
        assert_eq!(abort.message_id(), None);
        assert!(abort.pending_ack().is_none());

        assert_eq!(
            abort.on_event(AbortEvent::Queued("abort".to_owned())),
            Ok(())
        );
        assert!(abort.is_sent());
        assert_eq!(abort.message_id(), Some("abort"));
        assert!(abort.pending_ack().is_none());

        let before = abort.clone();
        assert_eq!(
            abort.on_event(AbortEvent::Queued("second".to_owned())),
            Err(IllegalAbortTransition)
        );
        assert_eq!(abort, before, "a refusal leaves the exchange alone");
    }

    #[test]
    fn a_peer_acknowledgement_needs_the_abort_it_replies_to() {
        let mut abort = AbortExchange::default();
        assert!(abort.peer_message_id_is_acceptable("aborted"));
        assert!(!abort.peer_message_id_is_acceptable(""));
        assert_eq!(
            abort.on_event(AbortEvent::PeerAborted(aborted("aborted", ""))),
            Err(IllegalAbortTransition),
            "nothing was sent, so nothing can be acknowledged"
        );
        assert_eq!(abort, AbortExchange::NotSent);

        abort
            .on_event(AbortEvent::Queued("abort".to_owned()))
            .expect("queued");
        let before = abort.clone();
        assert_eq!(
            abort.on_event(AbortEvent::PeerAborted(aborted("aborted", "other-abort"))),
            Err(IllegalAbortTransition),
            "an acknowledgement of another abort is refused"
        );
        assert_eq!(
            abort.on_event(AbortEvent::PeerAborted(aborted("", "abort"))),
            Err(IllegalAbortTransition),
            "an acknowledgement without an id is refused"
        );
        assert_eq!(abort, before);

        assert_eq!(
            abort.on_event(AbortEvent::PeerAborted(aborted("aborted", "abort"))),
            Ok(())
        );
        assert_eq!(abort.pending_ack(), Some(&*aborted("aborted", "abort")));
        assert_eq!(abort.message_id(), Some("abort"));
        assert!(abort.peer_message_id_is_acceptable("aborted"));
        assert!(!abort.peer_message_id_is_acceptable("fresh"));

        // The pinned message is an idempotent retry; a fresh id is not.
        assert_eq!(
            abort.on_event(AbortEvent::PeerAborted(aborted("aborted", "abort"))),
            Ok(())
        );
        let before = abort.clone();
        assert_eq!(
            abort.on_event(AbortEvent::PeerAborted(aborted("fresh", "abort"))),
            Err(IllegalAbortTransition)
        );
        assert_eq!(abort, before);
    }

    #[test]
    fn a_reset_ends_the_exchange_from_every_state() {
        let mut abort = AbortExchange::default();
        abort.reset();
        assert_eq!(abort, AbortExchange::NotSent);

        abort
            .on_event(AbortEvent::Queued("abort".to_owned()))
            .expect("queued");
        abort
            .on_event(AbortEvent::PeerAborted(aborted("aborted", "abort")))
            .expect("acknowledged");
        abort.reset();
        assert_eq!(abort, AbortExchange::NotSent);
        assert!(abort.pending_ack().is_none());
        assert_eq!(
            abort.on_event(AbortEvent::Queued("next".to_owned())),
            Ok(()),
            "the next attempt can abort again"
        );
    }
}
