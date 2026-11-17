//! Sub-phase state of one rotation attempt.
//!
//! [`crate::rotation::RotationState`] owns the lifecycle phase.  This module
//! owns what an attempt has achieved inside that phase, as data that exists
//! only where it is meaningful.  The fields of [`AttemptProgress`] are private:
//! the transition methods below are the only writers, and each one refuses a
//! step its current state does not allow with [`IllegalTransition`].
//!
//! Transition table (`->` is the only legal move; everything else is refused):
//!
//! | Method | From | To |
//! | --- | --- | --- |
//! | `mark_candidate_ready` | `Preparing(Dialing or Ready)` | `Preparing(Ready)` |
//! | `quiesce` | `Preparing(Ready)` | `Fencing { Open, Open }` |
//! | `freeze(d)` | `Fencing`, side `d` `Open`, no side `Drained` | side `d` `Frozen` |
//! | `drain(d)` | `Fencing`, side `d` `Frozen`, other side not `Open` | side `d` `Drained`; both `Drained` -> `Committing(NotSent)` |
//! | `send_commit` | `Committing(NotSent or Sent)` | `Committing(Sent)` |
//! | `accept_commit` | `Committing(Sent)` | `Retiring(NotSent)` |
//! | `send_retire` | `Retiring(NotSent or Sent)` | `Retiring(Sent)`, closure kept |
//! | `close_old_socket(s)` | `Retiring(Sent)` | closure records side `s` |
//! | `close_candidate_socket(s)` | any | closure records side `s` |
//! | `reserve_recovery_socket` | `Recovery(NeverReserved)` | `Recovery(Reserved)` |
//! | `release_recovery_socket` | `Recovery(Reserved)` | `Recovery(Released)` |
//!
//! A scheduled handover that is aborted or enters recovery keeps the progress
//! it had reached: the status snapshot still reports it and the recovery
//! anchor depends on whether the commit was accepted.  The accepted commit is
//! the `Retiring` stage itself, so "accepted but not sent" and "retire sent
//! before acceptance" have no representation.  A recovery attempt has no
//! handover stages at all; it holds only its episode roster and its
//! single-use candidate reservation.

use crate::rotation::RotationSide;
use crate::rotation_control::{DrainProof, DrainSet, FenceSnapshot, StreamRoster};
use crate::sequence::Direction;

/// A transition method was called in a state that does not allow it.  The
/// state is left unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IllegalTransition;

/// Candidate attachment progress while `Preparing`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateReadiness {
    Dialing,
    Ready,
}

/// One direction's immutable fence during `Quiescing` and `Draining`.  A
/// drain proof cannot exist without the fence it proves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SideFence {
    Open,
    Frozen(FenceSnapshot),
    Drained {
        fences: FenceSnapshot,
        proof: DrainProof,
    },
}

impl SideFence {
    pub(crate) fn fences(&self) -> Option<&FenceSnapshot> {
        match self {
            Self::Open => None,
            Self::Frozen(fences) | Self::Drained { fences, .. } => Some(fences),
        }
    }

    pub(crate) fn proof(&self) -> Option<&DrainProof> {
        match self {
            Self::Open | Self::Frozen(_) => None,
            Self::Drained { proof, .. } => Some(proof),
        }
    }

    fn freeze(&mut self, fences: FenceSnapshot) -> Result<(), IllegalTransition> {
        match self {
            Self::Open => {
                *self = Self::Frozen(fences);
                Ok(())
            }
            Self::Frozen(_) | Self::Drained { .. } => Err(IllegalTransition),
        }
    }

    fn drain(&mut self, proof: DrainProof) -> Result<(), IllegalTransition> {
        match core::mem::replace(self, Self::Open) {
            Self::Frozen(fences) => {
                *self = Self::Drained { fences, proof };
                Ok(())
            }
            other => {
                *self = other;
                Err(IllegalTransition)
            }
        }
    }
}

/// The owner's commit decision while `Committing`.  Acceptance is not a
/// variant: an accepted commit is the `Retiring` stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitDecision {
    NotSent,
    Sent,
}

/// Which endpoints have attested that one physical socket is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketClosure {
    Open,
    ClosedBy(RotationSide),
    Closed,
}

impl SocketClosure {
    /// Record one side's attestation.  Repeating a side changes nothing.
    #[must_use]
    pub(crate) fn record(self, side: RotationSide) -> Self {
        match self {
            Self::Open => Self::ClosedBy(side),
            Self::ClosedBy(recorded) if recorded == side => self,
            Self::ClosedBy(_) | Self::Closed => Self::Closed,
        }
    }

    pub(crate) fn is_closed_by(self, side: RotationSide) -> bool {
        match self {
            Self::Open => false,
            Self::ClosedBy(recorded) => recorded == side,
            Self::Closed => true,
        }
    }

    pub(crate) fn any_closed(self) -> bool {
        self != Self::Open
    }

    pub(crate) fn is_closed(self) -> bool {
        self == Self::Closed
    }

    /// `[owner, connector]`, the order of the status snapshot.
    pub(crate) fn flags(self) -> [bool; 2] {
        [
            self.is_closed_by(RotationSide::Owner),
            self.is_closed_by(RotationSide::Connector),
        ]
    }
}

/// Old-carrier retirement while `Retiring`.  Close evidence is recorded only
/// after RETIRE was sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Retirement {
    NotSent,
    Sent { old_socket: SocketClosure },
}

/// The single-use candidate reservation of a recovery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoverySocket {
    NeverReserved,
    Reserved,
    Released,
}

/// How far a scheduled handover has progressed.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Handover {
    Preparing(CandidateReadiness),
    /// `Quiescing` (not every side frozen) and `Draining` (every side frozen).
    Fencing {
        roster: StreamRoster,
        sides: [SideFence; 2],
    },
    Committing {
        proofs: DrainSet,
        commit: CommitDecision,
    },
    /// The connector accepted the commit.
    Retiring(Retirement),
}

/// What kind of attempt this is.  A kind never changes.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AttemptKind {
    Scheduled(Box<Handover>),
    /// Allocated by a validated RECOVERY_BEGIN.
    Recovery {
        roster: StreamRoster,
        socket: RecoverySocket,
    },
}

/// Sub-phase progress of one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttemptProgress {
    kind: AttemptKind,
    /// Candidate close evidence, recorded while `Aborting` or `Recovering`.
    candidate_socket: SocketClosure,
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::RelayToConnector => 0,
        Direction::ConnectorToRelay => 1,
    }
}

impl AttemptProgress {
    /// A scheduled handover whose candidate is still dialing.
    pub(crate) fn scheduled() -> Self {
        Self {
            kind: AttemptKind::Scheduled(Box::new(Handover::Preparing(
                CandidateReadiness::Dialing,
            ))),
            candidate_socket: SocketClosure::Open,
        }
    }

    /// A recovery attempt with its episode roster and no reservation yet.
    pub(crate) fn recovery(roster: StreamRoster) -> Self {
        Self {
            kind: AttemptKind::Recovery {
                roster,
                socket: RecoverySocket::NeverReserved,
            },
            candidate_socket: SocketClosure::Open,
        }
    }

    fn handover(&self) -> Option<&Handover> {
        match &self.kind {
            AttemptKind::Scheduled(handover) => Some(&**handover),
            AttemptKind::Recovery { .. } => None,
        }
    }

    fn handover_mut(&mut self) -> Result<&mut Handover, IllegalTransition> {
        match &mut self.kind {
            AttemptKind::Scheduled(handover) => Ok(&mut **handover),
            AttemptKind::Recovery { .. } => Err(IllegalTransition),
        }
    }

    pub(crate) fn is_recovery(&self) -> bool {
        matches!(self.kind, AttemptKind::Recovery { .. })
    }

    pub(crate) fn candidate_ready(&self) -> bool {
        match self.handover() {
            None | Some(Handover::Preparing(CandidateReadiness::Dialing)) => false,
            Some(_) => true,
        }
    }

    /// The roster fixed at QUIESCE, while fences are being exchanged.
    pub(crate) fn fencing_roster(&self) -> Option<&StreamRoster> {
        match self.handover() {
            Some(Handover::Fencing { roster, .. }) => Some(roster),
            _ => None,
        }
    }

    pub(crate) fn side_fence(&self, direction: Direction) -> Option<&SideFence> {
        match self.handover() {
            Some(Handover::Fencing { sides, .. }) => Some(&sides[direction_index(direction)]),
            _ => None,
        }
    }

    pub(crate) fn frozen_fence(&self, direction: Direction) -> Option<&FenceSnapshot> {
        self.side_fence(direction).and_then(SideFence::fences)
    }

    /// `[relay_to_connector, connector_to_relay]`.
    pub(crate) fn writers_frozen(&self) -> [bool; 2] {
        match self.handover() {
            None | Some(Handover::Preparing(_)) => [false, false],
            Some(Handover::Fencing { sides, .. }) => {
                [sides[0].fences().is_some(), sides[1].fences().is_some()]
            }
            Some(Handover::Committing { .. } | Handover::Retiring(_)) => [true, true],
        }
    }

    /// `[relay_to_connector, connector_to_relay]`.
    pub(crate) fn drain_proofs(&self) -> [bool; 2] {
        match self.handover() {
            None | Some(Handover::Preparing(_)) => [false, false],
            Some(Handover::Fencing { sides, .. }) => {
                [sides[0].proof().is_some(), sides[1].proof().is_some()]
            }
            Some(Handover::Committing { .. } | Handover::Retiring(_)) => [true, true],
        }
    }

    /// Both drain proofs, held while the commit decision is pending.
    pub(crate) fn drain_set(&self) -> Option<&DrainSet> {
        match self.handover() {
            Some(Handover::Committing { proofs, .. }) => Some(proofs),
            _ => None,
        }
    }

    pub(crate) fn commit_sent(&self) -> bool {
        matches!(
            self.handover(),
            Some(
                Handover::Committing {
                    commit: CommitDecision::Sent,
                    ..
                } | Handover::Retiring(_)
            )
        )
    }

    pub(crate) fn commit_accepted(&self) -> bool {
        matches!(self.handover(), Some(Handover::Retiring(_)))
    }

    pub(crate) fn retirement(&self) -> Option<Retirement> {
        match self.handover() {
            Some(Handover::Retiring(retirement)) => Some(*retirement),
            _ => None,
        }
    }

    pub(crate) fn old_socket(&self) -> SocketClosure {
        match self.retirement() {
            Some(Retirement::Sent { old_socket }) => old_socket,
            Some(Retirement::NotSent) | None => SocketClosure::Open,
        }
    }

    pub(crate) fn candidate_socket(&self) -> SocketClosure {
        self.candidate_socket
    }

    /// The immutable episode roster of a recovery attempt.
    pub(crate) fn recovery_roster(&self) -> Option<&StreamRoster> {
        match &self.kind {
            AttemptKind::Recovery { roster, .. } => Some(roster),
            AttemptKind::Scheduled(_) => None,
        }
    }

    pub(crate) fn recovery_socket(&self) -> Option<RecoverySocket> {
        match &self.kind {
            AttemptKind::Recovery { socket, .. } => Some(*socket),
            AttemptKind::Scheduled(_) => None,
        }
    }

    /// Candidate DATA_READY.  Repeating it changes nothing.
    pub(crate) fn mark_candidate_ready(&mut self) -> Result<(), IllegalTransition> {
        match self.handover_mut()? {
            Handover::Preparing(readiness) => {
                *readiness = CandidateReadiness::Ready;
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }

    /// Fix the roster and open both fences.  Requires a ready candidate.
    pub(crate) fn quiesce(&mut self, roster: StreamRoster) -> Result<(), IllegalTransition> {
        let handover = self.handover_mut()?;
        match handover {
            Handover::Preparing(CandidateReadiness::Ready) => {
                *handover = Handover::Fencing {
                    roster,
                    sides: [SideFence::Open, SideFence::Open],
                };
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }

    /// Record one direction's immutable fence.  Returns whether both
    /// directions are now frozen.
    pub(crate) fn freeze(
        &mut self,
        direction: Direction,
        fences: FenceSnapshot,
    ) -> Result<bool, IllegalTransition> {
        let Handover::Fencing { sides, .. } = self.handover_mut()? else {
            return Err(IllegalTransition);
        };
        if sides.iter().any(|side| side.proof().is_some()) {
            return Err(IllegalTransition);
        }
        sides[direction_index(direction)].freeze(fences)?;
        Ok(sides.iter().all(|side| side.fences().is_some()))
    }

    /// Record one direction's drain proof.  Refused until both directions
    /// are frozen.  When both are drained the handover moves to
    /// `Committing(NotSent)` and this returns `true`.
    pub(crate) fn drain(&mut self, proof: DrainProof) -> Result<bool, IllegalTransition> {
        let handover = self.handover_mut()?;
        let Handover::Fencing { sides, .. } = handover else {
            return Err(IllegalTransition);
        };
        let index = direction_index(proof.direction);
        if sides[1 - index].fences().is_none() {
            return Err(IllegalTransition);
        }
        sides[index].drain(proof)?;
        let (Some(relay_to_connector), Some(connector_to_relay)) =
            (sides[0].proof().cloned(), sides[1].proof().cloned())
        else {
            return Ok(false);
        };
        *handover = Handover::Committing {
            proofs: DrainSet {
                relay_to_connector,
                connector_to_relay,
            },
            commit: CommitDecision::NotSent,
        };
        Ok(true)
    }

    /// The owner sent COMMIT.  Repeating it changes nothing.
    pub(crate) fn send_commit(&mut self) -> Result<(), IllegalTransition> {
        match self.handover_mut()? {
            Handover::Committing { commit, .. } => {
                *commit = CommitDecision::Sent;
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }

    /// The connector acknowledged activation of a sent COMMIT.
    pub(crate) fn accept_commit(&mut self) -> Result<(), IllegalTransition> {
        let handover = self.handover_mut()?;
        match handover {
            Handover::Committing {
                commit: CommitDecision::Sent,
                ..
            } => {
                *handover = Handover::Retiring(Retirement::NotSent);
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }

    /// The owner sent RETIRE.  Repeating it keeps recorded close evidence.
    pub(crate) fn send_retire(&mut self) -> Result<(), IllegalTransition> {
        match self.handover_mut()? {
            Handover::Retiring(retirement) => {
                if *retirement == Retirement::NotSent {
                    *retirement = Retirement::Sent {
                        old_socket: SocketClosure::Open,
                    };
                }
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }

    /// Record one side's old-carrier close evidence after RETIRE.
    pub(crate) fn close_old_socket(
        &mut self,
        side: RotationSide,
    ) -> Result<SocketClosure, IllegalTransition> {
        match self.handover_mut()? {
            Handover::Retiring(Retirement::Sent { old_socket }) => {
                *old_socket = old_socket.record(side);
                Ok(*old_socket)
            }
            _ => Err(IllegalTransition),
        }
    }

    /// Record one side's candidate close evidence.
    pub(crate) fn close_candidate_socket(&mut self, side: RotationSide) -> SocketClosure {
        self.candidate_socket = self.candidate_socket.record(side);
        self.candidate_socket
    }

    /// Reserve the recovery candidate.  An attempt reserves at most once; a
    /// retry is a new attempt.
    pub(crate) fn reserve_recovery_socket(&mut self) -> Result<(), IllegalTransition> {
        match &mut self.kind {
            AttemptKind::Recovery { socket, .. } if *socket == RecoverySocket::NeverReserved => {
                *socket = RecoverySocket::Reserved;
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }

    /// Release a reserved recovery candidate after its close evidence.
    pub(crate) fn release_recovery_socket(&mut self) -> Result<(), IllegalTransition> {
        match &mut self.kind {
            AttemptKind::Recovery { socket, .. } if *socket == RecoverySocket::Reserved => {
                *socket = RecoverySocket::Released;
                Ok(())
            }
            _ => Err(IllegalTransition),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation_control::StreamFence;

    const RELAY: Direction = Direction::RelayToConnector;
    const CONNECTOR: Direction = Direction::ConnectorToRelay;

    fn roster() -> StreamRoster {
        StreamRoster {
            snapshot_id: "snap".to_owned(),
            stream_ids: vec![11],
        }
    }

    fn fences(direction: Direction) -> FenceSnapshot {
        FenceSnapshot {
            snapshot_id: "snap".to_owned(),
            entries: vec![StreamFence {
                stream_id: 11,
                direction,
                last_emitted: 4,
            }],
        }
    }

    fn proof(direction: Direction) -> DrainProof {
        DrainProof::new("snap", "digest", direction, Vec::new())
    }

    fn preparing_ready() -> AttemptProgress {
        let mut progress = AttemptProgress::scheduled();
        progress.mark_candidate_ready().expect("ready");
        progress
    }

    fn fencing() -> AttemptProgress {
        let mut progress = preparing_ready();
        progress.quiesce(roster()).expect("quiesce");
        progress
    }

    fn draining() -> AttemptProgress {
        let mut progress = fencing();
        assert_eq!(progress.freeze(RELAY, fences(RELAY)), Ok(false));
        assert_eq!(progress.freeze(CONNECTOR, fences(CONNECTOR)), Ok(true));
        progress
    }

    fn committing() -> AttemptProgress {
        let mut progress = draining();
        assert_eq!(progress.drain(proof(RELAY)), Ok(false));
        assert_eq!(progress.drain(proof(CONNECTOR)), Ok(true));
        progress
    }

    fn commit_sent() -> AttemptProgress {
        let mut progress = committing();
        progress.send_commit().expect("commit");
        progress
    }

    fn retiring() -> AttemptProgress {
        let mut progress = commit_sent();
        progress.accept_commit().expect("accept");
        progress
    }

    fn retire_sent() -> AttemptProgress {
        let mut progress = retiring();
        progress.send_retire().expect("retire");
        progress
    }

    fn recovery_reserved() -> AttemptProgress {
        let mut progress = AttemptProgress::recovery(roster());
        progress.reserve_recovery_socket().expect("reserve");
        progress
    }

    fn recovery_released() -> AttemptProgress {
        let mut progress = recovery_reserved();
        progress.release_recovery_socket().expect("release");
        progress
    }

    /// Every reachable state, by name.
    fn all_states() -> Vec<(&'static str, AttemptProgress)> {
        let mut one_frozen = fencing();
        one_frozen
            .freeze(CONNECTOR, fences(CONNECTOR))
            .expect("freeze");
        let mut one_drained = draining();
        one_drained.drain(proof(CONNECTOR)).expect("drain");
        let mut old_half_closed = retire_sent();
        old_half_closed
            .close_old_socket(RotationSide::Owner)
            .expect("close");
        vec![
            ("dialing", AttemptProgress::scheduled()),
            ("ready", preparing_ready()),
            ("fencing", fencing()),
            ("one_frozen", one_frozen),
            ("draining", draining()),
            ("one_drained", one_drained),
            ("committing", committing()),
            ("commit_sent", commit_sent()),
            ("retiring", retiring()),
            ("retire_sent", retire_sent()),
            ("old_half_closed", old_half_closed),
            ("recovery", AttemptProgress::recovery(roster())),
            ("recovery_reserved", recovery_reserved()),
            ("recovery_released", recovery_released()),
        ]
    }

    /// Apply `step` to every reachable state.  It must succeed exactly in the
    /// `legal` states and otherwise refuse without changing anything.
    fn assert_legal_only_in(
        legal: &[&str],
        step: impl Fn(&mut AttemptProgress) -> Result<(), IllegalTransition>,
    ) {
        let states = all_states();
        for name in legal {
            assert!(
                states.iter().any(|(state, _)| state == name),
                "unknown state {name}"
            );
        }
        for (name, before) in states {
            let mut after = before.clone();
            let result = step(&mut after);
            if legal.contains(&name) {
                assert_eq!(result, Ok(()), "{name} must allow the step");
            } else {
                assert_eq!(result, Err(IllegalTransition), "{name} must refuse");
                assert_eq!(after, before, "{name} must be unchanged by a refusal");
            }
        }
    }

    #[test]
    fn candidate_ready_is_legal_only_while_preparing() {
        assert_legal_only_in(&["dialing", "ready"], AttemptProgress::mark_candidate_ready);
        assert!(!AttemptProgress::scheduled().candidate_ready());
        assert!(preparing_ready().candidate_ready());
    }

    #[test]
    fn quiesce_requires_a_ready_candidate() {
        assert_legal_only_in(&["ready"], |progress| progress.quiesce(roster()));
        let progress = fencing();
        assert_eq!(progress.fencing_roster(), Some(&roster()));
        assert_eq!(progress.side_fence(RELAY), Some(&SideFence::Open));
        assert_eq!(progress.side_fence(CONNECTOR), Some(&SideFence::Open));
        assert!(progress.candidate_ready());
    }

    #[test]
    fn freeze_is_legal_only_for_an_open_side_before_any_drain() {
        assert_legal_only_in(&["fencing", "one_frozen"], |progress| {
            progress.freeze(RELAY, fences(RELAY)).map(|_| ())
        });
        // The connector side of `one_frozen` is already frozen.
        assert_legal_only_in(&["fencing"], |progress| {
            progress.freeze(CONNECTOR, fences(CONNECTOR)).map(|_| ())
        });
        let progress = draining();
        assert_eq!(progress.writers_frozen(), [true, true]);
        assert_eq!(progress.frozen_fence(RELAY), Some(&fences(RELAY)));
        assert_eq!(progress.drain_proofs(), [false, false]);
    }

    #[test]
    fn drain_requires_both_fences_and_an_undrained_side() {
        assert_legal_only_in(&["draining", "one_drained"], |progress| {
            progress.drain(proof(RELAY)).map(|_| ())
        });
        // The connector side of `one_drained` already holds its proof.
        assert_legal_only_in(&["draining"], |progress| {
            progress.drain(proof(CONNECTOR)).map(|_| ())
        });
        let mut one_drained = draining();
        assert_eq!(one_drained.drain(proof(RELAY)), Ok(false));
        assert_eq!(one_drained.drain_proofs(), [true, false]);
        assert_eq!(one_drained.drain_set(), None);
        assert_eq!(
            one_drained.side_fence(RELAY).and_then(SideFence::proof),
            Some(&proof(RELAY))
        );
    }

    #[test]
    fn both_drain_proofs_enter_committing_with_the_paired_set() {
        let progress = committing();
        assert_eq!(
            progress.drain_set(),
            Some(&DrainSet {
                relay_to_connector: proof(RELAY),
                connector_to_relay: proof(CONNECTOR),
            })
        );
        assert_eq!(progress.writers_frozen(), [true, true]);
        assert_eq!(progress.drain_proofs(), [true, true]);
        assert!(!progress.commit_sent());
        assert!(!progress.commit_accepted());
    }

    #[test]
    fn commit_is_sent_only_while_committing_and_accepted_only_once_sent() {
        assert_legal_only_in(&["committing", "commit_sent"], AttemptProgress::send_commit);
        assert_legal_only_in(&["commit_sent"], AttemptProgress::accept_commit);
        let sent = commit_sent();
        assert!(sent.commit_sent());
        assert!(!sent.commit_accepted());
        let accepted = retiring();
        assert!(accepted.commit_sent());
        assert!(accepted.commit_accepted());
        assert_eq!(accepted.retirement(), Some(Retirement::NotSent));
        assert_eq!(accepted.drain_set(), None);
    }

    #[test]
    fn retire_is_sent_only_after_acceptance_and_keeps_close_evidence() {
        assert_legal_only_in(
            &["retiring", "retire_sent", "old_half_closed"],
            AttemptProgress::send_retire,
        );
        let mut progress = retire_sent();
        assert_eq!(
            progress.close_old_socket(RotationSide::Connector),
            Ok(SocketClosure::ClosedBy(RotationSide::Connector))
        );
        progress.send_retire().expect("repeated retire");
        assert_eq!(progress.old_socket().flags(), [false, true]);
    }

    #[test]
    fn old_socket_closes_only_after_retire_was_sent() {
        assert_legal_only_in(&["retire_sent", "old_half_closed"], |progress| {
            progress.close_old_socket(RotationSide::Owner).map(|_| ())
        });
        let mut progress = retire_sent();
        assert_eq!(progress.old_socket(), SocketClosure::Open);
        assert_eq!(
            progress.close_old_socket(RotationSide::Owner),
            Ok(SocketClosure::ClosedBy(RotationSide::Owner))
        );
        assert_eq!(
            progress.close_old_socket(RotationSide::Connector),
            Ok(SocketClosure::Closed)
        );
    }

    #[test]
    fn recovery_socket_is_reserved_once_and_released_only_while_reserved() {
        assert_legal_only_in(&["recovery"], AttemptProgress::reserve_recovery_socket);
        assert_legal_only_in(
            &["recovery_reserved"],
            AttemptProgress::release_recovery_socket,
        );
        assert_eq!(
            AttemptProgress::recovery(roster()).recovery_socket(),
            Some(RecoverySocket::NeverReserved)
        );
        assert_eq!(
            recovery_reserved().recovery_socket(),
            Some(RecoverySocket::Reserved)
        );
        assert_eq!(
            recovery_released().recovery_socket(),
            Some(RecoverySocket::Released)
        );
        assert_eq!(AttemptProgress::scheduled().recovery_socket(), None);
    }

    #[test]
    fn a_recovery_attempt_has_no_handover_progress() {
        let progress = recovery_reserved();
        assert!(progress.is_recovery());
        assert_eq!(progress.recovery_roster(), Some(&roster()));
        assert!(!progress.candidate_ready());
        assert_eq!(progress.writers_frozen(), [false, false]);
        assert_eq!(progress.drain_proofs(), [false, false]);
        assert!(!progress.commit_sent());
        assert!(!progress.commit_accepted());
        assert_eq!(progress.retirement(), None);
        assert_eq!(progress.fencing_roster(), None);
        assert!(!AttemptProgress::scheduled().is_recovery());
        assert_eq!(AttemptProgress::scheduled().recovery_roster(), None);
    }

    #[test]
    fn candidate_closure_is_recorded_in_every_state() {
        for (name, mut progress) in all_states() {
            assert_eq!(progress.candidate_socket(), SocketClosure::Open, "{name}");
            assert_eq!(
                progress.close_candidate_socket(RotationSide::Connector),
                SocketClosure::ClosedBy(RotationSide::Connector),
                "{name}"
            );
            assert_eq!(
                progress.close_candidate_socket(RotationSide::Owner),
                SocketClosure::Closed,
                "{name}"
            );
            assert_eq!(progress.candidate_socket().flags(), [true, true], "{name}");
        }
    }

    #[test]
    fn socket_closure_transition_table() {
        use RotationSide::{Connector, Owner};
        use SocketClosure::{Closed, ClosedBy, Open};
        let table = [
            (Open, Owner, ClosedBy(Owner)),
            (Open, Connector, ClosedBy(Connector)),
            (ClosedBy(Owner), Owner, ClosedBy(Owner)),
            (ClosedBy(Owner), Connector, Closed),
            (ClosedBy(Connector), Connector, ClosedBy(Connector)),
            (ClosedBy(Connector), Owner, Closed),
            (Closed, Owner, Closed),
            (Closed, Connector, Closed),
        ];
        for (from, side, to) in table {
            assert_eq!(from.record(side), to, "{from:?} + {side:?}");
        }
        assert_eq!(Open.flags(), [false, false]);
        assert_eq!(ClosedBy(Owner).flags(), [true, false]);
        assert_eq!(ClosedBy(Connector).flags(), [false, true]);
        assert_eq!(Closed.flags(), [true, true]);
        assert!(!Open.any_closed());
        assert!(ClosedBy(Owner).any_closed());
        assert!(!ClosedBy(Owner).is_closed());
        assert!(Closed.is_closed());
    }

    #[test]
    fn side_fence_transition_table() {
        let mut side = SideFence::Open;
        assert_eq!(side.drain(proof(RELAY)), Err(IllegalTransition));
        assert_eq!(side, SideFence::Open);
        assert_eq!(side.freeze(fences(RELAY)), Ok(()));
        assert_eq!(side.freeze(fences(RELAY)), Err(IllegalTransition));
        assert_eq!(side, SideFence::Frozen(fences(RELAY)));
        assert_eq!(side.drain(proof(RELAY)), Ok(()));
        assert_eq!(side.drain(proof(RELAY)), Err(IllegalTransition));
        assert_eq!(side.freeze(fences(RELAY)), Err(IllegalTransition));
        assert_eq!(
            side,
            SideFence::Drained {
                fences: fences(RELAY),
                proof: proof(RELAY),
            }
        );
    }
}
