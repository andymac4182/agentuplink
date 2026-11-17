//! The connector's progress through one recovery attempt, as one explicit
//! state.
//!
//! `RecoveryRuntime` used to keep this as three `Option`s, one `bool` and
//! eight two-element arrays indexed by direction.  The combinations the
//! handlers could actually produce are the states below; the rest (a combined
//! closure digest without the peer's `RECOVERY_CLOSED`, a READY reply for a
//! direction whose snapshot was never answered, a fresh reconciliation before
//! both READY requests) have no representation.
//!
//! Episode stage, in order (guard sites are functions of `M2Actor`):
//!
//! | from            | event             | to           | guard site |
//! |-----------------|-------------------|--------------|------------|
//! | `Begun`         | `PeerClosed`      | `ClosedPair` | `handle_recovery_closed`: context, physical connection set and closure digest verified, journal entry new, no pair yet |
//! | `ClosedPair`    | `Prepared`        | `Prepared`   | `handle_rotate_prepare` (recovery purpose): attempt, episode, attempt number and combined digest bind this episode |
//! | `Prepared`, `Reconciled` | `Prepared` | unchanged stage, new PREPARE id | same site; the id was always overwritten |
//! | `Prepared`      | `FreshReconciled` | `Reconciled` | `maybe_finish_recovery`: both READY requests received, plans complete, obligations satisfied |
//!
//! `Begun` is entered by `handle_recovery_begin`, which builds the runtime
//! and sends this connector's `RECOVERY_CLOSED`.  Activation is not an event
//! here: `maybe_finish_recovery` moves the whole runtime to
//! `completed_recovery`, where it is retained to the episode deadline.
//!
//! RESUME leg, once per direction:
//!
//! | from               | event               | to                 | guard site |
//! |--------------------|---------------------|--------------------|------------|
//! | `AwaitingSnapshot` | `SnapshotRequested` | `SnapshotReceived` | `handle_resume`: `reply_to` is the PREPARE id, so the stage is `Prepared` |
//! | `SnapshotReceived` | `SnapshotReplied`   | `SnapshotReplied`  | `send_recovery_snapshot_replies`: candidate installed, both snapshots complete |
//! | `SnapshotReplied`  | `ReadyRequested`    | `ReadyReceived`    | `handle_resume`: `reply_to` is this leg's snapshot reply id |
//! | `ReadyReceived`    | `ReadyReplied`      | `ReadyReplied`     | `maybe_finish_recovery`: stage is `Reconciled`, successor installed |
//!
//! Every other (state, event) pair is refused and leaves the state unchanged.

/// How far one direction's RESUME exchange has come.
#[derive(Debug, Eq, PartialEq)]
enum ResumeLeg<R> {
    /// The owner has not sent this direction's snapshot RESUME.
    AwaitingSnapshot,
    /// The snapshot RESUME arrived; it is not answered yet.
    SnapshotReceived { request_id: String },
    /// The snapshot RESUMED was sent.
    SnapshotReplied {
        request_id: String,
        reply_id: String,
        reply: R,
    },
    /// The READY RESUME arrived; it is not answered yet.
    ReadyReceived {
        request_id: String,
        reply_id: String,
        reply: R,
        ready_request_id: String,
    },
    /// The READY RESUMED was sent.
    ReadyReplied {
        request_id: String,
        reply_id: String,
        reply: R,
        ready_request_id: String,
        ready_reply: R,
    },
}

impl<R> ResumeLeg<R> {
    fn name(&self) -> &'static str {
        match self {
            Self::AwaitingSnapshot => "awaiting_snapshot",
            Self::SnapshotReceived { .. } => "snapshot_received",
            Self::SnapshotReplied { .. } => "snapshot_replied",
            Self::ReadyReceived { .. } => "ready_received",
            Self::ReadyReplied { .. } => "ready_replied",
        }
    }
}

/// How far the episode-level handshake has come.
#[derive(Debug, Eq, PartialEq)]
enum Stage<C> {
    /// This connector's `RECOVERY_CLOSED` was sent; the owner's has not
    /// been accepted.
    Begun,
    /// Both closure records are held and their combined digest is fixed.
    ClosedPair {
        peer_closed: C,
        combined_digest: String,
    },
    /// The recovery candidate's PREPARE was accepted.
    Prepared {
        peer_closed: C,
        combined_digest: String,
        prepare_message_id: String,
    },
    /// Sequence state was reconciled once against the fresh READY pair.
    Reconciled {
        peer_closed: C,
        combined_digest: String,
        prepare_message_id: String,
    },
}

impl<C> Stage<C> {
    fn name(&self) -> &'static str {
        match self {
            Self::Begun => "begun",
            Self::ClosedPair { .. } => "closed_pair",
            Self::Prepared { .. } => "prepared",
            Self::Reconciled { .. } => "reconciled",
        }
    }
}

/// What can advance a [`RecoveryProgress`].  `index` is the direction index.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum RecoveryEvent<C, R> {
    /// The owner's `RECOVERY_CLOSED` was authenticated.
    PeerClosed {
        peer_closed: C,
        combined_digest: String,
    },
    /// The recovery candidate's PREPARE was accepted.
    Prepared { prepare_message_id: String },
    /// A direction's snapshot RESUME was accepted.
    SnapshotRequested { index: usize, request_id: String },
    /// A direction's snapshot RESUMED was built for sending.
    SnapshotReplied {
        index: usize,
        reply_id: String,
        reply: R,
    },
    /// A direction's READY RESUME was accepted.
    ReadyRequested { index: usize, request_id: String },
    /// Sequence state was reconciled against the fresh READY pair.
    FreshReconciled,
    /// A direction's READY RESUMED was built for sending.
    ReadyReplied { index: usize, reply: R },
}

impl<C, R> RecoveryEvent<C, R> {
    fn name(&self) -> &'static str {
        match self {
            Self::PeerClosed { .. } => "peer_closed",
            Self::Prepared { .. } => "prepared",
            Self::SnapshotRequested { .. } => "snapshot_requested",
            Self::SnapshotReplied { .. } => "snapshot_replied",
            Self::ReadyRequested { .. } => "ready_requested",
            Self::FreshReconciled => "fresh_reconciled",
            Self::ReadyReplied { .. } => "ready_replied",
        }
    }
}

/// A transition the recovery handshake does not have.  The progress is
/// unchanged.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct IllegalRecoveryTransition {
    /// The episode stage, or the leg state for a per-direction event.
    pub(super) from: &'static str,
    pub(super) event: &'static str,
}

/// One recovery attempt's handshake progress: the episode stage and the two
/// per-direction RESUME legs.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RecoveryProgress<C, R> {
    stage: Stage<C>,
    legs: [ResumeLeg<R>; 2],
}

impl<C, R> RecoveryProgress<C, R> {
    /// The progress of an attempt whose `RECOVERY_CLOSED` was just sent.
    pub(super) fn begun() -> Self {
        Self {
            stage: Stage::Begun,
            legs: [ResumeLeg::AwaitingSnapshot, ResumeLeg::AwaitingSnapshot],
        }
    }

    /// The owner's authenticated `RECOVERY_CLOSED`, once accepted.
    pub(super) fn peer_closed(&self) -> Option<&C> {
        match &self.stage {
            Stage::Begun => None,
            Stage::ClosedPair { peer_closed, .. }
            | Stage::Prepared { peer_closed, .. }
            | Stage::Reconciled { peer_closed, .. } => Some(peer_closed),
        }
    }

    /// The digest over both closure records, once both are held.
    pub(super) fn combined_digest(&self) -> Option<&str> {
        match &self.stage {
            Stage::Begun => None,
            Stage::ClosedPair {
                combined_digest, ..
            }
            | Stage::Prepared {
                combined_digest, ..
            }
            | Stage::Reconciled {
                combined_digest, ..
            } => Some(combined_digest),
        }
    }

    /// The recovery candidate's PREPARE id, once accepted.
    pub(super) fn prepare_message_id(&self) -> Option<&str> {
        match &self.stage {
            Stage::Begun | Stage::ClosedPair { .. } => None,
            Stage::Prepared {
                prepare_message_id, ..
            }
            | Stage::Reconciled {
                prepare_message_id, ..
            } => Some(prepare_message_id),
        }
    }

    /// Whether sequence state was reconciled against the fresh READY pair.
    pub(super) fn fresh_reconciled(&self) -> bool {
        matches!(self.stage, Stage::Reconciled { .. })
    }

    /// The id of a direction's snapshot RESUME, once received.
    pub(super) fn snapshot_request_id(&self, index: usize) -> Option<&str> {
        match &self.legs[index] {
            ResumeLeg::AwaitingSnapshot => None,
            ResumeLeg::SnapshotReceived { request_id }
            | ResumeLeg::SnapshotReplied { request_id, .. }
            | ResumeLeg::ReadyReceived { request_id, .. }
            | ResumeLeg::ReadyReplied { request_id, .. } => Some(request_id),
        }
    }

    /// Whether a direction's snapshot RESUMED was sent.
    pub(super) fn snapshot_replied(&self, index: usize) -> bool {
        self.snapshot_reply(index).is_some()
    }

    /// The id of a direction's snapshot RESUMED, once sent.
    pub(super) fn snapshot_reply_id(&self, index: usize) -> Option<&str> {
        match &self.legs[index] {
            ResumeLeg::AwaitingSnapshot | ResumeLeg::SnapshotReceived { .. } => None,
            ResumeLeg::SnapshotReplied { reply_id, .. }
            | ResumeLeg::ReadyReceived { reply_id, .. }
            | ResumeLeg::ReadyReplied { reply_id, .. } => Some(reply_id),
        }
    }

    /// A direction's snapshot RESUMED, once sent.
    pub(super) fn snapshot_reply(&self, index: usize) -> Option<&R> {
        match &self.legs[index] {
            ResumeLeg::AwaitingSnapshot | ResumeLeg::SnapshotReceived { .. } => None,
            ResumeLeg::SnapshotReplied { reply, .. }
            | ResumeLeg::ReadyReceived { reply, .. }
            | ResumeLeg::ReadyReplied { reply, .. } => Some(reply),
        }
    }

    /// The id of a direction's READY RESUME, once received.
    pub(super) fn ready_request_id(&self, index: usize) -> Option<&str> {
        match &self.legs[index] {
            ResumeLeg::AwaitingSnapshot
            | ResumeLeg::SnapshotReceived { .. }
            | ResumeLeg::SnapshotReplied { .. } => None,
            ResumeLeg::ReadyReceived {
                ready_request_id, ..
            }
            | ResumeLeg::ReadyReplied {
                ready_request_id, ..
            } => Some(ready_request_id),
        }
    }

    /// Whether both directions' READY RESUME were received.
    pub(super) fn both_ready_received(&self) -> bool {
        (0..self.legs.len()).all(|index| self.ready_request_id(index).is_some())
    }

    /// Whether a direction's READY RESUMED was sent.
    pub(super) fn ready_replied(&self, index: usize) -> bool {
        self.ready_reply(index).is_some()
    }

    /// A direction's READY RESUMED, once sent.
    pub(super) fn ready_reply(&self, index: usize) -> Option<&R> {
        match &self.legs[index] {
            ResumeLeg::ReadyReplied { ready_reply, .. } => Some(ready_reply),
            ResumeLeg::AwaitingSnapshot
            | ResumeLeg::SnapshotReceived { .. }
            | ResumeLeg::SnapshotReplied { .. }
            | ResumeLeg::ReadyReceived { .. } => None,
        }
    }

    /// The only place recovery handshake progress changes.
    pub(super) fn transition(
        &mut self,
        event: RecoveryEvent<C, R>,
    ) -> Result<(), IllegalRecoveryTransition> {
        let event_name = event.name();
        match event {
            RecoveryEvent::PeerClosed {
                peer_closed,
                combined_digest,
            } => self.stage_transition(event_name, |stage| match stage {
                Stage::Begun => Ok(Stage::ClosedPair {
                    peer_closed,
                    combined_digest,
                }),
                other => Err(other),
            }),
            RecoveryEvent::Prepared { prepare_message_id } => {
                self.stage_transition(event_name, |stage| match stage {
                    Stage::ClosedPair {
                        peer_closed,
                        combined_digest,
                    }
                    | Stage::Prepared {
                        peer_closed,
                        combined_digest,
                        ..
                    } => Ok(Stage::Prepared {
                        peer_closed,
                        combined_digest,
                        prepare_message_id,
                    }),
                    Stage::Reconciled {
                        peer_closed,
                        combined_digest,
                        ..
                    } => Ok(Stage::Reconciled {
                        peer_closed,
                        combined_digest,
                        prepare_message_id,
                    }),
                    other @ Stage::Begun => Err(other),
                })
            }
            RecoveryEvent::FreshReconciled => {
                if !self.both_ready_received() {
                    return Err(IllegalRecoveryTransition {
                        from: self.stage.name(),
                        event: event_name,
                    });
                }
                self.stage_transition(event_name, |stage| match stage {
                    Stage::Prepared {
                        peer_closed,
                        combined_digest,
                        prepare_message_id,
                    } => Ok(Stage::Reconciled {
                        peer_closed,
                        combined_digest,
                        prepare_message_id,
                    }),
                    other => Err(other),
                })
            }
            RecoveryEvent::SnapshotRequested { index, request_id } => {
                if self.prepare_message_id().is_none() {
                    return Err(IllegalRecoveryTransition {
                        from: self.stage.name(),
                        event: event_name,
                    });
                }
                self.leg_transition(index, event_name, |leg| match leg {
                    ResumeLeg::AwaitingSnapshot => Ok(ResumeLeg::SnapshotReceived { request_id }),
                    other => Err(other),
                })
            }
            RecoveryEvent::SnapshotReplied {
                index,
                reply_id,
                reply,
            } => self.leg_transition(index, event_name, |leg| match leg {
                ResumeLeg::SnapshotReceived { request_id } => Ok(ResumeLeg::SnapshotReplied {
                    request_id,
                    reply_id,
                    reply,
                }),
                other => Err(other),
            }),
            RecoveryEvent::ReadyRequested {
                index,
                request_id: ready_request_id,
            } => self.leg_transition(index, event_name, |leg| match leg {
                ResumeLeg::SnapshotReplied {
                    request_id,
                    reply_id,
                    reply,
                } => Ok(ResumeLeg::ReadyReceived {
                    request_id,
                    reply_id,
                    reply,
                    ready_request_id,
                }),
                other => Err(other),
            }),
            RecoveryEvent::ReadyReplied {
                index,
                reply: ready_reply,
            } => {
                if !self.fresh_reconciled() {
                    return Err(IllegalRecoveryTransition {
                        from: self.stage.name(),
                        event: event_name,
                    });
                }
                self.leg_transition(index, event_name, |leg| match leg {
                    ResumeLeg::ReadyReceived {
                        request_id,
                        reply_id,
                        reply,
                        ready_request_id,
                    } => Ok(ResumeLeg::ReadyReplied {
                        request_id,
                        reply_id,
                        reply,
                        ready_request_id,
                        ready_reply,
                    }),
                    other => Err(other),
                })
            }
        }
    }

    fn stage_transition(
        &mut self,
        event: &'static str,
        step: impl FnOnce(Stage<C>) -> Result<Stage<C>, Stage<C>>,
    ) -> Result<(), IllegalRecoveryTransition> {
        let from = self.stage.name();
        match step(std::mem::replace(&mut self.stage, Stage::Begun)) {
            Ok(next) => {
                self.stage = next;
                Ok(())
            }
            Err(unchanged) => {
                self.stage = unchanged;
                Err(IllegalRecoveryTransition { from, event })
            }
        }
    }

    fn leg_transition(
        &mut self,
        index: usize,
        event: &'static str,
        step: impl FnOnce(ResumeLeg<R>) -> Result<ResumeLeg<R>, ResumeLeg<R>>,
    ) -> Result<(), IllegalRecoveryTransition> {
        let Some(leg) = self.legs.get_mut(index) else {
            return Err(IllegalRecoveryTransition {
                from: "no_such_direction",
                event,
            });
        };
        let from = leg.name();
        match step(std::mem::replace(leg, ResumeLeg::AwaitingSnapshot)) {
            Ok(next) => {
                *leg = next;
                Ok(())
            }
            Err(unchanged) => {
                *leg = unchanged;
                Err(IllegalRecoveryTransition { from, event })
            }
        }
    }
}

impl IllegalRecoveryTransition {
    /// The payload-free protocol error text for a refused step.
    pub(super) fn detail(&self) -> String {
        format!("recovery step rejected {} while {}", self.event, self.from)
    }
}

/// Fixtures for actor tests that start part-way through a recovery.  They
/// reach their state through `transition`, so they cannot build one the
/// handlers could not.
#[cfg(test)]
impl<C: Default, R: Default> RecoveryProgress<C, R> {
    fn advanced_for_test(events: impl IntoIterator<Item = RecoveryEvent<C, R>>) -> Self {
        let mut progress = Self::begun();
        for event in events {
            progress
                .transition(event)
                .expect("fixture follows the legal recovery path");
        }
        progress
    }

    /// Both closure records held and the candidate PREPARE accepted.
    pub(super) fn prepared_for_test(prepare_message_id: &str) -> Self {
        Self::advanced_for_test([
            RecoveryEvent::PeerClosed {
                peer_closed: C::default(),
                combined_digest: "fixture-combined-digest".to_owned(),
            },
            RecoveryEvent::Prepared {
                prepare_message_id: prepare_message_id.to_owned(),
            },
        ])
    }

    /// The whole handshake done: both READY replies sent.
    pub(super) fn finished_for_test(combined_digest: &str) -> Self {
        let mut events = vec![
            RecoveryEvent::PeerClosed {
                peer_closed: C::default(),
                combined_digest: combined_digest.to_owned(),
            },
            RecoveryEvent::Prepared {
                prepare_message_id: "fixture-prepare".to_owned(),
            },
        ];
        for index in [0, 1] {
            events.push(RecoveryEvent::SnapshotRequested {
                index,
                request_id: format!("fixture-snapshot-{index}"),
            });
            events.push(RecoveryEvent::SnapshotReplied {
                index,
                reply_id: format!("fixture-snapshot-reply-{index}"),
                reply: R::default(),
            });
            events.push(RecoveryEvent::ReadyRequested {
                index,
                request_id: format!("fixture-ready-{index}"),
            });
        }
        events.push(RecoveryEvent::FreshReconciled);
        for index in [0, 1] {
            events.push(RecoveryEvent::ReadyReplied {
                index,
                reply: R::default(),
            });
        }
        Self::advanced_for_test(events)
    }
}

#[cfg(test)]
mod tests {
    use super::{IllegalRecoveryTransition, RecoveryEvent, RecoveryProgress};

    type Progress = RecoveryProgress<&'static str, &'static str>;
    type Event = RecoveryEvent<&'static str, &'static str>;

    fn peer_closed() -> Event {
        Event::PeerClosed {
            peer_closed: "peer-closed",
            combined_digest: "digest".to_owned(),
        }
    }

    fn prepared(id: &str) -> Event {
        Event::Prepared {
            prepare_message_id: id.to_owned(),
        }
    }

    fn snapshot_requested(index: usize) -> Event {
        Event::SnapshotRequested {
            index,
            request_id: format!("snapshot-{index}"),
        }
    }

    fn snapshot_replied(index: usize) -> Event {
        Event::SnapshotReplied {
            index,
            reply_id: format!("snapshot-reply-{index}"),
            reply: "snapshot-reply",
        }
    }

    fn ready_requested(index: usize) -> Event {
        Event::ReadyRequested {
            index,
            request_id: format!("ready-{index}"),
        }
    }

    fn ready_replied(index: usize) -> Event {
        Event::ReadyReplied {
            index,
            reply: "ready-reply",
        }
    }

    fn apply(progress: &mut Progress, events: impl IntoIterator<Item = Event>) {
        for event in events {
            let name = format!("{event:?}");
            progress
                .transition(event)
                .unwrap_or_else(|illegal| panic!("{name} refused: {illegal:?}"));
        }
    }

    /// Every stage/leg combination the legal path passes through, in order.
    fn legal_path() -> Vec<Event> {
        vec![
            peer_closed(),
            prepared("prepare"),
            snapshot_requested(0),
            snapshot_requested(1),
            snapshot_replied(0),
            snapshot_replied(1),
            ready_requested(0),
            ready_requested(1),
            Event::FreshReconciled,
            ready_replied(0),
            ready_replied(1),
        ]
    }

    fn refused(progress: &mut Progress, event: Event, from: &'static str, name: &'static str) {
        let before = format!("{progress:?}");
        assert_eq!(
            progress.transition(event),
            Err(IllegalRecoveryTransition { from, event: name })
        );
        assert_eq!(
            format!("{progress:?}"),
            before,
            "a refused event must not change the progress"
        );
    }

    #[test]
    fn recovery_progress_walks_the_whole_handshake() {
        let mut progress = Progress::begun();
        assert_eq!(progress.peer_closed(), None);
        assert_eq!(progress.combined_digest(), None);
        assert_eq!(progress.prepare_message_id(), None);
        assert!(!progress.fresh_reconciled());

        apply(&mut progress, [peer_closed()]);
        assert_eq!(progress.peer_closed(), Some(&"peer-closed"));
        assert_eq!(progress.combined_digest(), Some("digest"));
        assert_eq!(progress.prepare_message_id(), None);

        apply(&mut progress, [prepared("prepare")]);
        assert_eq!(progress.combined_digest(), Some("digest"));
        assert_eq!(progress.prepare_message_id(), Some("prepare"));

        for index in [1, 0] {
            assert_eq!(progress.snapshot_request_id(index), None);
            apply(&mut progress, [snapshot_requested(index)]);
            assert_eq!(
                progress.snapshot_request_id(index),
                Some(format!("snapshot-{index}").as_str())
            );
            assert!(!progress.snapshot_replied(index));
            assert_eq!(progress.snapshot_reply_id(index), None);
            apply(&mut progress, [snapshot_replied(index)]);
            assert!(progress.snapshot_replied(index));
            assert_eq!(
                progress.snapshot_reply_id(index),
                Some(format!("snapshot-reply-{index}").as_str())
            );
            assert_eq!(progress.snapshot_reply(index), Some(&"snapshot-reply"));
            assert_eq!(progress.ready_request_id(index), None);
        }
        assert!(!progress.both_ready_received());
        apply(&mut progress, [ready_requested(0)]);
        assert!(!progress.both_ready_received());
        apply(&mut progress, [ready_requested(1)]);
        assert!(progress.both_ready_received());
        assert_eq!(progress.ready_request_id(1), Some("ready-1"));

        assert!(!progress.fresh_reconciled());
        apply(&mut progress, [Event::FreshReconciled]);
        assert!(progress.fresh_reconciled());
        assert_eq!(progress.prepare_message_id(), Some("prepare"));

        for index in [0, 1] {
            assert!(!progress.ready_replied(index));
            apply(&mut progress, [ready_replied(index)]);
            assert!(progress.ready_replied(index));
            assert_eq!(progress.ready_reply(index), Some(&"ready-reply"));
            // Everything retained for duplicates is still there.
            assert_eq!(progress.snapshot_reply(index), Some(&"snapshot-reply"));
            assert_eq!(
                progress.snapshot_request_id(index),
                Some(format!("snapshot-{index}").as_str())
            );
        }
    }

    #[test]
    fn recovery_progress_replaces_the_prepare_id_without_losing_progress() {
        let mut progress = Progress::begun();
        apply(
            &mut progress,
            [
                peer_closed(),
                prepared("first"),
                snapshot_requested(0),
                prepared("second"),
            ],
        );
        assert_eq!(progress.prepare_message_id(), Some("second"));
        assert_eq!(progress.snapshot_request_id(0), Some("snapshot-0"));
        assert!(!progress.fresh_reconciled());

        let mut progress = Progress::begun();
        apply(&mut progress, legal_path());
        apply(&mut progress, [prepared("late")]);
        assert_eq!(progress.prepare_message_id(), Some("late"));
        assert!(progress.fresh_reconciled());
        assert!(progress.ready_replied(0) && progress.ready_replied(1));
    }

    #[test]
    fn recovery_progress_refuses_stage_events_out_of_order() {
        let mut progress = Progress::begun();
        refused(&mut progress, prepared("early"), "begun", "prepared");
        refused(
            &mut progress,
            Event::FreshReconciled,
            "begun",
            "fresh_reconciled",
        );
        refused(
            &mut progress,
            snapshot_requested(0),
            "begun",
            "snapshot_requested",
        );

        apply(&mut progress, [peer_closed()]);
        // A combined digest is fixed once: a second closure record is refused.
        refused(&mut progress, peer_closed(), "closed_pair", "peer_closed");
        refused(
            &mut progress,
            snapshot_requested(0),
            "closed_pair",
            "snapshot_requested",
        );

        apply(&mut progress, [prepared("prepare")]);
        refused(&mut progress, peer_closed(), "prepared", "peer_closed");
        // Fresh reconciliation needs both READY requests.
        refused(
            &mut progress,
            Event::FreshReconciled,
            "prepared",
            "fresh_reconciled",
        );
        apply(
            &mut progress,
            [
                snapshot_requested(0),
                snapshot_requested(1),
                snapshot_replied(0),
                snapshot_replied(1),
                ready_requested(0),
            ],
        );
        refused(
            &mut progress,
            Event::FreshReconciled,
            "prepared",
            "fresh_reconciled",
        );
        // A READY reply needs the fresh reconciliation.
        refused(&mut progress, ready_replied(0), "prepared", "ready_replied");
        apply(&mut progress, [ready_requested(1), Event::FreshReconciled]);
        refused(
            &mut progress,
            Event::FreshReconciled,
            "reconciled",
            "fresh_reconciled",
        );
        refused(&mut progress, peer_closed(), "reconciled", "peer_closed");
    }

    #[test]
    fn recovery_progress_refuses_leg_events_out_of_order() {
        let mut progress = Progress::begun();
        apply(&mut progress, [peer_closed(), prepared("prepare")]);

        // Nothing but the snapshot request is legal on a fresh leg.
        refused(
            &mut progress,
            snapshot_replied(0),
            "awaiting_snapshot",
            "snapshot_replied",
        );
        refused(
            &mut progress,
            ready_requested(0),
            "awaiting_snapshot",
            "ready_requested",
        );

        apply(&mut progress, [snapshot_requested(0)]);
        refused(
            &mut progress,
            snapshot_requested(0),
            "snapshot_received",
            "snapshot_requested",
        );
        // A READY request needs this direction's snapshot reply.
        refused(
            &mut progress,
            ready_requested(0),
            "snapshot_received",
            "ready_requested",
        );
        // The other direction is independent and still fresh.
        refused(
            &mut progress,
            snapshot_replied(1),
            "awaiting_snapshot",
            "snapshot_replied",
        );

        apply(&mut progress, [snapshot_replied(0)]);
        refused(
            &mut progress,
            snapshot_replied(0),
            "snapshot_replied",
            "snapshot_replied",
        );
        refused(
            &mut progress,
            snapshot_requested(0),
            "snapshot_replied",
            "snapshot_requested",
        );

        apply(&mut progress, [ready_requested(0)]);
        refused(
            &mut progress,
            ready_requested(0),
            "ready_received",
            "ready_requested",
        );

        apply(
            &mut progress,
            [
                snapshot_requested(1),
                snapshot_replied(1),
                ready_requested(1),
                Event::FreshReconciled,
                ready_replied(0),
            ],
        );
        refused(
            &mut progress,
            ready_replied(0),
            "ready_replied",
            "ready_replied",
        );
        refused(
            &mut progress,
            snapshot_requested(0),
            "ready_replied",
            "snapshot_requested",
        );
        refused(
            &mut progress,
            ready_replied(2),
            "no_such_direction",
            "ready_replied",
        );
    }
}
