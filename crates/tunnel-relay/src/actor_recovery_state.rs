//! The coordinator-side progress of one retained-recovery attempt.
//!
//! One `RecoveryRuntime` exists per recovery attempt: it is created when the
//! relay sends `RECOVERY_BEGIN` with its own `RECOVERY_CLOSED`, replaced by a
//! fresh one when a lost candidate is retried, and dropped when the
//! recovered candidate becomes the active carrier.  [`RecoveryProgress`] is
//! where that attempt is in the handshake.  It replaces the former
//! `peer_closed` / `closure_digest` / `candidate_ready` / `ready_sent` /
//! `remote_ready` / `activated` / `retry_not_before_ms` /
//! `retry_failed_connection_id` fields, whose combinations were not tied to
//! each other.
//!
//! # Transition table, as the actor implements it
//!
//! | from                         | event                 | to                           | guard site in `actor.rs` |
//! |------------------------------|-----------------------|------------------------------|--------------------------|
//! | (created)                    |                       | `LocalClosed`                | `begin_recovery_after_loss`'s and `retry_recovery_after_candidate_loss`'s `RecoveryRuntime` literals |
//! | `LocalClosed`                | `PeerClosureAccepted` | `ClosureAgreed{digest}`      | `handle_recovery_closed`: refused once a peer record was accepted |
//! | `ClosureAgreed`              | `CandidateAttached`   | `Attached{Resuming}`         | `attach_data_verified`: the ticket's closure digest must equal the agreed digest |
//! | `Attached{Resuming, ReadySent}` | `SnapshotsSent`    | `Attached{Resuming}`         | `start_recovery_snapshots`: phase `Recovering`, candidate attached and present |
//! | `Attached{Resuming}`         | `ReadySent`           | `Attached{ReadySent[f,f]}`   | `send_recovery_ready`: both READYs are queued as a pair, once |
//! | `Attached{ReadySent}`        | `RemoteReady(i)`      | `Attached{ReadySent}` with bit `i` | `handle_recovery_resumed`: READY `i` was sent and not yet acknowledged |
//! | `Attached{ReadySent[t,t]}`   | `Activated`           | `Attached{Activated}`        | `activate_recovery`: reached only from the acknowledged READY pair; at most once |
//! | `Attached{.., retry: None}`  | `RetryScheduled`      | `Attached{.., retry: Some}`  | `schedule_recovery_retry`: candidate attached, no retry pending |
//! | `Attached{.., retry: Some}`  | `RetryDispatched`     | `Attached{.., retry: None}`  | `dispatch_recovery_retry`: the delay elapsed inside the episode deadline |
//!
//! Every other (state, event) pair is refused and leaves the state alone.
//!
//! Where this differs from the states one might infer from the field names:
//!
//! * There is no separate "closure agreed, then candidate attached, then
//!   resuming" chain of three: attaching the candidate and starting the
//!   snapshot exchange are one step, and `SnapshotsSent` only restarts the
//!   exchange.
//! * The retry is not a state of its own but a side condition of an attached
//!   candidate.  It survives every exchange step, including activation: a
//!   candidate lost just before the READY pair is acknowledged leaves an
//!   activated attempt with a retry pending, and the retry timer then closes
//!   the session.  The dispatched retry replaces the whole runtime.
//! * The first attempt used to seed `closure_digest` with the relay's own
//!   record digest before the connector's record arrived.  Recovery tickets
//!   are minted only in `handle_recovery_closed`, always with the combined
//!   digest, so no ticket could match that seed; it is not kept.
//! * The connector's accepted `RECOVERY_CLOSED` record itself had no reader
//!   after acceptance; only the fact and the combined digest are retained.
//!
//! * `send_recovery_ready` used to test only "READY not sent yet"; it now
//!   tests "attached and READY not sent yet".  The two agree on every state
//!   the wire can produce: READY also needs both connector snapshots, which
//!   are accepted only as replies to the SNAPSHOT pair, and that pair is sent
//!   only on an attached candidate (a decoded `RESUMED` never has an empty
//!   `reply_to`).
//!
//! Combinations that can no longer be built: an accepted peer closure
//! without a digest, an attached candidate without an agreed closure, a READY
//! acknowledged before it was sent, one READY sent without the other,
//! activation without the acknowledged READY pair, and a retry with only one
//! of its deadline and failed-candidate identity.
//!
//! A transport acknowledgement appears nowhere in this machine: `ReadySent`
//! records that the coordinator queued its READY decisions, and
//! `RemoteReady` that the connector's authenticated `RESUMED` for that
//! direction was validated.

/// The delayed restart of an attempt whose candidate carrier was lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveryRetry {
    pub(super) not_before_ms: u64,
    pub(super) failed_connection_id: String,
}

/// The snapshot/READY exchange on an attached recovery candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeExchange {
    /// Snapshots and retained replay are in progress; READY is not sent.
    Resuming,
    /// Both READY decisions were queued; `remote_ready[i]` is whether the
    /// connector's READY for direction `i` was validated.
    ReadySent { remote_ready: [bool; 2] },
    /// The candidate's sequence state was reconciled and committed.
    Activated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    /// The relay's closure record is sent; the connector's is not accepted.
    LocalClosed,
    /// Both closure records are accepted under `digest`; a recovery ticket
    /// bound to it is being issued or is issued.
    ClosureAgreed { digest: String },
    /// The recovery candidate attached with a ticket bound to `digest`.
    Attached {
        digest: String,
        exchange: ResumeExchange,
        retry: Option<RecoveryRetry>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RecoveryEvent {
    /// The connector's `RECOVERY_CLOSED` was validated and combined with the
    /// relay's record into `digest`.
    PeerClosureAccepted { digest: String },
    /// The recovery candidate attached with a ticket bound to the digest.
    CandidateAttached,
    /// The relay queued its SNAPSHOT pair: the exchange (re)starts.
    SnapshotsSent,
    /// The relay queued both READY decisions.
    ReadySent,
    /// The connector's READY for one direction index was validated.
    RemoteReady(usize),
    /// The recovered sequence state is being committed.
    Activated,
    /// The attached candidate was lost; restart after a delay.
    RetryScheduled(RecoveryRetry),
    /// The delayed restart is being started.
    RetryDispatched,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IllegalRecoveryTransition {
    #[allow(dead_code)]
    pub(super) phase: &'static str,
    #[allow(dead_code)]
    pub(super) event: RecoveryEvent,
}

/// See the module documentation for the transition table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveryProgress(State);

impl RecoveryProgress {
    /// A new attempt: the relay's own closure record has been built.
    pub(super) fn local_closed() -> Self {
        Self(State::LocalClosed)
    }

    /// The only place a recovery attempt's progress changes.
    pub(super) fn on_event(
        &mut self,
        event: RecoveryEvent,
    ) -> Result<(), IllegalRecoveryTransition> {
        let next = match (&self.0, event) {
            (State::LocalClosed, RecoveryEvent::PeerClosureAccepted { digest }) => {
                State::ClosureAgreed { digest }
            }
            (State::ClosureAgreed { digest }, RecoveryEvent::CandidateAttached) => {
                State::Attached {
                    digest: digest.clone(),
                    exchange: ResumeExchange::Resuming,
                    retry: None,
                }
            }
            (
                State::Attached {
                    digest,
                    exchange,
                    retry,
                },
                event,
            ) => {
                let mut exchange = *exchange;
                let mut retry = retry.clone();
                match (exchange, retry.is_some(), event) {
                    (
                        ResumeExchange::Resuming | ResumeExchange::ReadySent { .. },
                        _,
                        RecoveryEvent::SnapshotsSent,
                    ) => exchange = ResumeExchange::Resuming,
                    (ResumeExchange::Resuming, _, RecoveryEvent::ReadySent) => {
                        exchange = ResumeExchange::ReadySent {
                            remote_ready: [false, false],
                        };
                    }
                    (
                        ResumeExchange::ReadySent { mut remote_ready },
                        _,
                        RecoveryEvent::RemoteReady(index),
                    ) if remote_ready.get(index) == Some(&false) => {
                        remote_ready[index] = true;
                        exchange = ResumeExchange::ReadySent { remote_ready };
                    }
                    (
                        ResumeExchange::ReadySent {
                            remote_ready: [true, true],
                        },
                        _,
                        RecoveryEvent::Activated,
                    ) => exchange = ResumeExchange::Activated,
                    (_, false, RecoveryEvent::RetryScheduled(scheduled)) => {
                        retry = Some(scheduled);
                    }
                    (_, true, RecoveryEvent::RetryDispatched) => retry = None,
                    (_, _, event) => return Err(self.illegal(event)),
                }
                State::Attached {
                    digest: digest.clone(),
                    exchange,
                    retry,
                }
            }
            (_, event) => return Err(self.illegal(event)),
        };
        self.0 = next;
        Ok(())
    }

    fn illegal(&self, event: RecoveryEvent) -> IllegalRecoveryTransition {
        IllegalRecoveryTransition {
            phase: self.phase_name(),
            event,
        }
    }

    fn phase_name(&self) -> &'static str {
        match &self.0 {
            State::LocalClosed => "local_closed",
            State::ClosureAgreed { .. } => "closure_agreed",
            State::Attached { exchange, .. } => match exchange {
                ResumeExchange::Resuming => "resuming",
                ResumeExchange::ReadySent { .. } => "ready_sent",
                ResumeExchange::Activated => "activated",
            },
        }
    }

    fn exchange(&self) -> Option<ResumeExchange> {
        match &self.0 {
            State::Attached { exchange, .. } => Some(*exchange),
            State::LocalClosed | State::ClosureAgreed { .. } => None,
        }
    }

    /// The connector's closure record was accepted for this attempt.
    pub(super) fn peer_closure_accepted(&self) -> bool {
        !matches!(self.0, State::LocalClosed)
    }

    /// The combined closure digest a recovery ticket must be bound to.
    pub(super) fn closure_digest(&self) -> Option<&str> {
        match &self.0 {
            State::LocalClosed => None,
            State::ClosureAgreed { digest } | State::Attached { digest, .. } => Some(digest),
        }
    }

    /// The recovery candidate attached for this attempt.  It may since have
    /// been lost; see [`Self::retry`].
    pub(super) fn candidate_attached(&self) -> bool {
        matches!(self.0, State::Attached { .. })
    }

    /// The candidate is attached and the READY pair has not been queued.
    pub(super) fn is_resuming(&self) -> bool {
        self.exchange() == Some(ResumeExchange::Resuming)
    }

    /// Both READY decisions were queued (and stay so through activation).
    pub(super) fn ready_sent(&self) -> bool {
        matches!(
            self.exchange(),
            Some(ResumeExchange::ReadySent { .. } | ResumeExchange::Activated)
        )
    }

    /// READY for direction `index` was sent and its acknowledgement is
    /// still outstanding.
    pub(super) fn awaits_remote_ready(&self, index: usize) -> bool {
        matches!(
            self.exchange(),
            Some(ResumeExchange::ReadySent { remote_ready }) if remote_ready.get(index) == Some(&false)
        )
    }

    /// Both READY acknowledgements were validated (and stay so through
    /// activation).
    pub(super) fn remote_ready_pair(&self) -> bool {
        matches!(
            self.exchange(),
            Some(
                ResumeExchange::ReadySent {
                    remote_ready: [true, true]
                } | ResumeExchange::Activated
            )
        )
    }

    pub(super) fn activated(&self) -> bool {
        self.exchange() == Some(ResumeExchange::Activated)
    }

    /// Bring an attempt that has not attached its candidate to the state
    /// just after attachment, agreeing a placeholder closure first if none
    /// was agreed.  An attached attempt is left as it is.
    #[cfg(test)]
    pub(super) fn attach_candidate_for_test(&mut self) {
        if !self.peer_closure_accepted() {
            self.on_event(RecoveryEvent::PeerClosureAccepted {
                digest: "test-closure".to_owned(),
            })
            .expect("a new attempt accepts the peer closure");
        }
        if !self.candidate_attached() {
            self.on_event(RecoveryEvent::CandidateAttached)
                .expect("an agreed closure accepts its candidate");
        }
    }

    /// The pending delayed restart, if the attached candidate was lost.
    pub(super) fn retry(&self) -> Option<&RecoveryRetry> {
        match &self.0 {
            State::Attached { retry, .. } => retry.as_ref(),
            State::LocalClosed | State::ClosureAgreed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry(id: &str) -> RecoveryRetry {
        RecoveryRetry {
            not_before_ms: 7,
            failed_connection_id: id.to_owned(),
        }
    }

    fn all_events() -> Vec<RecoveryEvent> {
        vec![
            RecoveryEvent::PeerClosureAccepted {
                digest: "other".to_owned(),
            },
            RecoveryEvent::CandidateAttached,
            RecoveryEvent::SnapshotsSent,
            RecoveryEvent::ReadySent,
            RecoveryEvent::RemoteReady(0),
            RecoveryEvent::RemoteReady(1),
            RecoveryEvent::RemoteReady(2),
            RecoveryEvent::Activated,
            RecoveryEvent::RetryScheduled(retry("candidate")),
            RecoveryEvent::RetryDispatched,
        ]
    }

    fn drive(events: &[RecoveryEvent]) -> RecoveryProgress {
        let mut progress = RecoveryProgress::local_closed();
        for event in events {
            progress
                .on_event(event.clone())
                .unwrap_or_else(|illegal| panic!("legal transition refused: {illegal:?}"));
        }
        progress
    }

    fn agreed() -> Vec<RecoveryEvent> {
        vec![RecoveryEvent::PeerClosureAccepted {
            digest: "digest".to_owned(),
        }]
    }

    fn attached() -> Vec<RecoveryEvent> {
        let mut events = agreed();
        events.push(RecoveryEvent::CandidateAttached);
        events
    }

    fn ready_sent(acknowledged: &[usize]) -> Vec<RecoveryEvent> {
        let mut events = attached();
        events.push(RecoveryEvent::SnapshotsSent);
        events.push(RecoveryEvent::ReadySent);
        events.extend(acknowledged.iter().copied().map(RecoveryEvent::RemoteReady));
        events
    }

    fn activated() -> Vec<RecoveryEvent> {
        let mut events = ready_sent(&[1, 0]);
        events.push(RecoveryEvent::Activated);
        events
    }

    /// Every event not in `legal` is refused in the state `prefix` reaches,
    /// and a refusal leaves that state exactly as it was.
    fn assert_only(prefix: &[RecoveryEvent], legal: &[RecoveryEvent]) {
        let state = drive(prefix);
        for event in all_events() {
            let mut next = state.clone();
            let result = next.on_event(event.clone());
            if legal.contains(&event) {
                assert!(result.is_ok(), "{event:?} is legal after {prefix:?}");
            } else {
                assert!(result.is_err(), "{event:?} is refused after {prefix:?}");
                assert_eq!(next, state, "a refusal leaves the state alone");
            }
        }
    }

    #[test]
    fn a_new_attempt_accepts_only_the_peer_closure() {
        let progress = RecoveryProgress::local_closed();
        assert!(!progress.peer_closure_accepted());
        assert_eq!(progress.closure_digest(), None);
        assert!(!progress.candidate_attached() && !progress.ready_sent());
        assert!(!progress.is_resuming() && !progress.activated());
        assert!(progress.retry().is_none());
        assert_only(
            &[],
            &[RecoveryEvent::PeerClosureAccepted {
                digest: "other".to_owned(),
            }],
        );
    }

    #[test]
    fn an_agreed_closure_pins_its_digest_and_accepts_only_the_candidate() {
        let progress = drive(&agreed());
        assert!(progress.peer_closure_accepted());
        assert_eq!(progress.closure_digest(), Some("digest"));
        assert!(!progress.candidate_attached());
        assert_only(&agreed(), &[RecoveryEvent::CandidateAttached]);
    }

    #[test]
    fn an_attached_candidate_resumes_before_ready() {
        let progress = drive(&attached());
        assert!(progress.candidate_attached() && progress.is_resuming());
        assert_eq!(progress.closure_digest(), Some("digest"));
        assert!(!progress.ready_sent() && !progress.remote_ready_pair());
        assert!(!progress.awaits_remote_ready(0) && !progress.awaits_remote_ready(1));
        assert_only(
            &attached(),
            &[
                RecoveryEvent::SnapshotsSent,
                RecoveryEvent::ReadySent,
                RecoveryEvent::RetryScheduled(retry("candidate")),
            ],
        );
    }

    #[test]
    fn ready_is_sent_as_a_pair_and_acknowledged_per_direction_once() {
        let progress = drive(&ready_sent(&[]));
        assert!(progress.ready_sent() && !progress.is_resuming());
        assert!(progress.awaits_remote_ready(0) && progress.awaits_remote_ready(1));
        assert!(!progress.awaits_remote_ready(2));
        assert_only(
            &ready_sent(&[]),
            &[
                RecoveryEvent::SnapshotsSent,
                RecoveryEvent::RemoteReady(0),
                RecoveryEvent::RemoteReady(1),
                RecoveryEvent::RetryScheduled(retry("candidate")),
            ],
        );

        let progress = drive(&ready_sent(&[1]));
        assert!(progress.awaits_remote_ready(0) && !progress.awaits_remote_ready(1));
        assert!(!progress.remote_ready_pair());
        assert_only(
            &ready_sent(&[1]),
            &[
                RecoveryEvent::SnapshotsSent,
                RecoveryEvent::RemoteReady(0),
                RecoveryEvent::RetryScheduled(retry("candidate")),
            ],
        );
    }

    #[test]
    fn a_new_snapshot_pair_restarts_the_exchange() {
        let mut events = ready_sent(&[0, 1]);
        events.push(RecoveryEvent::SnapshotsSent);
        let progress = drive(&events);
        assert!(progress.is_resuming() && !progress.ready_sent());
        assert!(!progress.remote_ready_pair());
    }

    #[test]
    fn activation_needs_the_acknowledged_ready_pair_and_happens_once() {
        let progress = drive(&ready_sent(&[0, 1]));
        assert!(progress.remote_ready_pair() && !progress.activated());
        assert_only(
            &ready_sent(&[0, 1]),
            &[
                RecoveryEvent::SnapshotsSent,
                RecoveryEvent::Activated,
                RecoveryEvent::RetryScheduled(retry("candidate")),
            ],
        );

        let progress = drive(&activated());
        assert!(progress.activated() && progress.ready_sent() && progress.remote_ready_pair());
        assert!(progress.candidate_attached() && !progress.is_resuming());
        assert!(!progress.awaits_remote_ready(0) && !progress.awaits_remote_ready(1));
        assert_only(
            &activated(),
            &[RecoveryEvent::RetryScheduled(retry("candidate"))],
        );
    }

    #[test]
    fn a_retry_is_scheduled_once_and_survives_the_exchange() {
        for prefix in [attached(), ready_sent(&[]), ready_sent(&[0])] {
            let mut events = prefix;
            events.push(RecoveryEvent::RetryScheduled(retry("lost")));
            let progress = drive(&events);
            assert_eq!(progress.retry(), Some(&retry("lost")));
            let mut again = progress.clone();
            assert!(
                again
                    .on_event(RecoveryEvent::RetryScheduled(retry("second")))
                    .is_err()
            );
            assert_eq!(again, progress);

            events.push(RecoveryEvent::RetryDispatched);
            let progress = drive(&events);
            assert!(progress.retry().is_none());
            assert!(progress.candidate_attached());
        }

        // A candidate lost just before the READY pair is acknowledged: the
        // retry stays pending through activation.
        let mut events = ready_sent(&[0]);
        events.push(RecoveryEvent::RetryScheduled(retry("lost")));
        events.push(RecoveryEvent::RemoteReady(1));
        events.push(RecoveryEvent::Activated);
        let progress = drive(&events);
        assert!(progress.activated());
        assert_eq!(progress.retry(), Some(&retry("lost")));
        events.push(RecoveryEvent::RetryDispatched);
        assert!(drive(&events).retry().is_none());
    }
}
