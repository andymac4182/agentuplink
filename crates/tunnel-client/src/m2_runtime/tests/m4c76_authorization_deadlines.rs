//! M4-76: the accepted grant remains a bound while a fresh challenge waits.
//! These handler tests use actual encoded DATA and bounded control queues;
//! they do not claim public-socket or already executing effect cancellation.

use super::*;
use crate::http_forward::{DeviceRead, HttpActorRequest};

const STREAM: u64 = 7;

struct Fixture {
    actor: M2Actor,
    key: CarrierKey,
    carrier: mpsc::Receiver<CarrierCommand>,
    control: mpsc::Receiver<crate::QueuedMessage>,
    accepted: DualDeadline,
}

impl Fixture {
    async fn new() -> Self {
        let (mut actor, key, carrier, control) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 1);
        actor.config.limits.grant_timeout_ms = 5_000;
        let mut stream = test_stream();
        stream.operation = HTTP_FORWARD_OPERATION.to_owned();
        stream.sequence = StreamState::new(STREAM, 1_024).expect("receiver sequence");
        stream.auth.deadline =
            DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(5))
                .expect("initial challenge deadline");
        stream.auth.operation_deadline =
            DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(60))
                .expect("operation deadline");
        let (notifier, _signal) = tunnel_http_bridge::reset_signal_pair();
        stream.http = Some(DeviceHttpState::new(
            notifier,
            1_024,
            tunnel_http_bridge::PauseController::new(false),
            None,
        ));
        actor.streams.insert(STREAM, stream);
        actor
            .handle_authorization_confirmed(AuthorizationConfirmed::new(
                "initial-confirmation",
                "initial-challenge",
                "session",
                1,
                STREAM,
                "challenge",
                "nonce",
                "permission",
                1,
                500,
            ))
            .await
            .expect("matching admission confirmation");
        let accepted = actor.streams[&STREAM].auth.deadline;
        assert!(actor.streams[&STREAM].auth.confirmed);
        let payload = b"synthetic buffered request bytes".to_vec();
        let frame = Frame::data(1, 1, STREAM, 1, 0, payload);
        let mut sender = StreamState::new(STREAM, 1_024).expect("sender sequence");
        sender
            .send_frame(Direction::RelayToConnector, &frame)
            .expect("normal sender credit");
        actor
            .handle_carrier_message(
                key.clone(),
                Message::Binary(frame.encode().expect("encoded DATA").into()),
            )
            .await
            .expect("authorized DATA handoff");
        Self {
            actor,
            key,
            carrier,
            control,
            accepted,
        }
    }

    async fn refresh(&mut self, deferred: bool) -> AuthorizationChallenge {
        if deferred {
            self.actor
                .send_control(
                    ControlMessage::Pong(Pong::new("queue-filler", "ping", "session", 1, 1)),
                    None,
                )
                .expect("fill the actual one-slot control queue");
        }
        self.actor.refresh_authorizations().await.expect("refresh");
        if deferred {
            assert!(self.actor.streams[&STREAM].auth.confirmed);
            assert_eq!(self.actor.pending_authorization_refreshes.len(), 1);
            let before = self.actor.pending_authorization_refreshes[&STREAM].auth_deadline;
            drop(self.control.try_recv().expect("release one real queue slot"));
            self.actor
                .flush_pending_authorization_refreshes(Instant::now(), SystemTime::now())
                .await
                .expect("admit the prepared refresh");
            let after = self.actor.streams[&STREAM].auth.deadline;
            assert_eq!(after.started, before.started);
            assert_eq!(after.started_wall, before.started_wall);
            assert_eq!(after.monotonic, before.monotonic);
            assert_eq!(after.wall, before.wall);
        }
        assert!(!self.actor.streams[&STREAM].auth.confirmed);
        let item = self.control.try_recv().expect("queued refresh challenge");
        let Message::Text(text) = &item.message else {
            panic!("control text");
        };
        let ControlMessage::AuthorizationChallenge(challenge) =
            decode_control(text.as_bytes()).expect("challenge JSON")
        else {
            panic!("authorization challenge");
        };
        challenge
    }

    async fn cross_accepted_deadline(&self) {
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            self.accepted.monotonic + Duration::from_millis(5),
        ))
        .await;
        assert!(self.accepted.expired());
        assert!(
            !self.actor.streams[&STREAM].auth.deadline.expired(),
            "the challenge still has time; the old grant is what elapsed"
        );
    }

    async fn read(&mut self) -> DeviceRead {
        let (reply, answer) = oneshot::channel();
        self.actor
            .handle_http_request(HttpActorRequest::Read {
                stream_id: STREAM,
                reply,
            })
            .await
            .expect("reader request");
        answer.await.expect("reader answered")
    }

    fn reset_reasons(&mut self) -> Vec<u16> {
        let mut reasons = Vec::new();
        while let Ok(command) = self.carrier.try_recv() {
            if let CarrierCommand::Frame(queued) = command {
                let frame = Frame::decode(&queued.bytes).expect("carrier frame");
                if let Some(reason) = frame.reset_reason().expect("reset framing") {
                    reasons.push(reason);
                }
            }
        }
        reasons
    }
}

fn confirmation(challenge: AuthorizationChallenge) -> AuthorizationConfirmed {
    AuthorizationConfirmed::new(
        "refresh-confirmation",
        challenge.message_id,
        "session",
        1,
        STREAM,
        challenge.challenge_id,
        challenge.nonce,
        challenge.permission_digest,
        challenge.grant_revision,
        2_000,
    )
}

#[tokio::test]
async fn m4c76_buffered_http_stops_at_prior_confirmation_for_both_queue_paths() {
    for deferred in [false, true] {
        let mut fixture = Fixture::new().await;
        fixture.refresh(deferred).await;
        fixture.cross_accepted_deadline().await;
        // No expiry tick ran after the deadline. The read is the check.
        assert!(matches!(fixture.read().await, DeviceRead::Closed));
        assert_eq!(fixture.reset_reasons(), [4_006]);
        assert!(fixture.actor.streams[&STREAM].auth.invalidated);
        assert_eq!(fixture.actor.active.key, fixture.key);
    }
}

#[tokio::test]
async fn m4c76_a_late_matching_confirmation_cannot_bridge_a_lapse() {
    for deferred in [false, true] {
        let mut fixture = Fixture::new().await;
        let challenge = fixture.refresh(deferred).await;
        fixture.cross_accepted_deadline().await;
        fixture
            .actor
            .handle_authorization_confirmed(confirmation(challenge))
            .await
            .expect("late answer is a stream lapse");
        assert!(fixture.actor.streams[&STREAM].auth.invalidated);
        assert_eq!(fixture.reset_reasons(), [4_006]);
    }
}

#[tokio::test]
async fn m4c76_timely_confirmation_renews_from_the_original_challenge_start() {
    let mut fixture = Fixture::new().await;
    let challenge = fixture.refresh(true).await;
    let started = fixture.actor.streams[&STREAM].auth.deadline;
    fixture
        .actor
        .handle_authorization_confirmed(confirmation(challenge))
        .await
        .expect("timely answer");
    let renewed = fixture.actor.streams[&STREAM].auth.deadline;
    assert!(fixture.actor.streams[&STREAM].auth.confirmed);
    assert_eq!(renewed.monotonic, started.started + Duration::from_secs(2));
    assert_eq!(renewed.wall, started.started_wall + Duration::from_secs(2));
    assert!(renewed.monotonic > fixture.accepted.monotonic);
    fixture.cross_accepted_deadline().await;
    assert!(matches!(fixture.read().await, DeviceRead::Data(data) if !data.is_empty()));
    assert!(fixture.reset_reasons().is_empty());
}

#[tokio::test]
async fn m4c76_a_matching_shortened_expired_confirmation_cannot_publish_authority() {
    let mut fixture = Fixture::new().await;
    let challenge = fixture.refresh(false).await;
    assert!(fixture.actor.streams[&STREAM].pending.is_empty());
    assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, 0);
    let started = fixture.actor.streams[&STREAM].auth.deadline.started;
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        started + Duration::from_millis(10),
    ))
    .await;
    assert!(
        !fixture.accepted.expired(),
        "the previous grant remains live"
    );
    let mut answer = confirmation(challenge);
    answer.remaining_ms = 1;
    fixture
        .actor
        .handle_authorization_confirmed(answer)
        .await
        .expect("shortened lifetime is checked before publication");
    assert!(fixture.actor.streams[&STREAM].auth.invalidated);
    assert!(!fixture.actor.streams[&STREAM].auth.confirmed);
    assert_eq!(fixture.reset_reasons(), [4_006]);
}

#[tokio::test]
async fn m4c76_both_queued_filesystem_refresh_paths_publish_the_challenge_bound() {
    use tunnel_fs_core::{Capability, CapabilitySet};
    use tunnel_fs_provider::FreshnessFailure;

    for deferred in [false, true] {
        let mut fixture = Fixture::new().await;
        let stream = fixture.actor.streams.get_mut(&STREAM).unwrap();
        stream.operation = FS_STREAM_OPERATION.to_owned();
        let authority = Arc::new(crate::fs_export::StreamAuthority::new_until(
            stream.auth.grant_revision,
            CapabilitySet::from_slice(&[Capability::Read, Capability::List]),
            stream.auth.deadline,
            stream.auth.operation_deadline,
        ));
        stream.fs_authority = Some(Arc::clone(&authority));
        // Keep the configuration fixed. Separate the legitimate starts, then
        // inject only the clock observation, not the actor's queue/accounting.
        tokio::time::sleep(Duration::from_millis(10)).await;
        fixture.refresh(deferred).await;
        let stream = &fixture.actor.streams[&STREAM];
        let challenge = stream.auth.deadline;
        let older_start = fixture
            .accepted
            .started_wall
            .max(stream.auth.operation_deadline.started_wall);
        let gap = challenge.started_wall.duration_since(older_start).unwrap();
        assert!(!gap.is_zero());
        let reversed = older_start + gap / 2;
        assert!(reversed < challenge.started_wall);
        assert!(!fixture.accepted.expired(), "the old grant has not elapsed");
        assert!(!fixture.actor.streams[&STREAM].auth.invalidated);
        let now = Instant::now();
        assert!(stream.authorization_expired_at(now, reversed));
        let observed = authority.observe_at(now, reversed);
        assert!(
            !observed.fresh,
            "provider checks the admitted challenge without actor tick"
        );
        assert_eq!(observed.freshness_failure, FreshnessFailure::DeadlineElapsed);
    }
}

#[tokio::test]
async fn m4c76_unanswered_refresh_preserves_frozen_stale_terminal_ordering() {
    let mut fixture = Fixture::new().await;
    fixture.refresh(false).await;
    fixture.actor.writes_frozen = true;
    fixture.cross_accepted_deadline().await;
    assert!(matches!(fixture.read().await, DeviceRead::Closed));
    assert!(fixture.reset_reasons().is_empty());
    assert_eq!(fixture.actor.pending_outputs.len(), 1);
    assert_eq!(fixture.actor.pending_outputs[0].reset_reason, Some(4_006));
    fixture.actor.writes_frozen = false;
    fixture.actor.flush_pending_outputs().await.expect("thaw");
    assert_eq!(fixture.reset_reasons(), [4_006]);
}

#[tokio::test]
async fn m4c76_a_refresh_still_waiting_for_queue_space_expires_without_nonce_replacement() {
    let mut fixture = Fixture::new().await;
    fixture
        .actor
        .send_control(
            ControlMessage::Pong(Pong::new("queue-filler", "ping", "session", 1, 1)),
            None,
        )
        .expect("fill actual control queue");
    fixture.actor.refresh_authorizations().await.expect("defer refresh");
    assert!(fixture.actor.streams[&STREAM].auth.confirmed);
    assert_eq!(fixture.actor.pending_authorization_refreshes.len(), 1);
    let original_id = fixture.actor.streams[&STREAM].auth.challenge_id.clone();
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        fixture.accepted.monotonic + Duration::from_millis(5),
    ))
    .await;
    fixture
        .actor
        .flush_pending_authorization_refreshes(Instant::now(), SystemTime::now())
        .await
        .expect("expired deferred refresh");
    assert!(fixture.actor.pending_authorization_refreshes.is_empty());
    assert!(fixture.actor.streams[&STREAM].auth.invalidated);
    assert_eq!(fixture.actor.streams[&STREAM].auth.challenge_id, original_id);
    assert_eq!(fixture.control.len(), 1, "only the original filler remains");
    assert_eq!(fixture.reset_reasons(), [4_006]);
}

#[test]
fn m4c76_every_deadline_keeps_its_own_wall_reversal_anchor() {
    let start = Instant::now();
    let wall = SystemTime::now();
    let mut stream = test_stream();
    stream.auth.operation_deadline = DualDeadline::new(start, wall, Duration::from_secs(60)).unwrap();
    stream.last_confirmed_deadline =
        DualDeadline::new(start, wall + Duration::from_secs(1), Duration::from_secs(5));
    stream.auth.deadline = DualDeadline::new(
        start + Duration::from_secs(2),
        wall + Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(stream.authorization_expired_at(
        start + Duration::from_secs(3),
        wall + Duration::from_millis(1_500),
    ));
    // Put the newer start in the accepted confirmation instead: a min fold
    // rooted in the current challenge would now miss this reversal.
    std::mem::swap(
        &mut stream.auth.deadline,
        stream.last_confirmed_deadline.as_mut().unwrap(),
    );
    assert!(stream.authorization_expired_at(
        start + Duration::from_secs(3),
        wall + Duration::from_millis(1_500),
    ));
}

#[tokio::test]
async fn m4c76_queued_challenge_expiry_keeps_transport_failure_and_releases_budget() {
    let mut fixture = Fixture::new().await;
    fixture.actor.config.limits.grant_timeout_ms = 200;
    fixture.actor.refresh_authorizations().await.expect("refresh");
    let deadline = fixture.actor.streams[&STREAM].auth.deadline;
    let budget = Arc::clone(&fixture.actor.control_queue.budget);
    assert!(budget.current() > 0, "the real queued message owns a charge");
    let (socket, mut peer) = test_websocket_pair().await.expect("real control socket");
    let (sink, reader) = socket.split();
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        deadline.monotonic + Duration::from_millis(5),
    ))
    .await;
    let (failure, mut failures) = mpsc::channel(1);
    let writer = tokio::spawn(crate::writer_loop(
        WriterKind::Control,
        sink,
        fixture.control,
        failure,
        CancellationToken::new(),
        None,
    ));
    let result = timeout(Duration::from_secs(2), writer)
        .await
        .expect("bounded writer join")
        .expect("writer joined");
    assert!(matches!(result, Err(ClientError::AuthorizationExpired)));
    let failure = failures.recv().await.expect("writer failure notification");
    let classified = crate::writer_failure_result(false, Some(failure.0)).unwrap_err();
    assert_eq!(classified.code(), "TRANSPORT_ERROR");
    assert!(classified.retryable());
    assert_eq!(budget.current(), 0, "queued message released at writer exit");
    drop(reader);
    // No expired challenge reached the peer, and both local socket halves
    // were dropped after the writer joined. This is writer cleanup evidence,
    // not a claim that a dead carrier can deliver a per-stream 4006 RESET.
    let ended = timeout(Duration::from_secs(2), peer.next())
        .await
        .expect("peer observes closed socket");
    assert!(!matches!(ended, Some(Ok(Message::Text(_)))));
}
