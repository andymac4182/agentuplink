//! Valid-state C240 evidence. Expected green on the existing aggregate guard;
//! no pending, sequence, replay, or retained-byte counter is seeded to overflow.
use super::*;

const STREAM: u64 = 7;
const LIMIT: usize = 256 * 1024;
const BULK: usize = 192 * 1024;

struct Fixture {
    actor: M2Actor,
    key: CarrierKey,
    carrier: mpsc::Receiver<CarrierCommand>,
    control: mpsc::Receiver<crate::QueuedMessage>,
    sender: StreamState,
}

impl Fixture {
    fn new(frozen: bool) -> Self {
        let (mut actor, key, carrier, control) = test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        // Install a valid configuration while all byte-owning queues are
        // empty. The carrier and aggregate limits agree from the first frame.
        actor.config.limits.max_queue_bytes = LIMIT;
        actor.config.limits.grant_timeout_ms = 5_000;
        actor
            .config
            .validate()
            .expect("valid minimum queue profile");
        assert_eq!(actor.aggregate_retained_bytes(), 0);
        actor.data_budget = Arc::new(QueueBudget {
            bytes: std::sync::atomic::AtomicUsize::new(0),
            maximum: LIMIT,
        });
        assert_eq!(LIMIT - critical_reserved_bytes(LIMIT), BULK);
        let mut stream = test_stream();
        stream.sequence = StreamState::new(STREAM, LIMIT as u64).expect("receiver sequence");
        let now = Instant::now();
        let wall = SystemTime::now();
        stream.auth.deadline = DualDeadline::new(now, wall, Duration::from_secs(5))
            .expect("live bounded authorization challenge");
        stream.auth.operation_deadline = DualDeadline::new(now, wall, Duration::from_secs(60))
            .expect("live echo-stream operation");
        actor.streams.insert(STREAM, stream);
        actor.writes_frozen = frozen;
        Self {
            actor,
            key,
            carrier,
            control,
            sender: StreamState::new(STREAM, LIMIT as u64).expect("sender sequence"),
        }
    }

    fn data(&mut self, payload: Vec<u8>) -> Frame {
        let next = self
            .sender
            .direction(Direction::RelayToConnector)
            .last_emitted()
            + 1;
        let frame = Frame::data(1, 1, STREAM, next, 0, payload);
        self.sender
            .send_frame(Direction::RelayToConnector, &frame)
            .expect("peer generates a valid sequence within its credit/replay limits");
        frame
    }

    async fn deliver(&mut self, frame: &Frame) -> Result<(), ClientError> {
        self.actor
            .handle_carrier_message(
                self.key.clone(),
                Message::Binary(frame.encode().expect("valid protocol encoding").into()),
            )
            .await
    }

    fn live(&self) {
        let stream = &self.actor.streams[&STREAM];
        assert!(
            !stream
                .auth
                .deadline
                .expired_at(Instant::now(), SystemTime::now())
        );
        assert!(
            !stream
                .auth
                .operation_deadline
                .expired_at(Instant::now(), SystemTime::now())
        );
        assert!(
            !stream.auth.confirmed && stream.auth.refresh_in_flight && !stream.auth.invalidated
        );
        assert_eq!(self.actor.auth_expired_streams, 0);
        assert_eq!(self.actor.expire_stream_calls, 0);
    }

    fn no_application_output(&mut self) {
        assert!(
            self.carrier.try_recv().is_err(),
            "no DATA or RESET before authorization"
        );
        assert!(
            self.control.try_recv().is_err(),
            "no invented control response"
        );
        assert!(self.actor.pending_outputs.is_empty());
        assert_eq!(self.actor.pending_output_bytes, 0);
    }

    async fn fill(&mut self) {
        let mut payloads = Vec::new();
        for marker in 1..=3 {
            // Each payload is also a valid echo record, not just a valid DATA
            // envelope. Nothing reaches the adapter before confirmation.
            let payload = record(&vec![marker; MAX_PAYLOAD_LEN - M2_RECORD_HEADER_BYTES]);
            assert_eq!(payload.len(), MAX_PAYLOAD_LEN);
            let frame = self.data(payload.clone());
            self.deliver(&frame)
                .await
                .expect("DATA fits the actual bulk ceiling");
            payloads.push(payload);
            assert_eq!(
                self.actor.aggregate_retained_bytes(),
                payloads.len() * MAX_PAYLOAD_LEN
            );
            self.live();
        }
        assert_eq!(
            pending_payloads(&self.actor),
            payloads.iter().cloned().map(Some).collect::<Vec<_>>()
        );
    }
}

fn pending_payloads(actor: &M2Actor) -> Vec<Option<Vec<u8>>> {
    actor.streams[&STREAM]
        .pending
        .iter()
        .map(|input| match input {
            BufferedInput::Data(bytes) => Some(bytes.clone()),
            BufferedInput::Fin => None,
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    sequence: [tunnel_protocol::DirectionSnapshot; 2],
    ready: [Vec<Frame>; 2],
    pending: Vec<Option<Vec<u8>>>,
    pending_bytes: usize,
    record: Vec<u8>,
    record_expected: Option<usize>,
    auth_identity: (String, String, String, u64),
    auth_flags: [bool; 3],
    auth_deadlines: [(Instant, SystemTime, Instant, SystemTime); 2],
    terminals: [bool; 5],
    feedback: BTreeMap<u64, PendingCarrierControl>,
    aggregate: usize,
    carrier_bytes: usize,
    writes_frozen: bool,
}

fn snapshot(actor: &M2Actor) -> Snapshot {
    let stream = &actor.streams[&STREAM];
    let deadline = |value: DualDeadline| {
        (
            value.started,
            value.started_wall,
            value.monotonic,
            value.wall,
        )
    };
    Snapshot {
        sequence: [
            stream
                .sequence
                .direction(Direction::RelayToConnector)
                .snapshot(),
            stream
                .sequence
                .direction(Direction::ConnectorToRelay)
                .snapshot(),
        ],
        ready: [
            stream.sequence.ready_frames(Direction::RelayToConnector),
            stream.sequence.ready_frames(Direction::ConnectorToRelay),
        ],
        pending: pending_payloads(actor),
        pending_bytes: stream.pending_bytes,
        record: stream.record_buffer.clone(),
        record_expected: stream.record_expected,
        auth_identity: (
            stream.auth.challenge_id.clone(),
            stream.auth.nonce.clone(),
            stream.auth.permission_digest.clone(),
            stream.auth.grant_revision,
        ),
        auth_flags: [
            stream.auth.confirmed,
            stream.auth.refresh_in_flight,
            stream.auth.invalidated,
        ],
        auth_deadlines: [
            deadline(stream.auth.deadline),
            deadline(stream.auth.operation_deadline),
        ],
        terminals: [
            stream.input_fin,
            stream.input_reset,
            stream.output_fin,
            stream.output_reset,
            stream.reset_queued,
        ],
        feedback: actor.active.pending_controls.clone(),
        aggregate: actor.aggregate_retained_bytes(),
        carrier_bytes: actor.data_budget.current(),
        writes_frozen: actor.writes_frozen,
    }
}

async fn reject_without_mutation(fixture: &mut Fixture, frame: &Frame) {
    fixture.live();
    let before = snapshot(&fixture.actor);
    // Also pin propagation through the real event -> carrier -> decoded-frame
    // chain. The full socket supervisor is not started by this unit test.
    let error = fixture
        .actor
        .handle_event(ActorEvent::Data(CarrierEvent::Message {
            key: fixture.key.clone(),
            message: Box::new(Message::Binary(frame.encode().unwrap().into())),
        }))
        .await
        .expect_err("bulk ceiling rejects the next payload byte");
    assert!(matches!(error, ClientError::QueueLimit));
    assert_eq!(error.code(), "RESOURCE_EXHAUSTED");
    assert!(
        !error.retryable(),
        "quota does not authorize an automatic replay/reconnect"
    );
    assert_eq!(
        snapshot(&fixture.actor),
        before,
        "rejected DATA must not mutate input, authorization, credit or terminals"
    );
    fixture.live();
    fixture.no_application_output();
}

#[tokio::test]
async fn c240_live_input_reaches_aggregate_limit_before_authorization_reset() {
    for frozen in [false, true] {
        let mut fixture = Fixture::new(frozen);
        fixture.fill().await;
        assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, BULK);
        assert_eq!(
            fixture.actor.streams[&STREAM]
                .sequence
                .direction(Direction::RelayToConnector)
                .delivered_contiguous(),
            3
        );
        let extra = fixture.data(vec![0x5a]);
        reject_without_mutation(&mut fixture, &extra).await;
        assert_eq!(fixture.actor.aggregate_retained_bytes(), BULK);
        assert!(
            BULK + extra.payload.len() < LIMIT,
            "the later full-ceiling fallback is never reached"
        );
    }
}

#[tokio::test]
async fn c240_gap_bytes_move_through_ready_to_pending_without_double_charging() {
    let mut fixture = Fixture::new(false);
    let gap = fixture.data(Vec::new());
    let mut payloads = vec![Some(Vec::new())];
    for marker in 1..=3 {
        let payload = record(&vec![marker; MAX_PAYLOAD_LEN - M2_RECORD_HEADER_BYTES]);
        let frame = fixture.data(payload.clone());
        fixture
            .deliver(&frame)
            .await
            .expect("valid DATA waits above the gap");
        payloads.push(Some(payload));
    }
    let direction = fixture.actor.streams[&STREAM]
        .sequence
        .direction(Direction::RelayToConnector);
    assert_eq!(
        (
            direction.recv_contiguous(),
            direction.ready_bytes(),
            direction.reorder_bytes()
        ),
        (0, 0, BULK)
    );
    assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, 0);
    assert_eq!(fixture.actor.aggregate_retained_bytes(), BULK);
    let rejected = fixture.data(vec![0x33]);
    reject_without_mutation(&mut fixture, &rejected).await;
    // This is a newly delivered legitimate empty frame, not a replay of the
    // rejected payload. It closes the gap without allocating another byte.
    fixture
        .deliver(&gap)
        .await
        .expect("zero-payload gap closure releases accounted ready bytes");
    let direction = fixture.actor.streams[&STREAM]
        .sequence
        .direction(Direction::RelayToConnector);
    assert_eq!(
        (
            direction.recv_contiguous(),
            direction.delivered_contiguous()
        ),
        (4, 4)
    );
    assert_eq!((direction.ready_bytes(), direction.reorder_bytes()), (0, 0));
    assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, BULK);
    assert_eq!(pending_payloads(&fixture.actor), payloads);
    assert_eq!(fixture.actor.aggregate_retained_bytes(), BULK);
    fixture.live();
    fixture.no_application_output();
}

#[tokio::test]
async fn c240_accepted_data_dispatches_once_only_after_matching_confirmation() {
    let mut fixture = Fixture::new(false);
    let payload = record(b"c240-accepted");
    let frame = fixture.data(payload.clone());
    fixture
        .deliver(&frame)
        .await
        .expect("bounded accepted input");
    assert_eq!(
        pending_payloads(&fixture.actor),
        vec![Some(payload.clone())]
    );
    fixture.no_application_output();
    fixture
        .actor
        .handle_control(ControlMessage::AuthorizationConfirmed(
            AuthorizationConfirmed::new(
                "c240-confirmed",
                "challenge",
                "session",
                1,
                STREAM,
                "challenge",
                "nonce",
                "permission",
                1,
                5_000,
            ),
        ))
        .await
        .expect("live matching confirmation dispatches accepted record");
    assert!(fixture.actor.streams[&STREAM].pending.is_empty());
    assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, 0);
    assert!(fixture.actor.streams[&STREAM].auth.confirmed);
    let mut data = Vec::new();
    while let Ok(command) = fixture.carrier.try_recv() {
        if let CarrierCommand::Frame(queued) = command {
            let output = Frame::decode(&queued.bytes).unwrap();
            assert_ne!(output.kind, FrameKind::Reset);
            if output.kind == FrameKind::Data {
                data.push(output);
            }
        }
    }
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].payload, payload);
    assert_eq!(data[0].sequence, 1);
    assert!(fixture.actor.pending_outputs.is_empty());
}

#[tokio::test]
async fn c240_explicit_revocation_clears_real_input_and_preserves_frozen_terminal_order() {
    for frozen in [false, true] {
        let mut fixture = Fixture::new(frozen);
        fixture.fill().await;
        fixture
            .actor
            .handle_control(ControlMessage::AuthorizationInvalidated(
                AuthorizationInvalidated::new(
                    "c240-invalidated",
                    "session",
                    1,
                    STREAM,
                    "challenge",
                    1,
                    "synthetic grant revoked",
                ),
            ))
            .await
            .expect("explicit live authorization invalidation");
        assert!(fixture.actor.streams[&STREAM].auth.invalidated);
        assert!(fixture.actor.streams[&STREAM].pending.is_empty());
        assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, 0);
        assert_eq!(fixture.actor.pending_output_bytes, 0);
        assert_eq!(fixture.actor.auth_expired_streams, 1);
        if frozen {
            assert!(
                fixture.carrier.try_recv().is_err(),
                "terminal cannot cross the freeze"
            );
            assert_eq!(fixture.actor.pending_outputs.len(), 1);
            let terminal = &fixture.actor.pending_outputs[0];
            assert_eq!(
                (terminal.kind, terminal.reset_reason),
                (FrameKind::Reset, Some(4_001))
            );
            assert!(terminal.payload.is_empty());
            assert_eq!(
                fixture.actor.streams[&STREAM]
                    .sequence
                    .direction(Direction::ConnectorToRelay)
                    .last_emitted(),
                0
            );
            fixture.actor.writes_frozen = false;
            fixture
                .actor
                .flush_pending_outputs()
                .await
                .expect("one terminal flushes after unfreeze");
        }
        let mut emitted = Vec::new();
        while let Ok(command) = fixture.carrier.try_recv() {
            if let CarrierCommand::Frame(queued) = command {
                emitted.push(Frame::decode(&queued.bytes).unwrap());
            }
        }
        assert_eq!(emitted.len(), 1, "no buffered application DATA is replayed");
        assert_eq!(
            (emitted[0].kind, emitted[0].sequence, emitted[0].ack),
            (FrameKind::Reset, 1, 3)
        );
        assert_eq!(emitted[0].reset_reason().unwrap(), Some(4_001));
        assert!(fixture.actor.pending_outputs.is_empty());
        assert_eq!(fixture.actor.data_budget.current(), 0);
        assert_eq!(
            fixture.actor.aggregate_retained_bytes(),
            2,
            "only the emitted RESET reason remains in bounded transport replay"
        );
        let late = fixture.data(record(b"after-revocation"));
        fixture
            .deliver(&late)
            .await
            .expect("late bytes acknowledged without dispatch");
        assert!(fixture.actor.streams[&STREAM].pending.is_empty());
        assert_eq!(fixture.actor.streams[&STREAM].pending_bytes, 0);
        assert_eq!(
            fixture.actor.streams[&STREAM]
                .sequence
                .direction(Direction::RelayToConnector)
                .delivered_contiguous(),
            4
        );
        fixture.no_application_output();
        assert_eq!(fixture.actor.aggregate_retained_bytes(), 2);
    }
}
