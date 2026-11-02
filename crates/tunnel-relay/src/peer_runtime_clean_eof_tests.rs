//! Real mTLS/H3 FIN regressions. Admission state is attached only after the
//! transport is established; these tests exercise receive classification,
//! not membership admission or the peer's reason for finishing its stream.

use super::*;
use std::{collections::BTreeMap, sync::Mutex as StdMutex};
use tokio::sync::mpsc;
use tunnel_cluster::{
    envelope::{HealthRequest, InternalRequest},
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipPolicy,
        MembershipRecord, MembershipVerifier, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey,
        TrustedPublisherKey,
    },
};

use crate::membership_runtime::PeerInvalidationReason;

const BODY: &[u8] = b"synthetic complete record";

#[derive(Clone, Copy, Debug)]
enum Admission {
    Expired,
    ExplicitExpiry,
    Live,
    Absent,
    LatchedRevocation,
}

impl Admission {
    fn context(self) -> Option<PeerAdmissionCancellation> {
        let token = CancellationToken::new();
        let past = Instant::now() - Duration::from_secs(1);
        Some(match self {
            Self::Absent => return None,
            Self::Expired => PeerAdmissionCancellation::from_token_with_deadline(token, past),
            Self::ExplicitExpiry => PeerAdmissionCancellation::from_token(token)
                .with_reason_for_test(PeerInvalidationReason::TrustExpired),
            Self::Live => PeerAdmissionCancellation::from_token_with_deadline(
                token,
                Instant::now() + Duration::from_secs(60),
            ),
            // A previously latched reason wins even after the deadline. The
            // uncancelled token models the dispatcher's CAS/cancel interval.
            Self::LatchedRevocation => {
                PeerAdmissionCancellation::from_token_with_deadline(token, past)
                    .with_reason_for_test(PeerInvalidationReason::MembershipRevoked)
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Wire {
    Empty,
    Complete,
    PartialPrefix,
    PartialBody,
}

impl Wire {
    fn bytes(self) -> Bytes {
        // Deliberately encode malformed cases on the wire, bypassing the
        // sender's valid-record API while using the real H3 transport.
        let body = match self {
            Self::Empty => return Bytes::new(),
            Self::Complete => BODY,
            Self::PartialPrefix => return Bytes::from_static(&[0, 0, 0]),
            Self::PartialBody => b"x",
        };
        let declared = if matches!(self, Self::PartialBody) {
            64
        } else {
            body.len() as u32
        };
        let mut bytes = declared.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[PeerRecordKind::ConsumerChunk.code(), 0, 0, 0]);
        bytes.extend_from_slice(body);
        Bytes::from(bytes)
    }
}

#[derive(Clone, Copy, Debug)]
struct Case {
    admission: Admission,
    wire: Wire,
    absolute_deadline: bool,
}

#[derive(Clone, Copy, Debug)]
enum Direction {
    Response,
    Request,
}

enum Receiver {
    Response(Box<PeerExchangeRecv>),
    Request(Box<InboundPeerRecv>),
}

impl Receiver {
    async fn read(&mut self, absolute: bool) -> Result<Option<PeerRecord>, PeerRuntimeError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        match (self, absolute) {
            (Self::Response(recv), false) => recv.recv_message().await,
            (Self::Response(recv), true) => recv.recv_message_until(deadline).await,
            (Self::Request(recv), false) => recv.recv_message().await,
            (Self::Request(recv), true) => recv.recv_message_until(deadline).await,
        }
    }

    fn budget(&self) -> StreamBudget {
        match self {
            Self::Response(recv) => recv.budget.clone(),
            Self::Request(recv) => recv.decoder.stream_budget().clone(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Eof,
    Expired,
    Truncated { expected: usize, received: usize },
    Other(String),
}

#[derive(Debug)]
struct Observation {
    complete_record: Option<Result<(PeerRecordKind, Vec<u8>), String>>,
    terminal: Outcome,
    baseline_bytes: usize,
    terminal_bytes: usize,
}

async fn observe(mut recv: Receiver, case: Case) -> Observation {
    let budget = recv.budget();
    let baseline_bytes = budget.reserved_bytes();
    let complete_record = if matches!(case.wire, Wire::Complete) {
        Some(match recv.read(case.absolute_deadline).await {
            // Drop the returned charged record before the EOF budget sample.
            Ok(Some(record)) => Ok((record.kind(), record.body().to_vec())),
            result => Err(format!("{result:?}")),
        })
    } else {
        None
    };
    let terminal = match recv.read(case.absolute_deadline).await {
        Ok(None) => Outcome::Eof,
        Err(PeerRuntimeError::MembershipExpired) => Outcome::Expired,
        Err(PeerRuntimeError::Frame(PeerFrameError::Truncated { expected, received })) => {
            Outcome::Truncated { expected, received }
        }
        result => Outcome::Other(format!("{result:?}")),
    };
    // Sample before dropping the receiver: drop cleanup must not conceal a
    // skipped decoder.finish(). Inbound retains its envelope at baseline.
    let terminal_bytes = budget.reserved_bytes();
    drop(recv);
    Observation {
        complete_record,
        terminal,
        baseline_bytes,
        terminal_bytes,
    }
}

struct EofHandler {
    direction: Direction,
    next_case: Arc<StdMutex<Option<Case>>>,
    observations: mpsc::Sender<Observation>,
}

impl PeerRequestHandler for EofHandler {
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        let case = self
            .next_case
            .lock()
            .expect("case lock")
            .take()
            .expect("case");
        let direction = self.direction;
        let observations = self.observations.clone();
        Box::pin(async move {
            let (mut send, mut recv) = stream.split();
            match direction {
                Direction::Response => {
                    while recv.recv_chunk().await?.is_some() {}
                    send.send_response(Response::new(())).await?;
                    let bytes = case.wire.bytes();
                    if !bytes.is_empty() {
                        send.send_chunk(bytes).await?;
                    }
                    send.finish().await
                }
                Direction::Request => {
                    send.send_response(Response::new(())).await?;
                    let receiver = inbound_receiver(identity, request, recv, case.admission);
                    let observation = observe(receiver, case).await;
                    send.finish().await?;
                    observations
                        .send(observation)
                        .await
                        .expect("bounded result channel");
                    Ok(())
                }
            }
        })
    }
}

async fn run_cases(
    direction: Direction,
    admissions: &[Admission],
    wires: &[Wire],
) -> Vec<(Case, Observation)> {
    let next_case = Arc::new(StdMutex::new(None));
    let (observations, mut results) = mpsc::channel(1);
    let fixture = H3Fixture::new_with_handler(Arc::new(EofHandler {
        direction,
        next_case: Arc::clone(&next_case),
        observations,
    }));
    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("real mTLS connection");
    let mut collected = Vec::new();
    for &admission in admissions {
        for &wire in wires {
            for absolute_deadline in [false, true] {
                let case = Case {
                    admission,
                    wire,
                    absolute_deadline,
                };
                *next_case.lock().expect("case lock") = Some(case);
                let mut stream = connection
                    .open(H3Fixture::health_request())
                    .await
                    .expect("real H3 request");
                if matches!(direction, Direction::Request) {
                    let bytes = wire.bytes();
                    if !bytes.is_empty() {
                        stream.send_chunk(bytes).await.expect("request body");
                    }
                }
                stream.finish().await.expect("request FIN");
                stream.recv_response().await.expect("response headers");
                let observation = match direction {
                    Direction::Response => {
                        let (_send, recv) = stream.split();
                        let budget = ConnectionBudget::new()
                            .open_stream()
                            .expect("stream budget");
                        let context = admission.context();
                        let receiver = PeerExchangeRecv {
                            recv,
                            decoder: PeerRecordDecoder::new(budget.clone()),
                            pending: VecDeque::new(),
                            response_seen: true,
                            budget,
                            admission_cancellation: context
                                .as_ref()
                                .map(PeerAdmissionCancellation::token),
                            admission_context: context,
                            route_hook: None,
                        };
                        observe(Receiver::Response(Box::new(receiver)), case).await
                    }
                    Direction::Request => {
                        let result = timeout(Duration::from_secs(3), results.recv())
                            .await
                            .expect("bounded server observation")
                            .expect("server observation");
                        while stream
                            .recv_chunk()
                            .await
                            .expect("empty response FIN")
                            .is_some()
                        {}
                        result
                    }
                };
                collected.push((case, observation));
            }
        }
    }
    drop(connection);
    // In particular, red regression assertions run only after cleanup.
    fixture.shutdown().await;
    collected
}

fn assert_cases(observations: Vec<(Case, Observation)>, expired: bool) {
    for (case, observation) in observations {
        if matches!(case.wire, Wire::Complete) {
            assert_eq!(
                observation.complete_record,
                Some(Ok((PeerRecordKind::ConsumerChunk, BODY.to_vec()))),
                "{case:?}"
            );
        }
        let expected = match case.wire {
            Wire::PartialPrefix => Outcome::Truncated {
                expected: 8,
                received: 3,
            },
            Wire::PartialBody => Outcome::Truncated {
                expected: 64,
                received: 1,
            },
            _ if expired => Outcome::Expired,
            _ => Outcome::Eof,
        };
        assert_eq!(observation.terminal, expected, "{case:?}");
        assert_eq!(
            observation.terminal_bytes, observation.baseline_bytes,
            "reservation retained before receiver drop: {case:?}"
        );
    }
}

#[tokio::test]
async fn expired_clean_response_eof_is_membership_expired() {
    assert_cases(
        run_cases(
            Direction::Response,
            &[Admission::Expired, Admission::ExplicitExpiry],
            &[Wire::Empty, Wire::Complete],
        )
        .await,
        true,
    );
}

#[tokio::test]
async fn expired_clean_request_eof_is_membership_expired() {
    assert_cases(
        run_cases(
            Direction::Request,
            &[Admission::Expired, Admission::ExplicitExpiry],
            &[Wire::Empty, Wire::Complete],
        )
        .await,
        true,
    );
}

#[tokio::test]
async fn non_expiry_clean_eof_controls() {
    for direction in [Direction::Response, Direction::Request] {
        assert_cases(
            run_cases(
                direction,
                &[
                    Admission::Live,
                    Admission::Absent,
                    Admission::LatchedRevocation,
                ],
                &[Wire::Empty, Wire::Complete],
            )
            .await,
            false,
        );
    }
}

#[tokio::test]
async fn truncated_eof_keeps_frame_error_and_releases_partial_budget() {
    for direction in [Direction::Response, Direction::Request] {
        assert_cases(
            run_cases(
                direction,
                &[Admission::Expired],
                &[Wire::PartialPrefix, Wire::PartialBody],
            )
            .await,
            false,
        );
    }
}

fn inbound_receiver(
    identity: TlsIdentity,
    request: Request<()>,
    recv: PeerServerRecv,
    admission: Admission,
) -> Receiver {
    let binding = signed_binding(&identity);
    let connection_budget = ConnectionBudget::new();
    let budget = connection_budget.open_stream().expect("inbound budget");
    let envelope = RequestEnvelope::new(
        InternalRoute::Health,
        "clean-eof-request",
        PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT),
        Destination::new(
            OwnerToken {
                tenant_id: Uuid::from_u128(1),
                device_id: Uuid::from_u128(2),
                deployment_incarnation: "clean-eof-incarnation".to_owned(),
                node_id: DESTINATION_NODE.to_owned(),
                boot_id: DESTINATION_BOOT.to_owned(),
                session_id: "clean-eof-session".to_owned(),
                epoch: 1,
            },
            Uuid::from_u128(3),
        ),
        2_000,
        Some(2_000),
        InternalRequest::Health(HealthRequest {
            check_id: "clean-eof-check".to_owned(),
        }),
    );
    // Retain an actual charged envelope, as the production receive half does.
    let envelope_record = budget
        .record_from_slice(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("envelope encoding"),
        )
        .expect("charged envelope");
    let context = admission.context();
    Receiver::Request(Box::new(InboundPeerRecv {
        identity,
        request,
        envelope,
        binding,
        recv,
        decoder: PeerRecordDecoder::new(budget),
        pending: VecDeque::new(),
        admission_cancellation: context.as_ref().map(PeerAdmissionCancellation::token),
        admission_context: context,
        _connection_budget: connection_budget,
        _envelope_record: envelope_record,
    }))
}

fn signed_binding(identity: &TlsIdentity) -> VerifiedPeerBinding {
    let policy = MembershipPolicy::new(
        "clean-eof-deployment",
        "clean-eof-incarnation",
        PrivateEndpointPolicy::allowlisted(["127.0.0.1"], ["localhost"], [443])
            .expect("endpoint policy"),
    )
    .expect("membership policy");
    let (issuer, _) = MembershipIssuer::generate("clean-eof-publisher").expect("issuer");
    let trusted = TrustedPublisherKey::new(
        "clean-eof-publisher",
        issuer.public_key().expect("public key"),
    )
    .expect("trusted publisher");
    let mut verifier = MembershipVerifier::new(policy, [trusted]).expect("verifier");
    let now = Utc::now();
    let not_before = now - chrono::Duration::seconds(1);
    let expires_at = now + chrono::Duration::seconds(30);
    let checkpoint = MembershipCheckpoint {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: "clean-eof-deployment".to_owned(),
        deployment_incarnation: "clean-eof-incarnation".to_owned(),
        checkpoint_version: 1,
        nonce: "clean-eof-synthetic-checkpoint-nonce-2026".to_owned(),
        minimum_versions: BTreeMap::from([(SOURCE_NODE.to_owned(), 1)]),
        issued_at: not_before,
        not_before,
        expires_at,
    };
    verifier
        .verify_checkpoint(
            &issuer
                .sign_checkpoint_bytes(checkpoint)
                .expect("signed checkpoint"),
            "clean-eof-synthetic-checkpoint-nonce-2026",
            now,
        )
        .expect("verified checkpoint");
    let spki = identity.spki_sha256().to_hex();
    let record = MembershipRecord {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: "clean-eof-deployment".to_owned(),
        deployment_incarnation: "clean-eof-incarnation".to_owned(),
        node_id: SOURCE_NODE.to_owned(),
        record_version: 1,
        roles: vec![RELAY_PEER_ROLE.to_owned()],
        peer_endpoint: "127.0.0.1:443".to_owned(),
        server_name: "localhost".to_owned(),
        keys: vec![RelayKey {
            key_id: "clean-eof-key".to_owned(),
            spki_sha256: spki.clone(),
            not_before,
            expires_at,
            revoked: false,
        }],
        issued_at: not_before,
        not_before,
        expires_at,
    };
    verifier
        .verify_membership(
            &issuer
                .sign_membership_bytes(record)
                .expect("signed membership"),
            now,
        )
        .expect("verified membership")
        .bind_peer(SOURCE_NODE, SOURCE_BOOT, &spki, now)
        .expect("authenticated source binding")
}
