//! Real provider completion racing ordinary FIN/ACK/STREAM_FORGET retirement.
//! No fabricated reports, sequence snapshots, or ledger counters. The actor
//! handlers and provider run unchanged; only their legal polling order varies.

use super::*;
use crate::http_forward::HttpActorRequest;
use futures_util::FutureExt;
use tunnel_fs_ninep::{Frame as NinepFrame, Message as NinepMessage};

const STREAM: u64 = 1;
const WINDOW: u64 = 65_536;
const BOUND: Duration = Duration::from_secs(5);

struct Exchange {
    actor: M2Actor,
    key: CarrierKey,
    carrier: mpsc::Receiver<CarrierCommand>,
    requests: mpsc::Receiver<HttpActorRequest>,
    _control: mpsc::Receiver<crate::QueuedMessage>,
    owner: StreamState,
    records: tunnel_fs_provider::RecordDecoder,
    root: tempfile::TempDir,
}

impl Exchange {
    async fn open() -> Self {
        let root = tempfile::tempdir().expect("synthetic export");
        std::fs::write(root.path().join("probe"), b"real-provider-probe")
            .expect("synthetic fixture file");
        let (mut actor, key, carrier, mut control) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        actor.config.exports.insert(
            "fs".to_owned(),
            crate::ExportConfig {
                kind: crate::ExportKind::Fs,
                fs: Some(crate::FsExportSettings {
                    root: root.path().to_owned(),
                    capabilities: vec!["read".to_owned(), "list".to_owned()],
                    features: Vec::new(),
                }),
                ..crate::ExportConfig::default()
            },
        );
        // One slot makes the full-channel control precise and bounded.
        let (sender, requests) = mpsc::channel(1);
        actor.http_requests = sender;
        let mut open = Open::new(
            "fs-open",
            "session",
            1,
            STREAM,
            "fs-operation",
            "fs",
            FS_STREAM_OPERATION,
            WINDOW,
            WINDOW,
        );
        open.metadata
            .insert("fs_capabilities".to_owned(), "read,list".to_owned());
        actor.handle_open(open).expect("actual FS OPEN");
        let challenge = drain_control_messages(&mut control)
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::AuthorizationChallenge(challenge) => Some(challenge),
                _ => None,
            })
            .expect("actual admission challenge");
        actor
            .handle_authorization_confirmed(AuthorizationConfirmed::new(
                "fs-confirmed",
                challenge.message_id,
                "session",
                1,
                STREAM,
                challenge.challenge_id,
                challenge.nonce,
                challenge.permission_digest,
                challenge.grant_revision,
                5_000,
            ))
            .await
            .expect("actual matching confirmation");
        assert!(actor.streams[&STREAM].auth.confirmed);
        assert_eq!(actor.fs_counters, crate::FsCounters::default());
        Self {
            actor,
            key,
            carrier,
            requests,
            _control: control,
            owner: StreamState::new(STREAM, WINDOW).expect("owner sequence"),
            records: tunnel_fs_provider::RecordDecoder::new(),
            root,
        }
    }

    fn receive_carrier(&mut self) {
        while let Ok(command) = self.carrier.try_recv() {
            let CarrierCommand::Frame(queued) = command else {
                panic!("unexpected command before FORGET");
            };
            let frame = Frame::decode(&queued.bytes).expect("actual emitted frame");
            self.owner
                .receive_frame(Direction::ConnectorToRelay, &frame)
                .expect("owner receives actual connector frame");
            if frame.kind == FrameKind::Data {
                self.records
                    .push(&frame.payload)
                    .expect("provider record bytes");
            }
            if matches!(
                frame.kind,
                FrameKind::Data | FrameKind::Fin | FrameKind::Reset
            ) {
                self.owner
                    .mark_delivered(Direction::ConnectorToRelay, frame.sequence)
                    .expect("owner delivers frame");
            }
        }
    }

    fn send_without_yield(&mut self, frame: Frame) {
        self.owner
            .send_frame(Direction::RelayToConnector, &frame)
            .expect("owner sequences actual outbound frame");
        self.actor
            .handle_frame(self.key.clone(), frame)
            .now_or_never()
            .expect("unsaturated actor frame handler completes without task polling")
            .expect("connector accepts owner frame");
    }

    fn ack(&mut self) {
        let received = self
            .owner
            .direction(Direction::ConnectorToRelay)
            .recv_contiguous();
        self.send_without_yield(Frame::ack(1, 1, STREAM, received));
    }

    async fn request(&mut self, tag: u16, message: NinepMessage) -> NinepMessage {
        let mut bytes = Vec::new();
        NinepFrame::new(tag, message)
            .encode(WINDOW as u32, &mut bytes)
            .expect("synthetic request framing");
        let sequence = self
            .owner
            .direction(Direction::RelayToConnector)
            .last_emitted()
            + 1;
        let ack = self
            .owner
            .direction(Direction::ConnectorToRelay)
            .recv_contiguous();
        self.send_without_yield(Frame::data(1, 1, STREAM, sequence, ack, bytes));
        timeout(BOUND, async {
            loop {
                self.receive_carrier();
                if let Some(record) = self.records.next_record().expect("actual provider record") {
                    let tunnel_fs_provider::Record::Message(bytes) = record else {
                        panic!("provider closed before replying");
                    };
                    let reply = tunnel_fs_ninep::decode_exact(&bytes, WINDOW as u32)
                        .expect("actual 9P reply");
                    assert_eq!(reply.tag, tag);
                    self.ack();
                    return reply.message;
                }
                let request = self.requests.recv().await.expect("live exchange task");
                assert!(!matches!(request, HttpActorRequest::Done { .. }));
                self.actor
                    .handle_http_request(request)
                    .await
                    .expect("actual actor request");
            }
        })
        .await
        .expect("bounded real provider response")
    }

    async fn exercise_provider(&mut self) {
        assert!(matches!(
            self.request(
                tunnel_fs_ninep::NOTAG,
                NinepMessage::Tversion {
                    msize: WINDOW as u32,
                    version: tunnel_fs_ninep::DIALECT.to_owned(),
                }
            )
            .await,
            NinepMessage::Rversion { .. }
        ));
        assert!(matches!(
            self.request(
                1,
                NinepMessage::Tattach {
                    fid: 0,
                    afid: tunnel_fs_ninep::NOFID,
                    uname: String::new(),
                    aname: String::new(),
                    n_uname: tunnel_fs_ninep::NONUNAME,
                }
            )
            .await,
            NinepMessage::Rattach { .. }
        ));
        assert!(matches!(
            self.request(
                2,
                NinepMessage::Twalk {
                    fid: 0,
                    newfid: 1,
                    names: vec!["probe".to_owned()],
                }
            )
            .await,
            NinepMessage::Rwalk { .. }
        ));
        let NinepMessage::Rgetattr(attributes) = self
            .request(
                3,
                NinepMessage::Tgetattr {
                    fid: 1,
                    request_mask: tunnel_fs_ninep::GETATTR_BASIC,
                },
            )
            .await
        else {
            panic!("real host metadata reply");
        };
        assert_eq!(attributes.size, 19);
        // The capability table refuses missing Write with EPERM before host
        // dispatch. Keep the exact reply in failure diagnostics.
        let refusal = self
            .request(
                4,
                NinepMessage::Tmkdir {
                    dfid: 0,
                    name: "refused".to_owned(),
                    mode: 0o700,
                    gid: u32::MAX,
                },
            )
            .await;
        assert_eq!(
            refusal,
            NinepMessage::Rlerror {
                code: tunnel_fs_core::FsErrorCode::Eperm
            },
            "actual read-only capability refusal"
        );
        assert!(!self.root.path().join("refused").exists());
        assert_eq!(self.actor.fs_counters.exchanges, 0, "no seeded ledger");
    }

    async fn finish_before_done(&mut self) {
        let sequence = self
            .owner
            .direction(Direction::RelayToConnector)
            .last_emitted()
            + 1;
        let ack = self
            .owner
            .direction(Direction::ConnectorToRelay)
            .recv_contiguous();
        self.send_without_yield(Frame::fin(1, 1, STREAM, sequence, ack));
        timeout(BOUND, async {
            loop {
                let request = self.requests.recv().await.expect("live exchange task");
                let finish = matches!(request, HttpActorRequest::Finish { .. });
                assert!(!matches!(request, HttpActorRequest::Done { .. }));
                self.actor
                    .handle_http_request(request)
                    .now_or_never()
                    .expect("actor reply needs no scheduling")
                    .expect("actual actor request");
                if finish {
                    return;
                }
            }
        })
        .await
        .expect("bounded normal provider FIN");
        // No task is polled between this actual Finish reply and retirement.
        self.receive_carrier();
        assert!(self.actor.streams[&STREAM].output_fin);
        assert!(!self.actor.streams[&STREAM].output_reset);
        self.ack();
        assert_eq!(self.actor.fs_counters.exchanges, 0);
        assert!(self.actor.http_handlers.diagnostics().snapshot().is_empty());
    }

    fn retire_without_yield(&mut self) {
        self.receive_carrier();
        let final_state = ResumeDirectionState::from_sequence_snapshot(
            STREAM,
            self.owner.snapshot().direction(Direction::RelayToConnector),
        )
        .expect("actual owner proof");
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "fs-forget".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: STREAM,
            operation_id: "fs-operation".to_owned(),
            direction: Direction::RelayToConnector,
            final_state,
        };
        self.actor
            .validate_stream_forget(&forget)
            .expect("all ordinary proof predicates");
        self.actor
            .handle_stream_forget(forget)
            .expect("ordinary FORGET");
        assert!(
            self.actor.streams.contains_key(&STREAM),
            "carrier barrier still required"
        );
        assert!(matches!(
            self.carrier.try_recv(),
            Ok(CarrierCommand::Barrier)
        ));
        self.actor
            .handle_barrier_complete(&self.key)
            .expect("ordinary barrier completion");
        assert!(self.actor.streams.is_empty());
        assert!(self.actor.pending_forgets.is_empty());
        assert_eq!(self.actor.status.borrow().streams, 0);
    }

    async fn done(&mut self) -> HttpActorRequest {
        timeout(BOUND, async {
            loop {
                let request = self.requests.recv().await.expect("exchange sends Done");
                if matches!(request, HttpActorRequest::Done { .. }) {
                    return request;
                }
                self.actor
                    .handle_http_request(request)
                    .await
                    .expect("remaining actual request");
            }
        })
        .await
        .expect("bounded exchange Done")
    }

    fn assert_ledger(&self) {
        let expected = crate::FsCounters {
            exchanges: 1,
            mutations_refused: 1,
            ..crate::FsCounters::default()
        };
        assert_eq!(self.actor.fs_counters, expected);
        assert_eq!(self.actor.status.borrow().fs, expected);
    }

    async fn task_released(&self) {
        // The actor remains the task owner until retirement aborts it. This
        // observes all task-owned actor senders released; it is not a join claim.
        timeout(BOUND, async {
            while self.actor.http_requests.strong_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned exchange future and pumps released");
    }
}

#[tokio::test]
async fn fs_completed_report_survives_forget_before_done() {
    let mut exchange = Exchange::open().await;
    exchange.exercise_provider().await;
    exchange.finish_before_done().await;
    exchange.retire_without_yield();
    exchange.task_released().await;
    exchange.assert_ledger();
    assert!(
        exchange
            .actor
            .http_handlers
            .diagnostics()
            .snapshot()
            .is_empty(),
        "Done did not run: retirement retained the actual completed report"
    );
}

#[tokio::test]
async fn fs_completed_report_done_before_forget_counts_once() {
    let mut exchange = Exchange::open().await;
    exchange.exercise_provider().await;
    exchange.finish_before_done().await;
    let done = exchange.done().await;
    exchange
        .actor
        .handle_http_request(done)
        .await
        .expect("Done first");
    exchange.assert_ledger();
    exchange.retire_without_yield();
    exchange.task_released().await;
    exchange.assert_ledger();
}

#[tokio::test]
async fn fs_completed_report_queued_done_after_forget_counts_once() {
    let mut exchange = Exchange::open().await;
    exchange.exercise_provider().await;
    exchange.finish_before_done().await;
    let done = exchange.done().await;
    exchange.retire_without_yield();
    exchange.assert_ledger();
    exchange
        .actor
        .handle_http_request(done)
        .await
        .expect("late actual Done");
    exchange.task_released().await;
    exchange.assert_ledger();
    let records = exchange.actor.http_handlers.diagnostics().snapshot();
    assert_eq!(records.len(), 1);
    let report = records[0]
        .fs
        .as_ref()
        .expect("original provider report retained");
    assert_eq!(report.stats.mutations_refused, 1);
    assert!(!report.root_unavailable);
    assert!(!report.empty_grant);
}

#[tokio::test]
async fn fs_completed_report_survives_full_done_channel() {
    let mut exchange = Exchange::open().await;
    exchange.exercise_provider().await;
    exchange.finish_before_done().await;
    // Any inbound read already queued is handled before reserving the only
    // channel slot. The reservation models another actor producer holding
    // that bounded capacity, without fabricating a provider/Done message.
    while let Ok(request) = exchange.requests.try_recv() {
        assert!(matches!(request, HttpActorRequest::Read { .. }));
        exchange
            .actor
            .handle_http_request(request)
            .now_or_never()
            .expect("ready read handler")
            .expect("actual pending read");
    }
    let permit = exchange
        .actor
        .http_requests
        .clone()
        .try_reserve_owned()
        .expect("reserve the one actor channel slot");
    assert_eq!(exchange.actor.http_requests.capacity(), 0);
    timeout(BOUND, async {
        // Three owners are the actor, this permit and the outer task's Done
        // sender: both pump-owned senders have been dropped by the real join.
        while exchange.actor.http_requests.strong_count() != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provider and both pumps complete while Done is backpressured");
    assert!(exchange.requests.try_recv().is_err());
    assert!(
        exchange
            .actor
            .http_handlers
            .diagnostics()
            .snapshot()
            .is_empty()
    );
    exchange.retire_without_yield();
    drop(permit);
    exchange.task_released().await;
    exchange.assert_ledger();
}

#[tokio::test]
async fn fs_forget_does_not_invent_a_report_before_provider_completion() {
    let mut exchange = Exchange::open().await;
    exchange.exercise_provider().await;
    let sequence = exchange
        .owner
        .direction(Direction::RelayToConnector)
        .last_emitted()
        + 1;
    let ack = exchange
        .owner
        .direction(Direction::ConnectorToRelay)
        .recv_contiguous();
    exchange.send_without_yield(Frame::reset(1, 1, STREAM, sequence, ack, M2_RESET_PROTOCOL));
    // Unlike provider-originated FIN, this actor-generated RESET does not
    // wait for serve() to return. Do not poll the provider before retirement.
    exchange.receive_carrier();
    assert!(exchange.actor.streams[&STREAM].output_reset);
    exchange.ack();
    exchange.retire_without_yield();
    exchange.task_released().await;
    assert_eq!(exchange.actor.fs_counters, crate::FsCounters::default());
    assert!(
        exchange
            .actor
            .http_handlers
            .diagnostics()
            .snapshot()
            .is_empty()
    );
}
