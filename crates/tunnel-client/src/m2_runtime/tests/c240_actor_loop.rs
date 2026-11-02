//! C240 scope A: ordinary protocol input through the real session loop.
//! The owner and grants are synthetic. This is not a public-route close oracle.
use super::*;
use std::sync::{Mutex, Weak};

const LIMIT: usize = 256 * 1024;
const BULK: usize = 192 * 1024;
const WINDOW: u64 = 128 * 1024;
const SCENARIO: Duration = Duration::from_secs(4);
const CLEANUP: Duration = Duration::from_secs(60);
type Proof<T = ()> = Result<T, String>;

macro_rules! require {
    ($condition:expr, $($detail:tt)+) => {
        if !$condition { return Err(format!($($detail)+)); }
    };
}

// Task-local scope avoids global state, cross-test traffic and setters. Every
// hook below observes the actor; none changes a queue, deadline or decision.
tokio::task_local! { static PROBE: Arc<Probe>; }

#[derive(Clone, Debug)]
struct StreamObservation {
    id: u64,
    pending: usize,
    challenge: String,
    digest: String,
    revision: u64,
    confirmed: bool,
    invalidated: bool,
    refresh: bool,
    auth: DualDeadline,
    operation: DualDeadline,
    inbound: tunnel_protocol::DirectionSnapshot,
    outbound: tunnel_protocol::DirectionSnapshot,
}

#[derive(Clone, Debug)]
struct Observation {
    at: Instant,
    wall: SystemTime,
    total: usize,
    carrier: usize,
    streams: Vec<StreamObservation>,
    frozen: bool,
    local_fence: Option<FenceSnapshot>,
    peer_fence: Option<FenceSnapshot>,
    pending_terminals: usize,
    recovery: bool,
    expired: u64,
}

#[derive(Default)]
struct Evidence {
    last: Option<Observation>,
    rejection: Option<(usize, Observation)>,
    budget: Option<Weak<QueueBudget>>,
    dispatches: Vec<u64>,
    phases: Vec<&'static str>,
    task_joins: Vec<bool>,
    carrier_closes: Vec<(String, bool)>,
    dial_joins: Vec<bool>,
    control_join: Option<bool>,
    stopping_at: Option<Instant>,
    closed_at: Option<Instant>,
}

#[derive(Default)]
struct Probe {
    evidence: Mutex<Evidence>,
    changed: Notify,
}

fn note(update: impl FnOnce(&mut Evidence)) {
    let _ = PROBE.try_with(|probe| {
        update(&mut probe.evidence.lock().expect("C240 passive probe lock"));
        probe.changed.notify_waiters();
    });
}

pub(in crate::m2_runtime) fn observe(actor: &M2Actor, rejected: Option<usize>) {
    let _ = PROBE.try_with(|_| {
        let snapshot = Observation {
            at: Instant::now(),
            wall: SystemTime::now(),
            total: actor.aggregate_retained_bytes(),
            carrier: actor.data_budget.current(),
            streams: actor
                .streams
                .iter()
                .map(|(&id, stream)| StreamObservation {
                    id,
                    pending: stream.pending_bytes,
                    challenge: stream.auth.challenge_id.clone(),
                    digest: stream.auth.permission_digest.clone(),
                    revision: stream.auth.grant_revision,
                    confirmed: stream.auth.confirmed,
                    invalidated: stream.auth.invalidated,
                    refresh: stream.auth.refresh_in_flight,
                    auth: stream.auth.deadline,
                    operation: stream.auth.operation_deadline,
                    inbound: stream
                        .sequence
                        .direction(Direction::RelayToConnector)
                        .snapshot(),
                    outbound: stream
                        .sequence
                        .direction(Direction::ConnectorToRelay)
                        .snapshot(),
                })
                .collect(),
            frozen: actor.writes_frozen,
            local_fence: actor.local_fence.clone(),
            peer_fence: actor.peer_fence.clone(),
            pending_terminals: actor
                .pending_outputs
                .iter()
                .filter(|output| output.kind == FrameKind::Reset)
                .count(),
            recovery: actor.recovery_requested || actor.recovery.is_some(),
            expired: actor.auth_expired_streams,
        };
        note(|evidence| {
            evidence
                .budget
                .get_or_insert_with(|| Arc::downgrade(&actor.data_budget));
            if let Some(additional) = rejected {
                evidence.rejection = Some((additional, snapshot.clone()));
            }
            evidence.last = Some(snapshot);
        });
    });
}

pub(in crate::m2_runtime) fn dispatch(stream_id: u64) {
    note(|e| e.dispatches.push(stream_id));
}
pub(in crate::m2_runtime) fn phase(phase: &'static str) {
    note(|e| {
        e.phases.push(phase);
        match phase {
            "stopping" => e.stopping_at = Some(Instant::now()),
            "closed" => e.closed_at = Some(Instant::now()),
            _ => unreachable!("closed lifecycle vocabulary"),
        }
    });
}
pub(in crate::m2_runtime) fn carrier_task_joined(ok: bool) {
    note(|e| e.task_joins.push(ok));
}
pub(in crate::m2_runtime) fn carrier_closed(id: &str, ok: bool) {
    note(|e| e.carrier_closes.push((id.to_owned(), ok)));
}
pub(in crate::m2_runtime) fn dial_joined(ok: bool) {
    note(|e| e.dial_joins.push(ok));
}
pub(in crate::m2_runtime) fn control_joined(ok: bool) {
    note(|e| e.control_join = Some(ok));
}

impl Probe {
    async fn wait(&self, predicate: impl Fn(&Observation) -> bool) -> Proof<Observation> {
        loop {
            let changed = self.changed.notified();
            if let Some(snapshot) = self
                .evidence
                .lock()
                .map_err(|_| "probe poisoned")?
                .last
                .clone()
                && predicate(&snapshot)
            {
                return Ok(snapshot);
            }
            changed.await;
        }
    }
}

#[derive(Clone, Debug)]
enum Wire {
    Control(Box<ControlMessage>),
    Frame(Frame),
    Pong(Vec<u8>),
}

#[derive(Default)]
struct Transcript {
    messages: Mutex<Vec<Wire>>,
    changed: Notify,
}

struct SendCommand(Message, oneshot::Sender<Proof>);
struct Peer {
    send: mpsc::Sender<SendCommand>,
    transcript: Arc<Transcript>,
    task: Option<JoinHandle<Proof>>,
}

impl Peer {
    fn spawn<S, E>(mut socket: S) -> Self
    where
        S: futures_util::Stream<Item = Result<Message, E>>
            + futures_util::Sink<Message, Error = E>
            + Unpin
            + Send
            + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let (send, mut commands) = mpsc::channel::<SendCommand>(8);
        let transcript = Arc::new(Transcript::default());
        let observed = transcript.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = commands.recv() => {
                        let Some(SendCommand(message, done)) = command else {
                            return Err("fixture command owner dropped before socket closed".to_owned());
                        };
                        let result = socket.send(message).await.map_err(|e| e.to_string());
                        let failed = result.is_err();
                        let _ = done.send(result);
                        if failed { return Err("fixture socket write failed".to_owned()); }
                    }
                    incoming = socket.next() => {
                        let Some(incoming) = incoming else { return Ok(()); };
                        let message = incoming.map_err(|e| e.to_string())?;
                        let wire = match message {
                            Message::Text(text) => Wire::Control(Box::new(decode_control(text.as_bytes()).map_err(|e| e.to_string())?)),
                            Message::Binary(bytes) => Wire::Frame(Frame::decode(&bytes).map_err(|e| e.to_string())?),
                            Message::Pong(bytes) => Wire::Pong(bytes.to_vec()),
                            Message::Ping(bytes) => {
                                socket.send(Message::Pong(bytes)).await.map_err(|e| e.to_string())?;
                                continue;
                            }
                            Message::Close(_) => {
                                // Flush the automatic close reply. EOF is only accepted here as
                                // teardown evidence, never as an empty/live-channel assertion.
                                socket.flush().await.map_err(|e| e.to_string())?;
                                return Ok(());
                            }
                            Message::Frame(_) => return Err("unexpected raw WebSocket frame".to_owned()),
                        };
                        {
                            let mut log = observed.messages.lock().map_err(|_| "transcript poisoned")?;
                            require!(log.len() < 128, "fixture transcript capacity exceeded");
                            log.push(wire);
                        }
                        observed.changed.notify_waiters();
                    }
                }
            }
        });
        Self {
            send,
            transcript,
            task: Some(task),
        }
    }

    async fn send(&self, message: Message) -> Proof {
        let (done, wait) = oneshot::channel();
        self.send
            .send(SendCommand(message, done))
            .await
            .map_err(|_| "peer writer ended")?;
        wait.await.map_err(|_| "peer write was not settled")?
    }

    async fn control(&self, message: ControlMessage) -> Proof {
        self.send(websocket_control(&message)).await
    }

    async fn frame(&self, frame: &Frame) -> Proof {
        self.send(Message::Binary(
            frame.encode().map_err(|e| e.to_string())?.into(),
        ))
        .await
    }

    fn messages(&self) -> Proof<Vec<Wire>> {
        Ok(self
            .transcript
            .messages
            .lock()
            .map_err(|_| "transcript poisoned")?
            .clone())
    }

    async fn wait<T>(&self, select: impl Fn(&[Wire]) -> Option<T>) -> Proof<T> {
        loop {
            let changed = self.transcript.changed.notified();
            if let Some(value) = select(&self.messages()?) {
                return Ok(value);
            }
            if self.task.as_ref().is_none_or(JoinHandle::is_finished) {
                return Err("peer ended before the required live observation".to_owned());
            }
            // Task completion also needs to be noticed without treating EOF
            // as success. This is polling for failure, not a no-output sleep.
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }

    async fn barrier(&self, marker: &'static [u8]) -> Proof {
        self.send(Message::Ping(marker.to_vec().into())).await?;
        self.wait(|log| {
            log.iter()
                .any(|wire| matches!(wire, Wire::Pong(value) if value == marker))
                .then_some(())
        })
        .await
    }

    async fn join(&mut self) -> Proof {
        // unfreeze() also joins inside the independently bounded scenario;
        // retain the handle here if that outer future is cancelled.
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let result = match timeout(M2_CLOSE_TIMEOUT, &mut *task).await {
            Ok(result) => result.map_err(|e| e.to_string()).and_then(|result| result),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("peer cleanup timed out (aborted and joined)".to_owned())
            }
        };
        self.task = None;
        result
    }
}

// Only a real candidate dial may enable the frozen cases. The initial two
// sockets use the existing loopback helper; the third uses mandatory mTLS.
// This server verifies only its synthetic attachment ticket, not a catalog.
struct Candidate {
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<(), tunnel_transport::TransportError>>>,
    socket: Option<oneshot::Receiver<axum::extract::ws::WebSocket>>,
    handed_off: Option<oneshot::Receiver<()>>,
    upgrades: Arc<std::sync::atomic::AtomicUsize>,
    peer: Option<Peer>,
}

impl Candidate {
    async fn prepare(
        config: &mut RuntimeConfig,
    ) -> Proof<(TcpListener, axum::Router, Arc<rustls::ServerConfig>, Self)> {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose, SanType,
        };
        let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params.self_signed(&ca_key).map_err(|e| e.to_string())?;
        let server_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params =
            CertificateParams::new(vec!["localhost".to_owned()]).map_err(|e| e.to_string())?;
        params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = params
            .signed_by(&server_key, &ca, &ca_key)
            .map_err(|e| e.to_string())?;
        let client_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::default();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names.push(SanType::URI(
            "urn:agent-tunnel:device:c240-synthetic-device"
                .try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        ));
        config.device_id = "c240-synthetic-device".to_owned();
        let client = params
            .signed_by(&client_key, &ca, &ca_key)
            .map_err(|e| e.to_string())?;
        let tls = tunnel_transport::load_server_config_from_pem_with_alpn(
            format!("{}{}", server.pem(), ca.pem()).as_bytes(),
            server_key.serialize_pem().as_bytes(),
            Some(ca.pem().as_bytes()),
            &[b"http/1.1"],
        )
        .map_err(|e| e.to_string())?;
        // Pin the generated bytes through the normal credential API, then
        // remove the owned files before any actor/socket task is started.
        let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
        for (name, bytes) in [
            ("client.pem", client.pem()),
            ("key.pem", client_key.serialize_pem()),
            ("ca.pem", ca.pem()),
        ] {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(directory.path().join(name))
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut file, bytes.as_bytes()).map_err(|e| e.to_string())?;
        }
        config.credentials.client_certificate = directory.path().join("client.pem");
        config.credentials.client_key = directory.path().join("key.pem");
        config.credentials.server_ca = directory.path().join("ca.pem");
        config.credentials.pin().map_err(|e| e.to_string())?;
        directory.close().map_err(|e| e.to_string())?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| e.to_string())?;
        config.relay_url = format!(
            "wss://{}/v1/device/control",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        let (socket_tx, socket) = oneshot::channel();
        let (done_tx, handed_off) = oneshot::channel();
        let transfer = Arc::new(Mutex::new(Some((socket_tx, done_tx))));
        let upgrades = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = upgrades.clone();
        let router = axum::Router::new().route(
            "/v1/device/data",
            axum::routing::get(
                move |headers: http::HeaderMap, ws: axum::extract::ws::WebSocketUpgrade| {
                    let transfer = transfer.clone();
                    let count = count.clone();
                    async move {
                        use axum::response::IntoResponse;
                        if headers
                            .get(http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            != Some("Bearer c240-synthetic-ticket")
                            || headers
                                .get(http::header::SEC_WEBSOCKET_PROTOCOL)
                                .and_then(|v| v.to_str().ok())
                                != Some(crate::DATA_SUBPROTOCOL)
                        {
                            return http::StatusCode::FORBIDDEN.into_response();
                        }
                        let Some((socket_tx, done_tx)) =
                            transfer.lock().expect("candidate transfer").take()
                        else {
                            return http::StatusCode::CONFLICT.into_response();
                        };
                        ws.protocols([crate::DATA_SUBPROTOCOL])
                            .on_upgrade(move |socket| async move {
                                count.fetch_add(1, Ordering::SeqCst);
                                let _ = socket_tx.send(socket);
                                let _ = done_tx.send(());
                                // No detached handler, retained socket or work after transfer.
                            })
                            .into_response()
                    }
                },
            ),
        );
        Ok((
            listener,
            router,
            tls,
            Self {
                cancel: CancellationToken::new(),
                task: None,
                socket: Some(socket),
                handed_off: Some(handed_off),
                upgrades,
                peer: None,
            },
        ))
    }

    async fn receive(&mut self) -> Proof {
        let socket = self
            .socket
            .take()
            .ok_or("candidate received twice")?
            .await
            .map_err(|_| "candidate upgrade failed")?;
        self.handed_off
            .take()
            .ok_or("candidate handoff received twice")?
            .await
            .map_err(|_| "candidate callback did not finish")?;
        use axum::extract::ws::Message as AxumMessage;
        // Adapt only the framework's WebSocket value types; the TLS and
        // WebSocket handshakes above are the actual production dial path.
        let socket = socket
            .with(|message: Message| {
                futures_util::future::ready(Ok::<_, axum::Error>(match message {
                    Message::Text(text) => AxumMessage::Text(text.as_str().into()),
                    Message::Binary(bytes) => AxumMessage::Binary(bytes),
                    Message::Ping(bytes) => AxumMessage::Ping(bytes),
                    Message::Pong(bytes) => AxumMessage::Pong(bytes),
                    Message::Close(_) => AxumMessage::Close(None),
                    Message::Frame(_) => unreachable!("fixture never sends raw frames"),
                }))
            })
            .map(|message| {
                message.map(|message| match message {
                    AxumMessage::Text(text) => Message::Text(text.as_str().into()),
                    AxumMessage::Binary(bytes) => Message::Binary(bytes),
                    AxumMessage::Ping(bytes) => Message::Ping(bytes),
                    AxumMessage::Pong(bytes) => Message::Pong(bytes),
                    AxumMessage::Close(_) => Message::Close(None),
                })
            });
        self.peer = Some(Peer::spawn(socket));
        Ok(())
    }

    async fn finish(&mut self) -> Proof {
        // A scenario may fail while the upgrade is in flight, before receive()
        // transfers its socket to Peer. Dropping the receiver closes any
        // queued socket, and a later send failure drops it in the callback.
        self.socket.take();
        self.handed_off.take();
        let peer_result = if let Some(peer) = &mut self.peer {
            peer.join().await
        } else {
            Ok(())
        };
        self.cancel.cancel();
        let server_result = if let Some(mut task) = self.task.take() {
            match timeout(M2_CLOSE_TIMEOUT, &mut task).await {
                Ok(result) => result
                    .map_err(|e| e.to_string())
                    .and_then(|result| result.map_err(|e| e.to_string())),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err("candidate listener cleanup timed out (aborted and joined)".to_owned())
                }
            }
        } else {
            Ok(())
        };
        combine(peer_result, server_result)
    }
}

struct Fixture {
    control: Peer,
    data: Peer,
    candidate: Option<Candidate>,
    actor: Option<JoinHandle<Result<(), ClientError>>>,
    cancellation: CancellationToken,
    readiness: watch::Receiver<Readiness>,
    probe: Arc<Probe>,
    senders: BTreeMap<u64, StreamState>,
    challenges: BTreeMap<u64, AuthorizationChallenge>,
    natural: Option<Result<(), ClientError>>,
}

impl Fixture {
    async fn new(frozen: bool) -> Proof<Self> {
        let mut config = RuntimeConfig::default();
        config.limits.max_streams = 2;
        config.limits.max_queue_bytes = LIMIT;
        config.limits.grant_timeout_ms = 5_000;
        let prepared = if frozen {
            Some(Candidate::prepare(&mut config).await?)
        } else {
            None
        };
        config.validate().map_err(|e| e.to_string())?;
        require!(
            LIMIT - critical_reserved_bytes(LIMIT) == BULK,
            "unexpected configured bulk ceiling"
        );
        let (control, control_peer) = test_websocket_pair().await?;
        let (data, data_peer) = test_websocket_pair().await?;
        let candidate = prepared.map(|(listener, router, tls, mut candidate)| {
            candidate.task = Some(tokio::spawn(tunnel_transport::serve_with_listener_options(
                listener,
                router,
                tls,
                candidate.cancel.clone(),
                tunnel_transport::AcceptedSocketOptions {
                    capacity: tunnel_transport::ListenerCapacity {
                        max_connections: 1,
                        refusal_margin: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tunnel_transport::ListenerTimeouts::default(),
            )));
            candidate
        });
        let (control_sink, control_stream) = control.split();
        let (data_sink, data_stream) = data.split();
        let cancellation = CancellationToken::new();
        let session = SessionInfo {
            session_id: "session".to_owned(),
            epoch: 1,
            generation: 1,
        };
        let (readiness_tx, readiness) = watch::channel(Readiness::Ready(session.clone()));
        let (status, _status_rx) = watch::channel(ConnectionStatus::default());
        let probe = Arc::new(Probe::default());
        let actor = tokio::spawn(PROBE.scope(
            probe.clone(),
            run_m2_session(
                config,
                session,
                runtime_welcome(),
                "owner".to_owned(),
                None,
                RotationConfig::default(),
                control_sink,
                control_stream,
                data_sink,
                data_stream,
                cancellation.clone(),
                readiness_tx,
                status,
                None,
                None,
                None,
                HttpHandlers::default(),
            ),
        ));
        Ok(Self {
            control: Peer::spawn(control_peer),
            data: Peer::spawn(data_peer),
            candidate,
            actor: Some(actor),
            cancellation,
            readiness,
            probe,
            senders: BTreeMap::new(),
            challenges: BTreeMap::new(),
            natural: None,
        })
    }

    async fn open(&mut self, id: u64) -> Proof {
        let mut open = test_open(id);
        open.initial_send_window = WINDOW;
        open.initial_receive_window = WINDOW;
        open.metadata.insert(
            "permission_digest".to_owned(),
            "c240-synthetic-permission".to_owned(),
        );
        open.metadata
            .insert("grant_revision".to_owned(), "7".to_owned());
        self.control.control(ControlMessage::Open(open)).await?;
        self.control
            .wait(|log| {
                log.iter().find_map(|wire| match wire {
                    Wire::Control(message) => match message.as_ref() {
                        ControlMessage::Opened(opened) if opened.stream_id == id => {
                            Some(opened.clone())
                        }
                        _ => None,
                    },
                    _ => None,
                })
            })
            .await
            .and_then(|opened| {
                require!(
                    opened.send_window == WINDOW && opened.receive_window == WINDOW,
                    "negotiated credit differs from fixture"
                );
                Ok(())
            })?;
        let challenge = self
            .control
            .wait(|log| {
                log.iter().find_map(|wire| match wire {
                    Wire::Control(message) => match message.as_ref() {
                        ControlMessage::AuthorizationChallenge(challenge)
                            if challenge.stream_id == id =>
                        {
                            Some(challenge.clone())
                        }
                        _ => None,
                    },
                    _ => None,
                })
            })
            .await?;
        self.challenges.insert(id, challenge);
        self.senders
            .insert(id, StreamState::new(id, WINDOW).map_err(|e| e.to_string())?);
        Ok(())
    }

    fn assign(&mut self, id: u64, payload: Vec<u8>) -> Proof<Frame> {
        let sender = self.senders.get_mut(&id).ok_or("sender was not admitted")?;
        let sequence = sender.direction(Direction::RelayToConnector).last_emitted() + 1;
        let frame = Frame::data(1, 1, id, sequence, 0, payload);
        sender
            .send_frame(Direction::RelayToConnector, &frame)
            .map_err(|e| e.to_string())?;
        Ok(frame)
    }

    async fn deliver(&mut self, frame: &Frame) -> Proof {
        self.data.frame(frame).await?;
        self.data.wait(|log| log.iter().any(|wire| matches!(wire, Wire::Frame(reply) if reply.stream_id == frame.stream_id && reply.ack >= frame.sequence)).then_some(())).await?;
        // The wire ACK clears actual sender replay before the next assignment;
        // every returned cumulative credit also passes the sequence validator.
        let sender = self
            .senders
            .get_mut(&frame.stream_id)
            .ok_or("sender missing")?;
        for wire in self.data.messages()? {
            if let Wire::Frame(reply) = wire
                && reply.stream_id == frame.stream_id
                && matches!(reply.kind, FrameKind::Ack | FrameKind::WindowUpdate)
            {
                sender
                    .receive_frame(Direction::ConnectorToRelay, &reply)
                    .map_err(|e| e.to_string())?;
            }
        }
        self.probe
            .wait(|snapshot| {
                snapshot.carrier == 0
                    && snapshot.streams.iter().any(|stream| {
                        stream.id == frame.stream_id
                            && stream.inbound.delivered_contiguous >= frame.sequence
                    })
            })
            .await?;
        Ok(())
    }

    async fn confirmation(&self, id: u64) -> Proof {
        let challenge = self.challenges.get(&id).ok_or("challenge missing")?;
        self.control
            .control(ControlMessage::AuthorizationConfirmed(
                AuthorizationConfirmed::new(
                    "c240-confirmed",
                    challenge.message_id.clone(),
                    "session",
                    1,
                    id,
                    challenge.challenge_id.clone(),
                    challenge.nonce.clone(),
                    challenge.permission_digest.clone(),
                    challenge.grant_revision,
                    5_000,
                ),
            ))
            .await
    }

    async fn invalidation(&self, id: u64) -> Proof {
        let challenge = self.challenges.get(&id).ok_or("challenge missing")?;
        self.control
            .control(ControlMessage::AuthorizationInvalidated(
                AuthorizationInvalidated::new(
                    "c240-invalidated",
                    "session",
                    1,
                    id,
                    challenge.challenge_id.clone(),
                    7,
                    "synthetic grant revoked",
                ),
            ))
            .await
    }

    fn attempt() -> tunnel_protocol::rotation_control::RotationAttemptIdentity {
        tunnel_protocol::rotation_control::RotationAttemptIdentity {
            session_id: "session".to_owned(),
            epoch: 1,
            owner_id: "owner".to_owned(),
            rotation_id: "c240-rotation".to_owned(),
            old_generation: 1,
            new_generation: 2,
            old_connection_id: "connection".to_owned(),
            new_connection_id: "c240-candidate".to_owned(),
        }
    }

    async fn freeze(&mut self) -> Proof<(FenceSnapshot, FenceSnapshot)> {
        let attempt = Self::attempt();
        self.control
            .control(ControlMessage::RotatePrepare(RotatePrepare {
                message_id: "c240-prepare".to_owned(),
                reply_to: String::new(),
                attempt: attempt.clone(),
                attachment_purpose: Default::default(),
                attachment_ticket: "c240-synthetic-ticket".to_owned(),
                reconnect_credential: None,
                remaining_ms: 10_000,
            }))
            .await?;
        self.candidate
            .as_mut()
            .ok_or("candidate fixture missing")?
            .receive()
            .await?;
        self.control
            .control(ControlMessage::DataReady(DataReady::new(
                "c240-ready",
                "c240-prepare",
                "session",
                1,
                2,
                "c240-candidate",
            )))
            .await?;
        self.control
            .control(ControlMessage::RotateQuiesce(RotateQuiesce {
                message_id: "c240-quiesce".to_owned(),
                reply_to: "c240-prepare".to_owned(),
                attempt: attempt.clone(),
                roster: tunnel_protocol::rotation_control::StreamRoster::new(
                    "c240-roster",
                    self.senders.keys().copied().collect(),
                ),
                remaining_ms: 10_000,
            }))
            .await?;
        let local = self
            .control
            .wait(|log| {
                log.iter().find_map(|wire| match wire {
                    Wire::Control(message) => match message.as_ref() {
                        ControlMessage::RotateFrozen(frozen) => Some(frozen.clone()),
                        _ => None,
                    },
                    _ => None,
                })
            })
            .await?;
        let peer = FenceSnapshot::new(
            "c240-roster",
            self.senders
                .iter()
                .map(|(&id, sender)| {
                    // These are real already-assigned frames held by the fixture, not
                    // invented sequence counts or new writes after quiesce.
                    StreamFence::new(
                        id,
                        Direction::RelayToConnector,
                        sender.direction(Direction::RelayToConnector).last_emitted(),
                    )
                })
                .collect(),
        );
        self.control
            .control(ControlMessage::RotateFrozen(RotateFrozen {
                message_id: "c240-owner-frozen".to_owned(),
                reply_to: local.message_id,
                attempt,
                snapshot: peer.clone(),
            }))
            .await?;
        let observed = self
            .probe
            .wait(|state| state.frozen && state.peer_fence.is_some())
            .await?;
        require!(
            observed.local_fence.as_ref() == Some(&local.snapshot)
                && observed.peer_fence.as_ref() == Some(&peer),
            "real immutable fences differ"
        );
        require!(
            self.candidate
                .as_ref()
                .unwrap()
                .upgrades
                .load(Ordering::SeqCst)
                == 1,
            "candidate was not attached exactly once"
        );
        Ok((local.snapshot, peer))
    }

    async fn unfreeze(&mut self) -> Proof {
        let attempt = Self::attempt();
        self.control
            .control(ControlMessage::RotateAbort(RotateAbort {
                message_id: "c240-abort".to_owned(),
                reply_to: String::new(),
                attempt: attempt.clone(),
                reason: "synthetic owner abort".to_owned(),
                remaining_ms: 10_000,
            }))
            .await?;
        let aborted = self
            .control
            .wait(|log| {
                log.iter().find_map(|wire| match wire {
                    Wire::Control(message) => match message.as_ref() {
                        ControlMessage::RotateAborted(aborted) => Some(aborted.clone()),
                        _ => None,
                    },
                    _ => None,
                })
            })
            .await?;
        // The owner's final closure message follows an actual joined peer;
        // do not manufacture bilateral closure while a candidate remains live.
        self.candidate
            .as_mut()
            .ok_or("candidate missing")?
            .peer
            .as_mut()
            .ok_or("candidate peer missing")?
            .join()
            .await?;
        self.control
            .control(ControlMessage::RotateAborted(RotateAborted {
                message_id: "c240-owner-aborted".to_owned(),
                reply_to: aborted.message_id,
                attempt,
                reason: "synthetic owner abort".to_owned(),
                closed_connection_id: "c240-candidate".to_owned(),
            }))
            .await?;
        self.probe.wait(|state| !state.frozen).await?;
        Ok(())
    }

    async fn natural_completion(&mut self) -> Proof {
        let joined = self.actor.as_mut().ok_or("actor already joined")?.await;
        self.actor = None;
        self.natural = Some(joined.map_err(|e| e.to_string())?);
        Ok(())
    }

    fn live(&self, state: &Observation) -> Proof {
        require!(
            !state.recovery && state.expired == 0,
            "quota witness had recovery/expiry"
        );
        for stream in &state.streams {
            let challenge = self
                .challenges
                .get(&stream.id)
                .ok_or("unadmitted observed stream")?;
            require!(
                !stream.confirmed && stream.refresh && !stream.invalidated,
                "authorization changed before quota"
            );
            require!(
                !stream.auth.expired_at(state.at, state.wall)
                    && !stream.operation.expired_at(state.at, state.wall),
                "quota arrived outside the live authorization/operation window"
            );
            require!(
                stream.challenge == challenge.challenge_id
                    && stream.digest == challenge.permission_digest
                    && stream.revision == challenge.grant_revision,
                "synthetic grant identity changed"
            );
        }
        Ok(())
    }

    fn no_application_or_reset(&self) -> Proof {
        for peer in [&self.control, &self.data].into_iter().chain(
            self.candidate
                .as_ref()
                .and_then(|candidate| candidate.peer.as_ref()),
        ) {
            for wire in peer.messages()? {
                match wire {
                    Wire::Frame(frame) => require!(
                        !matches!(
                            frame.kind,
                            FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                        ),
                        "unexpected application output/terminal: {:?}",
                        frame.kind
                    ),
                    Wire::Control(message) => require!(
                        !matches!(
                            message.as_ref(),
                            ControlMessage::RotateRequest(_)
                                | ControlMessage::RecoveryBegin(_)
                                | ControlMessage::Resume(_)
                        ),
                        "unexpected recovery/replay request"
                    ),
                    Wire::Pong(_) => {}
                }
            }
        }
        require!(
            self.probe
                .evidence
                .lock()
                .map_err(|_| "probe poisoned")?
                .dispatches
                .is_empty(),
            "buffered input reached application dispatch"
        );
        Ok(())
    }

    async fn finish(&mut self) -> Proof {
        // A natural quota result must already have been collected by the
        // scenario. Controls and failed scenarios request stop only here.
        let actor_result = if let Some(mut actor) = self.actor.take() {
            self.cancellation.cancel();
            match timeout(CLEANUP, &mut actor).await {
                Ok(result) => result
                    .map_err(|e| e.to_string())
                    .and_then(|result| result.map_err(|e| e.safe_message())),
                Err(_) => {
                    actor.abort();
                    let _ = actor.await;
                    Err("actor cleanup timed out (aborted and joined)".to_owned())
                }
            }
        } else {
            Ok(())
        };
        let control_result = self.control.join().await;
        let data_result = self.data.join().await;
        let candidate_result = if let Some(candidate) = &mut self.candidate {
            candidate.finish().await
        } else {
            Ok(())
        };
        let cleanup = combine(
            combine(actor_result, control_result),
            combine(data_result, candidate_result),
        );
        let ownership = self.check_ownership();
        combine(cleanup, ownership)
    }

    fn check_ownership(&self) -> Proof {
        let evidence = self.probe.evidence.lock().map_err(|_| "probe poisoned")?;
        require!(
            matches!(&*self.readiness.borrow(), Readiness::Closed { .. }),
            "session did not publish Closed"
        );
        require!(
            evidence.phases == ["stopping", "closed"],
            "readiness lifecycle was not stopping/closed"
        );
        require!(
            evidence.control_join == Some(true),
            "control writer was not joined successfully"
        );
        require!(
            evidence
                .stopping_at
                .zip(evidence.closed_at)
                .is_some_and(|(start, end)| end.duration_since(start) < M2_CLOSE_TIMEOUT),
            "cleanup reached a product close timeout; joined fallback is not a clean acceptance pass"
        );
        let carriers = if self.candidate.is_some() { 2 } else { 1 };
        require!(
            evidence.task_joins.len() == carriers * 2
                && evidence.task_joins.iter().all(|joined| *joined),
            "carrier task panic or timeout/abort in {:?}",
            evidence.task_joins
        );
        let mut closes = evidence.carrier_closes.clone();
        closes.sort();
        let expected = if self.candidate.is_some() {
            vec![
                ("c240-candidate".to_owned(), true),
                ("connection".to_owned(), true),
            ]
        } else {
            vec![("connection".to_owned(), true)]
        };
        require!(
            closes == expected,
            "carrier closure ownership mismatch: {closes:?}"
        );
        require!(
            evidence.dial_joins
                == if self.candidate.is_some() {
                    vec![true]
                } else {
                    vec![]
                },
            "candidate dial was not joined"
        );
        require!(
            evidence
                .budget
                .as_ref()
                .is_some_and(|budget| budget.upgrade().is_none()),
            "real carrier budget is still owned after actor/peer joins"
        );
        // The returned actor future has dropped its stream/pending owners.
        // Neither this Weak witness nor Closed.queue_bytes measures RSS.
        Ok(())
    }
}

fn combine(first: Proof, second: Proof) -> Proof {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(format!("{first}; additional cleanup failure: {second}")),
    }
}

fn quota_predicate(result: Option<&Result<(), ClientError>>, evidence: &Evidence) -> bool {
    matches!(result, Some(Err(ClientError::QueueLimit)))
        && evidence
            .rejection
            .as_ref()
            .is_some_and(|(additional, state)| state.total == BULK && *additional > 0)
        && evidence.dispatches.is_empty()
}

async fn quota_case(frozen: bool, cross: bool) -> Proof {
    let mut fixture = timeout(Duration::from_secs(5), Fixture::new(frozen))
        .await
        .map_err(|_| "setup timed out")??;
    let scenario = timeout(SCENARIO, async {
        fixture.open(1).await?;
        fixture.open(2).await?;
        let mut frames = Vec::new();
        for (id, marker) in [(1, 1u8), (1, 2), (2, 3)] {
            frames.push(fixture.assign(
                id,
                record(&vec![marker; MAX_PAYLOAD_LEN - M2_RECORD_HEADER_BYTES]),
            )?);
        }
        let crossing = if cross {
            Some(fixture.assign(2, vec![0])?)
        } else {
            None
        };
        let fences = if frozen {
            Some(fixture.freeze().await?)
        } else {
            None
        };
        for frame in &frames {
            fixture.deliver(frame).await?;
        }
        fixture.data.barrier(b"c240-filled").await?;
        let before = fixture
            .probe
            .wait(|state| state.total == BULK && state.carrier == 0)
            .await?;
        fixture.live(&before)?;
        require!(
            before
                .streams
                .iter()
                .map(|stream| stream.pending)
                .sum::<usize>()
                == BULK,
            "ceiling was not actual pending bytes"
        );
        fixture.no_application_or_reset()?;
        if let Some(crossing) = crossing {
            fixture.data.frame(&crossing).await?;
            fixture.natural_completion().await?;
            let evidence = fixture
                .probe
                .evidence
                .lock()
                .map_err(|_| "probe poisoned")?;
            require!(
                quota_predicate(fixture.natural.as_ref(), &evidence),
                "natural QueueLimit predicate did not hold"
            );
            let error = fixture.natural.as_ref().unwrap().as_ref().unwrap_err();
            require!(
                error.code() == "RESOURCE_EXHAUSTED" && !error.retryable(),
                "connector quota diagnostic changed"
            );
            let (_, rejected) = evidence.rejection.as_ref().unwrap();
            fixture.live(rejected)?;
            require!(
                rejected.frozen == frozen,
                "quota did not occur in the requested writer phase"
            );
            for stream in &rejected.streams {
                let original = before
                    .streams
                    .iter()
                    .find(|old| old.id == stream.id)
                    .ok_or("stream disappeared")?;
                require!(
                    stream.inbound == original.inbound
                        && stream.outbound == original.outbound
                        && stream.pending == original.pending,
                    "crossing frame mutated sequence or pending data"
                );
            }
            if let Some((local, peer)) = fences {
                require!(
                    rejected.local_fence.as_ref() == Some(&local)
                        && rejected.peer_fence.as_ref() == Some(&peer),
                    "fences changed after freeze"
                );
            }
        } else {
            fixture.control.barrier(b"c240-without-crossing").await?;
            require!(
                fixture
                    .actor
                    .as_ref()
                    .is_some_and(|actor| !actor.is_finished()),
                "in-capacity control ended the session"
            );
            let evidence = fixture
                .probe
                .evidence
                .lock()
                .map_err(|_| "probe poisoned")?;
            require!(
                !quota_predicate(None, &evidence) && evidence.rejection.is_none(),
                "quota oracle accepted an omitted crossing"
            );
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|_| {
        Err("scenario exceeded four seconds; no live-window quota proof".to_owned())
    });
    let cleanup = fixture.finish().await;
    let wire = fixture.no_application_or_reset();
    combine(combine(scenario, cleanup), wire)
}

async fn authorization_case(frozen: bool, invalidate: bool) -> Proof {
    let mut fixture = timeout(Duration::from_secs(5), Fixture::new(frozen))
        .await
        .map_err(|_| "setup timed out")??;
    let scenario = timeout(SCENARIO, async {
        fixture.open(1).await?;
        let payload = record(b"c240-accepted-once");
        let frame = fixture.assign(1, payload.clone())?;
        let fences = if frozen { Some(fixture.freeze().await?) } else { None };
        fixture.deliver(&frame).await?;
        fixture.data.barrier(b"c240-buffered").await?;
        fixture.no_application_or_reset()?;
        let before = fixture.probe.wait(|state| state.streams.first().is_some_and(|stream| stream.pending == payload.len())).await?;
        fixture.live(&before)?;
        if invalidate {
            fixture.invalidation(1).await?;
            let invalidated = fixture.probe.wait(|state| state.streams.first().is_some_and(|stream| stream.invalidated)).await?;
            require!(invalidated.streams[0].pending == 0 && invalidated.expired == 1, "invalidation did not release pending input exactly once");
            if let Some((local, peer)) = fences {
                fixture.control.barrier(b"c240-invalidated-frozen").await?;
                fixture.data.barrier(b"c240-no-frozen-terminal").await?;
                fixture.no_application_or_reset()?;
                require!(invalidated.pending_terminals == 1 && invalidated.streams[0].outbound.last_emitted == 0, "frozen terminal consumed a sequence or was not retained");
                require!(invalidated.local_fence.as_ref() == Some(&local) && invalidated.peer_fence.as_ref() == Some(&peer), "invalidation changed immutable fences");
                fixture.unfreeze().await?;
            }
        } else { fixture.confirmation(1).await?; }
        fixture.data.wait(|log| log.iter().any(|wire| matches!(wire, Wire::Frame(frame) if frame.kind == if invalidate { FrameKind::Reset } else { FrameKind::Data })).then_some(())).await?;
        fixture.control.barrier(b"c240-authorized-control").await?;
        fixture.data.barrier(b"c240-authorized-data").await?;
        if invalidate {
            let settled = fixture.probe.wait(|state| state.carrier == 0 && state.pending_terminals == 0 && state.streams[0].outbound.replay_bytes == 2).await?;
            require!(settled.total == 2 && settled.streams[0].pending == 0, "invalidation retained something other than its unacknowledged two-byte terminal");
        }
        require!(fixture.actor.as_ref().is_some_and(|actor| !actor.is_finished()), "authorization control ended the session");
        let frames: Vec<_> = fixture.data.messages()?.into_iter().filter_map(|wire| match wire {
            Wire::Frame(frame) if matches!(frame.kind, FrameKind::Data | FrameKind::Fin | FrameKind::Reset) => Some(frame), _ => None,
        }).collect();
        require!(frames.len() == 1 && frames[0].sequence == 1, "authorization control did not emit exactly one sequenced result");
        if invalidate {
            require!(frames[0].kind == FrameKind::Reset && frames[0].reset_reason().map_err(|e| e.to_string())? == Some(M2_RESET_AUTH_EXPIRED), "explicit invalidation was not exact RESET4001");
        } else { require!(frames[0].kind == FrameKind::Data && frames[0].payload == payload, "confirmation did not execute the accepted record exactly once"); }
        let evidence = fixture.probe.evidence.lock().map_err(|_| "probe poisoned")?;
        require!(!quota_predicate(None, &evidence) && evidence.rejection.is_none(), "quota oracle accepted authorization control");
        require!(evidence.dispatches == if invalidate { vec![] } else { vec![1] }, "application dispatch count changed");
        Ok(())
    }).await.unwrap_or_else(|_| Err("authorization scenario exceeded its live-window bound".to_owned()));
    let cleanup = fixture.finish().await;
    // Joined peers make this a complete transcript, including messages that
    // might have been in flight at the scenario's final live barrier.
    let final_output = (|| {
        let expected = if invalidate {
            FrameKind::Reset
        } else {
            FrameKind::Data
        };
        let frames: Vec<_> = fixture
            .data
            .messages()?
            .into_iter()
            .filter_map(|wire| match wire {
                Wire::Frame(frame)
                    if matches!(
                        frame.kind,
                        FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                    ) =>
                {
                    Some(frame)
                }
                _ => None,
            })
            .collect();
        require!(
            frames.len() == 1 && frames[0].kind == expected && frames[0].sequence == 1,
            "late or replayed application output after the live barrier"
        );
        if let Some(peer) = fixture
            .candidate
            .as_ref()
            .and_then(|candidate| candidate.peer.as_ref())
        {
            require!(peer.messages()?.iter().all(|wire| !matches!(wire, Wire::Frame(frame) if matches!(frame.kind, FrameKind::Data | FrameKind::Fin | FrameKind::Reset))), "application output crossed candidate before commit");
        }
        let evidence = fixture
            .probe
            .evidence
            .lock()
            .map_err(|_| "probe poisoned")?;
        require!(
            evidence.dispatches == if invalidate { vec![] } else { vec![1] },
            "late application dispatch during teardown"
        );
        Ok(())
    })();
    combine(combine(scenario, cleanup), final_output)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c240_actor_live_quota_closes_and_joins_without_authorization_reset() {
    quota_case(false, true)
        .await
        .expect("normal actor quota proof");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c240_actor_quota_under_real_fences_closes_all_three_sockets() {
    quota_case(true, true)
        .await
        .expect("frozen actor quota proof");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c240_actor_without_crossing_stays_live_and_rejects_quota_oracle() {
    quota_case(false, false)
        .await
        .expect("omitted-crossing control");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c240_actor_confirmation_executes_buffered_record_exactly_once() {
    authorization_case(false, false)
        .await
        .expect("real confirmation control");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c240_actor_invalidation_is_one_4001_without_session_quota_failure() {
    authorization_case(false, true)
        .await
        .expect("real invalidation control");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c240_actor_invalidation_terminal_waits_for_bilateral_abort() {
    authorization_case(true, true)
        .await
        .expect("frozen invalidation control");
}
