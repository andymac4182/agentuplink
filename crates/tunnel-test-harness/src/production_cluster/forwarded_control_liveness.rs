//! M6-C68 real-socket regression for a control session forwarded to its owner.
//!
//! Fresh sessions normally choose their ingress as owner. This test opens a
//! second control socket through relay-b while relay-a still owns the device,
//! then completes HELLO only after the predecessor closes. The already-routed
//! H3 request therefore establishes a real new session on relay-a. Both the
//! catalog token and actor snapshot must prove that remote ownership before
//! any fault is injected.
//!
//! The cut proxy closes the device half but keeps the ingress half open,
//! discarding its output and sending no further input or FIN. This fixture
//! explicitly uses the production 60-second peer idle timeout instead of the
//! other gates' accelerated ten seconds. Healthy idleness exceeds that peer
//! deadline (70 seconds), answering both ingress WS Pings and owner protocol
//! PINGs with exact session bindings. A bound protocol PING/PONG resets
//! the peer idle clock immediately before the cut; no 60-second transport
//! expiry can substitute for the required 35-second device cleanup. Busy
//! owner output is covered separately by the scheduler unit tests.
//! The owner must keep renewing its lease after the cut, then release a still
//! valid lease and its actor session within the device idle/disconnect bound.
//! A fresh, fully operational connector for the same device must follow.

use super::{ProductionCluster, connect_failure_to_harness, open_consumer_stream};
use crate::{Harness, HarnessError, HarnessOptions, Result, RunningHarness};
use futures_util::{SinkExt, StreamExt};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::OwnerClaim;
use tunnel_core::RotationConfig;
use tunnel_protocol::{
    ControlMessage, DEVICE_CONTROL_IDLE_TIMEOUT, DEVICE_CONTROL_PING_INTERVAL, Hello, OwnerFenced,
    RotationPolicy, ServiceAdvertisement, Welcome, decode_control, encode_control,
};
use uuid::Uuid;

type DeviceSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
const PHASE: Duration = Duration::from_secs(10);
// The stated 30 s device idle + 5 s disconnect hand-off. Reconnect must also
// finish inside the client's 60 s OWNER_BUSY window.
const RELEASE_BOUND: Duration = Duration::from_secs(DEVICE_CONTROL_IDLE_TIMEOUT.as_secs() + 5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL; real three-relay device-control liveness acceptance"]
async fn m6c68_forwarded_control_releases_a_blackholed_device_and_reconnects() {
    let mut harness = Harness::start(
        HarnessOptions::from_env()
            .expect("harness options")
            .rotation(RotationConfig::default()),
    )
    .await
    .expect("harness startup");
    let peer_idle_timeout = tunnel_transport::PeerTransportLimits::default().idle_timeout;
    assert!(
        peer_idle_timeout > RELEASE_BOUND,
        "peer idle must not mask device liveness"
    );
    let catalog = Arc::new(
        harness
            .production_catalog()
            .expect("production catalog")
            .clone(),
    );
    let mut cluster = ProductionCluster::start_with_peer_idle_timeout(
        &mut harness,
        catalog,
        None,
        Default::default(),
        None,
        None,
        Default::default(),
        peer_idle_timeout,
    )
    .await
    .expect("three production relays");
    let resign = cluster.start_membership_resigning().await;
    let scenario = if resign.is_ok() {
        timeout(
            Duration::from_secs(150),
            run(&cluster, &harness, peer_idle_timeout),
        )
        .await
        .map_err(|_| HarnessError::Timeout("M6-C68 forwarded scenario".into()))
        .and_then(|result| result)
    } else {
        resign
    };
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    scenario.expect("forwarded device liveness acceptance");
    cluster_cleanup.expect("cluster cleanup joined");
    harness_cleanup.expect("harness cleanup joined");
}

async fn run(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    peer_idle_timeout: Duration,
) -> Result<()> {
    let device = &harness.topology.devices_a[0];
    let service_id = harness.topology.service_ids[&device.id];
    let tls = Arc::new(
        tunnel_transport::load_client_config_from_pem_with_alpn(
            device.certificate.certificate_pem.as_bytes(),
            device.certificate.private_key_pem.as_bytes(),
            harness.pki.server_ca.certificate_pem.as_bytes(),
            &[b"http/1.1"],
        )
        .map_err(|error| failure("device TLS", error))?,
    );
    let owner_addr = device_addr(cluster, "relay-a")?;
    let ingress_addr = device_addr(cluster, "relay-b")?;
    let mut predecessor = open_socket(owner_addr, Arc::clone(&tls), None).await?;
    let predecessor_welcome = handshake(&mut predecessor, device.id, service_id).await?;
    let predecessor_owner = owner(cluster, device)
        .await?
        .ok_or_else(|| failure("bootstrap", "predecessor owner missing"))?;
    require(
        predecessor_owner.token.node_id == "relay-a",
        "predecessor must own on relay-a",
    )?;

    let proxy = CutProxy::start(ingress_addr).await?;
    let mut forwarded = open_socket(proxy.address, Arc::clone(&tls), None).await?;
    // A local control handler requires HELLO first and closes on this Ping.
    // Its Pong proves this socket is in the remote control pump before HELLO.
    forwarded
        .send(Message::Ping(vec![0x68].into()))
        .await
        .map_err(|e| failure("pre-HELLO Ping", e))?;
    match read_socket(&mut forwarded).await? {
        Message::Pong(payload) => require(payload.as_ref() == [0x68], "pre-HELLO Pong binding")?,
        _ => return Err(failure("remote routing", "pre-HELLO Pong missing")),
    }
    // Allow the real Redis-backed owner admission to reach its HELLO read.
    // This delay never establishes success: WELCOME and actor ownership below
    // must independently prove the genuine forwarding path actually won.
    sleep(Duration::from_millis(250)).await;
    predecessor
        .close(None)
        .await
        .map_err(|e| failure("predecessor close", e))?;
    drop(predecessor);
    wait_no_owner(cluster, device, Instant::now() + PHASE).await?;
    let welcome = handshake(&mut forwarded, device.id, service_id).await?;
    let live = owner(cluster, device)
        .await?
        .ok_or_else(|| failure("forwarded owner", "missing"))?;
    require(
        live.token.node_id == "relay-a"
            && live.token.session_id == welcome.session_id
            && live.token.epoch == welcome.epoch
            && live.token.session_id != predecessor_welcome.session_id
            && live.token.epoch > predecessor_owner.token.epoch,
        "forwarded WELCOME must bind a fresh remote owner",
    )?;
    require(
        cluster
            .relay("relay-b")?
            .snapshot()
            .await?
            .sessions
            .is_empty(),
        "ingress must not own a local session",
    )?;

    // The data carrier stays reachable. Only control disappearance must be
    // enough to end the owner's complete two-socket session.
    let data = open_socket(
        owner_addr,
        Arc::clone(&tls),
        Some(&welcome.attachment_ticket),
    )
    .await?;
    match next_control(&mut forwarded).await? {
        ControlMessage::DataReady(ready) => require(
            ready.session_id == welcome.session_id && ready.generation == welcome.generation,
            "DATA_READY must bind the forwarded session",
        )?,
        _ => return Err(failure("data attachment", "DATA_READY missing")),
    }
    let _data = TaskGuard(tokio::spawn(drain_data(data)));
    let quiet = peer_idle_timeout + DEVICE_CONTROL_PING_INTERVAL;
    let (pings, owner_pings) = healthy_idle(cluster, &mut forwarded, &welcome, quiet).await?;
    let before = owner(cluster, device)
        .await?
        .ok_or_else(|| failure("healthy idle", "owner lost"))?;
    require(
        before.token == live.token,
        "healthy forwarded owner must survive longer than peer idle timeout",
    )?;
    require(
        control_count(cluster, &welcome.session_id).await?.is_some(),
        "healthy actor session must remain present",
    )?;

    // This real application-level round trip reaches the owner, resetting
    // both H3 receive timers as well as the ingress's device idle deadline.
    let ping_id = Uuid::new_v4().to_string();
    send_control(
        &mut forwarded,
        &ControlMessage::Ping(tunnel_protocol::Ping::new(
            &ping_id,
            &welcome.session_id,
            welcome.epoch,
            68,
        )),
    )
    .await?;
    loop {
        match next_control(&mut forwarded).await? {
            ControlMessage::Pong(pong) => {
                require(
                    pong.reply_to == ping_id
                        && pong.session_id == welcome.session_id
                        && pong.epoch == welcome.epoch
                        && pong.nonce == 68,
                    "pre-cut owner PONG binding",
                )?;
                break;
            }
            ControlMessage::Ping(ping) => answer_owner_ping(&mut forwarded, ping, &welcome).await?,
            _ => return Err(failure("pre-cut owner PING", "PONG missing")),
        }
    }
    let cut = Instant::now();
    proxy.cut.cancel();
    timeout(PHASE, async {
        while !proxy.cut_applied.load(Ordering::Acquire) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| failure("proxy cut", "not applied"))?;
    drop(forwarded);
    expect_owner_busy(ingress_addr, Arc::clone(&tls), device.id, service_id).await?;

    let mut last_claim = before;
    let mut renewals = 0_u64;
    loop {
        if cut.elapsed() > RELEASE_BOUND {
            expect_owner_busy(ingress_addr, Arc::clone(&tls), device.id, service_id).await?;
            return Err(failure(
                "release",
                "remote owner still holds session and refuses OWNER_BUSY after 35 seconds",
            ));
        }
        let current = owner(cluster, device).await?;
        if let Some(current) = current {
            require(
                current.token == live.token,
                "owner changed before explicit release observation",
            )?;
            if current.lease_expires_at > last_claim.lease_expires_at {
                renewals += 1;
            }
            last_claim = current;
        } else {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let released_after = cut.elapsed();
    require(
        released_after >= Duration::from_secs(25),
        "a shorter peer/transport timeout hid device liveness",
    )?;
    require(
        renewals >= 2,
        "owner must renew its lease twice after the cut",
    )?;
    require(
        last_claim.lease_expires_at > chrono::Utc::now() + chrono::Duration::seconds(5),
        "release must precede lease expiry",
    )?;
    require(
        proxy.discarded.load(Ordering::Acquire) > 0,
        "proxy must discard ingress output after the cut",
    )?;
    require(
        control_count(cluster, &welcome.session_id).await?.is_none(),
        "released owner actor session must be removed",
    )?;

    // Reconnect only after proving that both Redis and the remote actor have
    // released the old session. Landing at the ingress cannot hide a leak.
    let files = tempfile::tempdir().map_err(HarnessError::Io)?;
    let canary = "m6c68-forwarded:";
    let profile = crate::acceptance::helpers::write_device_profile(
        files.path(),
        device.id,
        service_id,
        canary,
        ingress_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let client = tunnel_client::connect(tunnel_client::ConnectOptions {
        config: profile.config,
        cancellation: CancellationToken::new(),
        profile: tunnel_client::TransportProfile::M2,
    })
    .await
    .map_err(|e| failure("fresh connector", e))?;
    let recovery: Result<()> = async {
        let mut client = client.clone();
        let session = timeout(PHASE, client.wait_ready())
            .await
            .map_err(|_| failure("reconnect", "readiness timed out"))?
            .map_err(|e| failure("reconnect", e))?;
        require(
            session.session_id != welcome.session_id,
            "reconnect must have a fresh session",
        )?;
        let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
        let mut stream = open_consumer_stream(
            cluster.relay("relay-c")?.consumer_addr()?,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        stream.round_trip(b"after-cut", canary.as_bytes()).await?;
        require(
            cut.elapsed() < Duration::from_secs(60),
            "reconnect must finish inside OWNER_BUSY window",
        )?;
        Ok(())
    }
    .await;
    let stopped = client
        .stop()
        .await
        .map_err(|e| failure("reconnected client stop", e));
    recovery?;
    stopped?;
    println!(
        "m6c68-forwarded-liveness ok relays=3 owner=relay-a ingress=relay-b idle_pings={pings} owner_pings={owner_pings} healthy_idle_ms={} owner_renewals_after_cut={renewals} discarded_bytes={} release_after_cut_ms={} release_bound_ms={} reconnect_after_cut_ms={}",
        quiet.as_millis(),
        proxy.discarded.load(Ordering::Acquire),
        released_after.as_millis(),
        RELEASE_BOUND.as_millis(),
        cut.elapsed().as_millis()
    );
    Ok(())
}

async fn answer_owner_ping(
    socket: &mut DeviceSocket,
    ping: tunnel_protocol::Ping,
    welcome: &Welcome,
) -> Result<()> {
    require(
        ping.session_id == welcome.session_id && ping.epoch == welcome.epoch,
        "owner heartbeat must bind the current session",
    )?;
    send_control(
        socket,
        &ControlMessage::Pong(tunnel_protocol::Pong::new(
            Uuid::new_v4().to_string(),
            ping.message_id,
            ping.session_id,
            ping.epoch,
            ping.nonce,
        )),
    )
    .await
}

async fn healthy_idle(
    cluster: &ProductionCluster,
    socket: &mut DeviceSocket,
    welcome: &Welcome,
    quiet: Duration,
) -> Result<(u64, u64)> {
    let started = Instant::now();
    let deadline = started + quiet;
    let mut pings = 0_u64;
    let mut owner_pings = 0_u64;
    while Instant::now() < deadline {
        let failure_detail = match timeout_at(deadline, socket.next()).await {
            Err(_) => break,
            Ok(Some(Ok(Message::Ping(payload)))) => {
                pings += 1;
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|e| failure("healthy Pong", e))?;
                continue;
            }
            Ok(Some(Ok(Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(ControlMessage::Ping(ping)) = decode_control(text.as_bytes()) {
                    answer_owner_ping(socket, ping, welcome).await?;
                    owner_pings += 1;
                    continue;
                }
                "unexpected control text".to_owned()
            }
            Ok(Some(Err(error))) => error.to_string(),
            Ok(_) => "control closed or unexpected frame".to_owned(),
        };
        let snapshot = cluster.relay("relay-a")?.snapshot().await?;
        return Err(failure(
            "healthy idle",
            format!(
                "{failure_detail}; elapsed_ms={} pings={pings} owner_pings={owner_pings} terminal_reasons={:?} peer_fault_causes={:?}",
                started.elapsed().as_millis(),
                snapshot
                    .session_terminal_events
                    .iter()
                    .map(|event| event.reason)
                    .collect::<Vec<_>>(),
                snapshot.peer_fault_diagnostics.cause_counts,
            ),
        ));
    }
    require(pings >= 6, "healthy control must answer six ingress Pings")?;
    require(
        owner_pings >= 6,
        "healthy control must answer six bound owner PINGs",
    )?;
    Ok((pings, owner_pings))
}

async fn expect_owner_busy(
    address: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    device: Uuid,
    service: Uuid,
) -> Result<()> {
    let mut socket = open_socket(address, tls, None).await?;
    send_control(
        &mut socket,
        &ControlMessage::Hello(hello_message(device, service)),
    )
    .await?;
    loop {
        match read_socket(&mut socket).await? {
            Message::Close(Some(frame)) => {
                return require(
                    u16::from(frame.code) == tunnel_protocol::CONTROL_OWNER_BUSY_CLOSE_CODE
                        && frame.reason == tunnel_protocol::CONTROL_OWNER_BUSY_CLOSE_REASON,
                    "duplicate control must be refused with typed OWNER_BUSY",
                );
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(|e| failure("duplicate Pong", e))?,
            _ => return Err(failure("duplicate control", "OWNER_BUSY close missing")),
        }
    }
}

fn failure(phase: &str, error: impl std::fmt::Display) -> HarnessError {
    HarnessError::Process(format!("M6-C68 {phase}: {error}"))
}

fn require(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(failure("assertion", detail))
    }
}

fn device_addr(cluster: &ProductionCluster, node: &str) -> Result<SocketAddr> {
    cluster
        .relay(node)?
        .running
        .as_ref()
        .map(|relay| relay.device_addr)
        .ok_or_else(|| failure("device address", "relay stopped"))
}

async fn owner(
    cluster: &ProductionCluster,
    device: &crate::DeviceFixture,
) -> Result<Option<OwnerClaim>> {
    cluster
        .catalog
        .current_owner(device.tenant_id, device.id, chrono::Utc::now())
        .await
        .map_err(|e| failure("owner read", e))
}

async fn wait_no_owner(
    cluster: &ProductionCluster,
    device: &crate::DeviceFixture,
    deadline: Instant,
) -> Result<()> {
    timeout_at(deadline, async {
        while owner(cluster, device).await?.is_some() {
            sleep(Duration::from_millis(25)).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| failure("owner release", "deadline elapsed"))?
}

async fn control_count(cluster: &ProductionCluster, session_id: &str) -> Result<Option<u64>> {
    Ok(cluster
        .relay("relay-a")?
        .snapshot()
        .await?
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .map(|session| session.control_queue_enqueued))
}

async fn open_socket(
    address: SocketAddr,
    tls: Arc<rustls::ClientConfig>,
    ticket: Option<&str>,
) -> Result<DeviceSocket> {
    let (path, protocol) = if ticket.is_some() {
        ("data", "agent-tunnel.data.v1")
    } else {
        ("control", "agent-tunnel.control.v1")
    };
    let mut request = format!("wss://localhost:{}/v1/tunnel/{path}", address.port())
        .into_client_request()
        .map_err(|e| failure("WebSocket request", e))?;
    request
        .headers_mut()
        .insert("sec-websocket-protocol", HeaderValue::from_static(protocol));
    if let Some(ticket) = ticket {
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {ticket}"))
                .map_err(|_| failure("ticket header", "invalid encoding"))?,
        );
    }
    let (socket, response) = timeout(
        PHASE,
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(tls))),
    )
    .await
    .map_err(|_| failure("WebSocket handshake", "timed out"))?
    .map_err(|e| failure("WebSocket handshake", e))?;
    require(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok())
            == Some(protocol),
        "selected device subprotocol",
    )?;
    Ok(socket)
}

async fn read_socket(socket: &mut DeviceSocket) -> Result<Message> {
    timeout(PHASE, socket.next())
        .await
        .map_err(|_| failure("socket read", "timed out"))?
        .ok_or_else(|| failure("socket read", "closed"))?
        .map_err(|e| failure("socket read", e))
}

async fn send_control(socket: &mut DeviceSocket, message: &ControlMessage) -> Result<()> {
    let bytes = encode_control(message).map_err(|e| failure("encode control", e))?;
    let text = String::from_utf8(bytes).map_err(|e| failure("control encoding", e))?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|e| failure("send control", e))
}

async fn next_control(socket: &mut DeviceSocket) -> Result<ControlMessage> {
    loop {
        match read_socket(socket).await? {
            Message::Text(text) => {
                return decode_control(text.as_bytes()).map_err(|e| failure("decode control", e));
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(|e| failure("control Pong", e))?,
            Message::Pong(_) => {}
            _ => return Err(failure("control read", "unexpected frame")),
        }
    }
}

fn hello_message(device: Uuid, service: Uuid) -> Hello {
    let mut hello = Hello::new(Uuid::new_v4().to_string(), device.to_string(), 1, 0);
    hello.features = [
        "m1-control-data",
        "authorization-challenge",
        "echo",
        "ordered-rotation-v1",
        "owner-fencing-v1",
    ]
    .map(str::to_owned)
    .to_vec();
    hello.services = vec![ServiceAdvertisement::new(
        service.to_string(),
        "echo",
        "1",
        ["echo", "data", "fin", "ack"],
    )];
    let rotation = RotationConfig::default();
    hello.rotation_policy = Some(RotationPolicy::new(
        rotation.interval_seconds * 1_000,
        rotation.handshake_timeout_seconds * 1_000,
        rotation.overlap_seconds * 1_000,
    ));
    hello
}

async fn handshake(socket: &mut DeviceSocket, device: Uuid, service: Uuid) -> Result<Welcome> {
    let hello = hello_message(device, service);
    let hello_id = hello.message_id.clone();
    send_control(socket, &ControlMessage::Hello(hello)).await?;
    let ControlMessage::Welcome(welcome) = next_control(socket).await? else {
        return Err(failure("HELLO", "WELCOME missing"));
    };
    require(welcome.reply_to == hello_id, "WELCOME reply binding")?;
    let ControlMessage::OwnerFence(fence) = next_control(socket).await? else {
        return Err(failure("HELLO", "OWNER_FENCE missing"));
    };
    require(
        fence.session_id == welcome.session_id
            && fence.epoch == welcome.epoch
            && welcome.owner_id.as_ref() == Some(&fence.owner_id),
        "OWNER_FENCE binding",
    )?;
    send_control(
        socket,
        &ControlMessage::OwnerFenced(OwnerFenced::from_fence(Uuid::new_v4().to_string(), &fence)),
    )
    .await?;
    Ok(welcome)
}

async fn drain_data(mut socket: DeviceSocket) {
    while let Some(Ok(message)) = socket.next().await {
        match message {
            Message::Ping(payload)
                if socket.send(Message::Pong(payload.clone())).await.is_err() =>
            {
                break;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

struct TaskGuard(JoinHandle<()>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct CutProxy {
    address: SocketAddr,
    cut: CancellationToken,
    cut_applied: Arc<AtomicBool>,
    discarded: Arc<AtomicU64>,
    _task: TaskGuard,
}
impl CutProxy {
    async fn start(upstream: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(HarnessError::Io)?;
        let address = listener.local_addr().map_err(HarnessError::Io)?;
        let cut = CancellationToken::new();
        let stop = cut.clone();
        let cut_applied = Arc::new(AtomicBool::new(false));
        let applied = Arc::clone(&cut_applied);
        let discarded = Arc::new(AtomicU64::new(0));
        let count = Arc::clone(&discarded);
        // Exactly one known control socket, avoiding protocol guesses based
        // on TLS byte positions or the order of arbitrary connections.
        let task = TaskGuard(tokio::spawn(async move {
            let Ok((mut device, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut relay) = TcpStream::connect(upstream).await else {
                return;
            };
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut device, &mut relay) => return,
                _ = stop.cancelled() => {}
            }
            drop(device);
            applied.store(true, Ordering::Release);
            let mut buffer = [0_u8; 8192];
            loop {
                match relay.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(bytes) => {
                        count.fetch_add(bytes as u64, Ordering::Relaxed);
                    }
                }
            }
        }));
        Ok(Self {
            address,
            cut,
            cut_applied,
            discarded,
            _task: task,
        })
    }
}
