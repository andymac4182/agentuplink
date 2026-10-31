//! M6-C68's actual-CLI acceptance: lose both client TCP paths while retaining
//! both ingress halves, then require the same process to become ready again.
//!
//! The existing one-shot HELLO barrier is armed only after a predecessor owns
//! on A. It holds the CLI's forwarded HELLO from B after real peer admission,
//! letting the predecessor close before registration. A fresh owner on A and
//! no session on B prove the remote path before the cut. The barrier is then
//! permanently released; reconnect and cleanup use ordinary production paths.
//! The raw sibling gate retains its independent protocol-heartbeat witnesses.

use super::{
    PHASE, ProductionCluster, RELEASE_BOUND, device_addr, failure, handshake, open_socket, owner,
    require, wait_no_owner,
};
use crate::{
    Harness, HarnessError, HarnessOptions, Result, RunningHarness,
    acceptance::helpers::write_device_profile,
    process::{ManagedProcess, ProcessSpec},
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Write,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_core::RotationConfig;
use tunnel_relay::ControlAttachBarrier;

// The existing single-relay process gate uses this exact retry policy/bound:
// 30 s idle + 5 s hand-off + 1 s maximum retry step + 4 s scheduling margin.
const CLI_RECONNECT_BOUND: Duration = Duration::from_secs(40);
const HEALTHY_IDLE: Duration = Duration::from_secs(70);
const POLL: Duration = Duration::from_millis(25);
const CANARY: &str = "m6c68-cli-forwarded:";
const _: () = assert!(CLI_RECONNECT_BOUND.as_secs() < 60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and tunnel-client; actual CLI three-relay cut-path acceptance"]
async fn m6c68_cli_reconnects_after_both_forwarded_paths_vanish() {
    let mut harness = Harness::start(
        HarnessOptions::from_env()
            .expect("harness options")
            .rotation(RotationConfig::default()),
    )
    .await
    .expect("harness startup");
    let barrier = Arc::new(ControlAttachBarrier::default());
    let peer_idle = tunnel_transport::PeerTransportLimits::default().idle_timeout;
    assert!(peer_idle > RELEASE_BOUND && HEALTHY_IDLE > peer_idle);
    let catalog = Arc::new(harness.production_catalog().expect("catalog").clone());
    let mut cluster = ProductionCluster::start_with_peer_idle_timeout(
        &mut harness,
        catalog,
        None,
        Default::default(),
        None,
        None,
        [("relay-a".to_owned(), Arc::clone(&barrier))].into(),
        peer_idle,
    )
    .await
    .expect("three production relays");
    let scenario = match cluster.start_membership_resigning().await {
        Ok(()) => timeout(Duration::from_secs(160), run(&cluster, &harness, &barrier))
            .await
            .map_err(|_| failure("CLI scenario", "160-second deadline elapsed"))
            .and_then(|result| result),
        Err(error) => Err(error),
    };
    barrier.release();
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    let evidence = scenario.expect("actual CLI forwarded cut-path acceptance");
    cluster_cleanup.expect("cluster cleanup joined");
    harness_cleanup.expect("harness cleanup joined");
    println!(
        "m6c68-forwarded-cli ok relays=3 owner=relay-a ingress=relay-b same_cli_pid=true barrier_hits=1 healthy_idle_ms={} idle_data_generation_changes={} held_relay_halves=2 held_route_indices={:?} owner_busy_refusals={} owner_renewals_after_cut={} discarded_bytes={} release_after_cut_ms={} release_bound_ms={} second_ready_after_cut_ms={} ready_bound_ms={} exact_canaries=3 clean_stop=true",
        HEALTHY_IDLE.as_millis(),
        evidence.idle_data_generation_changes,
        evidence.held_routes,
        evidence.owner_busy,
        evidence.renewals,
        evidence.discarded,
        evidence.released.as_millis(),
        RELEASE_BOUND.as_millis(),
        evidence.ready.as_millis(),
        CLI_RECONNECT_BOUND.as_millis(),
    );
}

struct Evidence {
    idle_data_generation_changes: usize,
    held_routes: BTreeSet<u64>,
    owner_busy: usize,
    renewals: u64,
    discarded: u64,
    released: Duration,
    ready: Duration,
}

async fn run(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    barrier: &Arc<ControlAttachBarrier>,
) -> Result<Evidence> {
    let device = &harness.topology.devices_a[0];
    let service_id = harness.topology.service_ids[&device.id];
    let tls = tunnel_transport::load_client_config_from_pem_with_alpn(
        device.certificate.certificate_pem.as_bytes(),
        device.certificate.private_key_pem.as_bytes(),
        harness.pki.server_ca.certificate_pem.as_bytes(),
        &[b"http/1.1"],
    )
    .map_err(|e| failure("CLI fixture TLS", e))?;
    let mut predecessor = open_socket(device_addr(cluster, "relay-a")?, tls, None).await?;
    let predecessor_welcome = handshake(&mut predecessor, device.id, service_id).await?;
    let predecessor_owner = owner(cluster, device)
        .await?
        .ok_or_else(|| failure("CLI predecessor", "owner missing"))?;
    require(
        predecessor_owner.token.node_id == "relay-a",
        "CLI predecessor owns on A",
    )?;
    require(barrier.arm(), "CLI forwarded HELLO barrier arms once")?;

    let proxy = CutPaths::start(device_addr(cluster, "relay-b")?).await?;
    let files = tempfile::tempdir().map_err(HarnessError::Io)?;
    let profile = write_device_profile(
        files.path(),
        device.id,
        service_id,
        CANARY,
        proxy.address,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&profile.config_path)
        .and_then(|mut file| {
            file.write_all(b"\n[reconnect]\ninitial_delay_ms = 200\nmax_delay_ms = 1000\n")
        })
        .map_err(HarnessError::Io)?;
    let mut cli = ManagedProcess::spawn(
        "m6c68-forwarded-cli",
        ProcessSpec::new(super::super::client_binary_path()?)
            .arg("connect")
            .arg("--config")
            .arg(profile.config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;
    let scenario: Result<Evidence> = async {
        let pid = cli
            .id()
            .ok_or_else(|| failure("CLI startup", "PID missing"))?;
        timeout(PHASE, barrier.wait_reached())
            .await
            .map_err(|_| failure("CLI forwarded HELLO", "barrier not reached"))?;
        require(
            barrier.is_held() && barrier.hit_count() == 1,
            "CLI forwarded HELLO is held once",
        )?;
        predecessor
            .close(None)
            .await
            .map_err(|e| failure("CLI predecessor close", e))?;
        drop(predecessor);
        wait_no_owner(cluster, device, Instant::now() + PHASE).await?;
        // A timed-out barrier is a fixture failure, never an alternate success.
        require(
            barrier.is_held(),
            "CLI HELLO remains held until predecessor release",
        )?;
        barrier.release();
        let first = wait_ready(&mut cli, pid, 1, Instant::now() + PHASE).await?;
        let live = owner(cluster, device)
            .await?
            .ok_or_else(|| failure("CLI first ready", "owner missing"))?;
        require(
            live.token.node_id == "relay-a"
                && live.token.session_id == first.id
                && live.token.epoch == first.epoch
                && first.id != predecessor_welcome.session_id
                && first.epoch > predecessor_owner.token.epoch,
            "CLI first ready binds a fresh remote owner on A",
        )?;
        require(
            cluster
                .relay("relay-b")?
                .snapshot()
                .await?
                .sessions
                .is_empty(),
            "CLI ingress B must not own the first session",
        )?;
        require(
            old_session_present(cluster, &first.id).await?,
            "CLI owner A has first session",
        )?;
        println!("m6c68-forwarded-cli phase=first-ready owner=relay-a ingress=relay-b barrier_hits=1");
        echo(cluster, harness, b"before-idle").await
            .map_err(|error| failure("CLI initial canary", error))?;
        let quiet_until = Instant::now() + HEALTHY_IDLE;
        while Instant::now() < quiet_until {
            let events = events(&mut cli, pid)?;
            require(
                count_state(&events, "ready") == 1
                    && count_state(&events, "disconnected") == 0
                    && count_state(&events, "backoff") == 0,
                "healthy idle CLI keeps its original session without retries",
            )?;
            sleep(Duration::from_millis(100)).await;
        }
        require(
            owner(cluster, device)
                .await?
                .is_some_and(|claim| claim.token == live.token),
            "healthy idle preserves the exact remote owner",
        )?;
        // Opening a new real consumer stream requires an OPEN_ACK on control.
        // This reaches the remote owner immediately before the cut, leaving
        // its 60 s inbound peer deadline outside the 35 s device cleanup bound.
        timeout(
            Duration::from_secs(5),
            echo(cluster, harness, b"before-cut"),
        )
        .await
        .map_err(|_| failure("pre-cut canary", "five-second deadline elapsed"))??;
        let idle_events = events(&mut cli, pid)?;
        let idle_generations: BTreeSet<_> = idle_events.iter()
            .filter(|event| event["state"] == "status")
            .filter_map(|event| event["generation"].as_u64())
            .collect();
        // Per-stream H3 idleness may replace only the M2 data carrier. That
        // is documented same-session recovery, not a control reconnect. Cut
        // its current socket, never a carrier that has already retired.
        let selected_routes = proxy.active_indices();
        require(
            selected_routes.len() == 2 && selected_routes.contains(&0),
            "the CLI has its original control route and one current data route",
        )?;
        require(idle_events.iter().filter(|event| event["state"] == "status").all(|event|
            event["session_id"] == first.id && event["epoch"] == first.epoch),
            "idle data recovery preserves the CLI control session and epoch")?;
        require(!idle_generations.is_empty(), "CLI publishes its data generation")?;
        let mut last_claim = owner(cluster, device)
            .await?
            .ok_or_else(|| failure("CLI before cut", "owner missing"))?;
        require(
            last_claim.token == live.token,
            "CLI owner unchanged immediately before cut",
        )?;
        let cut = Instant::now();
        proxy.generation.send_modify(|generation| *generation += 1);
        timeout(PHASE, async {
            while proxy.held_indices() != selected_routes {
                sleep(POLL).await;
            }
        })
        .await
        .map_err(|_| failure("CLI path cut", "both relay halves were not held"))?;
        println!("m6c68-forwarded-cli phase=cut held_relay_halves=2 held_route_indices={selected_routes:?} healthy_idle_ms={} data_generations={idle_generations:?}", HEALTHY_IDLE.as_millis());

        let mut renewals = 0;
        let mut old_token_present = true;
        let mut old_actor_present = true;
        let released = loop {
            if cut.elapsed() > RELEASE_BOUND {
                let owner_busy = events(&mut cli, pid)?.iter()
                    .filter(|event| event["state"] == "backoff" && event["code"] == "OWNER_BUSY")
                    .count();
                return Err(failure(
                    "CLI old owner release",
                    format!("35-second deadline elapsed: old_owner_present={old_token_present} old_actor_present={old_actor_present} renewals={renewals} owner_busy={owner_busy}"),
                ));
            }
            // Autoreconnect can atomically replace the old token between two
            // polls. Require the old actor to disappear as well; a new local
            // session on B cannot conceal a leaked remote session on A.
            let current = owner(cluster, device).await?;
            old_token_present = current
                .as_ref()
                .is_some_and(|claim| claim.token == live.token);
            old_actor_present = old_session_present(cluster, &first.id).await?;
            if !old_token_present && !old_actor_present {
                break cut.elapsed();
            }
            if let Some(current) = current.filter(|claim| claim.token == live.token) {
                if current.lease_expires_at > last_claim.lease_expires_at {
                    renewals += 1;
                }
                last_claim = current;
            }
            events(&mut cli, pid)?;
            sleep(POLL).await;
        };
        require(released <= RELEASE_BOUND, "CLI old owner release is observed within 35 seconds")?;
        require(
            renewals >= 2,
            "CLI old owner renews its lease twice after the cut",
        )?;
        require(
            last_claim.lease_expires_at > chrono::Utc::now() + chrono::Duration::seconds(5),
            "CLI old owner release precedes lease expiry",
        )?;
        let second = wait_ready(&mut cli, pid, 2, cut + CLI_RECONNECT_BOUND).await?;
        let ready = cut.elapsed();
        require(
            second.id != first.id && second.epoch > first.epoch,
            "CLI second ready has fresh session and higher epoch",
        )?;
        let final_events = events(&mut cli, pid)?;
        require(
            count_state(&final_events, "ready") == 2,
            "CLI emits exactly two ready events",
        )?;
        require(
            final_events
                .iter()
                .any(|event| event["state"] == "disconnected" && event["session_id"] == first.id),
            "CLI reports losing its original session",
        )?;
        require(
            final_events
                .iter()
                .any(|event| event["state"] == "reconnected" && event["session_id"] == second.id),
            "CLI reconnected event binds the second ready session",
        )?;
        let owner_busy = final_events
            .iter()
            .filter(|event| event["state"] == "backoff" && event["code"] == "OWNER_BUSY")
            .count();
        require(
            owner_busy > 0,
            "CLI retries OWNER_BUSY while the remote old session remains",
        )?;
        let replacement = owner(cluster, device)
            .await?
            .ok_or_else(|| failure("CLI reconnect", "replacement owner missing"))?;
        require(
            replacement.token.session_id == second.id && replacement.token.epoch == second.epoch,
            "CLI second ready binds the replacement catalog owner",
        )?;
        require(
            !old_session_present(cluster, &first.id).await?,
            "CLI old remote session stays absent",
        )?;
        echo(cluster, harness, b"after-reconnect").await?;
        events(&mut cli, pid)?;
        let discarded = proxy.discarded.load(Ordering::Acquire);
        require(
            discarded > 0,
            "cut proxy discards ingress output after disconnect",
        )?;
        require(
            barrier.hit_count() == 1 && !barrier.is_held(),
            "reconnect passes released barrier without another hold",
        )?;
        Ok(Evidence {
            idle_data_generation_changes: idle_generations.len() - 1,
            held_routes: selected_routes,
            owner_busy,
            renewals,
            discarded,
            released,
            ready,
        })
    }
    .await;
    barrier.release();
    let stop = cli.request_stop().await;
    let stopped = timeout(Duration::from_secs(3), async {
        let status = cli.wait().await?;
        require(
            status.success(),
            "CLI exits successfully after its stop signal",
        )?;
        loop {
            if count_state(&read_events(&cli)?, "stopped") == 1 {
                break Ok::<(), HarnessError>(());
            }
            sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| failure("CLI clean stop", "three-second deadline elapsed"));
    let cli_cleanup = cli.shutdown(Duration::from_secs(3)).await;
    let proxy_cleanup = proxy.shutdown().await;
    let evidence = scenario?;
    stop?;
    stopped??;
    require(
        cli_cleanup?.success(),
        "CLI stopped cleanly without forced kill",
    )?;
    proxy_cleanup?;
    wait_no_owner(cluster, device, Instant::now() + PHASE).await?;
    Ok(evidence)
}

struct Ready {
    id: String,
    epoch: u64,
}

fn events(cli: &mut ManagedProcess, pid: u32) -> Result<Vec<Value>> {
    if let Some(status) = cli.try_wait()? {
        return Err(failure(
            "CLI continuity",
            format!("process exited with {status}"),
        ));
    }
    require(cli.id() == Some(pid), "CLI PID stays unchanged")?;
    read_events(cli)
}

fn read_events(cli: &ManagedProcess) -> Result<Vec<Value>> {
    let output = cli.stdout();
    // A stricter bound than ManagedProcess's 1 MiB capture means truncation
    // cannot produce a passing event transcript. Check the terminal stopped
    // record too, after the child has exited.
    require(
        output.len() < 512 * 1024 && cli.stderr().len() < 512 * 1024,
        "CLI transcript remains below its capture bound",
    )?;
    let mut events = Vec::new();
    // The capture task may be in the middle of the last line. Never treat a
    // partial JSON record as a ready event or print captured CLI text.
    for line in output.split_inclusive(|byte| *byte == b'\n') {
        if !line.ends_with(b"\n") {
            break;
        }
        let value: Value = serde_json::from_slice(line)
            .map_err(|_| failure("CLI JSON", "malformed complete event"))?;
        if let Some(result) = value.get("result") {
            events.push(result.clone());
        }
    }
    Ok(events)
}

fn count_state(events: &[Value], state: &str) -> usize {
    events
        .iter()
        .filter(|event| event["state"] == state)
        .count()
}

async fn wait_ready(
    cli: &mut ManagedProcess,
    pid: u32,
    number: usize,
    deadline: Instant,
) -> Result<Ready> {
    loop {
        require(
            Instant::now() < deadline,
            "CLI ready event arrives within its declared bound",
        )?;
        let events = events(cli, pid)?;
        if let Some(event) = events
            .iter()
            .filter(|event| event["state"] == "ready")
            .nth(number - 1)
        {
            return Ok(Ready {
                id: event["session_id"]
                    .as_str()
                    .ok_or_else(|| failure("CLI ready", "session missing"))?
                    .to_owned(),
                epoch: event["epoch"]
                    .as_u64()
                    .ok_or_else(|| failure("CLI ready", "epoch missing"))?,
            });
        }
        sleep(POLL).await;
    }
}

async fn old_session_present(cluster: &ProductionCluster, session: &str) -> Result<bool> {
    Ok(cluster
        .relay("relay-a")?
        .snapshot()
        .await?
        .sessions
        .iter()
        .any(|current| current.session_id == session))
}

async fn echo(cluster: &ProductionCluster, harness: &RunningHarness, bytes: &[u8]) -> Result<()> {
    let device = &harness.topology.devices_a[0];
    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let mut stream = super::open_consumer_stream(
        cluster.relay("relay-c")?.consumer_addr()?,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        harness.topology.service_ids[&device.id],
    )
    .await
    .map_err(super::connect_failure_to_harness)?;
    stream.round_trip(bytes, CANARY.as_bytes()).await
}

/// Eight concurrent carriers at most; completed tasks are joined as they
/// finish. Only the two generation-zero sockets can be cut and retained.
/// All later TCP connections preserve opaque TLS bytes and flow normally.
struct CutPaths {
    address: SocketAddr,
    generation: watch::Sender<u64>,
    active: Arc<Mutex<BTreeSet<u64>>>,
    held: Arc<Mutex<BTreeSet<u64>>>,
    discarded: Arc<AtomicU64>,
    stop: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl CutPaths {
    async fn start(upstream: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(HarnessError::Io)?;
        let address = listener.local_addr().map_err(HarnessError::Io)?;
        let (generation, _) = watch::channel(0);
        let active = Arc::new(Mutex::new(BTreeSet::new()));
        let held = Arc::new(Mutex::new(BTreeSet::new()));
        let accepted = Arc::new(AtomicU64::new(0));
        let discarded = Arc::new(AtomicU64::new(0));
        let stop = CancellationToken::new();
        let task = tokio::spawn({
            let generation = generation.clone();
            let active = Arc::clone(&active);
            let held = Arc::clone(&held);
            let accepted = Arc::clone(&accepted);
            let discarded = Arc::clone(&discarded);
            let stop = stop.clone();
            async move {
                let slots = Arc::new(Semaphore::new(8));
                let mut routes: JoinSet<Result<()>> = JoinSet::new();
                let outcome: Result<()> = async {
                    loop {
                        let permit = tokio::select! {
                            biased;
                            _ = stop.cancelled() => break,
                            result = routes.join_next(), if !routes.is_empty() => {
                                result.expect("one route").map_err(|_| failure("cut proxy", "route panicked"))??;
                                continue;
                            }
                            permit = slots.clone().acquire_owned() => permit.map_err(|_| failure("cut proxy", "capacity closed"))?,
                        };
                        let (mut device, _) = tokio::select! {
                            _ = stop.cancelled() => break,
                            socket = listener.accept() => socket.map_err(HarnessError::Io)?,
                        };
                        let index = accepted.fetch_add(1, Ordering::AcqRel);
                        let mut cut = generation.subscribe();
                        let born = *cut.borrow_and_update();
                        let active = Arc::clone(&active);
                        let held = Arc::clone(&held);
                        let discarded = Arc::clone(&discarded);
                        let stop = stop.clone();
                        routes.spawn(async move {
                            let _permit = permit;
                            let mut relay = timeout(PHASE, TcpStream::connect(upstream)).await
                                .map_err(|_| failure("cut proxy", "upstream connect timed out"))?
                                .map_err(HarnessError::Io)?;
                            active.lock().expect("active routes").insert(index);
                            let cut_path = tokio::select! {
                                _ = stop.cancelled() => false,
                                _ = tokio::io::copy_bidirectional(&mut device, &mut relay) => false,
                                changed = cut.wait_for(|generation| *generation > born) => changed.is_ok(),
                            };
                            if cut_path {
                                drop(device);
                                held.lock().expect("held routes").insert(index);
                                let mut buffer = [0; 8192];
                                loop {
                                    let read = tokio::select! {
                                        _ = stop.cancelled() => break,
                                        read = relay.read(&mut buffer) => read,
                                    };
                                    match read {
                                        Ok(0) | Err(_) => { stop.cancelled().await; break; }
                                        Ok(bytes) => { discarded.fetch_add(bytes as u64, Ordering::Relaxed); }
                                    }
                                }
                            }
                            active.lock().expect("active routes").remove(&index);
                            Ok(())
                        });
                    }
                    Ok(())
                }.await;
                stop.cancel();
                while let Some(result) = routes.join_next().await {
                    result.map_err(|_| failure("cut proxy cleanup", "route panicked"))??;
                }
                outcome
            }
        });
        Ok(Self {
            address,
            generation,
            active,
            held,
            discarded,
            stop,
            task: Some(task),
        })
    }

    fn active_indices(&self) -> BTreeSet<u64> {
        self.active.lock().expect("active routes").clone()
    }
    fn held_indices(&self) -> BTreeSet<u64> {
        self.held.lock().expect("held routes").clone()
    }

    async fn shutdown(mut self) -> Result<()> {
        self.stop.cancel();
        let task = self.task.as_mut().expect("proxy task");
        timeout_at(Instant::now() + PHASE, task)
            .await
            .map_err(|_| failure("cut proxy cleanup", "deadline elapsed"))?
            .map_err(|_| failure("cut proxy cleanup", "task panicked"))?
    }
}

impl Drop for CutPaths {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
