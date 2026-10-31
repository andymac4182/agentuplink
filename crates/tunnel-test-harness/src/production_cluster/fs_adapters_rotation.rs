//! M4-68: installed framework reads/writes across the first actual 300 s
//! scheduled rotation. Host effects precede the earliest possible freeze;
//! immutable per-stream fences, rather than elapsed time, prove overlap.
//! Non-owner filesystem admission remains an explicit negative control.

mod driver;
mod evidence;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::time::{sleep, sleep_until, timeout, timeout_at};
use tunnel_client::{
    ConnectOptions, ConnectionHandle, FsExportSettings, LocalExport, LocalExportKind,
    http_forward::HttpHandlers,
};
use tunnel_core::RotationConfig;
use tunnel_fs_ninep::{Message, flags::O_RDONLY};
use tunnel_relay::RelaySessionSnapshot;
use uuid::Uuid;

use super::fs_wire::{NinepClient, Target, UpgradeFailure};
use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{
    ConnectionId, Direction, Harness, HarnessError, HarnessOptions, OidcTokenOptions, ProxyConfig,
    ProxyHandle, Result, TcpProxy,
};
use driver::{Driver, Event};
pub use evidence::{FsAdaptersRotationEvidence, validate_fs_adapters_rotation_evidence};
use evidence::{StreamProof, expected_versions};

const ADAPTERS: [&str; 4] = ["files", "mastra", "ai", "bash"];
const SCENARIO: Duration = Duration::from_secs(480);
const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(25);
const SUBPROTOCOL: &str = tunnel_fs_core::TRANSPORT_SUBPROTOCOL;

fn fail(message: &str) -> HarnessError {
    HarnessError::Process(format!("fs adapters rotation: {message}"))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Execute the production fixture and its independent evidence validator.
///
/// # Errors
/// A setup, bounded scenario, evidence or joined-cleanup failure.
pub async fn verify() -> Result<FsAdaptersRotationEvidence> {
    if std::env::var_os("NODE_TLS_REJECT_UNAUTHORIZED").is_some() {
        return Err(fail("NODE_TLS_REJECT_UNAUTHORIZED must be absent"));
    }
    let policy = RotationConfig::default();
    if (
        policy.interval_seconds,
        policy.handshake_timeout_seconds,
        policy.overlap_seconds,
    ) != (300, 10, 30)
    {
        return Err(fail(
            "default rotation policy no longer matches the declared gate",
        ));
    }
    let options = HarnessOptions::from_env()?
        .fs_services(true)
        .rotation(RotationConfig::default());
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| fail("harness startup deadline"))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let mut errors = Vec::new();
            push_cleanup_error(
                &mut errors,
                "catalog setup cleanup",
                harness
                    .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
                    .await,
            );
            return finish_scenario_with_cleanup(Err(error), errors);
        }
    };
    let scenario = run(&mut cluster, &harness).await;
    let mut errors = Vec::new();
    push_cleanup_error(
        &mut errors,
        "relay cleanup",
        cluster
            .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await,
    );
    // Each later resource still gets a bounded cleanup attempt if an earlier
    // one used its entire allowance. Never return early on a cleanup error.
    push_cleanup_error(
        &mut errors,
        "catalog cleanup",
        harness
            .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await,
    );
    let mut evidence = finish_scenario_with_cleanup(scenario, errors)?;
    evidence.cleanup_joined = true;
    if let Err(error) = validate_fs_adapters_rotation_evidence(&evidence) {
        eprintln!("fs adapters bounded evidence: {evidence:?}");
        return Err(error);
    }
    Ok(evidence)
}

struct CreationBracket {
    lower: Instant,
    upper: Instant,
    lower_protocol_ms: u64,
    session: RelaySessionSnapshot,
}

/// Snapshot before each absence observation, not after its response: session
/// insertion can race the delivery of an already captured absent snapshot.
async fn observe_creation(cluster: &ProductionCluster, device: Uuid) -> Result<CreationBracket> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut absent: Option<(Instant, u64)> = None;
    loop {
        let before = Instant::now();
        let snapshot = timeout_at(deadline.into(), cluster.relay("relay-a")?.snapshot())
            .await
            .map_err(|_| fail("session-creation snapshot deadline"))??;
        if let Some(session) = snapshot
            .sessions
            .iter()
            .find(|s| s.device_id == device.to_string())
        {
            let (lower, lower_protocol_ms) =
                absent.ok_or_else(|| fail("creation was not bracketed by an absent snapshot"))?;
            let upper = Instant::now();
            if upper.duration_since(lower) > Duration::from_secs(1) {
                return Err(fail("session creation bracket exceeded one second"));
            }
            return Ok(CreationBracket {
                lower,
                upper,
                lower_protocol_ms,
                session: session.clone(),
            });
        }
        absent = Some((before, snapshot.monotonic_now_ms));
        if Instant::now() >= deadline {
            return Err(fail("owner session creation deadline"));
        }
        sleep(POLL).await;
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<FsAdaptersRotationEvidence> {
    cluster.start_membership_resigning().await?;
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| fail("missing device"))?;
    let echo = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| fail("missing echo export"))?;
    let service = harness
        .fs_service("rotation-write")
        .ok_or_else(|| fail("missing writable export"))?
        .service_id;
    let control_service = harness
        .fs_service("read-list")
        .ok_or_else(|| fail("missing independent export"))?
        .service_id;
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    seed(directory.path())?;
    let device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .ok_or_else(|| fail("owner not running"))?
        .device_addr;
    let profiles = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut proxy = TcpProxy::bind(device_addr, ProxyConfig::default()).await?;
    let prepared: Result<_> = (|| {
        let mut profile = write_device_profile(
            profiles.path(),
            device.id,
            echo,
            "m4-adapters-rotation",
            proxy.local_addr(),
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile.config.rotation = RotationConfig::default();
        for (id, writable) in [(service, true), (control_service, false)] {
            profile.config.exports.insert(
                id.to_string(),
                LocalExport {
                    kind: LocalExportKind::Fs,
                    device_canary: None,
                    mcp: None,
                    acp: None,
                    cua: None,
                    fs: Some(FsExportSettings {
                        root: directory.path().to_path_buf(),
                        features: Vec::new(),
                        capabilities: if writable {
                            vec!["read".into(), "write".into(), "list".into()]
                        } else {
                            vec!["read".into(), "list".into()]
                        },
                    }),
                },
            );
        }
        profile
            .config
            .validate()
            .map_err(|_| fail("device profile invalid"))?;
        Ok(profile)
    })();
    let profile = match prepared {
        Ok(profile) => profile,
        Err(error) => {
            let mut errors = Vec::new();
            push_cleanup_error(
                &mut errors,
                "proxy setup cleanup",
                proxy
                    .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
                    .await,
            );
            return finish_scenario_with_cleanup(Err(error), errors);
        }
    };
    // Polling starts before the connector future gets its first turn.
    let (bracket, connected) = tokio::join!(
        observe_creation(cluster, device.id),
        timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect_with_http_handlers(
                ConnectOptions::new(profile.config),
                HttpHandlers::new(),
            )
        ),
    );
    let mut client = match connected {
        Ok(Ok(client)) => client,
        _ => {
            let mut errors = Vec::new();
            push_cleanup_error(
                &mut errors,
                "proxy startup cleanup",
                proxy
                    .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
                    .await,
            );
            return finish_scenario_with_cleanup(Err(fail("connector startup failed")), errors);
        }
    };
    let mut drivers = Vec::new();
    let mut control = None;
    let scenario = async {
        let bracket = bracket?;
        let ready = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| fail("connector readiness deadline"))?
            .map_err(|_| fail("connector readiness failure"))?;
        if ready.session_id != bracket.session.session_id {
            return Err(fail("session changed during startup"));
        }
        let deadline = bracket.lower + SCENARIO;
        timeout_at(
            deadline.into(),
            exercise(
                cluster,
                harness,
                &client,
                &proxy,
                directory.path(),
                profiles.path(),
                service,
                control_service,
                &bracket,
                &mut drivers,
                &mut control,
            ),
        )
        .await
        .map_err(|_| fail("480-second scenario deadline"))?
    }
    .await;
    if let Err(error) = &scenario {
        eprintln!("fs adapters scenario failed: {error}");
    }
    let mut errors = Vec::new();
    // Always release physical faults before asking workers to terminate.
    for connection in proxy.connections() {
        push_cleanup_error(
            &mut errors,
            "proxy release",
            proxy.resume(Direction::ClientToTarget, connection.id).await,
        );
    }
    for driver in &mut drivers {
        push_cleanup_error(
            &mut errors,
            "framework cleanup",
            driver
                .shutdown(Instant::now() + Duration::from_secs(5))
                .await,
        );
    }
    if let Some(control) = control.take() {
        control.close().await;
    }
    let stopped = match timeout(CLEANUP_TIMEOUT, client.stop()).await {
        Ok(result) => result.map_err(|_| fail("connector cleanup failed")),
        Err(_) => Err(fail("connector cleanup deadline")),
    };
    let retry_join = stopped.is_err();
    push_cleanup_error(&mut errors, "connector cleanup", stopped);
    push_cleanup_error(
        &mut errors,
        "proxy cleanup",
        proxy
            .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await,
    );
    if retry_join {
        // stop() retains its join handle when its caller times out. Closing
        // the transport may unblock it; retain and join that same supervisor,
        // without erasing the initial cleanup failure or restarting anything.
        let joined = match timeout(CLEANUP_TIMEOUT, client.stop()).await {
            Ok(result) => result.map_err(|_| fail("connector final join failed")),
            Err(_) => Err(fail("connector final join deadline")),
        };
        push_cleanup_error(&mut errors, "connector final join", joined);
    }
    finish_scenario_with_cleanup(scenario, errors)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn exercise(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    client: &ConnectionHandle,
    proxy: &ProxyHandle,
    root: &Path,
    private: &Path,
    service: Uuid,
    control_service: Uuid,
    bracket: &CreationBracket,
    drivers: &mut Vec<Driver>,
    control: &mut Option<NinepClient>,
) -> Result<FsAdaptersRotationEvidence> {
    let device = &harness.topology.devices_a[0];
    let principal = &harness.topology.consumers_a[0];
    let owner_addr = cluster.relay("relay-a")?.consumer_addr()?;
    let ca = &harness.pki.server_ca.certificate_der;
    let token = harness.oidc.issue_with(
        &principal.name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(900),
            scope: Some("echo:invoke fs:connect".into()),
            ..OidcTokenOptions::default()
        },
    )?;
    let target = Target {
        consumer_addr: owner_addr,
        device_id: device.id,
        service: service.to_string(),
    };
    let control_target = Target {
        consumer_addr: owner_addr,
        device_id: device.id,
        service: control_service.to_string(),
    };
    let mut e = FsAdaptersRotationEvidence {
        interval_seconds: 300,
        handshake_seconds: 10,
        overlap_seconds: 30,
        token_seconds: 900,
        creation_bracket_ms: millis(bracket.upper.duration_since(bracket.lower)),
        generation_before: bracket.session.active_generation,
        rotations_before: bracket.session.rotations_completed,
        ..FsAdaptersRotationEvidence::default()
    };
    if client.status_snapshot().fs.exchanges != 0 || client.status_snapshot().fs.bytes_written != 0
    {
        return Err(fail("filesystem ledger was not initially empty"));
    }
    let non_owner = Target {
        consumer_addr: cluster.relay("relay-b")?.consumer_addr()?,
        device_id: device.id,
        service: service.to_string(),
    };
    e.non_owner_refused = refused(&non_owner, ca, &token, 503, "DEVICE_NOT_OWNED_HERE").await?;
    let mut canary = NinepClient::connect(&control_target, ca, &token, Some(SUBPROTOCOL))
        .await
        .map_err(|_| fail("independent control admission failed"))?;
    canary.version(65_536).await?;
    canary.attach(0).await?;
    canary.walk(0, 1, &["control.txt"]).await?;
    canary.lopen(1, O_RDONLY).await?;
    require_control_read(&mut canary).await?;
    *control = Some(canary);

    let ca_path = private.join("node-ca.pem");
    std::fs::write(&ca_path, &harness.pki.server_ca.certificate_pem).map_err(HarnessError::Io)?;
    for adapter in ADAPTERS {
        let plan = private.join(format!("{adapter}.json"));
        write_private(&plan, &serde_json::to_vec(&serde_json::json!({
            "adapter": adapter, "token": token,
            "endpoint": format!("https://127.0.0.1:{}/v1/devices/{}/services/{service}/fs", owner_addr.port(), device.id),
        })).map_err(HarnessError::Json)?)?;
        let mut driver = Driver::start(adapter, &plan, &ca_path).await?;
        let ready = driver.event("ready", Instant::now() + WAIT).await;
        let _ = std::fs::remove_file(plan);
        // Retain every spawned child before propagating a startup failure.
        drivers.push(driver);
        let ready = ready?;
        if ready.adapter != adapter
            || ready.versions != expected_versions()
            || ready.node != "v24.21.0"
        {
            return Err(fail(
                "driver did not load the pinned Node/framework versions",
            ));
        }
        e.versions = ready.versions;
        e.node = ready.node;
    }
    for driver in drivers.iter_mut() {
        for role in ["read", "write"] {
            let id = open_one(cluster, bracket, driver, role).await?;
            e.held_streams.push(StreamProof {
                adapter: driver.adapter.into(),
                role: role.into(),
                stream_id: id,
                ..StreamProof::default()
            });
        }
    }
    // Both the 300 s idle bound and the 300 s public-operation budget remain
    // unchanged. Short completed canaries keep sessions live; held operations
    // start only near cutover and are never parked for the whole interval.
    let stage_at = bracket.lower + Duration::from_secs(285);
    while Instant::now() + Duration::from_secs(20) < stage_at {
        all(drivers, "canary", "canary", Instant::now() + WAIT).await?;
        require_control_read(control.as_mut().ok_or_else(|| fail("control missing"))?).await?;
        let session = owner(cluster, bracket).await?;
        clean_before(&session, bracket)?;
        sleep(Duration::from_secs(15)).await;
    }
    if Instant::now() >= stage_at {
        return Err(fail("framework preparation missed staging window"));
    }
    sleep_until(stage_at.into()).await;
    let armed = all(
        drivers,
        "arm_rotation",
        "armed",
        stage_at + Duration::from_secs(5),
    )
    .await?;
    eprintln!(
        "fs adapters stage=armed elapsed_ms={}",
        millis(bracket.lower.elapsed())
    );
    for event in armed {
        if event.probes.len() != 2
            || event
                .probes
                .values()
                .any(|p| !p.armed || p.sent != 0 || p.replies != 0)
        {
            return Err(fail("pre-send rendezvous did not remain undispatched"));
        }
    }
    host_empty(root, "write")?;
    let connection = data_connection(client, proxy)?;
    let pause_at = bracket.lower + Duration::from_secs(295);
    if Instant::now() >= pause_at {
        return Err(fail("staging missed carrier-pause deadline"));
    }
    sleep_until(pause_at.into()).await;
    clean_before(&owner(cluster, bracket).await?, bracket)?;
    proxy.pause(Direction::ClientToTarget, connection).await?;
    let earliest_freeze = bracket.lower + Duration::from_secs(300);
    let sent = all(
        drivers,
        "release",
        "sent",
        earliest_freeze - Duration::from_millis(500),
    )
    .await?;
    await_host(root, "write", earliest_freeze - Duration::from_millis(250)).await?;
    e.host_checked_at_ms = millis(bracket.lower.elapsed());
    e.host_before_freeze = e.host_checked_at_ms < 300_000;
    eprintln!(
        "fs adapters stage=host_before_freeze elapsed_ms={}",
        e.host_checked_at_ms
    );
    for (adapter, event) in ADAPTERS.into_iter().zip(sent) {
        for proof in e
            .held_streams
            .iter_mut()
            .filter(|proof| proof.adapter == adapter)
        {
            proof.probe = event
                .probes
                .get(&proof.role)
                .cloned()
                .ok_or_else(|| fail("sent probe missing"))?;
        }
    }
    let request_snapshot = owner(cluster, bracket).await?;
    for proof in &mut e.held_streams {
        let stream = request_snapshot
            .streams
            .iter()
            .find(|s| s.stream_id == proof.stream_id)
            .ok_or_else(|| fail("held stream disappeared"))?;
        proof.request_emitted = stream.last_emitted_relay_to_connector;
    }
    let frozen = await_freeze(
        cluster,
        bracket,
        &e.held_streams,
        pause_at + Duration::from_secs(24),
    )
    .await?;
    e.frozen_sockets = frozen.sockets;
    e.frozen_phase = frozen.phase.clone();
    e.scheduled_start_lower_ms = frozen
        .rotation_started_at_ms
        .ok_or_else(|| fail("rotation start timestamp missing"))?
        .saturating_sub(bracket.lower_protocol_ms);
    for proof in &mut e.held_streams {
        let stream = frozen
            .streams
            .iter()
            .find(|s| s.stream_id == proof.stream_id)
            .ok_or_else(|| fail("frozen stream missing"))?;
        proof.received_before_freeze = stream.recv_contiguous_connector_to_relay;
    }
    e.freeze = frozen.rotation_diagnostics;
    eprintln!("fs adapters stage=frozen proof={:?}", e.freeze);
    sleep(Duration::from_millis(100)).await;
    e.freeze_repeat = owner(cluster, bracket).await?.rotation_diagnostics;
    let status = all(
        drivers,
        "status",
        "status",
        pause_at + Duration::from_secs(25),
    )
    .await?;
    if status
        .iter()
        .flat_map(|event| event.probes.values())
        .any(|p| p.replies != 0 || p.sent != 1)
    {
        return Err(fail(
            "a held framework exchange was answered before fault release",
        ));
    }
    let released = Instant::now();
    proxy.resume(Direction::ClientToTarget, connection).await?;
    let results = all(
        drivers,
        "finish_rotation",
        "rotation_result",
        pause_at + Duration::from_secs(29),
    )
    .await?;
    e.resumed_in_ms = millis(released.elapsed());
    e.native_rotation = ADAPTERS
        .into_iter()
        .zip(results)
        .map(|(name, event)| (name.into(), event))
        .collect();
    eprintln!(
        "fs adapters stage=native_rotation results={:?}",
        e.native_rotation
    );
    let completed = await_complete(cluster, bracket, pause_at + Duration::from_secs(29)).await?;
    e.rotations_after = completed.rotations_completed;
    e.generation_after = completed.active_generation;
    e.stable_session_epoch = completed.session_id == bracket.session.session_id
        && completed.epoch == bracket.session.epoch;
    e.replayed_frames = completed.total_replayed_frames;
    e.forced_retirement = completed.rotation_deadline_forced_retirement;
    e.recovery = completed.rotation_recovery_reason.is_some()
        || completed.last_activated_recovery_reason.is_some();
    e.completed = completed.rotation_diagnostics;
    e.final_sockets = completed.sockets;
    e.socket_peak = proxy.diagnostics().peak_active;
    host_exact(root, "write")?;
    e.host_after_rotation = true;
    e.host_negative_red = host_negative_control(root)?;
    all(drivers, "close_rotation", "closed", Instant::now() + WAIT).await?;
    let ledger = await_ledger(client, 8, Instant::now() + WAIT).await?;
    e.completed_exchanges = ledger.exchanges;
    e.completed_bytes_written = ledger.bytes_written;

    let mut last_revoked_stream_id = 0;
    for driver in drivers.iter_mut() {
        last_revoked_stream_id = open_one(cluster, bracket, driver, "revoked").await?;
    }
    all(
        drivers,
        "arm_revocation",
        "armed",
        Instant::now() + Duration::from_secs(5),
    )
    .await?;
    host_empty(root, "revoked")?;
    let connection = data_connection(client, proxy)?;
    proxy.pause(Direction::ClientToTarget, connection).await?;
    let revocation_pause = Instant::now();
    let sent = all(
        drivers,
        "release",
        "sent",
        revocation_pause + Duration::from_secs(3),
    )
    .await?;
    if sent.iter().any(|event| {
        event
            .probes
            .get("revoked")
            .is_none_or(|p| p.sent != 1 || p.replies != 0)
    }) {
        return Err(fail("revoked write was not sent and unanswered"));
    }
    await_host(root, "revoked", revocation_pause + Duration::from_secs(5)).await?;
    e.host_before_revocation = true;
    let revoked = Instant::now();
    cluster
        .catalog
        .revoke_grant(
            device.tenant_id,
            principal.id,
            device.id,
            service,
            chrono::Utc::now(),
        )
        .await
        .map_err(|_| fail("grant revocation failed"))?;
    let results = all(
        drivers,
        "finish_revocation",
        "revocation_result",
        revocation_pause + Duration::from_secs(24),
    )
    .await?;
    e.revocation_in_ms = millis(revoked.elapsed());
    e.native_revocation = ADAPTERS
        .into_iter()
        .zip(results)
        .map(|(name, event)| (name.into(), event))
        .collect();
    eprintln!(
        "fs adapters stage=native_revocation results={:?}",
        e.native_revocation
    );
    proxy.resume(Direction::ClientToTarget, connection).await?;
    sleep(Duration::from_millis(1500)).await;
    let quiet = all(
        drivers,
        "status",
        "status",
        Instant::now() + Duration::from_secs(3),
    )
    .await?;
    if quiet.iter().any(|event| {
        event.probes.get("revoked").is_none_or(|p| {
            p.writes != 1 || p.written_bytes != 4096 || p.replies != 0 || p.close_code != Some(1008)
        })
    }) {
        return Err(fail(
            "native revoked operation replayed or gained a late reply",
        ));
    }
    require_control_read(control.as_mut().ok_or_else(|| fail("control missing"))?).await?;
    e.independent_grant_survived = true;
    host_exact(root, "revoked")?;
    e.host_after_revocation = true;
    let before_refusal = owner(cluster, bracket).await?;
    // Revocation removes this service from discovery. The filesystem contract
    // requires the same exact 404 as a nonexistent export, not a discoverable
    // export's 403. Do not accept another status or a code inside message text.
    e.revoked_admission_refused = refused(&target, ca, &token, 404, "EXPORT_NOT_FOUND").await?;
    let after_refusal = owner(cluster, bracket).await?;
    let before_ids: BTreeSet<_> = before_refusal.streams.iter().map(|s| s.stream_id).collect();
    e.revoked_admission_no_stream_opened = after_refusal
        .streams
        .iter()
        .all(|stream| before_ids.contains(&stream.stream_id));
    // actor::allocate_stream_id uses checked_add(1), with no reuse. All four
    // framework children are now idle and this is the only new permitted
    // socket. Its next ID detects even a forbidden OPEN that was removed
    // between snapshots. It sends no 9P version/attach/data request.
    e.last_revoked_stream_id = last_revoked_stream_id;
    e.next_control_stream_id =
        next_control_stream(cluster, bracket, &control_target, ca, &token).await?;
    // No calls are replayed or ambiguous files removed. The exact observed host
    // state survives until the fixture directory is removed after cleanup.
    e.replayed_frames = owner(cluster, bracket).await?.total_replayed_frames;
    Ok(e)
}

async fn all(
    drivers: &mut [Driver],
    command: &str,
    event: &str,
    deadline: Instant,
) -> Result<Vec<Event>> {
    for driver in drivers.iter_mut() {
        driver.send(command, deadline).await?;
    }
    let mut events = Vec::with_capacity(drivers.len());
    for driver in drivers {
        events.push(driver.event(event, deadline).await?);
    }
    Ok(events)
}

async fn owner(
    cluster: &ProductionCluster,
    bracket: &CreationBracket,
) -> Result<RelaySessionSnapshot> {
    timeout(Duration::from_secs(2), cluster.relay("relay-a")?.snapshot())
        .await
        .map_err(|_| fail("owner snapshot deadline"))??
        .sessions
        .into_iter()
        .find(|s| s.session_id == bracket.session.session_id && s.epoch == bracket.session.epoch)
        .ok_or_else(|| fail("original owner session/epoch disappeared"))
}

fn clean_before(session: &RelaySessionSnapshot, bracket: &CreationBracket) -> Result<()> {
    if session.rotations_completed != 0
        || session.phase != "active"
        || session.active_generation != bracket.session.active_generation
        || session.candidate_generation.is_some()
        || session.total_replayed_frames != 0
        || session.last_activated_recovery_reason.is_some()
    {
        return Err(fail(
            "session rotated or recovered before the selected policy interval",
        ));
    }
    Ok(())
}

async fn open_one(
    cluster: &ProductionCluster,
    bracket: &CreationBracket,
    driver: &mut Driver,
    role: &str,
) -> Result<u64> {
    let before: BTreeSet<_> = owner(cluster, bracket)
        .await?
        .streams
        .iter()
        .map(|s| s.stream_id)
        .collect();
    let deadline = Instant::now() + WAIT;
    driver.send(&format!("open_{role}"), deadline).await?;
    let opened = driver.event("opened", deadline).await?;
    if opened.role != role || opened.probe.attaches != 1 {
        return Err(fail("native session did not attach exactly once"));
    }
    let after = owner(cluster, bracket).await?;
    let added: Vec<_> = after
        .streams
        .iter()
        .filter(|s| !before.contains(&s.stream_id))
        .collect();
    if let [stream] = added.as_slice() {
        Ok(stream.stream_id)
    } else {
        Err(fail("native session stream mapping was not unique"))
    }
}

fn data_connection(client: &ConnectionHandle, proxy: &ProxyHandle) -> Result<ConnectionId> {
    let status = client.status_snapshot();
    let connections = proxy.connections();
    if status.phase != "active" || status.candidate_generation.is_some() || connections.len() != 2 {
        return Err(fail("carrier did not settle to two sockets"));
    }
    connections
        .iter()
        .find(|c| {
            Some(c.source_addr) == status.active_local_addr
                && Some(c.source_addr) != status.control_local_addr
        })
        .map(|c| c.id)
        .ok_or_else(|| fail("active data socket was not uniquely identified"))
}

async fn await_freeze(
    cluster: &ProductionCluster,
    bracket: &CreationBracket,
    streams: &[StreamProof],
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let snapshot = owner(cluster, bracket).await?;
        if let Some(rotation) = &snapshot.rotation_diagnostics
            && rotation.attempt_active
            && rotation.writer_barrier_flushed == [true; 2]
            && ["quiescing", "draining", "committing"].contains(&snapshot.phase.as_str())
            && streams.iter().all(|held| {
                let cursor = snapshot
                    .streams
                    .iter()
                    .find(|s| s.stream_id == held.stream_id)
                    .map(|s| s.recv_contiguous_connector_to_relay);
                rotation
                    .connector_fence_sequences
                    .iter()
                    .any(|(id, fence)| {
                        *id == held.stream_id && cursor.is_some_and(|cursor| *fence > cursor)
                    })
            })
        {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return Err(fail(
                "all eight selected exchanges did not enter the same freeze",
            ));
        }
        sleep(POLL).await;
    }
}

async fn await_complete(
    cluster: &ProductionCluster,
    bracket: &CreationBracket,
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let snapshot = owner(cluster, bracket).await?;
        if snapshot.rotations_completed == 1 && snapshot.phase == "active" {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return Err(fail("clean rotation completion deadline"));
        }
        sleep(POLL).await;
    }
}

async fn await_ledger(
    client: &ConnectionHandle,
    exchanges: u64,
    deadline: Instant,
) -> Result<tunnel_client::FsCounters> {
    loop {
        let counters = client.status_snapshot().fs;
        if counters.exchanges >= exchanges {
            return Ok(counters);
        }
        if Instant::now() >= deadline {
            return Err(fail("completed filesystem exchange reports missing"));
        }
        sleep(POLL).await;
    }
}

async fn require_control_read(client: &mut NinepClient) -> Result<()> {
    match client.read(1, 0, 64).await? {
        Message::Rread { data } if data == b"independent-grant-canary" => Ok(()),
        _ => Err(fail("independently granted control stopped reading")),
    }
}

async fn refused(
    target: &Target,
    ca: &[u8],
    token: &str,
    expected: u16,
    label: &str,
) -> Result<bool> {
    match NinepClient::connect(target, ca, token, Some(SUBPROTOCOL)).await {
        Err(UpgradeFailure::Status { status, body }) => {
            let matches = refusal_matches(status, body.as_deref(), expected, label);
            if !matches {
                eprintln!(
                    "fs adapters refusal mismatch expected_status={expected} expected_label={label} observed={:?}",
                    refusal_diagnostic(status, body.as_deref())
                );
            }
            Ok(matches)
        }
        Err(UpgradeFailure::Harness(error)) => Err(error),
        Ok(client) => {
            eprintln!(
                "fs adapters refusal mismatch expected_status={expected} expected_label={label} observed_status=101 observed=upgrade"
            );
            client.close().await;
            Ok(false)
        }
    }
}

fn refusal_matches(status: u16, body: Option<&[u8]>, expected: u16, label: &str) -> bool {
    let observed = refusal_diagnostic(status, body);
    let (code, reason) = if label == "DEVICE_NOT_OWNED_HERE" {
        ("BACKEND_UNAVAILABLE", Some(label))
    } else {
        (label, None)
    };
    observed.status == expected
        && observed.shape == "filesystem_error"
        && observed.code == code
        && observed.execution == "absent"
        && reason.is_none_or(|reason| observed.reason == reason)
}

/// Never retain arbitrary error text, IDs, paths, or credentials in a failure
/// diagnostic. The byte bound also limits JSON work on a wrong peer response.
#[derive(Debug, PartialEq, Eq)]
struct RefusalDiagnostic {
    status: u16,
    shape: &'static str,
    code: &'static str,
    reason: &'static str,
    execution: &'static str,
}

fn refusal_diagnostic(status: u16, body: Option<&[u8]>) -> RefusalDiagnostic {
    let mut result = RefusalDiagnostic {
        status,
        shape: "missing",
        code: "absent",
        reason: "absent",
        execution: "absent",
    };
    let Some(body) = body else { return result };
    if body.len() > 16_384 {
        result.shape = "oversized";
        return result;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        result.shape = "invalid_json";
        return result;
    };
    let Some(error) = value.get("error").and_then(serde_json::Value::as_object) else {
        result.shape = "invalid_shape";
        return result;
    };
    result.shape = "filesystem_error";
    result.code = match error.get("code").and_then(serde_json::Value::as_str) {
        Some("UNAUTHENTICATED") => "UNAUTHENTICATED",
        Some("EXPORT_NOT_FOUND") => "EXPORT_NOT_FOUND",
        Some("ACCESS_DENIED") => "ACCESS_DENIED",
        Some("CAPABILITIES_CHANGED") => "CAPABILITIES_CHANGED",
        Some("RESOURCE_EXHAUSTED") => "RESOURCE_EXHAUSTED",
        Some("DEVICE_OFFLINE") => "DEVICE_OFFLINE",
        Some("BACKEND_UNAVAILABLE") => "BACKEND_UNAVAILABLE",
        None => "absent",
        Some(_) => "other",
    };
    result.reason = match error.get("message").and_then(serde_json::Value::as_str) {
        Some(message) if message.starts_with("DEVICE_NOT_OWNED_HERE:") => "DEVICE_NOT_OWNED_HERE",
        None => "absent",
        Some(_) => "other",
    };
    result.execution = match value.get("execution").or_else(|| error.get("execution")) {
        None => "absent",
        Some(value) => match value.as_str() {
            Some("not_dispatched") => "not_dispatched",
            Some("unknown") => "unknown",
            Some("completed") => "completed",
            _ => "other",
        },
    };
    result
}

async fn next_control_stream(
    cluster: &ProductionCluster,
    bracket: &CreationBracket,
    target: &Target,
    ca: &[u8],
    token: &str,
) -> Result<u64> {
    let before: BTreeSet<_> = owner(cluster, bracket)
        .await?
        .streams
        .iter()
        .map(|s| s.stream_id)
        .collect();
    let client = NinepClient::connect(target, ca, token, Some(SUBPROTOCOL))
        .await
        .map_err(|_| fail("post-refusal independent control admission failed"))?;
    let sampled = owner(cluster, bracket).await.map(|after| {
        after
            .streams
            .into_iter()
            .filter(|s| !before.contains(&s.stream_id))
            .map(|s| s.stream_id)
            .collect::<Vec<_>>()
    });
    // Close on success and snapshot failure alike; cluster cleanup later joins
    // every server task. First prove this new registration is gone/terminal.
    client.close().await;
    let cleanup = async {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let after = owner(cluster, bracket).await?;
            if after
                .streams
                .iter()
                .all(|s| before.contains(&s.stream_id) || s.terminal)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(fail("post-refusal control registration cleanup deadline"));
            }
            sleep(POLL).await;
        }
    }
    .await;
    let mut errors = Vec::new();
    push_cleanup_error(&mut errors, "post-refusal control cleanup", cleanup);
    let sampled = finish_scenario_with_cleanup(sampled, errors)?;
    match sampled.as_slice() {
        [id] => Ok(*id),
        _ => Err(fail("post-refusal control stream was not unique")),
    }
}

fn fixture_text(adapter: &str, operation: &str) -> Vec<u8> {
    let prefix = format!("{adapter}:{operation}:");
    format!(
        "{prefix}{}",
        &"0123456789abcdef".repeat(256)[..4096 - prefix.len()]
    )
    .into_bytes()
}

fn seed(root: &Path) -> Result<()> {
    for adapter in ADAPTERS {
        std::fs::create_dir(root.join(adapter)).map_err(HarnessError::Io)?;
        std::fs::write(
            root.join(adapter).join("read.txt"),
            fixture_text(adapter, "read"),
        )
        .map_err(HarnessError::Io)?;
    }
    for role in ["read", "write", "revoked"] {
        std::fs::create_dir(root.join("ai").join(role)).map_err(HarnessError::Io)?;
    }
    std::fs::write(root.join("control.txt"), b"independent-grant-canary").map_err(HarnessError::Io)
}

fn host_path(root: &Path, adapter: &str, role: &str) -> Result<PathBuf> {
    if adapter != "ai" {
        return Ok(root.join(adapter).join(format!("{role}.txt")));
    }
    let entries = std::fs::read_dir(root.join("ai").join(role))
        .map_err(HarnessError::Io)?
        .take(2)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(HarnessError::Io)?;
    if let [entry] = entries.as_slice()
        && entry.file_type().map_err(HarnessError::Io)?.is_file()
    {
        return Ok(entry.path());
    }
    Err(fail(
        "AI upload directory did not contain exactly one regular file",
    ))
}

fn host_empty(root: &Path, role: &str) -> Result<()> {
    for adapter in ADAPTERS {
        if std::fs::metadata(host_path(root, adapter, role)?)
            .map_err(HarnessError::Io)?
            .len()
            != 0
        {
            return Err(fail(
                "host write occurred while the request was still undispatched",
            ));
        }
    }
    Ok(())
}

fn host_exact(root: &Path, role: &str) -> Result<()> {
    let mut expected = std::collections::BTreeMap::new();
    expected.insert(
        root.join("control.txt"),
        b"independent-grant-canary".to_vec(),
    );
    for adapter in ADAPTERS {
        expected.insert(
            root.join(adapter).join("read.txt"),
            fixture_text(adapter, "read"),
        );
        expected.insert(
            host_path(root, adapter, "write")?,
            fixture_text(adapter, "write"),
        );
        if role == "revoked" {
            expected.insert(host_path(root, adapter, role)?, fixture_text(adapter, role));
        }
    }
    expected.insert(host_path(root, "ai", "read")?, fixture_text("ai", "read"));
    let mut actual = BTreeSet::new();
    let mut directories = vec![root.to_path_buf()];
    let mut actual_directories = BTreeSet::from([root.to_path_buf()]);
    let mut expected_directories = BTreeSet::from([root.to_path_buf()]);
    expected_directories.extend(ADAPTERS.map(|adapter| root.join(adapter)));
    expected_directories
        .extend(["read", "write", "revoked"].map(|role| root.join("ai").join(role)));
    let mut entries = 0;
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).map_err(HarnessError::Io)? {
            entries += 1;
            if entries > 32 {
                return Err(fail("host tree exceeds its exact fixture bound"));
            }
            let entry = entry.map_err(HarnessError::Io)?;
            let kind = entry.file_type().map_err(HarnessError::Io)?;
            if kind.is_dir() {
                actual_directories.insert(entry.path());
                directories.push(entry.path());
            } else if kind.is_file() {
                actual.insert(entry.path());
            } else {
                return Err(fail("unexpected non-regular host entry"));
            }
        }
    }
    if actual != expected.keys().cloned().collect() || actual_directories != expected_directories {
        return Err(fail("unexpected host file set"));
    }
    for (path, bytes) in expected {
        if std::fs::metadata(&path).map_err(HarnessError::Io)?.len() != bytes.len() as u64
            || std::fs::read(path).map_err(HarnessError::Io)? != bytes
        {
            return Err(fail(
                "host image differs from the independent expected bytes",
            ));
        }
    }
    Ok(())
}

async fn await_host(root: &Path, role: &str, deadline: Instant) -> Result<()> {
    loop {
        if host_exact(root, role).is_ok() && Instant::now() < deadline {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(fail(
                "host effect was not observed before its strict staging deadline",
            ));
        }
        sleep(POLL).await;
    }
}

fn host_negative_control(root: &Path) -> Result<bool> {
    let path = host_path(root, "files", "write")?;
    let original = std::fs::read(&path).map_err(HarnessError::Io)?;
    let mut changed = original.clone();
    let byte = changed
        .first_mut()
        .ok_or_else(|| fail("negative-control image empty"))?;
    *byte ^= 1;
    std::fs::write(&path, changed).map_err(HarnessError::Io)?;
    let red = host_exact(root, "write").is_err();
    std::fs::write(path, original).map_err(HarnessError::Io)?;
    host_exact(root, "write")?;
    Ok(red)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(HarnessError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_adapters_rotation_refusal_requires_exact_status_and_nested_code() {
        let exact = br#"{"error":{"code":"EXPORT_NOT_FOUND","message":"no such filesystem export","requestId":"synthetic"}}"#;
        assert!(refusal_matches(404, Some(exact), 404, "EXPORT_NOT_FOUND"));
        for (name, status, body) in [
            ("wrong status", 403, Some(exact.as_slice())),
            ("actual upgrade", 101, None),
            ("missing body", 404, None),
            ("malformed JSON", 404, Some(b"EXPORT_NOT_FOUND".as_slice())),
            (
                "flat code",
                404,
                Some(br#"{"code":"EXPORT_NOT_FOUND"}"#.as_slice()),
            ),
            (
                "error string",
                404,
                Some(br#"{"error":"EXPORT_NOT_FOUND"}"#.as_slice()),
            ),
            (
                "misleading message",
                404,
                Some(
                    br#"{"error":{"code":"ACCESS_DENIED","message":"EXPORT_NOT_FOUND"}}"#
                        .as_slice(),
                ),
            ),
            (
                "code suffix",
                404,
                Some(br#"{"error":{"code":"EXPORT_NOT_FOUND_extra"}}"#.as_slice()),
            ),
            (
                "wrong code",
                404,
                Some(br#"{"error":{"code":"ACCESS_DENIED"}}"#.as_slice()),
            ),
            (
                "wrong execution shape",
                404,
                Some(
                    br#"{"error":{"code":"EXPORT_NOT_FOUND"},"execution":"not_dispatched"}"#
                        .as_slice(),
                ),
            ),
        ] {
            assert!(
                !refusal_matches(status, body, 404, "EXPORT_NOT_FOUND"),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn fs_adapters_rotation_refusal_diagnostics_are_bounded_closed_labels() {
        let body = br#"{"error":{"code":"private-token-sentinel","message":"private-path-sentinel","requestId":"private-id-sentinel"},"execution":"private-effect-sentinel"}"#;
        let diagnostic = refusal_diagnostic(502, Some(body));
        assert_eq!(diagnostic.code, "other");
        assert_eq!(diagnostic.reason, "other");
        assert_eq!(diagnostic.execution, "other");
        assert!(!format!("{diagnostic:?}").contains("private-"));
        assert_eq!(
            refusal_diagnostic(404, Some(&vec![b'x'; 16_385])).shape,
            "oversized"
        );
        let non_owner = br#"{"error":{"code":"BACKEND_UNAVAILABLE","message":"DEVICE_NOT_OWNED_HERE: synthetic"}}"#;
        assert!(refusal_matches(
            503,
            Some(non_owner),
            503,
            "DEVICE_NOT_OWNED_HERE"
        ));
        let misleading = br#"{"error":{"code":"BACKEND_UNAVAILABLE","message":"unrelated DEVICE_NOT_OWNED_HERE"}}"#;
        assert!(!refusal_matches(
            503,
            Some(misleading),
            503,
            "DEVICE_NOT_OWNED_HERE"
        ));
    }

    fn written_fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        seed(directory.path()).unwrap();
        std::fs::write(
            directory.path().join("ai/read/opaque"),
            fixture_text("ai", "read"),
        )
        .unwrap();
        for adapter in ADAPTERS {
            let path = if adapter == "ai" {
                directory.path().join("ai/write/opaque")
            } else {
                directory.path().join(adapter).join("write.txt")
            };
            std::fs::write(path, fixture_text(adapter, "write")).unwrap();
        }
        directory
    }

    #[test]
    fn fs_adapters_rotation_host_oracle_detects_tampering_and_restores_control() {
        let directory = written_fixture();
        host_exact(directory.path(), "write").unwrap();
        assert!(host_negative_control(directory.path()).unwrap());
        host_exact(directory.path(), "write").unwrap();
    }

    #[test]
    fn fs_adapters_rotation_host_oracle_rejects_extra_effects() {
        for relative in ["unexpected.txt", "ai/write/extra"] {
            let directory = written_fixture();
            std::fs::write(directory.path().join(relative), b"extra").unwrap();
            assert!(
                host_exact(directory.path(), "write").is_err(),
                "accepted {relative}"
            );
        }
        let directory = written_fixture();
        std::fs::create_dir(directory.path().join("extra-directory")).unwrap();
        assert!(host_exact(directory.path(), "write").is_err());
    }

    #[test]
    fn fs_adapters_rotation_host_payload_matches_the_driver_rule() {
        let bytes = fixture_text("files", "write");
        assert_eq!(bytes.len(), 4096);
        assert!(bytes.starts_with(b"files:write:0123456789abcdef"));
        assert_ne!(bytes, fixture_text("files", "revoked"));
    }
}
