//! C244: actual relay/device replies withheld at an ordered consumer boundary.
//! This proves confirmation ordering, not a clunk cancelled before dispatch.

mod retirement;

use retirement::{DeviceTerminal, await_device_terminal};
use std::{path::Path, process::Stdio, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{sleep, timeout};
use tunnel_client::{
    ConnectOptions, ConnectionHandle, FsExportSettings, LocalExport, LocalExportKind,
    http_forward::HttpHandlers,
};

use super::{
    CLEANUP_TIMEOUT, Harness, HarnessError, HarnessOptions, LEDGER_WAIT, OidcTokenOptions,
    ProductionCluster, Result, RunningHarness, STARTUP_TIMEOUT, await_owner,
    finish_scenario_with_cleanup, push_cleanup_error, repository_root, synthetic_bytes,
    write_device_profile, write_private,
};

const SCENARIO: Duration = Duration::from_secs(90);
const WAIT: Duration = Duration::from_secs(15);
const MAX_LINE: u64 = 16_384;
const HELD_SIZE: u64 = 97;
const PROBE_SIZE: u64 = 193;

fn fail(detail: &str) -> HarnessError {
    HarnessError::Process(format!("filesystem fid confirmation: {detail}"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum HeldKind {
    Walk,
    Clunk,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaseProof {
    kind: HeldKind,
    original_fid: u32,
    parallel_fid: u32,
    reused_fid: u32,
    original_tag: u16,
    held_tag: u16,
    probe_tag: u16,
    flush_tag: u16,
    original_sent: u64,
    held_received: u64,
    probe_received: u64,
    caller_settled: u64,
    parallel_sent: u64,
    held_delivered: u64,
    cleanup_sent: u64,
    cleanup_delivered: u64,
    reused_sent: u64,
    flush_received: u64,
    reserved_after_caller: usize,
    reserved_during_hold: usize,
    reserved_at_end: usize,
    premature_clunks: usize,
    provider_probe_kind: String,
    provider_probe_size: u64,
    provider_probe_errno: u32,
    probe_settled: String,
    caller_code: String,
    caller_outcome: String,
    caller_retryable: bool,
    caller_size: u64,
    parallel_wire_reply: String,
    parallel_valid: bool,
    reuse_size: u64,
    state: String,
    unexpected_closes: usize,
    request_timeout_ms: u64,
    operation_timeout_ms: u64,
    delivery_order_preserved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefusalProof {
    code: String,
    outcome: String,
    clunks_after_refusal: usize,
    first_fid: u32,
    second_fid: u32,
    probe_size: u64,
    state: String,
    reserved_at_end: usize,
    preabort_code: String,
    preabort_sent: usize,
    unexpected_closes: usize,
}

/// Closed labels, identifiers and counts only; never host paths or payloads.
#[derive(Debug, Serialize)]
pub struct FsFidOrderingEvidence {
    relay_count: usize,
    owner_matches: bool,
    client_module_matches: bool,
    node_matches: bool,
    held_owner_checks: usize,
    cases: Vec<CaseProof>,
    refusal: RefusalProof,
    completed_exchanges: u64,
    mutations_dispatched: u64,
    bytes_written: u64,
    session_unchanged: bool,
    host_unchanged: bool,
    cleanup_joined: bool,
    device_terminal: DeviceTerminal,
}

fn validate_case(case: &CaseProof) -> Result<()> {
    if case.original_fid == 0
        || case.parallel_fid == case.original_fid
        || case.reused_fid != case.original_fid
    {
        return Err(fail(
            "fid reused before confirmation, or not reusable after confirmed cleanup",
        ));
    }
    if case.reserved_after_caller != 1
        || case.reserved_during_hold != 2
        || case.reserved_at_end != 0
        || case.premature_clunks != 0
    {
        return Err(fail("unconfirmed resource ownership accounting differs"));
    }
    if !(case.original_sent < case.held_received
        && case.held_received < case.probe_received
        && case.probe_received < case.caller_settled
        && case.caller_settled < case.parallel_sent
        && case.parallel_sent < case.held_delivered
        && case.held_received < case.flush_received
        && case.flush_received < case.held_delivered
        && case.cleanup_sent < case.cleanup_delivered
        && case.cleanup_delivered < case.reused_sent)
    {
        return Err(fail(
            "actual reply/caller/parallel/cleanup ordering differs",
        ));
    }
    if case.probe_tag == case.held_tag
        || case.flush_tag == case.held_tag
        || case.flush_tag == case.probe_tag
        || case.parallel_wire_reply != "Rwalk"
        || !case.parallel_valid
        || case.reuse_size != PROBE_SIZE
        || case.state != "ready"
        || case.unexpected_closes != 0
        || !case.delivery_order_preserved
        || case.operation_timeout_ms != 2_000
        || case.request_timeout_ms <= case.operation_timeout_ms
        || case.caller_retryable
    {
        return Err(fail(
            "parallel validity, transport order, tag identity or unchanged deadline contract differs",
        ));
    }
    match case.kind {
        HeldKind::Walk => {
            if case.held_tag != case.original_tag
                || case.cleanup_sent <= case.held_delivered
                || case.provider_probe_kind != "Rgetattr"
                || case.provider_probe_size != HELD_SIZE
                || case.provider_probe_errno != 0
                || case.probe_settled != "reply"
                || case.caller_code != "DEADLINE_EXCEEDED"
                || case.caller_outcome != "failed"
                || case.caller_size != 0
            {
                return Err(fail(
                    "unanswered walk did not preserve its actually bound fid until settlement",
                ));
            }
        }
        HeldKind::Clunk => {
            if case.held_tag == case.original_tag
                || case.cleanup_sent >= case.held_received
                || case.cleanup_delivered != case.held_delivered
                || case.provider_probe_kind != "Rlerror"
                || case.provider_probe_size != 0
                || case.provider_probe_errno != 22
                || case.probe_settled != "EINVAL"
                || case.caller_code != "ok"
                || case.caller_outcome != "complete"
                || case.caller_size != HELD_SIZE
            {
                return Err(fail(
                    "applied clunk with held response did not preserve client confirmation ownership",
                ));
            }
        }
    }
    Ok(())
}

/// Validate only C244's declared real-endpoint confirmation boundary.
///
/// # Errors
/// Missing actual-endpoint, ordering, resource ownership or cleanup witnesses.
pub fn validate_fs_fid_ordering_evidence(evidence: &FsFidOrderingEvidence) -> Result<()> {
    if evidence.relay_count != 3
        || !evidence.owner_matches
        || !evidence.client_module_matches
        || !evidence.node_matches
        || evidence.held_owner_checks != 2
        || evidence.cases.len() != 2
        || evidence.cases[0].kind != HeldKind::Walk
        || evidence.cases[1].kind != HeldKind::Clunk
    {
        return Err(fail(
            "real endpoint and both selected holds were not established",
        ));
    }
    for case in &evidence.cases {
        validate_case(case)?;
    }
    let refusal = &evidence.refusal;
    if refusal.code != "ENOENT"
        || refusal.outcome != "not_started"
        || refusal.clunks_after_refusal != 0
        || refusal.first_fid == 0
        || refusal.first_fid != refusal.second_fid
        || refusal.probe_size != PROBE_SIZE
        || refusal.state != "ready"
        || refusal.reserved_at_end != 0
        || refusal.preabort_code != "ABORTED"
        || refusal.preabort_sent != 0
        || refusal.unexpected_closes != 0
    {
        return Err(fail(
            "definite refusal or pre-dispatch abort positive control differs",
        ));
    }
    if evidence.completed_exchanges != 3
        || evidence.mutations_dispatched != 0
        || evidence.bytes_written != 0
        || !evidence.session_unchanged
        || !evidence.host_unchanged
        || !evidence.cleanup_joined
        || !evidence.device_terminal.quiescent()
        || evidence.completed_exchanges != evidence.device_terminal.exchanges
        || evidence.mutations_dispatched != evidence.device_terminal.mutations_dispatched
        || evidence.bytes_written != evidence.device_terminal.bytes_written
    {
        return Err(fail(&format!(
            "independent device/host/session/cleanup witness differs completed_exchanges={} mutations_dispatched={} bytes_written={} session_unchanged={} host_unchanged={} cleanup_joined={} device_terminal={:?}",
            evidence.completed_exchanges,
            evidence.mutations_dispatched,
            evidence.bytes_written,
            evidence.session_unchanged,
            evidence.host_unchanged,
            evidence.cleanup_joined,
            evidence.device_terminal,
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "lowercase", deny_unknown_fields)]
enum Event {
    Ready {
        node: String,
        module: String,
    },
    #[serde(rename_all = "camelCase")]
    Held {
        kind: HeldKind,
        fid: u32,
        held_tag: u16,
        probe_tag: u16,
        parallel_fid: u32,
        reserved_after_caller: usize,
        reserved_during_hold: usize,
        premature_clunks: usize,
        provider_probe_kind: String,
        provider_probe_size: u64,
        provider_probe_errno: u32,
        probe_received: u64,
        received: usize,
        delivered: usize,
    },
    Case {
        result: CaseProof,
    },
    Refusal {
        result: RefusalProof,
    },
    Done {
        cases: usize,
    },
    Exiting,
    Failure {
        phase: String,
    },
}

struct Driver {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
}

impl Driver {
    fn start(plan: &Path, ca: &Path) -> Result<Self> {
        let mut child = tokio::process::Command::new("node")
            .arg(repository_root().join("packages/client/e2e/fid-ordering.ts"))
            .arg(plan)
            .env("NODE_EXTRA_CA_CERTS", ca)
            .env_remove("NODE_OPTIONS")
            .env_remove("NODE_TLS_REJECT_UNAUTHORIZED")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(HarnessError::Io)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| fail("driver stdin absent"))?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| fail("driver stdout absent"))?,
        );
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
    async fn event(&mut self) -> Result<Event> {
        let mut line = Vec::new();
        let count = timeout(
            WAIT,
            (&mut self.stdout)
                .take(MAX_LINE + 1)
                .read_until(b'\n', &mut line),
        )
        .await
        .map_err(|_| fail("driver event deadline"))?
        .map_err(HarnessError::Io)?;
        if count == 0 || count as u64 > MAX_LINE || line.last() != Some(&b'\n') {
            return Err(fail("driver event missing or beyond bound"));
        }
        let event: Event = serde_json::from_slice(&line).map_err(HarnessError::Json)?;
        if let Event::Failure { phase } = &event {
            let known = match phase.as_str() {
                "startup" | "held-walk" | "held-clunk" | "definite-refusal" | "report" => {
                    phase.as_str()
                }
                _ => "unknown-phase",
            };
            return Err(fail(&format!("driver failed at {known}")));
        }
        Ok(event)
    }
    async fn send(&mut self, command: &str) -> Result<()> {
        timeout(WAIT, async {
            self.stdin.write_all(command.as_bytes()).await?;
            self.stdin.write_all(b"\n").await?;
            self.stdin.flush().await
        })
        .await
        .map_err(|_| fail("driver command deadline"))?
        .map_err(HarnessError::Io)
    }
    async fn stop(&mut self) -> Result<()> {
        let graceful = timeout(CLEANUP_TIMEOUT, async {
            self.send("exit").await?;
            if !matches!(self.event().await?, Event::Exiting) {
                return Err(fail("driver exit acknowledgement absent"));
            }
            let status = self.child.wait().await.map_err(HarnessError::Io)?;
            if !status.success() {
                return Err(fail("driver exit status failed"));
            }
            Ok(())
        })
        .await
        .map_err(|_| fail("driver cleanup deadline"))
        .and_then(std::convert::identity);
        if graceful.is_err() {
            let _ = self.child.start_kill();
            if !matches!(
                timeout(Duration::from_secs(2), self.child.wait()).await,
                Ok(Ok(_))
            ) {
                return Err(fail("driver forced cleanup did not join"));
            }
        }
        graceful
    }
}

/// Run the real Redis/relay/device/Node fixture without changing runtime policy.
///
/// # Errors
/// Fixture setup, evidence, bounded scenario, or joined cleanup failure.
pub async fn verify() -> Result<FsFidOrderingEvidence> {
    if std::env::var_os("NODE_TLS_REJECT_UNAUTHORIZED").is_some() {
        return Err(fail("NODE_TLS_REJECT_UNAUTHORIZED must be absent"));
    }
    let mut harness = timeout(
        STARTUP_TIMEOUT,
        Harness::start(HarnessOptions::from_env()?.fs_services(true)),
    )
    .await
    .map_err(|_| fail("catalog startup deadline"))??;
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
    // Keep the sole supervisor handle through all transport teardown, including
    // a cancelled first stop. A second join is cleanup, never a scenario retry.
    let mut client = None;
    let scenario = run(&mut cluster, &harness, &mut client).await;
    let mut errors = Vec::new();
    push_cleanup_error(
        &mut errors,
        "relay cleanup",
        cluster
            .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await,
    );
    push_cleanup_error(
        &mut errors,
        "catalog cleanup",
        harness
            .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await,
    );
    if let Some(client) = client.as_ref() {
        push_cleanup_error(&mut errors, "device final join", stop_client(client).await);
    }
    let mut evidence = finish_scenario_with_cleanup(scenario, errors)?;
    evidence.cleanup_joined = true;
    validate_fs_fid_ordering_evidence(&evidence)?;
    Ok(evidence)
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    client_owner: &mut Option<ConnectionHandle>,
) -> Result<FsFidOrderingEvidence> {
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| fail("device absent"))?;
    let echo = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| fail("primary export absent"))?;
    let service = harness
        .fs_service("client-rw")
        .ok_or_else(|| fail("filesystem export absent"))?;
    let work = tempfile::tempdir().map_err(HarnessError::Io)?;
    let host = work.path().join("host");
    std::fs::create_dir(&host).map_err(HarnessError::Io)?;
    std::fs::write(host.join("held.bin"), synthetic_bytes(HELD_SIZE as usize))
        .map_err(HarnessError::Io)?;
    std::fs::write(host.join("probe.bin"), synthetic_bytes(PROBE_SIZE as usize))
        .map_err(HarnessError::Io)?;
    std::fs::create_dir(host.join("parallel")).map_err(HarnessError::Io)?;
    std::fs::write(host.join("parallel/entry.bin"), synthetic_bytes(31))
        .map_err(HarnessError::Io)?;
    crate::c11_capture::record_payload_sentinel(&synthetic_bytes(64))?;
    let owner = cluster.relay("relay-a")?;
    let address = owner
        .running
        .as_ref()
        .ok_or_else(|| fail("owner relay absent"))?
        .device_addr;
    let expected_owner = owner.node_id.clone();
    let endpoint = format!(
        "https://127.0.0.1:{}/v1/devices/{}/services/{}/fs",
        owner.consumer_addr()?.port(),
        device.id,
        service.service_id
    );
    let mut profile = write_device_profile(
        work.path(),
        device.id,
        echo,
        "fid-confirmation-canary",
        address,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.exports.insert(
        service.service_id.to_string(),
        LocalExport {
            kind: LocalExportKind::Fs,
            device_canary: None,
            mcp: None,
            acp: None,
            cua: None,
            fs: Some(FsExportSettings {
                root: host.clone(),
                capabilities: vec![
                    "read".into(),
                    "list".into(),
                    "write".into(),
                    "delete".into(),
                ],
                features: Vec::new(),
            }),
        },
    );
    profile
        .config
        .validate()
        .map_err(|_| fail("device profile invalid"))?;
    *client_owner = Some(
        timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect_with_http_handlers(
                ConnectOptions::new(profile.config.clone()),
                HttpHandlers::new(),
            ),
        )
        .await
        .map_err(|_| fail("device startup deadline"))?
        .map_err(|_| fail("device startup failed"))?,
    );
    let client = client_owner
        .as_mut()
        .ok_or_else(|| fail("device ownership absent"))?;
    // Keep process ownership outside the timed future, so a deadline still
    // reaches the same explicit join/kill cleanup below.
    let mut driver = None;
    let scenario = timeout(SCENARIO, async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready()).await.map_err(|_| fail("device readiness deadline"))?
            .map_err(|_| fail("device not ready"))?;
        let actual_owner = await_owner(cluster, device.tenant_id, device.id, &session.session_id).await?;
        let baseline = client.status_snapshot().fs;
        if baseline.exchanges != 0 || baseline.mutations_dispatched != 0 || baseline.bytes_written != 0 {
            return Err(fail("device ledger was not empty before consumer startup"));
        }
        let token = harness.oidc.issue_with(&harness.topology.consumers_a[0].name,
            OidcTokenOptions { scope: Some("echo:invoke fs:connect".into()), ..OidcTokenOptions::default() })?;
        let plan = work.path().join("plan.json");
        write_private(&plan, &serde_json::to_vec(&serde_json::json!({ "endpoint": endpoint, "token": token })).map_err(HarnessError::Json)?)?;
        let ca = work.path().join("ca.pem");
        std::fs::write(&ca, &harness.pki.server_ca.certificate_pem).map_err(HarnessError::Io)?;
        driver = Some(Driver::start(&plan, &ca)?);
        let driver = driver.as_mut().ok_or_else(|| fail("driver ownership absent"))?;
            let Event::Ready { node, module } = driver.event().await? else { return Err(fail("driver readiness absent")); };
            let expected_module = std::fs::canonicalize(repository_root().join("packages/client/src/index.ts"))
                .map_err(|_| fail("expected client module absent"))?;
            let module_matches = std::fs::canonicalize(module).is_ok_and(|actual| actual == expected_module);
            let mut cases = Vec::new();
            for selected in [HeldKind::Walk, HeldKind::Clunk] {
                let Event::Held { kind, fid, held_tag, probe_tag, parallel_fid, reserved_after_caller, reserved_during_hold,
                    premature_clunks, provider_probe_kind, provider_probe_size, provider_probe_errno, probe_received, received, delivered } = driver.event().await? else { return Err(fail("ordered reply hold absent")); };
                let probe_matches = match kind {
                    HeldKind::Walk => provider_probe_kind == "Rgetattr" && provider_probe_size == HELD_SIZE && provider_probe_errno == 0,
                    HeldKind::Clunk => provider_probe_kind == "Rlerror" && provider_probe_size == 0 && provider_probe_errno == 22,
                };
                if !probe_matches || probe_received == 0 { return Err(fail("held exact-fid provider probe differs")); }
                if kind != selected || fid == 0 || fid == parallel_fid || held_tag == probe_tag
                    || reserved_after_caller != 1 || reserved_during_hold != 2 || premature_clunks != 0 || received <= delivered
                {
                    eprintln!("fs fid held kind={kind:?} fid={fid} parallel_fid={parallel_fid} reserved_after={reserved_after_caller} reserved_during={reserved_during_hold} premature_clunks={premature_clunks} probe_kind={provider_probe_kind} probe_size={provider_probe_size} probe_errno={provider_probe_errno} probe_received={probe_received} received={received} delivered={delivered}");
                    return Err(fail("held reply already permits premature cleanup or fid reuse"));
                }
                let deadline = tokio::time::Instant::now() + WAIT;
                loop {
                    let status = client.status_snapshot();
                    if status.phase == "active" && status.session_id.as_deref() == Some(session.session_id.as_str())
                        && status.epoch == Some(session.epoch) && status.streams == 1 { break; }
                    if tokio::time::Instant::now() >= deadline { return Err(fail("held real device stream/session not observed")); }
                    sleep(Duration::from_millis(10)).await;
                }
                if await_owner(cluster, device.tenant_id, device.id, &session.session_id).await? != expected_owner {
                    return Err(fail("owner changed during held reply"));
                }
                driver.send("release").await?;
                let Event::Case { result } = driver.event().await? else { return Err(fail("case proof absent")); };
                if result.kind != selected || result.original_fid != fid || result.parallel_fid != parallel_fid
                    || result.held_tag != held_tag || result.probe_tag != probe_tag
                    || result.reserved_after_caller != reserved_after_caller || result.reserved_during_hold != reserved_during_hold
                    || result.premature_clunks != premature_clunks || result.provider_probe_kind != provider_probe_kind
                    || result.provider_probe_size != provider_probe_size || result.provider_probe_errno != provider_probe_errno
                    || result.probe_received != probe_received {
                    return Err(fail("final case does not match independently observed held checkpoint"));
                }
                if let Err(error) = validate_case(&result) {
                    eprintln!("fs fid case kind={:?} fid={} parallel_fid={} reused_fid={} held_received={} held_delivered={} cleanup_sent={} cleanup_delivered={} reused_sent={}",
                        result.kind, result.original_fid, result.parallel_fid, result.reused_fid,
                        result.held_received, result.held_delivered, result.cleanup_sent, result.cleanup_delivered, result.reused_sent);
                    return Err(error);
                }
                cases.push(result);
            }
            let Event::Refusal { result: refusal } = driver.event().await? else { return Err(fail("definite refusal control absent")); };
            if !matches!(driver.event().await?, Event::Done { cases: 3 }) { return Err(fail("all three real sessions did not finish")); }
            // Handler Done publishes its ledger before asynchronous STREAM_FORGET
            // and carrier barriers necessarily retire the stream. Observe every
            // final predicate together under the existing ledger deadline.
            let terminal = await_device_terminal(client.status(), &session.session_id, session.epoch,
                tokio::time::Instant::now() + LEDGER_WAIT).await?;
            Ok(FsFidOrderingEvidence {
                relay_count: cluster.relays.len(), owner_matches: actual_owner == expected_owner,
                client_module_matches: module_matches, node_matches: node == "v24.21.0", held_owner_checks: cases.len(), cases, refusal,
                completed_exchanges: terminal.exchanges, mutations_dispatched: terminal.mutations_dispatched, bytes_written: terminal.bytes_written,
                session_unchanged: terminal.quiescent(),
                host_unchanged: std::fs::read(host.join("held.bin")).map_err(HarnessError::Io)? == synthetic_bytes(HELD_SIZE as usize)
                    && std::fs::read(host.join("probe.bin")).map_err(HarnessError::Io)? == synthetic_bytes(PROBE_SIZE as usize)
                    && std::fs::read(host.join("parallel/entry.bin")).map_err(HarnessError::Io)? == synthetic_bytes(31)
                    && std::fs::read_dir(&host).map_err(HarnessError::Io)?.count() == 3
                    && std::fs::read_dir(host.join("parallel")).map_err(HarnessError::Io)?.count() == 1,
                cleanup_joined: false, device_terminal: terminal,
            })
    }).await.map_err(|_| fail("scenario deadline")).and_then(std::convert::identity);
    let mut errors = Vec::new();
    if let Some(driver) = driver.as_mut() {
        push_cleanup_error(&mut errors, "driver cleanup", driver.stop().await);
    }
    push_cleanup_error(&mut errors, "device cleanup", stop_client(client).await);
    finish_scenario_with_cleanup(scenario, errors)
}

async fn stop_client(client: &ConnectionHandle) -> Result<()> {
    timeout(CLEANUP_TIMEOUT, client.stop())
        .await
        .map_err(|_| fail("device cleanup deadline"))
        .and_then(|result| result.map_err(|_| fail("device cleanup failed")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(kind: HeldKind) -> CaseProof {
        let walk = kind == HeldKind::Walk;
        serde_json::from_value(serde_json::json!({
            "kind": if walk { "walk" } else { "clunk" },
            "originalFid": 1, "parallelFid": 2, "reusedFid": 1,
            "originalTag": 1, "heldTag": if walk { 1 } else { 4 }, "probeTag": 5, "flushTag": 6,
            "originalSent": 1, "heldReceived": 6, "probeReceived": 7, "callerSettled": 8, "parallelSent": 12,
            "heldDelivered": 15, "cleanupSent": if walk { 20 } else { 5 },
            "cleanupDelivered": if walk { 24 } else { 15 }, "reusedSent": 25, "flushReceived": 10,
            "reservedAfterCaller": 1, "reservedDuringHold": 2, "reservedAtEnd": 0, "prematureClunks": 0,
            "providerProbeKind": if walk { "Rgetattr" } else { "Rlerror" },
            "providerProbeSize": if walk { HELD_SIZE } else { 0 }, "providerProbeErrno": if walk { 0 } else { 22 },
            "probeSettled": if walk { "reply" } else { "EINVAL" },
            "callerCode": if walk { "DEADLINE_EXCEEDED" } else { "ok" },
            "callerOutcome": if walk { "failed" } else { "complete" }, "callerRetryable": false,
            "callerSize": if walk { 0 } else { HELD_SIZE }, "parallelWireReply": "Rwalk", "parallelValid": true,
            "reuseSize": PROBE_SIZE, "state": "ready", "unexpectedCloses": 0,
            "requestTimeoutMs": 30_000, "operationTimeoutMs": 2_000, "deliveryOrderPreserved": true
        })).expect("synthetic complete case proof")
    }

    fn passing() -> FsFidOrderingEvidence {
        FsFidOrderingEvidence {
            relay_count: 3,
            owner_matches: true,
            client_module_matches: true,
            node_matches: true,
            held_owner_checks: 2,
            cases: vec![case(HeldKind::Walk), case(HeldKind::Clunk)],
            refusal: RefusalProof {
                code: "ENOENT".into(),
                outcome: "not_started".into(),
                clunks_after_refusal: 0,
                first_fid: 1,
                second_fid: 1,
                probe_size: PROBE_SIZE,
                state: "ready".into(),
                reserved_at_end: 0,
                preabort_code: "ABORTED".into(),
                preabort_sent: 0,
                unexpected_closes: 0,
            },
            completed_exchanges: 3,
            mutations_dispatched: 0,
            bytes_written: 0,
            session_unchanged: true,
            host_unchanged: true,
            cleanup_joined: true,
            device_terminal: DeviceTerminal::from_status(
                &tunnel_client::ConnectionStatus {
                    phase: "active".into(),
                    session_id: Some("expected-session".into()),
                    epoch: Some(7),
                    fs: tunnel_client::FsCounters {
                        exchanges: 3,
                        ..tunnel_client::FsCounters::default()
                    },
                    ..tunnel_client::ConnectionStatus::default()
                },
                "expected-session",
                7,
            ),
        }
    }

    #[test]
    fn fs_fid_ordering_accepts_the_two_distinct_real_confirmation_schedules() {
        validate_fs_fid_ordering_evidence(&passing()).expect("complete proof");
    }

    #[test]
    fn fs_fid_ordering_rejects_premature_walk_and_clunk_release() {
        for index in 0..2 {
            let mut proof = passing();
            proof.cases[index].parallel_fid = proof.cases[index].original_fid;
            assert!(validate_fs_fid_ordering_evidence(&proof).is_err());
            let mut proof = passing();
            proof.cases[index].reserved_after_caller = 0;
            assert!(validate_fs_fid_ordering_evidence(&proof).is_err());
        }
    }

    #[test]
    fn fs_fid_ordering_rejects_early_cleanup_reordered_delivery_and_unproven_reuse() {
        for mutation in [
            |proof: &mut CaseProof| proof.cleanup_sent = proof.held_delivered - 1,
            |proof: &mut CaseProof| proof.delivery_order_preserved = false,
            |proof: &mut CaseProof| proof.reused_sent = proof.cleanup_delivered,
            |proof: &mut CaseProof| proof.flush_received = proof.held_delivered + 1,
            |proof: &mut CaseProof| proof.probe_tag = proof.held_tag,
            |proof: &mut CaseProof| proof.probe_received = proof.held_received,
        ] {
            let mut proof = case(HeldKind::Walk);
            mutation(&mut proof);
            assert!(validate_case(&proof).is_err());
        }
    }

    #[test]
    fn fs_fid_ordering_does_not_call_a_still_bound_fid_an_applied_clunk() {
        let mut proof = case(HeldKind::Clunk);
        proof.provider_probe_kind = "Rgetattr".into();
        proof.provider_probe_size = HELD_SIZE;
        proof.provider_probe_errno = 0;
        assert!(validate_case(&proof).is_err());
    }

    #[test]
    fn fs_fid_ordering_retains_each_failed_final_scalar_in_the_diagnostic() {
        let mut proof = passing();
        proof.completed_exchanges = 4;
        proof.mutations_dispatched = 2;
        proof.bytes_written = 17;
        proof.session_unchanged = false;
        proof.host_unchanged = false;
        proof.cleanup_joined = false;
        proof.device_terminal.streams = 1;
        proof.device_terminal.replay_frames = 2;
        let error = validate_fs_fid_ordering_evidence(&proof)
            .expect_err("independent witnesses must refuse")
            .to_string();
        for scalar in [
            "completed_exchanges=4",
            "mutations_dispatched=2",
            "bytes_written=17",
            "session_unchanged=false",
            "host_unchanged=false",
            "cleanup_joined=false",
            "streams: 1",
            "replay_frames: 2",
        ] {
            assert!(
                error.contains(scalar),
                "lost failed scalar {scalar}: {error}"
            );
        }
    }

    #[test]
    fn fs_fid_ordering_requires_independent_host_device_session_and_cleanup_witnesses() {
        for mutation in [
            |proof: &mut FsFidOrderingEvidence| proof.completed_exchanges = 0,
            |proof: &mut FsFidOrderingEvidence| proof.mutations_dispatched = 1,
            |proof: &mut FsFidOrderingEvidence| proof.host_unchanged = false,
            |proof: &mut FsFidOrderingEvidence| proof.session_unchanged = false,
            |proof: &mut FsFidOrderingEvidence| proof.cleanup_joined = false,
            |proof: &mut FsFidOrderingEvidence| proof.refusal.second_fid += 1,
            |proof: &mut FsFidOrderingEvidence| proof.cases[0].parallel_valid = false,
        ] {
            let mut proof = passing();
            mutation(&mut proof);
            assert!(validate_fs_fid_ordering_evidence(&proof).is_err());
        }
    }
}
