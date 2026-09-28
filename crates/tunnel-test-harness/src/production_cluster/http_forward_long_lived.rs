//! Task row M4-71 over the real cluster: a long-lived `http-forward/1`
//! exchange is not cut at the connector's single-request timeout, and a
//! request that never produces a response head still is.
//!
//! The route is the production one: consumer HTTP/1.1 → relay-c (non-owner
//! Axum ingress) → HTTP/3 peer hop → relay-a (owner actor) → device data
//! WebSocket → `tunnel-client` → an in-process handler.  The connector runs
//! with `limits.operation_timeout_ms` set to [`OPERATION_TIMEOUT`] (2 s), and
//! both bridge ends with an absolute deadline of [`BRIDGE_DEADLINE`].
//!
//! * `sse`: a GET whose SSE head is sent at once and whose events follow
//!   [`EVENT_GAP`] apart, each gap longer than the connector's timeout, for
//!   longer in total than both the connector's timeout and the relay's own
//!   `operation_timeout` (30 s by default).  It must end cleanly and
//!   byte-exact, and the connector must count no expired stream.  Before
//!   M4-71 the connector reset it about 2 s after its OPEN.
//! * `no-head`: a POST whose handler never answers.  It must fail at the
//!   connector's timeout, not at the bridge's absolute deadline, and the
//!   handler must be cancelled.  Through this non-owner ingress the failure
//!   is `502 HTTP_STREAM_INTERRUPTED` rather than `504
//!   HTTP_DEADLINE_EXCEEDED` (task row M4-73, pre-existing).
//! * `late-unary` (the row's control): a POST whose handler answers with a
//!   complete body only after twice the timeout.  A unary request still ends
//!   at its deadline: the consumer gets the gateway failure, never the late
//!   answer.
//!
//! All payloads, credentials and headers are synthetic.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tunnel_client::http_forward::{
    HttpExport, HttpHandler, HttpHandlerError, HttpHandlerFuture, HttpHandlers,
};
use tunnel_client::{ConnectOptions, LocalExport, LocalExportKind};
use tunnel_http_bridge::{BridgeConfig, ChannelBody, Outcome, Profile};
use tunnel_http_forward::{HttpVersion, Method, Occurrence, RequestPolicy, ResponsePolicy};
use tunnel_relay::{HttpForwardExport, HttpForwardExports};

use super::http_forward_real_path::{
    connect_consumer, empty_stream, error_chain, full_body, handler_body, request,
};
use super::{
    CLEANUP_TIMEOUT, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    finish_scenario_with_cleanup, push_cleanup_error,
};
use crate::acceptance::helpers::write_device_profile;
use crate::oidc::OidcTokenOptions;
use crate::{Harness, HarnessError, HarnessOptions, Result};

/// The connector's `limits.operation_timeout_ms` for this gate.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
/// Both bridge ends' absolute application deadline.
pub const BRIDGE_DEADLINE: Duration = Duration::from_secs(120);
/// The silence between SSE events: longer than the connector's timeout.
pub const EVENT_GAP: Duration = Duration::from_secs(3);
/// SSE events sent; with [`EVENT_GAP`] the stream lasts 33 s, longer than
/// the relay's default 30 s `operation_timeout` as well.
pub const SSE_EVENT_COUNT: usize = 12;
/// How late the no-head and late-unary failures may arrive after the
/// connector's timeout.  Far below [`BRIDGE_DEADLINE`], so an answer inside
/// it can only be the response-head bound.
pub const HEAD_TIMEOUT_SLACK: Duration = Duration::from_secs(10);
/// A consumer retry is allowed only for a `503` that proves nothing was
/// dispatched (a peer route re-forming after the membership re-sign).
const NOT_DISPATCHED_RETRIES: usize = 10;
/// Payload-free marker of the gate's own run in its printed evidence.
const GATE: &str = "m4-71 http-forward long-lived";

fn sse_event(index: usize) -> Bytes {
    Bytes::from(format!("id: {index}\ndata: synthetic-event-{index}\n\n"))
}

fn sse_bytes() -> Vec<u8> {
    (0..SSE_EVENT_COUNT)
        .flat_map(|index| sse_event(index).to_vec())
        .collect()
}

/// Everything the gate measured.  Counts, durations, statuses and closed
/// codes only.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpForwardLongLivedEvidence {
    pub owner_node: String,
    pub ingress_node: String,
    pub non_owner_ingress: bool,
    pub connector_operation_timeout_ms: u128,
    pub relay_operation_timeout_ms: u128,
    pub bridge_deadline_ms: u128,
    /// `sse`
    pub sse_status: u16,
    pub sse_content_type: String,
    pub sse_events_expected: usize,
    pub sse_bytes_expected: usize,
    pub sse_bytes_received: usize,
    pub sse_byte_exact: bool,
    pub sse_ended_cleanly: bool,
    pub sse_duration_ms: u128,
    pub sse_retries: usize,
    pub sse_device_response: Option<String>,
    pub sse_device_error: Option<String>,
    /// The connector's `stream_auth.expired_streams`, before and after `sse`.
    pub expired_streams_before_sse: u64,
    pub expired_streams_after_sse: u64,
    /// `no-head`
    pub no_head_status: u16,
    pub no_head_code: String,
    pub no_head_elapsed_ms: u128,
    pub no_head_retries: usize,
    pub no_head_handler_cancelled: bool,
    /// `late-unary`
    pub late_unary_status: u16,
    pub late_unary_code: String,
    pub late_unary_elapsed_ms: u128,
    pub late_unary_retries: usize,
    pub late_unary_answer_seen: bool,
}

/// The device's deadline failure reaches a consumer on a non-owner ingress
/// as `502 HTTP_STREAM_INTERRUPTED`, not `504 HTTP_DEADLINE_EXCEEDED`: the
/// owner forwards the device's RESET (`ADAPTER_FAILURE`) but not the
/// `RESULT_STATUS` detail that names the deadline.  That is the same answer
/// the pre-M4-71 code gave at the same instant, and it is task row M4-73,
/// not this gate's subject; what this gate pins is *when* the request ends.
fn gateway_failure(status: u16) -> bool {
    matches!(status, 502 | 504)
}

fn deadline_code(code: &str) -> bool {
    matches!(code, "HTTP_DEADLINE_EXCEEDED" | "HTTP_STREAM_INTERRUPTED")
}

/// Validate the evidence against the gate's rules.
///
/// # Errors
/// The first rule the evidence breaks, by name.
pub fn validate_http_forward_long_lived_evidence(
    evidence: &HttpForwardLongLivedEvidence,
) -> Result<()> {
    let timeout_ms = evidence.connector_operation_timeout_ms;
    let head_window = timeout_ms..=timeout_ms + HEAD_TIMEOUT_SLACK.as_millis();
    let checks = [
        ("non_owner_ingress", evidence.non_owner_ingress),
        (
            "timeouts_configured",
            timeout_ms == OPERATION_TIMEOUT.as_millis()
                && evidence.bridge_deadline_ms == BRIDGE_DEADLINE.as_millis()
                && evidence.relay_operation_timeout_ms > 0,
        ),
        ("sse_status", evidence.sse_status == 200),
        (
            "sse_content_type",
            evidence.sse_content_type == "text/event-stream",
        ),
        (
            "sse_byte_exact",
            evidence.sse_byte_exact
                && evidence.sse_bytes_received == evidence.sse_bytes_expected
                && evidence.sse_bytes_expected > 0,
        ),
        ("sse_ended_cleanly", evidence.sse_ended_cleanly),
        (
            "sse_outlived_both_timeouts",
            evidence.sse_duration_ms > timeout_ms
                && evidence.sse_duration_ms > evidence.relay_operation_timeout_ms,
        ),
        (
            "sse_device_complete",
            evidence.sse_device_response.as_deref() == Some("Complete")
                && evidence.sse_device_error.is_none(),
        ),
        (
            "sse_no_expired_stream",
            evidence.expired_streams_after_sse == evidence.expired_streams_before_sse,
        ),
        ("no_head_status", gateway_failure(evidence.no_head_status)),
        ("no_head_code", deadline_code(&evidence.no_head_code)),
        (
            "no_head_at_the_timeout",
            head_window.contains(&evidence.no_head_elapsed_ms),
        ),
        (
            "no_head_handler_cancelled",
            evidence.no_head_handler_cancelled,
        ),
        (
            "late_unary_status",
            gateway_failure(evidence.late_unary_status),
        ),
        ("late_unary_code", deadline_code(&evidence.late_unary_code)),
        (
            "late_unary_at_the_timeout",
            head_window.contains(&evidence.late_unary_elapsed_ms),
        ),
        ("late_unary_answer_hidden", !evidence.late_unary_answer_seen),
    ];
    for (rule, passed) in checks {
        if !passed {
            return Err(HarnessError::InvalidInput(format!(
                "{GATE}: rule {rule} failed"
            )));
        }
    }
    Ok(())
}

fn profile() -> Result<Arc<Profile>> {
    let policy = |error| HarnessError::InvalidInput(format!("http-forward profile: {error:?}"));
    let mut request = RequestPolicy::new(1024 * 1024).map_err(policy)?;
    for (method, path) in [
        (Method::Get, "/sse"),
        (Method::Post, "/stall"),
        (Method::Post, "/late"),
    ] {
        request.allow_route(method, path).map_err(policy)?;
    }
    request.allow_http_version(HttpVersion::Http11);
    request
        .headers
        .allow("accept", Occurrence::Repeatable)
        .map_err(policy)?;
    let mut response = ResponsePolicy::new(16 * 1024 * 1024).map_err(policy)?;
    response
        .headers
        .allow("content-type", Occurrence::Singleton)
        .map_err(policy)?;
    response
        .headers
        .allow("cache-control", Occurrence::Repeatable)
        .map_err(policy)?;
    Ok(Arc::new(Profile { request, response }))
}

fn bridge_config() -> Result<BridgeConfig> {
    BridgeConfig::default()
        .with_deadline(BRIDGE_DEADLINE)
        .map_err(|error| HarnessError::InvalidInput(format!("bridge config: {error}")))
}

#[derive(Default)]
struct HandlerState {
    stall_cancellations: AtomicUsize,
    late_answers: AtomicUsize,
}

fn handler(state: Arc<HandlerState>) -> Arc<dyn HttpHandler> {
    Arc::new(
        move |request: http::Request<ChannelBody>| -> HttpHandlerFuture {
            let state = Arc::clone(&state);
            Box::pin(async move {
                match request.uri().path() {
                    "/sse" => {
                        let (tx, rx) = mpsc::channel::<Bytes>(1);
                        tokio::spawn(async move {
                            for index in 0..SSE_EVENT_COUNT {
                                if index > 0 {
                                    sleep(EVENT_GAP).await;
                                }
                                if tx.send(sse_event(index)).await.is_err() {
                                    return;
                                }
                            }
                        });
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "text/event-stream")
                            .header("cache-control", "no-store")
                            .body(handler_body(rx))
                            .map_err(|_| HttpHandlerError)
                    }
                    "/stall" => {
                        // Never answers.  The bridge cancels the handler by
                        // dropping this future, which the guard counts.
                        struct Guard(Arc<HandlerState>);
                        impl Drop for Guard {
                            fn drop(&mut self) {
                                self.0.stall_cancellations.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        let _guard = Guard(Arc::clone(&state));
                        std::future::pending::<()>().await;
                        Err(HttpHandlerError)
                    }
                    "/late" => {
                        sleep(OPERATION_TIMEOUT * 2).await;
                        state.late_answers.fetch_add(1, Ordering::SeqCst);
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(full_body(b"late-unary-answer"))
                            .map_err(|_| HttpHandlerError)
                    }
                    _ => Err(HttpHandlerError),
                }
            })
        },
    )
}

/// Run the gate on a fresh harness and production cluster.
///
/// # Errors
/// Any setup, scenario, validation or cleanup failure.
pub async fn verify() -> Result<HttpForwardLongLivedEvidence> {
    let options = HarnessOptions::from_env()?.http_forward_service(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout(format!("{GATE}: harness startup timed out")))??;
    let setup = profile().and_then(|profile| Ok((profile, bridge_config()?)));
    let (profile, config) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let exports = match HttpForwardExports::new().with_profile(
        crate::FIXTURE_HTTP_FORWARD_PROFILE,
        HttpForwardExport::new(Arc::clone(&profile), config),
    ) {
        Ok(exports) => exports,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::InvalidInput(error.to_owned()));
        }
    };
    harness.http_forward = Some(exports);
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, profile, config),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            if let Err(error) = validate_http_forward_long_lived_evidence(&evidence) {
                eprintln!("{GATE} evidence (failed validation): {evidence:?}");
                return Err(error);
            }
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(format!(
            "{GATE}: scenario exceeded its bounded deadline"
        ))),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    profile: Arc<Profile>,
    config: BridgeConfig,
) -> Result<HttpForwardLongLivedEvidence> {
    let mut evidence = HttpForwardLongLivedEvidence {
        connector_operation_timeout_ms: OPERATION_TIMEOUT.as_millis(),
        relay_operation_timeout_ms: tunnel_relay::RelayLimits::default()
            .operation_timeout
            .as_millis(),
        bridge_deadline_ms: config.deadline().as_millis(),
        sse_events_expected: SSE_EVENT_COUNT,
        ..HttpForwardLongLivedEvidence::default()
    };
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("http-forward device is missing".into()))?;
    let echo_service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("http-forward echo service missing".into()))?;
    let http_service = harness
        .http_forward_service
        .ok_or_else(|| HarnessError::InvalidInput("http-forward service was not seeded".into()))?;
    let owner_device_addr = cluster
        .relay("relay-a")?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| HarnessError::Process("relay-a is not running".into()))?;
    let directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut device_profile = write_device_profile(
        directory.path(),
        device.id,
        echo_service,
        "m4-71-long-lived-canary",
        owner_device_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    device_profile.config.limits.operation_timeout_ms =
        u64::try_from(OPERATION_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    device_profile.config.exports.insert(
        http_service.to_string(),
        LocalExport {
            kind: LocalExportKind::HttpForward,
            device_canary: None,
            mcp: None,
            acp: None,
            cua: None,
            fs: None,
        },
    );
    device_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("device config: {error}")))?;
    let state = Arc::new(HandlerState::default());
    let handlers = HttpHandlers::new().with_export(
        http_service.to_string(),
        HttpExport {
            profile,
            config,
            handler: handler(Arc::clone(&state)),
        },
    );
    let device_diagnostics = handlers.diagnostics();
    let mut client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect_with_http_handlers(
            ConnectOptions::new(device_profile.config.clone()),
            handlers,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{GATE}: device startup timed out")))?
    .map_err(|error| HarnessError::Process(format!("{GATE}: device: {error}")))?;
    let scenario = async {
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout(format!("{GATE}: device readiness timed out")))?
            .map_err(|error| HarnessError::Process(format!("device not ready: {error}")))?;
        exercise(
            cluster,
            harness,
            &state,
            &device_diagnostics,
            &client,
            (device.tenant_id, device.id, http_service),
            &session.session_id,
            &mut evidence,
        )
        .await
    }
    .await;
    let stop = timeout(CLEANUP_TIMEOUT, client.stop()).await;
    if scenario.is_err() {
        eprintln!("{GATE} partial evidence: {evidence:?}");
    }
    scenario?;
    match stop {
        Ok(Ok(())) => Ok(evidence),
        Ok(Err(error)) => Err(HarnessError::Process(format!("device stop: {error}"))),
        Err(_) => Err(HarnessError::Timeout("device stop timed out".into())),
    }
}

/// One consumer exchange's observations.
struct Answer {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    ended_cleanly: bool,
    elapsed: Duration,
    retries: usize,
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    state: &Arc<HandlerState>,
    device_diagnostics: &tunnel_client::http_forward::DeviceHttpDiagnostics,
    client: &tunnel_client::ConnectionHandle,
    (tenant_id, device_id, service_id): (uuid::Uuid, uuid::Uuid, uuid::Uuid),
    session_id: &str,
    evidence: &mut HttpForwardLongLivedEvidence,
) -> Result<()> {
    let owner = {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            let owner = cluster
                .catalog
                .current_owner(tenant_id, device_id, chrono::Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?;
            if let Some(owner) = owner
                && owner.token.session_id == session_id
            {
                break owner;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "{GATE}: device owner claim not observed"
                )));
            }
            sleep(Duration::from_millis(50)).await;
        }
    };
    evidence.owner_node = owner.token.node_id.clone();
    let ingress = cluster.relay("relay-c")?;
    evidence.ingress_node = ingress.node_id.clone();
    evidence.non_owner_ingress = owner.token.node_id == "relay-a" && ingress.node_id == "relay-c";
    let ingress_addr = ingress.consumer_addr()?;
    let ca = harness.pki.server_ca.certificate_der.clone();
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            scope: Some("echo:invoke http:invoke".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    let base = format!("/v1/devices/{device_id}/services/{service_id}/http");

    // The fixture's membership records live 60 s and a re-sign invalidates
    // in-flight peer hops, so re-sign once, with nothing in flight, before
    // the long case: it then has a whole record lifetime to run in.
    cluster.resign_membership_now().await?;
    wait_peers_ready(cluster).await?;

    // `sse`
    evidence.expired_streams_before_sse = client.status_snapshot().stream_auth.expired_streams;
    let before = device_diagnostics.snapshot().len();
    let sse = send(
        ingress_addr,
        &ca,
        "GET",
        &format!("{base}/sse"),
        &token,
        &[("accept", "text/event-stream")],
    )
    .await?;
    evidence.sse_status = sse.status;
    evidence.sse_content_type = sse.content_type;
    let expected = sse_bytes();
    evidence.sse_bytes_expected = expected.len();
    evidence.sse_bytes_received = sse.body.len();
    evidence.sse_byte_exact = sse.body == expected;
    evidence.sse_ended_cleanly = sse.ended_cleanly;
    evidence.sse_duration_ms = sse.elapsed.as_millis();
    evidence.sse_retries = sse.retries;
    let record = wait_for_device_record(device_diagnostics, before).await?;
    if let Some(report) = record.report {
        evidence.sse_device_response = Some(format!("{:?}", report.response));
        evidence.sse_device_error = report.error.map(|code| format!("{code:?}"));
        if report.response != Outcome::Complete {
            eprintln!("{GATE}: sse device report {report:?}");
        }
    }
    evidence.expired_streams_after_sse = client.status_snapshot().stream_auth.expired_streams;

    // The long case used most of the records' 60 s; re-sign again, with
    // nothing in flight, so the short cases cannot straddle their expiry.
    cluster.resign_membership_now().await?;
    wait_peers_ready(cluster).await?;

    // `no-head`
    let no_head = send(
        ingress_addr,
        &ca,
        "POST",
        &format!("{base}/stall"),
        &token,
        &[],
    )
    .await?;
    evidence.no_head_status = no_head.status;
    evidence.no_head_code = error_code(&no_head.body);
    evidence.no_head_elapsed_ms = no_head.elapsed.as_millis();
    evidence.no_head_retries = no_head.retries;
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.stall_cancellations.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
    }
    evidence.no_head_handler_cancelled = state.stall_cancellations.load(Ordering::SeqCst) > 0;

    // `late-unary`, the control.
    let late = send(
        ingress_addr,
        &ca,
        "POST",
        &format!("{base}/late"),
        &token,
        &[],
    )
    .await?;
    evidence.late_unary_status = late.status;
    evidence.late_unary_code = error_code(&late.body);
    evidence.late_unary_elapsed_ms = late.elapsed.as_millis();
    evidence.late_unary_retries = late.retries;
    evidence.late_unary_answer_seen = late
        .body
        .windows(b"late-unary-answer".len())
        .any(|window| window == b"late-unary-answer");
    Ok(())
}

async fn wait_peers_ready(cluster: &ProductionCluster) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if cluster
            .relays
            .iter()
            .filter(|relay| relay.running.is_some())
            .all(|relay| relay.peer_runtime.is_ready())
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "{GATE}: peer readiness did not return after the membership re-sign"
            )));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_device_record(
    diagnostics: &tunnel_client::http_forward::DeviceHttpDiagnostics,
    before: usize,
) -> Result<tunnel_client::http_forward::DeviceHttpExchangeRecord> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let records = diagnostics.snapshot();
        if records.len() > before
            && let Some(record) = records.last()
        {
            return Ok(record.clone());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "{GATE}: the device never recorded the exchange"
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// The closed `code` of a gateway error body, or empty.
fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// Send one request on a fresh consumer connection and read its whole
/// answer, timing it from the request's send.  A `503` whose body proves
/// `not_dispatched` is retried a bounded number of times: it reached no
/// handler, so a resend cannot duplicate anything.
async fn send(
    addr: std::net::SocketAddr,
    ca: &[u8],
    method: &str,
    uri: &str,
    token: &str,
    extra: &[(&str, &str)],
) -> Result<Answer> {
    let mut retries = 0;
    loop {
        let (mut sender, connection) = connect_consumer(addr, ca).await?;
        let started = Instant::now();
        let response = timeout(
            BRIDGE_DEADLINE,
            sender.send_request(request(method, uri, Some(token), extra, empty_stream())?),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!("{GATE}: {uri}: no response head")))?
        .map_err(|error| HarnessError::Http(format!("{GATE}: {uri}: {}", error_chain(&error))))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        let mut ended_cleanly = false;
        loop {
            match timeout(BRIDGE_DEADLINE, body.frame()).await {
                Err(_) => break,
                Ok(None) => {
                    ended_cleanly = true;
                    break;
                }
                Ok(Some(Err(error))) => {
                    eprintln!("{GATE}: {uri}: body error: {}", error_chain(&error));
                    break;
                }
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        bytes.extend_from_slice(&data);
                    }
                }
            }
        }
        let elapsed = started.elapsed();
        connection.abort();
        let not_dispatched = status == 503
            && serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/error/execution")
                        .and_then(serde_json::Value::as_str)
                        .map(|execution| execution == "not_dispatched")
                })
                .unwrap_or(false);
        if not_dispatched && retries < NOT_DISPATCHED_RETRIES {
            retries += 1;
            sleep(Duration::from_millis(500)).await;
            continue;
        }
        return Ok(Answer {
            status,
            content_type,
            body: bytes,
            ended_cleanly,
            elapsed,
            retries,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Mutation = fn(&mut HttpForwardLongLivedEvidence);

    fn passing() -> HttpForwardLongLivedEvidence {
        let expected = sse_bytes().len();
        HttpForwardLongLivedEvidence {
            owner_node: "relay-a".into(),
            ingress_node: "relay-c".into(),
            non_owner_ingress: true,
            connector_operation_timeout_ms: OPERATION_TIMEOUT.as_millis(),
            relay_operation_timeout_ms: 30_000,
            bridge_deadline_ms: BRIDGE_DEADLINE.as_millis(),
            sse_status: 200,
            sse_content_type: "text/event-stream".into(),
            sse_events_expected: SSE_EVENT_COUNT,
            sse_bytes_expected: expected,
            sse_bytes_received: expected,
            sse_byte_exact: true,
            sse_ended_cleanly: true,
            sse_duration_ms: 33_100,
            sse_retries: 0,
            sse_device_response: Some("Complete".into()),
            sse_device_error: None,
            expired_streams_before_sse: 0,
            expired_streams_after_sse: 0,
            no_head_status: 504,
            no_head_code: "HTTP_DEADLINE_EXCEEDED".into(),
            no_head_elapsed_ms: 2_050,
            no_head_retries: 0,
            no_head_handler_cancelled: true,
            late_unary_status: 504,
            late_unary_code: "HTTP_DEADLINE_EXCEEDED".into(),
            late_unary_elapsed_ms: 2_040,
            late_unary_retries: 0,
            late_unary_answer_seen: false,
        }
    }

    /// The SSE stream lasts longer than both the connector's timeout and the
    /// relay's default operation timeout.
    #[test]
    fn the_stream_outlives_both_timeouts_by_construction() {
        let stream = EVENT_GAP * u32::try_from(SSE_EVENT_COUNT - 1).unwrap_or(u32::MAX);
        assert!(EVENT_GAP > OPERATION_TIMEOUT);
        assert!(stream > tunnel_relay::RelayLimits::default().operation_timeout);
        assert!(stream + HEAD_TIMEOUT_SLACK < BRIDGE_DEADLINE);
        assert!(OPERATION_TIMEOUT + HEAD_TIMEOUT_SLACK < BRIDGE_DEADLINE);
    }

    #[test]
    fn passing_evidence_validates() {
        validate_http_forward_long_lived_evidence(&passing()).unwrap();
    }

    /// Each rule rejects the evidence of the defect it guards.
    #[test]
    fn each_rule_rejects_its_defect() {
        let cases: [(&str, Mutation); 10] = [
            // The pre-M4-71 shape: the connector reset the stream at its
            // timeout, so the body errored after about 2 s.
            ("sse_ended_cleanly", |e| {
                e.sse_ended_cleanly = false;
                e.sse_duration_ms = 2_100;
            }),
            ("sse_byte_exact", |e| e.sse_byte_exact = false),
            ("sse_outlived_both_timeouts", |e| e.sse_duration_ms = 20_000),
            ("sse_device_complete", |e| {
                e.sse_device_response = Some("Aborted".into());
            }),
            ("sse_no_expired_stream", |e| e.expired_streams_after_sse = 1),
            // The head bound lost: the bridge's absolute deadline answered.
            ("no_head_at_the_timeout", |e| e.no_head_elapsed_ms = 120_000),
            ("no_head_code", |e| {
                e.no_head_code = "HTTP_STREAM_INTERRUPTED".into()
            }),
            ("no_head_handler_cancelled", |e| {
                e.no_head_handler_cancelled = false;
            }),
            ("late_unary_answer_hidden", |e| {
                e.late_unary_answer_seen = true
            }),
            ("late_unary_status", |e| e.late_unary_status = 200),
        ];
        for (rule, mutate) in cases {
            let mut evidence = passing();
            mutate(&mut evidence);
            let error = validate_http_forward_long_lived_evidence(&evidence)
                .expect_err(rule)
                .to_string();
            assert!(
                error.contains(&format!("rule {rule} failed")),
                "{rule}: {error}"
            );
        }
    }
}
