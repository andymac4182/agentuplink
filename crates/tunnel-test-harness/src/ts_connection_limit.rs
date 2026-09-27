//! M6-C200: the shared TypeScript client against a real relay listener at its
//! connection limit.
//!
//! The listener is the relay's own accept path,
//! [`tunnel_transport::serve_with_listener_options`] (what `tunnel-relay` runs
//! for its public listeners), with a one-connection limit, a real TLS
//! certificate and the default refusal margin.  One Rust TLS connection is
//! served and held, so the next connection is over the limit.  `node` then runs
//! `packages/client/e2e/connection-limit.ts`, which drives the package's own
//! `fetchDescriptor` and `upgrade` at the listener and prints what the client
//! reported: the code must be `CONNECTION_LIMIT` with `retryAfterMs` equal to
//! the listener's hint ([`tunnel_transport::CONNECTION_LIMIT_RETRY_AFTER_MS`]),
//! at both stages.
//!
//! The control then releases the held connection and runs the same driver at
//! the same URL with the same trust: the router must answer (its fixed
//! `EXPORT_NOT_FOUND`), which is what shows the first run's refusal came from
//! the limit and not from TLS, the URL or the driver.  The harness waits the
//! reported `retryAfterMs` before the control, as a retrying caller must.
//!
//! Nothing here reads a payload: the driver's report is closed codes and
//! integers, and its stderr is inherited.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use axum::{Router, http::StatusCode, response::IntoResponse};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    AcceptedSocketOptions, CONNECTION_LIMIT_RETRY_AFTER_MS, ListenerCapacity, ListenerTimeouts,
    serve_with_listener_options,
};

use crate::HarnessError;

const SERVER_NAME: &str = "localhost";
const HELD_BODY: &str = "m6-c200-held";
const ROUTER_NOT_FOUND_BODY: &str = r#"{"error":{"code":"EXPORT_NOT_FOUND","message":"m6-c200 fixture router","requestId":"m6-c200"}}"#;
const DRIVER_DEADLINE: Duration = Duration::from_secs(60);

/// What the client reported at one stage.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageReport {
    pub code: String,
    pub retry_after_ms: Option<u64>,
    pub retryable: bool,
    pub outcome: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DriverReport {
    event: String,
    mode: String,
    client_module: PathBuf,
    descriptor: StageReport,
    upgrade: Option<StageReport>,
}

/// The evidence the command validates and prints.
#[derive(Clone, Debug)]
pub struct TsConnectionLimitEvidence {
    pub listener_max_connections: usize,
    pub held_connection_served: bool,
    pub client_module_is_the_package: bool,
    pub descriptor: StageReport,
    pub upgrade: StageReport,
    pub waited_ms: u64,
    pub control_descriptor: StageReport,
}

/// Run the gate.
pub async fn verify_ts_connection_limit() -> Result<TsConnectionLimitEvidence, HarnessError> {
    let root = repository_root();
    let driver = root.join("packages/client/e2e/connection-limit.ts");
    if !driver.is_file() {
        return Err(HarnessError::InvalidInput(
            "the M6-C200 driver is not where this gate expects it".into(),
        ));
    }
    let scratch = tempfile::tempdir().map_err(HarnessError::Io)?;

    let key = KeyPair::generate().map_err(|error| HarnessError::Pki(error.to_string()))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "M6-C200 listener fixture");
    params.subject_alt_names.push(SanType::DnsName(
        SERVER_NAME
            .try_into()
            .map_err(|error: rcgen::Error| HarnessError::Pki(error.to_string()))?,
    ));
    let certificate = params
        .self_signed(&key)
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let certificate_pem = certificate.pem();
    let ca_path = scratch.path().join("m6-c200-ca.pem");
    std::fs::write(&ca_path, &certificate_pem).map_err(HarnessError::Io)?;
    let server_config = tunnel_transport::load_server_config_from_pem(
        certificate_pem.as_bytes(),
        key.serialize_pem().as_bytes(),
        None,
    )
    .map_err(|error| HarnessError::Pki(format!("listener TLS: {error}")))?;
    let roots = tunnel_transport::require_root_certificates(certificate_pem.as_bytes())
        .map_err(|error| HarnessError::Pki(format!("fixture roots: {error}")))?;
    let mut client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Pki(error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client_config = Arc::new(client_config);

    // `/hold` serves the connection that fills the limit; every other request
    // the router sees gets the contract's JSON 404, the control's answer.
    let router = Router::new()
        .route("/hold", axum::routing::get(|| async { HELD_BODY }))
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                ROUTER_NOT_FOUND_BODY,
            )
                .into_response()
        });
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(HarnessError::Io)?;
    let address = listener.local_addr().map_err(HarnessError::Io)?;
    let listener_max_connections = 1;
    let options = AcceptedSocketOptions {
        listener: Some("consumer"),
        capacity: ListenerCapacity {
            max_connections: listener_max_connections,
            ..ListenerCapacity::default()
        },
        ..AcceptedSocketOptions::default()
    };
    let timeouts = ListenerTimeouts {
        handshake_timeout: Duration::from_secs(10),
        pre_request_timeout: Duration::from_secs(60),
        http1_header_read_timeout: Duration::from_secs(60),
    };
    let cancel = CancellationToken::new();
    let server = tokio::spawn(serve_with_listener_options(
        listener,
        router,
        server_config,
        cancel.clone(),
        options,
        timeouts,
    ));

    let result = async {
        let mut held = hold_one(address, client_config.clone()).await?;
        let endpoint = format!(
            "https://{SERVER_NAME}:{}/v1/devices/m6-c200/services/fs/fs",
            address.port()
        );
        let limited = run_driver(&driver, &ca_path, &endpoint, "limit").await?;
        let upgrade = limited.upgrade.clone().ok_or_else(|| {
            HarnessError::Process("the limit run reported no upgrade stage".into())
        })?;

        // Release the permit, then retry as a caller must: after the hint.
        held.shutdown().await.ok();
        drop(held);
        let waited_ms = limited
            .descriptor
            .retry_after_ms
            .unwrap_or(CONNECTION_LIMIT_RETRY_AFTER_MS);
        tokio::time::sleep(Duration::from_millis(waited_ms)).await;
        let control = run_driver(&driver, &ca_path, &endpoint, "control").await?;
        let package = root.join("packages/client/src/index.ts");
        Ok::<_, HarnessError>(TsConnectionLimitEvidence {
            listener_max_connections,
            held_connection_served: true,
            client_module_is_the_package: same_file(&limited.client_module, &package)
                && same_file(&control.client_module, &package),
            descriptor: limited.descriptor,
            upgrade,
            waited_ms,
            control_descriptor: control.descriptor,
        })
    }
    .await;

    cancel.cancel();
    let joined = timeout(Duration::from_secs(10), server)
        .await
        .map_err(|_| HarnessError::Timeout("the fixture listener did not stop".into()))?;
    let evidence = result?;
    joined
        .map_err(|error| HarnessError::Process(format!("fixture listener task: {error}")))?
        .map_err(|error| HarnessError::Process(format!("fixture listener: {error}")))?;
    validate_ts_connection_limit(&evidence)?;
    Ok(evidence)
}

/// Every claim the command prints, checked.
pub fn validate_ts_connection_limit(
    evidence: &TsConnectionLimitEvidence,
) -> Result<(), HarnessError> {
    let fail = |message: String| Err(HarnessError::Process(message));
    if evidence.listener_max_connections != 1 || !evidence.held_connection_served {
        return fail("the listener was not filled by one served connection".into());
    }
    if !evidence.client_module_is_the_package {
        return fail("the driver did not run this package's own client".into());
    }
    let expected = StageReport {
        code: "CONNECTION_LIMIT".into(),
        retry_after_ms: Some(CONNECTION_LIMIT_RETRY_AFTER_MS),
        retryable: true,
        outcome: "not_started".into(),
    };
    for (stage, report) in [
        ("descriptor", &evidence.descriptor),
        ("upgrade", &evidence.upgrade),
    ] {
        if report != &expected {
            return fail(format!(
                "the client reported the over-limit {stage} as code={} retry_after_ms={:?} retryable={} outcome={}",
                report.code, report.retry_after_ms, report.retryable, report.outcome
            ));
        }
    }
    if evidence.waited_ms < CONNECTION_LIMIT_RETRY_AFTER_MS {
        return fail("the control did not wait for the retry hint".into());
    }
    let control = &evidence.control_descriptor;
    if control.code != "EXPORT_NOT_FOUND" || control.retry_after_ms.is_some() {
        return fail(format!(
            "the control under the limit did not reach the router: code={} retry_after_ms={:?}",
            control.code, control.retry_after_ms
        ));
    }
    Ok(())
}

/// Open one TLS connection, complete one request on it and keep it open, so
/// it holds the listener's only permit.
async fn hold_one(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> Result<TlsStream<TcpStream>, HarnessError> {
    let tcp = TcpStream::connect(address)
        .await
        .map_err(HarnessError::Io)?;
    let name = SERVER_NAME
        .try_into()
        .map_err(|_| HarnessError::InvalidInput("fixture server name".into()))?;
    let mut stream = timeout(
        Duration::from_secs(10),
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    .map_err(|_| HarnessError::Timeout("the held connection's TLS handshake".into()))?
    .map_err(HarnessError::Io)?;
    let request =
        format!("GET /hold HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: keep-alive\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(HarnessError::Io)?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let served = timeout(Duration::from_secs(10), async {
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok::<_, std::io::Error>(false);
            }
            buffer.extend_from_slice(&chunk[..read]);
            if String::from_utf8_lossy(&buffer).contains(HELD_BODY) {
                return Ok(true);
            }
        }
    })
    .await
    .map_err(|_| HarnessError::Timeout("the held connection was not served".into()))?
    .map_err(HarnessError::Io)?;
    if !served {
        return Err(HarnessError::Process(
            "the held connection closed before it was served".into(),
        ));
    }
    Ok(stream)
}

async fn run_driver(
    driver: &Path,
    ca_path: &Path,
    endpoint: &str,
    mode: &str,
) -> Result<DriverReport, HarnessError> {
    let child = tokio::process::Command::new("node")
        .arg(driver)
        .arg(endpoint)
        .arg(mode)
        .env("NODE_EXTRA_CA_CERTS", ca_path)
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_TLS_REJECT_UNAUTHORIZED")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| HarnessError::Process(format!("spawning the M6-C200 driver: {error}")))?;
    let output = timeout(DRIVER_DEADLINE, child.wait_with_output())
        .await
        .map_err(|_| HarnessError::Timeout("the M6-C200 driver did not finish".into()))?
        .map_err(HarnessError::Io)?;
    if !output.status.success() {
        return Err(HarnessError::Process(format!(
            "the M6-C200 driver exited with {:?}",
            output.status.code()
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| HarnessError::Process("the M6-C200 driver wrote non-UTF-8".into()))?;
    let mut lines = stdout.lines().filter(|line| !line.trim().is_empty());
    let line = lines
        .next()
        .ok_or_else(|| HarnessError::Process("the M6-C200 driver printed no report".into()))?;
    if lines.next().is_some() {
        return Err(HarnessError::Process(
            "the M6-C200 driver printed more than one line".into(),
        ));
    }
    let report: DriverReport = serde_json::from_str(line).map_err(HarnessError::Json)?;
    if report.event != "report" || report.mode != mode {
        return Err(HarnessError::Process(
            "the M6-C200 driver's report is not for this mode".into(),
        ));
    }
    if (mode == "limit") != report.upgrade.is_some() {
        return Err(HarnessError::Process(
            "the M6-C200 driver's upgrade stage does not match its mode".into(),
        ));
    }
    Ok(report)
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// The repository root, from this crate's own manifest directory.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing() -> TsConnectionLimitEvidence {
        let limit = StageReport {
            code: "CONNECTION_LIMIT".into(),
            retry_after_ms: Some(CONNECTION_LIMIT_RETRY_AFTER_MS),
            retryable: true,
            outcome: "not_started".into(),
        };
        TsConnectionLimitEvidence {
            listener_max_connections: 1,
            held_connection_served: true,
            client_module_is_the_package: true,
            descriptor: limit.clone(),
            upgrade: limit,
            waited_ms: CONNECTION_LIMIT_RETRY_AFTER_MS,
            control_descriptor: StageReport {
                code: "EXPORT_NOT_FOUND".into(),
                retry_after_ms: None,
                retryable: false,
                outcome: "not_started".into(),
            },
        }
    }

    /// The validator refuses each way the pre-fix client (or a broken run)
    /// could have looked, so a pass is not a validator that cannot fail.
    #[test]
    fn m6c200_validator_refuses_the_pre_fix_client_and_broken_runs() {
        assert!(validate_ts_connection_limit(&passing()).is_ok());

        let mut pre_fix = passing();
        pre_fix.descriptor.code = "BACKEND_UNAVAILABLE".into();
        pre_fix.descriptor.retry_after_ms = None;
        assert!(validate_ts_connection_limit(&pre_fix).is_err());

        let mut no_hint_at_upgrade = passing();
        no_hint_at_upgrade.upgrade.retry_after_ms = None;
        assert!(validate_ts_connection_limit(&no_hint_at_upgrade).is_err());

        let mut tls_refused = passing();
        tls_refused.control_descriptor.code = "INSECURE_ENDPOINT".into();
        assert!(validate_ts_connection_limit(&tls_refused).is_err());

        let mut other_module = passing();
        other_module.client_module_is_the_package = false;
        assert!(validate_ts_connection_limit(&other_module).is_err());

        let mut impatient = passing();
        impatient.waited_ms = 0;
        assert!(validate_ts_connection_limit(&impatient).is_err());
    }
}
