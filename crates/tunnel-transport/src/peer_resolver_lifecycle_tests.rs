//! C246: deterministic wire evidence for unresolved request termination.
//! These fixtures do not attribute the historical hosted cleanup failure.

use super::*;
use crate::{load_peer_client_config_from_pem, load_peer_server_config_from_pem};
use h3::quic::SendStream as _;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use std::{future::Future, task::Poll};
use tokio::sync::Notify;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const BOUND: Duration = Duration::from_secs(5);
const BODY: &[u8] = b"c246-admitted-sibling";

fn limits() -> PeerTransportLimits {
    PeerTransportLimits {
        handshake_timeout: BOUND,
        stream_timeout: BOUND,
        idle_timeout: BOUND,
        drain_timeout: Duration::from_secs(1),
        ..Default::default()
    }
}

struct Endpoints {
    server: quinn::Endpoint,
    client: PeerClient,
    destination: PeerDestination,
    pins: SharedPeerPins,
}

fn endpoints(server_limits: &PeerTransportLimits) -> TestResult<Endpoints> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&ca_key)?;
    let issue = |node: &str| -> TestResult<(String, String, crate::SpkiSha256)> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec!["localhost".into()])?;
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node}").try_into()?,
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&key, &ca, &ca_key)?;
        Ok((
            format!("{}{}", cert.pem(), ca.pem()),
            key.serialize_pem(),
            crate::spki_sha256_from_der(cert.der())?,
        ))
    };
    let (server_chain, server_key, server_pin) = issue("c246-server")?;
    let (client_chain, client_key, client_pin) = issue("c246-client")?;
    let mut server_config = load_peer_server_config_from_pem(
        server_chain.as_bytes(),
        server_key.as_bytes(),
        ca.pem().as_bytes(),
    )?;
    server_limits.apply_to_server_config(&mut server_config)?;
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let destination = PeerDestination::new(server.local_addr()?, "localhost");
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(load_peer_client_config_from_pem(
        client_chain.as_bytes(),
        client_key.as_bytes(),
        ca.pem().as_bytes(),
    )?);
    let client = PeerClient::new(
        client_endpoint,
        ApprovedPeerPins::new([server_pin])?,
        limits(),
    )?;
    Ok(Endpoints {
        server,
        client,
        destination,
        pins: SharedPeerPins::new(ApprovedPeerPins::new([client_pin])?)?,
    })
}

fn request(path: &str) -> Request<()> {
    Request::builder()
        .uri(format!("https://localhost/{path}"))
        .body(())
        .expect("fixture request")
}

async fn sibling_body(stream: &mut PeerClientStream) -> TestResult {
    let body = timeout(BOUND, stream.recv_chunk()).await??;
    if body.as_ref().map(PeerBodyChunk::as_bytes) != Some(BODY) {
        return Err("sibling body changed or was absent".into());
    }
    drop(body);
    if timeout(BOUND, stream.recv_chunk()).await??.is_some() {
        return Err("sibling response had an extra chunk".into());
    }
    Ok(())
}

#[derive(Debug)]
struct Observation {
    target_rejected: bool,
    target_responded: bool,
    target_protocol_error: bool,
    target_error: Option<String>,
    sibling_completed: bool,
    sibling_error: Option<String>,
    connection_close_before_cleanup: Option<String>,
    policy_calls: usize,
    client_cleanup: Option<String>,
    server_cleanup: Option<String>,
}

async fn join_server(mut task: tokio::task::JoinHandle<TestResult>) -> TestResult {
    match timeout(BOUND, &mut task).await {
        Ok(result) => result?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("server cleanup exceeded its bound".into())
        }
    }
}

// The raw listener supplies the real resolver to the actual production
// handle_incoming_stream branch. Only the explicit reset control substitutes
// a wire action; the fixture does not send GOAWAY or close the connection in
// place of testing that one unresolved-stream cancellation edge.
#[derive(Clone, Copy)]
enum ResolverCase {
    PreCancelled,
    PendingHeaders,
    ResetControl,
    Malformed,
}

async fn planned_resolver_case(case: ResolverCase, prove_drain: bool) -> TestResult<Observation> {
    let Endpoints {
        server,
        client,
        destination,
        pins,
    } = endpoints(&limits())?;
    let cancel = CancellationToken::new();
    let release = Arc::new(Notify::new());
    let begin_drain = Arc::new(Notify::new());
    let drain_complete = Arc::new(Notify::new());
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let server_cancel = cancel.clone();
    let server_release = release.clone();
    let server_calls = policy_calls.clone();
    let server_begin_drain = begin_drain.clone();
    let server_drain_complete = drain_complete.clone();
    let server_task = tokio::spawn(async move {
        let incoming = timeout(BOUND, server.accept())
            .await?
            .ok_or("no connection")?;
        let connection = timeout(BOUND, incoming).await??;
        let identity = verified_peer_identity(&connection).map_err(map_probe_error)?;
        pins.snapshot().verify(&identity).map_err(map_probe_error)?;
        let mut h3_connection = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await?;
        let policy = Arc::new(move |_: &TlsIdentity, _: &Request<()>| {
            server_calls.fetch_add(1, Ordering::AcqRel);
            true
        });
        let handler = Arc::new(
            move |_: TlsIdentity, _: Request<()>, mut stream: PeerServerStream| {
                let release = server_release.clone();
                async move {
                    stream.send_response(Response::new(())).await?;
                    release.notified().await;
                    stream.send_chunk(Bytes::from_static(BODY)).await?;
                    stream.finish().await
                }
            },
        );
        let permits = Arc::new(Semaphore::new(2));
        let bytes = Arc::new(AtomicUsize::new(0));
        let first = timeout(BOUND, h3_connection.accept())
            .await??
            .ok_or("no sibling")?;
        let mut tasks = JoinSet::new();
        tasks.spawn(handle_incoming_stream(
            first,
            identity.clone(),
            pins.clone(),
            policy.clone(),
            handler.clone(),
            limits(),
            bytes.clone(),
            permits.clone().acquire_owned().await?,
            None,
            server_cancel.child_token(),
            PlannedDrainSignal::new(),
        ));
        let mut target = timeout(BOUND, h3_connection.accept())
            .await??
            .ok_or("no target")?;
        if matches!(case, ResolverCase::ResetControl) {
            // Positive wire control: no response headers, but an intentional
            // request-scoped reset cannot become an empty successful FIN.
            target
                .frame_stream
                .reset(h3::error::Code::H3_REQUEST_REJECTED.value());
            drop(target);
        } else {
            let planned = PlannedDrainSignal::new();
            if matches!(case, ResolverCase::PreCancelled) {
                planned.close_admission();
                planned.token.cancel();
            }
            let mut resolving = Box::pin(handle_incoming_stream(
                target,
                identity,
                pins,
                policy,
                handler,
                limits(),
                bytes,
                permits.acquire_owned().await?,
                None,
                server_cancel.child_token(),
                planned.clone(),
            ));
            if matches!(case, ResolverCase::PendingHeaders) {
                // The raw client writes only the HEADERS frame type. There
                // is no frame length yet, so the actual resolve future must
                // enter Pending before the planned cancellation is issued.
                std::future::poll_fn(|cx| match resolving.as_mut().poll(cx) {
                    Poll::Pending => Poll::Ready(Ok(())),
                    Poll::Ready(result) => Poll::Ready(Err(format!(
                        "header-resolution barrier was not pending: {result:?}"
                    ))),
                })
                .await?;
                planned.close_admission();
                planned.token.cancel();
            }
            resolving.await?;
        }
        let transport_result = loop {
            tokio::select! {
                _ = server_cancel.cancelled() => break Ok(()),
                _ = server_begin_drain.notified() => {
                    timeout(BOUND, h3_connection.shutdown(0)).await??;
                },
                result = h3_connection.accept() => match result {
                    Ok(Some(_)) => break Err("unexpected third request".into()),
                    Ok(None) => {
                        server_drain_complete.notify_one();
                        break Ok(())
                    },
                    Err(error) if error.is_h3_no_error() || error.is_remote_no_error_application_close() => break Ok(()),
                    Err(error) => break Err(Box::new(error) as Box<dyn std::error::Error + Send + Sync>),
                },
            }
        };
        server_cancel.cancel();
        let joined = timeout(BOUND, tasks.join_next()).await?;
        if let Some(result) = joined {
            result??;
        }
        connection.close(quinn::VarInt::from_u32(0), b"c246 fixture cleanup");
        server.close(quinn::VarInt::from_u32(0), b"c246 fixture cleanup");
        transport_result
    });
    let scenario = async {
        let connection = client.connect(destination).await?;
        let mut sibling = connection.open(request("sibling")).await?;
        sibling.finish().await?;
        if timeout(BOUND, sibling.recv_response()).await??.status() != http::StatusCode::OK {
            return Err("sibling response was not admitted".into());
        }
        let (target_rejected, target_responded, target_protocol_error, target_error) =
            if matches!(case, ResolverCase::PendingHeaders | ResolverCase::Malformed) {
                let (mut send, mut recv) = timeout(BOUND, connection.inner.connection.open_bi()).await??;
                let bytes: &[u8] = if matches!(case, ResolverCase::Malformed) {
                    &[0, 0] // DATA before HEADERS is a genuine H3_FRAME_UNEXPECTED.
                } else {
                    &[1] // HEADERS type only: the frame length is still pending.
                };
                timeout(BOUND, send.write_all(bytes)).await??;
                let result = timeout(BOUND, recv.read(&mut [0; 1])).await?;
                let rejected = matches!(&result, Err(quinn::ReadError::Reset(code)) if code.into_inner() == h3::error::Code::H3_REQUEST_REJECTED.value());
                let protocol_error = matches!(&result, Err(quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(close))) if close.error_code.into_inner() == h3::error::Code::H3_FRAME_UNEXPECTED.value());
                (rejected, false, protocol_error, Some(format!("{result:?}")))
            } else {
                let mut target = connection.open(request("unresolved")).await?;
                target.finish().await?;
                let result = timeout(BOUND, target.recv_response()).await?;
                (matches!(&result, Err(PeerTransportError::GoAway)), result.is_ok(), false, result.err().map(|error| error.to_string()))
            };
        release.notify_one();
        let sibling_result = sibling_body(&mut sibling).await;
        let observation = Observation {
            target_rejected,
            target_responded,
            target_protocol_error,
            target_error,
            sibling_completed: sibling_result.is_ok(),
            sibling_error: sibling_result.err().map(|error| error.to_string()),
            connection_close_before_cleanup: connection
                .inner
                .connection
                .close_reason()
                .map(|error| error.to_string()),
            policy_calls: policy_calls.load(Ordering::Acquire),
            client_cleanup: None,
            server_cleanup: None,
        };
        drop(sibling);
        if prove_drain {
            begin_drain.notify_one();
            timeout(BOUND, drain_complete.notified()).await
                .map_err(|_| "rejected resolver left ongoing request accounting charged during GOAWAY")?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observation)
    }
    .await;
    release.notify_one();
    let client_cleanup = client.shutdown().await.err().map(|error| error.to_string());
    cancel.cancel();
    let server_cleanup = join_server(server_task)
        .await
        .err()
        .map(|error| error.to_string());
    let mut observation = scenario?;
    observation.client_cleanup = client_cleanup;
    observation.server_cleanup = server_cleanup;
    Ok(observation)
}

fn assert_request_scoped(observation: Observation) {
    assert!(
        observation.target_rejected && !observation.target_responded,
        "target did not receive a scoped rejection: {:?}; {observation:?}",
        observation.target_error
    );
    assert!(
        observation.sibling_completed,
        "admitted sibling failed: {:?}; {observation:?}",
        observation.sibling_error
    );
    assert!(
        observation.connection_close_before_cleanup.is_none(),
        "request ended the connection: {observation:?}"
    );
    assert_eq!(
        observation.policy_calls, 1,
        "target reached policy: {observation:?}"
    );
    assert!(
        observation.client_cleanup.is_none() && observation.server_cleanup.is_none(),
        "cleanup failed: {observation:?}"
    );
}

#[tokio::test]
async fn m6c246_unresolved_planned_cancellation_preserves_admitted_sibling() -> TestResult {
    assert_request_scoped(planned_resolver_case(ResolverCase::PreCancelled, false).await?);
    Ok(())
}

#[tokio::test]
async fn m6c246_unresolved_reset_wire_control_preserves_admitted_sibling() -> TestResult {
    assert_request_scoped(planned_resolver_case(ResolverCase::ResetControl, false).await?);
    Ok(())
}

#[tokio::test]
async fn m6c246_cancellation_during_header_resolution_preserves_sibling() -> TestResult {
    assert_request_scoped(planned_resolver_case(ResolverCase::PendingHeaders, false).await?);
    Ok(())
}

#[tokio::test]
async fn m6c246_rejected_resolver_releases_ongoing_request_accounting() -> TestResult {
    assert_request_scoped(planned_resolver_case(ResolverCase::ResetControl, true).await?);
    Ok(())
}

#[tokio::test]
async fn m6c246_malformed_first_frame_remains_a_connection_protocol_error() -> TestResult {
    let observation = planned_resolver_case(ResolverCase::Malformed, false).await?;
    // The fixture's early server-task return can close QUIC before its H3
    // driver delivers the protocol code to the raw client. Assert the exact
    // actual server error, without inventing that wire-delivery ordering.
    assert!(observation.server_cleanup.as_deref().is_some_and(|error|
        error.contains("Local error: Application { code: H3_FRAME_UNEXPECTED, reason: \"first request frame is not headers\" }")
    ), "malformed frame was hidden (wire code observed={}): {observation:?}", observation.target_protocol_error);
    assert!(
        !observation.target_rejected && !observation.sibling_completed,
        "malformed frame was treated as scoped cancellation: {observation:?}"
    );
    Ok(())
}

// Unlike the planned fixture, this uses the complete production PeerServer.
// Finishing a response returns QUIC stream credit before the handler future
// releases its application permit. Holding that future makes the semaphore
// refusal deterministic without relaxing transport or application limits.
async fn capacity_resolver_case(hold_finished_permit: bool) -> TestResult<Observation> {
    let server_limits = PeerTransportLimits {
        max_streams_per_connection: 2,
        ..limits()
    };
    let Endpoints {
        server,
        client,
        destination,
        pins,
    } = endpoints(&server_limits)?;
    let cancel = CancellationToken::new();
    let release_first = Arc::new(Notify::new());
    let release_sibling = Arc::new(Notify::new());
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let handler_first = release_first.clone();
    let handler_sibling = release_sibling.clone();
    let handler_count = handler_calls.clone();
    let peer_server = PeerServer::new_with_pin_provider(
        server,
        pins,
        server_limits,
        |_: &TlsIdentity, _: &Request<()>| true,
        move |_: TlsIdentity, request: Request<()>, mut stream: PeerServerStream| {
            let release_first = handler_first.clone();
            let release_sibling = handler_sibling.clone();
            let calls = handler_count.clone();
            async move {
                calls.fetch_add(1, Ordering::AcqRel);
                while stream.recv_chunk().await?.is_some() {}
                stream.send_response(Response::new(())).await?;
                if request.uri().path() == "/sibling" {
                    release_sibling.notified().await;
                }
                stream.send_chunk(Bytes::from_static(BODY)).await?;
                stream.finish().await?;
                if request.uri().path() == "/finished" && hold_finished_permit {
                    release_first.notified().await;
                }
                // Keep the stream's permit alive across the explicit hold.
                drop(stream);
                Ok(())
            }
        },
    )?;
    let server_cancel = cancel.clone();
    let server_task = tokio::spawn(async move {
        peer_server.serve(server_cancel).await?;
        Ok(())
    });
    let scenario = async {
        let connection = client.connect(destination).await?;
        let mut finished = connection.open(request("finished")).await?;
        finished.finish().await?;
        if timeout(BOUND, finished.recv_response()).await??.status() != http::StatusCode::OK {
            return Err("finished response was not admitted".into());
        }
        sibling_body(&mut finished).await?;
        drop(finished);
        let mut sibling = connection.open(request("sibling")).await?;
        sibling.finish().await?;
        if timeout(BOUND, sibling.recv_response()).await??.status() != http::StatusCode::OK {
            return Err("capacity sibling response was not admitted".into());
        }
        if handler_calls.load(Ordering::Acquire) != 2 {
            return Err("capacity barrier did not retain exactly two admitted handlers".into());
        }
        let mut target = connection.open(request("over-capacity")).await?;
        target.finish().await?;
        let target_result = timeout(BOUND, target.recv_response()).await?;
        let target_responded = if target_result
            .as_ref()
            .is_ok_and(|head| head.status() == http::StatusCode::OK)
        {
            sibling_body(&mut target).await.is_ok()
        } else {
            false
        };
        release_sibling.notify_one();
        let sibling_result = sibling_body(&mut sibling).await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Observation {
            target_rejected: matches!(&target_result, Err(PeerTransportError::GoAway)),
            target_responded,
            target_protocol_error: false,
            target_error: target_result.err().map(|error| error.to_string()),
            sibling_completed: sibling_result.is_ok(),
            sibling_error: sibling_result.err().map(|error| error.to_string()),
            connection_close_before_cleanup: connection
                .inner
                .connection
                .close_reason()
                .map(|error| error.to_string()),
            policy_calls: handler_calls.load(Ordering::Acquire),
            client_cleanup: None,
            server_cleanup: None,
        })
    }
    .await;
    release_first.notify_one();
    release_sibling.notify_one();
    let client_cleanup = client.shutdown().await.err().map(|error| error.to_string());
    cancel.cancel();
    let server_cleanup = join_server(server_task)
        .await
        .err()
        .map(|error| error.to_string());
    let mut observation = scenario?;
    observation.client_cleanup = client_cleanup;
    observation.server_cleanup = server_cleanup;
    Ok(observation)
}

#[tokio::test]
async fn m6c246_unresolved_capacity_refusal_preserves_admitted_sibling() -> TestResult {
    let observation = capacity_resolver_case(true).await?;
    assert!(
        observation.target_rejected && !observation.target_responded,
        "capacity target was not rejected: {observation:?}"
    );
    assert!(
        observation.sibling_completed,
        "capacity refusal ended sibling: {observation:?}"
    );
    assert_eq!(
        observation.policy_calls, 2,
        "capacity target was admitted: {observation:?}"
    );
    assert!(
        observation.connection_close_before_cleanup.is_none(),
        "capacity refusal closed connection: {observation:?}"
    );
    assert!(
        observation.client_cleanup.is_none() && observation.server_cleanup.is_none(),
        "capacity cleanup failed: {observation:?}"
    );
    Ok(())
}

#[tokio::test]
async fn m6c246_released_capacity_control_serves_target_and_sibling() -> TestResult {
    let observation = capacity_resolver_case(false).await?;
    assert!(
        observation.target_responded && !observation.target_rejected,
        "released capacity target did not complete: {observation:?}"
    );
    assert!(
        observation.sibling_completed,
        "released capacity sibling failed: {observation:?}"
    );
    assert_eq!(
        observation.policy_calls, 3,
        "released capacity admission count changed: {observation:?}"
    );
    assert!(
        observation.connection_close_before_cleanup.is_none(),
        "released capacity connection failed: {observation:?}"
    );
    assert!(
        observation.client_cleanup.is_none() && observation.server_cleanup.is_none(),
        "released capacity cleanup failed: {observation:?}"
    );
    Ok(())
}
