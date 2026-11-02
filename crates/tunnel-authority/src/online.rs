//! One operator-approved writer, with no network administration surface.
use crate::{
    Result,
    online_config::{Config, Inventory},
    online_state::{Coordinator, Engine, Round, validate_nonce},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tunnel_catalog::{CatalogError, RedisMembershipPublisher};
use tunnel_transport::{CertificateRole, leaf_identity_from_der};

const CONNECTION_LIMIT: usize = 64;
const REQUEST_BUDGET: Duration = Duration::from_secs(2);
const PUBLISH_BUDGET: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRequest {
    deployment_id: String,
    deployment_incarnation: String,
    nonce: String,
}

struct Application {
    inventory: Inventory,
    coordinator: Coordinator,
    node_permits: BTreeMap<String, Arc<Semaphore>>,
}

pub fn check(config: Config) -> Result<()> {
    config.tls()?;
    config.redis()?;
    Engine::open(config, Arc::new(AtomicBool::new(false)))?;
    Ok(())
}

pub fn run(config: Config) -> Result<()> {
    // Bounded local private-file reads happen before entering Tokio. Online
    // durable mutations run on the single permitted blocking operation.
    let tls = config.tls()?;
    let (redis_url, redis_tls) = config.redis()?;
    let fatal = Arc::new(AtomicBool::new(false));
    let engine = Engine::open(config.clone(), Arc::clone(&fatal))?;
    let inventory = engine.inventory();
    let expected_run = engine.expected_run();
    let coordinator = Coordinator::new(engine, Arc::clone(&fatal));
    let application = Arc::new(Application {
        node_permits: inventory
            .nodes
            .iter()
            .map(|node| (node.node_id.clone(), Arc::new(Semaphore::new(1))))
            .collect(),
        inventory,
        coordinator,
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "cannot start authority runtime")?;
    let result = runtime.block_on(async {
        let listener = TcpListener::bind(config.bind).await.map_err(|_| "cannot bind private authority listener")?;
        let acceptor = TlsAcceptor::from(tls);
        let connections = Arc::new(Semaphore::new(CONNECTION_LIMIT));
        let mut tasks = JoinSet::new();
        let mut publisher = tokio::spawn(publish_loop(Arc::clone(&application), redis_url, redis_tls, expected_run));
        let mut publisher_completed = false;
        let stop = shutdown_signal();
        tokio::pin!(stop);
        eprintln!("authority_started: readiness=pending_publication");
        let outcome = loop {
            tokio::select! {
                _ = &mut stop => break Ok(()),
                result = &mut publisher => { publisher_completed = true; break result.unwrap_or(Err("publisher task failed")); },
                Some(result) = tasks.join_next() => {
                    if result.is_err() { break Err("authority connection task failed"); }
                }
                accepted = listener.accept() => {
                    let (socket, _) = accepted.map_err(|_| "authority accept failed")?;
                    let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else { continue; };
                    let acceptor = acceptor.clone();
                    let application = Arc::clone(&application);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let accepted = tokio::time::timeout(REQUEST_BUDGET, acceptor.accept(socket)).await;
                        let Ok(Ok(tls)) = accepted else { return; };
                        let identity = tls.get_ref().1.peer_certificates().and_then(|chain| chain.first())
                            .and_then(|leaf| leaf_identity_from_der(leaf.as_ref()).ok());
                        let authorized = identity.as_ref().filter(|identity| matches!(identity.role(), CertificateRole::Peer { .. }))
                            .filter(|identity| application.inventory.permits_client(identity.role_id(), &identity.spki_sha256().to_hex()));
                        let node_permit = authorized.and_then(|identity| application.node_permits.get(identity.role_id()))
                            .map(|permit| Arc::clone(permit).try_acquire_owned());
                        let (authorization, _node_permit) = match node_permit {
                            None => (StatusCode::FORBIDDEN, None),
                            Some(Err(_)) => (StatusCode::TOO_MANY_REQUESTS, None),
                            Some(Ok(permit)) => (StatusCode::OK, Some(permit)),
                        };
                        let service = service_fn(move |request| handle(Arc::clone(&application), authorization, request));
                        let mut builder = http1::Builder::new();
                        builder.keep_alive(false).max_headers(16).max_buf_size(8192);
                        let _ = tokio::time::timeout(REQUEST_BUDGET,
                            builder.serve_connection(TokioIo::new(tls), service)).await;
                    });
                }
            }
        };
        if !publisher_completed { publisher.abort(); let _ = publisher.await; }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        outcome
    });
    // A stuck fsync is not cancellable. Its timeout already latched fatal;
    // bound runtime shutdown rather than waiting forever on a blocking worker.
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

async fn handle(
    application: Arc<Application>,
    authorization: StatusCode,
    request: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if authorization != StatusCode::OK {
        return Ok(response(
            authorization,
            b"{\"status\":\"refused\"}".to_vec(),
        ));
    }
    if request.method() == "GET" && request.uri().path() == "/livez" {
        return Ok(response(StatusCode::OK, b"{\"status\":\"live\"}".to_vec()));
    }
    if request.method() == "GET"
        && request.uri().path() == "/readyz"
        && request.uri().query().is_none()
    {
        let ready = application
            .coordinator
            .call(false, |engine| Ok(engine.ready()))
            .await
            .unwrap_or(false);
        return Ok(response(
            if ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            if ready {
                b"{\"status\":\"ready\"}".to_vec()
            } else {
                b"{\"status\":\"unavailable\"}".to_vec()
            },
        ));
    }
    if request.uri().path() != "/v1/checkpoint" || request.uri().query().is_some() {
        return Ok(response(StatusCode::NOT_FOUND, Vec::new()));
    }
    if request.method() != "POST" {
        return Ok(response(StatusCode::METHOD_NOT_ALLOWED, Vec::new()));
    }
    if request
        .headers()
        .get("content-type")
        .is_none_or(|v| v != "application/json")
    {
        return Ok(response(StatusCode::UNSUPPORTED_MEDIA_TYPE, Vec::new()));
    }
    let body = match Limited::new(request.into_body(), 4096).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(response(StatusCode::PAYLOAD_TOO_LARGE, Vec::new())),
    };
    let request: CheckpointRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return Ok(response(StatusCode::BAD_REQUEST, Vec::new())),
    };
    if request.deployment_id != application.inventory.deployment_id
        || request.deployment_incarnation != application.inventory.deployment_incarnation
        || validate_nonce(&request.nonce).is_err()
    {
        return Ok(response(StatusCode::BAD_REQUEST, Vec::new()));
    }
    let result = application
        .coordinator
        .call(false, move |engine| engine.checkpoint(request.nonce))
        .await;
    Ok(match result {
        Ok(bytes) => response(StatusCode::OK, bytes),
        Err(_) => response(
            StatusCode::SERVICE_UNAVAILABLE,
            b"{\"status\":\"unavailable\"}".to_vec(),
        ),
    })
}

fn response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("connection", "close")
        .body(Full::new(Bytes::from(body)))
        .expect("fixed valid response headers")
}

async fn publish_loop(
    application: Arc<Application>,
    url: zeroize::Zeroizing<String>,
    tls: tunnel_catalog::RedisTlsOptions,
    expected_run: String,
) -> Result<()> {
    let mut publisher = None;
    let mut cadence = tokio::time::interval(Duration::from_secs(20));
    cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        cadence.tick().await;
        if application.coordinator.fatal.load(Ordering::SeqCst) {
            return Err("authority persistence failed closed");
        }
        if publisher.is_none() {
            let connected = tokio::time::timeout(
                PUBLISH_BUDGET,
                RedisMembershipPublisher::connect_with_tls(
                    &url,
                    &application.inventory.redis_namespace,
                    tls.clone(),
                ),
            )
            .await;
            match connected {
                Ok(Ok(connected)) => {
                    if connected.bound_redis_run_id() != expected_run {
                        return fatal_publisher(
                            &application,
                            "Redis run differs from independent durable approval; recovery required",
                        );
                    }
                    publisher = Some(connected);
                }
                _ => {
                    eprintln!("authority_publication_unavailable: stage=connect");
                    continue;
                }
            }
        }
        let round = match application
            .coordinator
            .call(true, Engine::reserve_round)
            .await
        {
            Ok(round) => round,
            Err(_) => {
                eprintln!("authority_publication_unavailable: stage=reserve");
                continue;
            }
        };
        let result = tokio::time::timeout(
            PUBLISH_BUDGET,
            publish_round(publisher.as_ref().expect("connected publisher"), &round),
        )
        .await;
        match result {
            Ok(Ok(())) => {
                if application
                    .coordinator
                    .call(true, move |engine| engine.confirm(round))
                    .await
                    .is_ok()
                {
                    eprintln!("authority_publication_confirmed");
                }
            }
            Ok(Err(CatalogError::Conflict(_))) | Ok(Err(CatalogError::InvalidInput(_))) => {
                return fatal_publisher(
                    &application,
                    "membership publication conflict; independent authority state review required",
                );
            }
            _ => {
                // Every record in this attempted round already has a durable
                // spent version. Reconnect and reserve a higher round; never
                // replay the ambiguous write or extend the old confirmation.
                publisher = None;
                eprintln!("authority_publication_unavailable: stage=publish");
            }
        }
    }
}

fn fatal_publisher(application: &Application, reason: &'static str) -> Result<()> {
    application.coordinator.fatal.store(true, Ordering::SeqCst);
    Err(reason)
}

async fn publish_round(
    publisher: &RedisMembershipPublisher,
    round: &Round,
) -> std::result::Result<(), CatalogError> {
    let mut pending = round.records.iter();
    let mut tasks = JoinSet::new();
    loop {
        while tasks.len() < 4 {
            let Some((node, record)) = pending.next() else {
                break;
            };
            let publisher = publisher.clone();
            let node = node.clone();
            let record = record.clone();
            tasks.spawn(async move {
                publisher
                    .publish_signed_membership_for_node(&node, &record)
                    .await
            });
        }
        match tasks.join_next().await {
            Some(Ok(result)) => result?,
            Some(Err(_)) => return Err(CatalogError::Conflict("publisher worker failed")),
            None => return Ok(()),
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
