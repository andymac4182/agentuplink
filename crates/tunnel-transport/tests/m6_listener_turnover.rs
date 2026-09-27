//! M6-C193: connection turnover while a public listener is full.
//!
//! Before the fix a listener permit was held for a whole keep-alive
//! connection, and a busy keep-alive connection never closed, so while one
//! client's keep-alive flood held every permit, a client that connected later
//! was refused `503 CONNECTION_LIMIT` for the whole flood.  Under pressure (a
//! connection arriving with every permit held within the last second) a
//! served connection that has used its budget is now closed after its current
//! response: `Connection: close` on HTTP/1.1, GOAWAY on HTTP/2; and a
//! connection over the limit waits briefly for a freed permit before it is
//! refused, so the permit reaches a waiting client.  These tests use real TCP
//! sockets and real TLS 1.3 handshakes.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::{any, get},
};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    AcceptedSocketDiagnostics, AcceptedSocketOptions, ListenerCapacity, ListenerTimeouts,
    ListenerTurnover, require_root_certificates, serve_with_listener_options,
};

const SERVER_NAME: &str = "localhost";
const QUICK_BODY: &str = "quick-ok";
/// Chunks the slow route streams, one every [`SLOW_CHUNK_GAP`].
const SLOW_CHUNKS: usize = 12;
const SLOW_CHUNK_GAP: Duration = Duration::from_millis(200);
const SLOW_CHUNK: &[u8] = b"synthetic-slow-chunk\n";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Deadlines long enough that idle keep-alive connections keep their permits
/// for the whole test.
fn holding_timeouts() -> ListenerTimeouts {
    ListenerTimeouts {
        handshake_timeout: Duration::from_secs(10),
        pre_request_timeout: Duration::from_secs(60),
        http1_header_read_timeout: Duration::from_secs(60),
    }
}

fn slow_body() -> Body {
    let chunks = futures_util::stream::unfold(0_usize, |sent| async move {
        if sent == SLOW_CHUNKS {
            return None;
        }
        tokio::time::sleep(SLOW_CHUNK_GAP).await;
        Some((
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(SLOW_CHUNK)),
            sent + 1,
        ))
    });
    Body::from_stream(chunks)
}

/// A raw upgrade that echoes bytes, standing in for a WebSocket: what matters
/// is the `101` and that the upgraded stream outlives the turnover budget.
async fn echo_upgrade(mut request: Request) -> Response {
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let Ok(upgraded) = upgrade.await else { return };
        let mut io = hyper_util::rt::TokioIo::new(upgraded);
        let mut buffer = [0_u8; 256];
        while let Ok(read) = io.read(&mut buffer).await {
            if read == 0 || io.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
    });
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    response
        .headers_mut()
        .insert(header::UPGRADE, HeaderValue::from_static("synthetic-echo"));
    response
}

struct Fixture {
    address: SocketAddr,
    http1: Arc<rustls::ClientConfig>,
    http2: Arc<rustls::ClientConfig>,
    diagnostics: AcceptedSocketDiagnostics,
    cancel: CancellationToken,
    server: tokio::task::JoinHandle<Result<(), tunnel_transport::TransportError>>,
}

impl Fixture {
    async fn start(
        capacity: ListenerCapacity,
        turnover: Option<ListenerTurnover>,
    ) -> TestResult<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "M6 listener turnover fixture");
        params
            .subject_alt_names
            .push(SanType::DnsName(SERVER_NAME.try_into()?));
        let certificate = params.self_signed(&key)?;
        let certificate_pem = certificate.pem();
        let server_config = tunnel_transport::load_server_config_from_pem(
            certificate_pem.as_bytes(),
            key.serialize_pem().as_bytes(),
            None,
        )?;
        let client = |alpn: &[u8]| -> TestResult<Arc<rustls::ClientConfig>> {
            let roots = require_root_certificates(certificate_pem.as_bytes())?;
            let mut config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = vec![alpn.to_vec()];
            Ok(Arc::new(config))
        };

        let router = Router::new()
            .route("/quick", get(|| async { QUICK_BODY }))
            .route("/slow", get(|| async { Response::new(slow_body()) }))
            .route("/upgrade", any(echo_upgrade));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let diagnostics = AcceptedSocketDiagnostics::new();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_with_listener_options(
            listener,
            router,
            server_config,
            cancel.clone(),
            AcceptedSocketOptions {
                diagnostics: Some(diagnostics.clone()),
                capacity,
                turnover,
                ..AcceptedSocketOptions::default()
            },
            holding_timeouts(),
        ));
        Ok(Self {
            address,
            http1: client(b"http/1.1")?,
            http2: client(b"h2")?,
            diagnostics,
            cancel,
            server,
        })
    }

    async fn connect(&self) -> std::io::Result<TlsStream<TcpStream>> {
        connect(self.address, self.http1.clone()).await
    }

    async fn shutdown(self) -> TestResult {
        self.cancel.cancel();
        let result = timeout(Duration::from_secs(20), self.server)
            .await
            .map_err(|_| "listener did not join after cancellation")??;
        result?;
        Ok(())
    }
}

async fn connect(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await?;
    TlsConnector::from(config)
        .connect(SERVER_NAME.try_into().expect("fixture server name"), tcp)
        .await
}

/// One HTTP/1.1 response: status, lower-cased head, and a body read by
/// `content-length`, by chunked framing, or to end of stream.
struct Http1Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Http1Response {
    fn closes(&self) -> bool {
        self.head.contains("\r\nconnection: close\r\n")
    }
}

async fn read_http1(stream: &mut TlsStream<TcpStream>) -> std::io::Result<Http1Response> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut rest = buffer[head_end..].to_vec();
    let length = head
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse::<usize>().ok());
    let body = if status == 101 {
        rest
    } else if let Some(length) = length {
        while rest.len() < length {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            rest.extend_from_slice(&chunk[..read]);
        }
        rest
    } else if head.contains("\r\ntransfer-encoding: chunked\r\n") {
        let mut body = Vec::new();
        loop {
            let line_end = loop {
                if let Some(end) = rest.windows(2).position(|w| w == b"\r\n") {
                    break end;
                }
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                rest.extend_from_slice(&chunk[..read]);
            };
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&rest[..line_end])
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim(),
                16,
            )
            .map_err(|_| std::io::Error::other("bad chunk size"))?;
            while rest.len() < line_end + 2 + size + 2 {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                rest.extend_from_slice(&chunk[..read]);
            }
            body.extend_from_slice(&rest[line_end + 2..line_end + 2 + size]);
            rest.drain(..line_end + 2 + size + 2);
            if size == 0 {
                break;
            }
        }
        body
    } else {
        stream.read_to_end(&mut rest).await?;
        rest
    };
    Ok(Http1Response { status, head, body })
}

async fn get_http1(
    stream: &mut TlsStream<TcpStream>,
    path: &str,
) -> std::io::Result<Http1Response> {
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: keep-alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_http1(stream).await
}

/// Whether the peer closed the stream: a read returns end of stream or an
/// error within `wait`.
async fn closed_within(stream: &mut TlsStream<TcpStream>, wait: Duration) -> bool {
    matches!(
        timeout(wait, stream.read(&mut [0_u8; 1])).await,
        Ok(Ok(0) | Err(_))
    )
}

/// Keep the listener under pressure: a connection over the limit every
/// 50 ms, each answered `503` and closed.  Stops with `stop`.
fn keep_pressure(fixture: &Fixture, stop: CancellationToken) -> tokio::task::JoinHandle<usize> {
    let address = fixture.address;
    let config = fixture.http1.clone();
    tokio::spawn(async move {
        let mut refused = 0;
        while !stop.is_cancelled() {
            if let Ok(mut stream) = connect(address, config.clone()).await
                && let Ok(response) = get_http1(&mut stream, "/quick").await
                && response.status == 503
            {
                refused += 1;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        refused
    })
}

async fn wait_for(what: &str, bound: Duration, mut done: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + bound;
    while !done() {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// The owner-decided acceptance of M6-C193, at small scale: a keep-alive
/// flood holds every permit and keeps more connections arriving (so the
/// listener is under pressure); a client that connects during the flood is
/// served within a bounded time.
///
/// Red before the fix: the flood's served connections never closed, so the
/// late client was refused `CONNECTION_LIMIT` on every attempt until the
/// bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_pressure_a_late_client_is_served_while_a_flood_holds_every_permit() -> TestResult {
    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: 4,
            refusal_margin: 2,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover {
            max_age: Duration::from_secs(1),
            max_requests: 1_000_000,
            ..ListenerTurnover::default()
        }),
    )
    .await?;

    // Six closed-loop flood workers that ignore Retry-After: four hold the
    // four permits with busy keep-alive connections, two are refused and
    // reconnect at once.  Each reconnects when its connection is closed.
    let stop = CancellationToken::new();
    let flood_served = Arc::new(AtomicUsize::new(0));
    let flood_holding = Arc::new(AtomicUsize::new(0));
    let mut flood = Vec::new();
    for _ in 0..6 {
        let (address, config) = (fixture.address, fixture.http1.clone());
        let (stop, served, holding) = (stop.clone(), flood_served.clone(), flood_holding.clone());
        flood.push(tokio::spawn(async move {
            while !stop.is_cancelled() {
                let Ok(mut stream) = connect(address, config.clone()).await else {
                    continue;
                };
                let mut counted = false;
                while !stop.is_cancelled() {
                    let Ok(response) = get_http1(&mut stream, "/quick").await else {
                        break;
                    };
                    if response.status != 200 {
                        break;
                    }
                    if !counted {
                        holding.fetch_add(1, Ordering::AcqRel);
                        counted = true;
                    }
                    served.fetch_add(1, Ordering::AcqRel);
                    if response.closes() {
                        break;
                    }
                }
                if counted {
                    holding.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }));
    }
    wait_for(
        "the flood to hold every permit",
        Duration::from_secs(10),
        || {
            flood_holding.load(Ordering::Acquire) == 4
                && fixture.diagnostics.capacity_refusals() > 0
        },
    )
    .await?;

    // The late client: one request per attempt, a new connection after each
    // refusal, 20 ms apart.
    let started = Instant::now();
    let bound = Duration::from_secs(10);
    let mut refusals = 0_usize;
    let served_after = loop {
        assert!(
            started.elapsed() < bound,
            "the late client was refused {refusals} times and never served in {bound:?} \
             (flood served {}, recycled {})",
            flood_served.load(Ordering::Acquire),
            fixture.diagnostics.fairness_recycles()
        );
        if let Ok(mut stream) = fixture.connect().await
            && let Ok(response) = get_http1(&mut stream, "/quick").await
        {
            if response.status == 200 {
                assert_eq!(response.body, QUICK_BODY.as_bytes());
                break started.elapsed();
            }
            assert_eq!(response.status, 503, "{}", response.head);
            refusals += 1;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let recycled = fixture.diagnostics.fairness_recycles();
    assert!(recycled > 0, "served without any turnover");
    assert!(
        tunnel_transport::listener_fairness()
            .iter()
            .any(|listener| listener.listener == "unnamed" && listener.recycled > 0),
        "the process-wide turnover counter did not move"
    );
    eprintln!(
        "M6-C193 late client served after {served_after:?} and {refusals} refusals; \
         flood served {}, connections recycled {recycled}, capacity refusals {}",
        flood_served.load(Ordering::Acquire),
        fixture.diagnostics.capacity_refusals()
    );

    stop.cancel();
    for worker in flood {
        let _ = timeout(Duration::from_secs(10), worker).await;
    }
    fixture.shutdown().await
}

/// Normal operation is unchanged: with every permit held but no connection
/// refused, keep-alive connections are never recycled, however old they are
/// or however many requests they serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_pressure_nothing_is_recycled() -> TestResult {
    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: 4,
            refusal_margin: 2,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover {
            max_age: Duration::from_secs(1),
            max_requests: 5,
            ..ListenerTurnover::default()
        }),
    )
    .await?;
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(fixture.connect().await?);
    }
    // 20 requests per connection over about 2.4 s: past both budgets.
    for _ in 0..20 {
        for stream in &mut held {
            let response = get_http1(stream, "/quick").await?;
            assert_eq!(response.status, 200, "{}", response.head);
            assert!(
                !response.closes(),
                "a connection was recycled with no pressure: {}",
                response.head
            );
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    assert_eq!(fixture.diagnostics.capacity_refusals(), 0);
    assert_eq!(fixture.diagnostics.fairness_recycles(), 0);
    drop(held);
    fixture.shutdown().await
}

/// A long HTTP/1.1 response is never cut: a connection past its budget under
/// pressure has its streaming response marked `Connection: close`, receives
/// the whole body, and only then is closed.  A `101` upgrade is never marked,
/// and the upgraded stream keeps working past the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_turnover_never_cuts_a_response_or_an_upgrade() -> TestResult {
    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: 2,
            refusal_margin: 1,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover {
            max_age: Duration::from_secs(1),
            max_requests: 1_000_000,
            ..ListenerTurnover::default()
        }),
    )
    .await?;
    let mut streaming = fixture.connect().await?;
    let mut upgrading = fixture.connect().await?;
    let stop = CancellationToken::new();
    let pressure = keep_pressure(&fixture, stop.clone());
    wait_for("pressure", Duration::from_secs(10), || {
        fixture.diagnostics.capacity_refusals() > 0
    })
    .await?;
    // Both connections are now past their age budget under pressure.
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    let slow = timeout(Duration::from_secs(20), get_http1(&mut streaming, "/slow")).await??;
    assert_eq!(slow.status, 200, "{}", slow.head);
    assert!(
        slow.closes(),
        "the budget-spent connection was not marked: {}",
        slow.head
    );
    assert_eq!(
        slow.body,
        SLOW_CHUNK.repeat(SLOW_CHUNKS),
        "the streaming response was cut"
    );
    assert!(
        closed_within(&mut streaming, Duration::from_secs(5)).await,
        "the recycled connection stayed open after its response"
    );

    let upgrade = format!(
        "GET /upgrade HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: upgrade\r\nUpgrade: synthetic-echo\r\n\r\n"
    );
    upgrading.write_all(upgrade.as_bytes()).await?;
    upgrading.flush().await?;
    let switched = timeout(Duration::from_secs(10), read_http1(&mut upgrading)).await??;
    assert_eq!(switched.status, 101, "{}", switched.head);
    assert!(
        !switched.closes(),
        "a 101 was marked for turnover: {}",
        switched.head
    );
    // The upgraded stream outlives the budget and keeps echoing.
    for round in 0..3 {
        tokio::time::sleep(Duration::from_millis(600)).await;
        let message = format!("synthetic-upgrade-{round}");
        upgrading.write_all(message.as_bytes()).await?;
        upgrading.flush().await?;
        let mut echoed = vec![0_u8; message.len()];
        timeout(Duration::from_secs(5), upgrading.read_exact(&mut echoed)).await??;
        assert_eq!(echoed, message.as_bytes(), "the upgraded stream was cut");
    }
    assert!(fixture.diagnostics.fairness_recycles() >= 1);

    stop.cancel();
    let _ = timeout(Duration::from_secs(10), pressure).await;
    drop(upgrading);
    fixture.shutdown().await
}

/// HTTP/2 turnover is a graceful GOAWAY: a stream already in flight when the
/// connection is chosen runs to its end, a new stream is not accepted, and
/// the connection then closes and frees its permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_turnover_sends_goaway_and_lets_streams_finish() -> TestResult {
    use http_body_util::BodyExt;

    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: 2,
            refusal_margin: 1,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover {
            max_age: Duration::from_secs(1),
            max_requests: 1_000_000,
            ..ListenerTurnover::default()
        }),
    )
    .await?;
    let tls = connect(fixture.address, fixture.http2.clone()).await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await?;
    let connection_closed = Arc::new(AtomicBool::new(false));
    let driver = {
        let closed = connection_closed.clone();
        tokio::spawn(async move {
            let _ = connection.await;
            closed.store(true, Ordering::Release);
        })
    };
    let request = |path: &str| {
        http::Request::builder()
            .uri(format!("https://{SERVER_NAME}{path}"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("request")
    };
    // The second permit is held by a plain HTTP/1.1 connection.
    let mut other = fixture.connect().await?;
    assert_eq!(get_http1(&mut other, "/quick").await?.status, 200);

    // Before pressure: a quick request, and the slow stream starts.
    assert_eq!(sender.send_request(request("/quick")).await?.status(), 200);
    let slow = sender.send_request(request("/slow")).await?;
    assert_eq!(slow.status(), 200);
    let slow_body = tokio::spawn(async move { slow.into_body().collect().await });

    let stop = CancellationToken::new();
    let pressure = keep_pressure(&fixture, stop.clone());
    wait_for("pressure", Duration::from_secs(10), || {
        fixture.diagnostics.capacity_refusals() > 0
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // A response past the budget chooses this connection: GOAWAY.
    let quick = sender.send_request(request("/quick")).await?;
    assert_eq!(quick.status(), 200);
    wait_for("the turnover", Duration::from_secs(5), || {
        fixture.diagnostics.fairness_recycles() >= 1
    })
    .await?;
    // The in-flight stream still completes in full.
    let body = timeout(Duration::from_secs(20), slow_body)
        .await
        .map_err(|_| "the in-flight stream never finished")???
        .to_bytes();
    assert_eq!(
        body,
        SLOW_CHUNK.repeat(SLOW_CHUNKS),
        "GOAWAY cut the stream"
    );
    // Then the connection closes, and it takes no new stream.
    wait_for(
        "the HTTP/2 connection to close",
        Duration::from_secs(10),
        || connection_closed.load(Ordering::Acquire),
    )
    .await?;
    assert!(
        sender.send_request(request("/quick")).await.is_err(),
        "a GOAWAY connection accepted a new stream"
    );

    stop.cancel();
    let _ = timeout(Duration::from_secs(10), pressure).await;
    let _ = driver.await;
    drop(other);
    fixture.shutdown().await
}

/// The hand-off: a connection accepted over the limit waits (before TLS) for
/// a freed permit and is then served, not refused; one that waits longer than
/// the hand-off bound is refused `503` exactly as before.
///
/// Red without the hand-off: the waiting connection was answered `503` at
/// once, and a permit freed by turnover went to whichever connection the
/// listener accepted next -- in the flood test above, 80 of 80 recycled
/// permits in 20 s went back to flood workers and the late client was refused
/// 855 times out of 855 (`red-no-handoff` before this test existed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_over_the_limit_gets_a_permit_freed_while_it_waits() -> TestResult {
    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: 1,
            refusal_margin: 2,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover::default()),
    )
    .await?;
    let mut holder = fixture.connect().await?;
    assert_eq!(get_http1(&mut holder, "/quick").await?.status, 200);

    // Past the hand-off bound with the permit still held: the documented 503.
    let started = Instant::now();
    let mut refused = fixture.connect().await?;
    let response = get_http1(&mut refused, "/quick").await?;
    assert_eq!(response.status, 503, "{}", response.head);
    assert!(
        started.elapsed() >= tunnel_transport::HANDOFF_WAIT - Duration::from_millis(50),
        "refused before the hand-off wait: {:?}",
        started.elapsed()
    );
    assert_eq!(fixture.diagnostics.capacity_refusals(), 1);

    // A connection that arrives while full, then a permit frees within the
    // wait: it is served.
    let (address, config) = (fixture.address, fixture.http1.clone());
    let waiting = tokio::spawn(async move {
        let mut stream = connect(address, config).await?;
        get_http1(&mut stream, "/quick").await
    });
    tokio::time::sleep(tunnel_transport::HANDOFF_WAIT / 3).await;
    assert!(
        !waiting.is_finished(),
        "the waiting connection was answered"
    );
    drop(holder);
    let response = timeout(Duration::from_secs(10), waiting).await???;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(response.body, QUICK_BODY.as_bytes());
    assert_eq!(fixture.diagnostics.fairness_handoffs(), 1);
    assert_eq!(fixture.diagnostics.capacity_refusals(), 1);
    fixture.shutdown().await
}

/// M6-C193 review (N2): the hand-off has its own bounded queue, separate from
/// the refusal margin.  With that queue full, a further connection over the
/// limit is refused `503` at once through the margin, not held for the
/// hand-off wait, so the explicit refusal stays the overload signal.
///
/// Red while waiting shared the refusal margin: every refusal first waited
/// for the hand-off, so the second connection was answered only after about
/// 500 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_handoff_queue_full_further_connections_are_refused_at_once() -> TestResult {
    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: 1,
            refusal_margin: 2,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover {
            handoff_queue: 1,
            ..ListenerTurnover::default()
        }),
    )
    .await?;
    let mut holder = fixture.connect().await?;
    assert_eq!(get_http1(&mut holder, "/quick").await?.status, 200);

    // A silent connection takes the only hand-off slot for the whole wait.
    let _waiting = TcpStream::connect(fixture.address).await?;
    wait_for(
        "the waiting connection's accept",
        Duration::from_secs(5),
        || fixture.diagnostics.nodelay_counts().0 >= 2,
    )
    .await?;

    let started = Instant::now();
    let mut refused = fixture.connect().await?;
    let response = get_http1(&mut refused, "/quick").await?;
    let elapsed = started.elapsed();
    assert_eq!(response.status, 503, "{}", response.head);
    assert!(
        elapsed < tunnel_transport::HANDOFF_WAIT * 3 / 5,
        "with the hand-off queue full the refusal waited {elapsed:?}"
    );
    assert_eq!(fixture.diagnostics.fairness_handoffs(), 0);
    drop(holder);
    fixture.shutdown().await
}

/// M6-C193 review (B2): each connection's turnover age is drawn between 50%
/// and 100% of `max_age`, so connections that were all open when pressure
/// began are recycled spread over that range, not in one burst.
///
/// Red with a fixed age: all eight first recycles landed within one request
/// interval of each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turnover_of_connections_open_before_pressure_is_spread_out() -> TestResult {
    const HOLDERS: usize = 8;
    let max_age = Duration::from_secs(2);
    let fixture = Fixture::start(
        ListenerCapacity {
            max_connections: HOLDERS,
            refusal_margin: 2,
            ..ListenerCapacity::default()
        },
        Some(ListenerTurnover {
            max_age,
            max_requests: 1_000_000,
            // No hand-off, so the pressure connections never take a permit.
            handoff_queue: 0,
        }),
    )
    .await?;
    let mut held = Vec::new();
    for _ in 0..HOLDERS {
        let mut stream = fixture.connect().await?;
        assert_eq!(get_http1(&mut stream, "/quick").await?.status, 200);
        held.push(stream);
    }
    let stop = CancellationToken::new();
    let pressure = keep_pressure(&fixture, stop.clone());
    wait_for("pressure", Duration::from_secs(10), || {
        fixture.diagnostics.capacity_refusals() > 0
    })
    .await?;
    let pressure_began = Instant::now();

    // Each holder keeps requesting until its connection is marked; the time
    // it is marked is its first recycle.
    let mut workers = Vec::new();
    for mut stream in held {
        workers.push(tokio::spawn(async move {
            loop {
                let response = get_http1(&mut stream, "/quick").await?;
                if response.closes() {
                    return Ok::<_, std::io::Error>(Instant::now());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }));
    }
    let mut recycled_at = Vec::new();
    for worker in workers {
        let at = timeout(max_age * 3, worker)
            .await
            .map_err(|_| "a holder was never recycled under pressure")???;
        recycled_at.push(at.saturating_duration_since(pressure_began));
    }
    recycled_at.sort();
    let spread = recycled_at[HOLDERS - 1] - recycled_at[0];
    eprintln!("M6-C193 first recycles after pressure began: {recycled_at:?}; spread {spread:?}");
    assert!(
        spread >= max_age / 5,
        "first recycles were not spread out: {recycled_at:?}"
    );
    assert!(
        recycled_at[0] >= max_age / 2 - Duration::from_millis(300),
        "a connection recycled before half its max age: {recycled_at:?}"
    );

    stop.cancel();
    let _ = timeout(Duration::from_secs(10), pressure).await;
    fixture.shutdown().await
}
