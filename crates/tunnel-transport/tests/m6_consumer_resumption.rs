//! M6-C194 option (e): TLS 1.3 session resumption on the public consumer
//! listener only.
//!
//! A reconnect that resumes skips the server's certificate signature, so the
//! reconnects that turnover (M6-C193) and `CONNECTION_LIMIT` refusals cause
//! cost the relay less.  Resumption stays off on every mTLS listener (device,
//! peer, and a consumer listener configured with a client CA), so each mTLS
//! connection still presents fresh certificate evidence.  Real TCP sockets
//! and real TLS 1.3 handshakes through the relay's own listener.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, routing::get};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::HandshakeKind;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    AcceptedSocketOptions, ListenerTimeouts, require_root_certificates, serve_with_listener_options,
};

const SERVER_NAME: &str = "localhost";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Pki {
    ca_pem: String,
    server_pem: String,
    server_key_pem: String,
    client_chain: Vec<CertificateDer<'static>>,
    client_key_pem: String,
}

fn pki() -> TestResult<Pki> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "M6-C194 synthetic CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;

    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "M6-C194 synthetic relay");
    server_params
        .subject_alt_names
        .push(SanType::DnsName(SERVER_NAME.try_into()?));
    let server = server_params.signed_by(&server_key, &ca, &ca_key)?;

    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "M6-C194 synthetic client");
    let client = client_params.signed_by(&client_key, &ca, &ca_key)?;

    Ok(Pki {
        ca_pem: ca.pem(),
        server_pem: server.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_chain: vec![client.der().clone()],
        client_key_pem: client_key.serialize_pem(),
    })
}

/// A client with rustls's default in-memory session store, which resumes
/// whenever the server issued it a ticket.
fn resuming_client(pki: &Pki, with_certificate: bool) -> TestResult<Arc<rustls::ClientConfig>> {
    let roots = require_root_certificates(pki.ca_pem.as_bytes())?;
    let builder = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots);
    let mut config = if with_certificate {
        builder.with_client_auth_cert(
            pki.client_chain.clone(),
            PrivateKeyDer::from_pem_slice(pki.client_key_pem.as_bytes())?,
        )?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn serve(config: Arc<rustls::ServerConfig>) -> TestResult<(SocketAddr, CancellationToken)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let cancel = CancellationToken::new();
    tokio::spawn(serve_with_listener_options(
        listener,
        Router::new().route("/quick", get(|| async { "quick-ok" })),
        config,
        cancel.clone(),
        AcceptedSocketOptions::default(),
        ListenerTimeouts::default(),
    ));
    Ok((address, cancel))
}

/// Connect, complete one request (which also delivers any session tickets
/// the server sends after its handshake), and report how the handshake went.
async fn one_request(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> TestResult<HandshakeKind> {
    let tcp = TcpStream::connect(address).await?;
    let mut tls = TlsConnector::from(config)
        .connect(SERVER_NAME.try_into()?, tcp)
        .await?;
    let kind = tls
        .get_ref()
        .1
        .handshake_kind()
        .ok_or("no handshake kind")?;
    tls.write_all(
        format!("GET /quick HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), tls.read_to_end(&mut response)).await??;
    assert!(
        String::from_utf8_lossy(&response).contains("quick-ok"),
        "request not served"
    );
    Ok(kind)
}

/// Red before the fix: the consumer listener used the same configuration as
/// the mTLS listeners, with resumption disabled, so the second handshake was
/// `Full`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumer_listener_resumes_tls13_sessions() -> TestResult {
    let pki = pki()?;
    let server = tunnel_transport::load_consumer_server_config_from_pem(
        pki.server_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        None,
    )?;
    assert_eq!(server.max_early_data_size, 0, "0-RTT must stay off");
    let (address, cancel) = serve(server).await?;
    let client = resuming_client(&pki, false)?;
    assert_eq!(
        one_request(address, client.clone()).await?,
        HandshakeKind::Full
    );
    for _ in 0..3 {
        assert_eq!(
            one_request(address, client.clone()).await?,
            HandshakeKind::Resumed,
            "a reconnect to the consumer listener did not resume"
        );
    }
    cancel.cancel();
    Ok(())
}

/// A bare TLS server for `config`: each connection gets two bytes and a
/// clean close.  The mTLS configurations are checked at the TLS layer: the
/// relay's HTTP listener would also demand a role SAN these synthetic client
/// certificates do not carry, which is not what this test is about.
async fn serve_bare(config: Arc<rustls::ServerConfig>) -> TestResult<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let _ = tls.write_all(b"ok").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    Ok(address)
}

async fn bare_handshake(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> TestResult<HandshakeKind> {
    let tcp = TcpStream::connect(address).await?;
    let mut tls = TlsConnector::from(config)
        .connect(SERVER_NAME.try_into()?, tcp)
        .await?;
    let kind = tls
        .get_ref()
        .1
        .handshake_kind()
        .ok_or("no handshake kind")?;
    // Reading to the end also takes in any ticket the server sent.
    let mut received = Vec::new();
    timeout(Duration::from_secs(10), tls.read_to_end(&mut received)).await??;
    assert_eq!(received, b"ok");
    Ok(kind)
}

/// Resumption stays off wherever client certificates are required: an mTLS
/// consumer listener, and the device/peer configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_listeners_never_resume() -> TestResult {
    let pki = pki()?;
    let mtls_consumer = tunnel_transport::load_consumer_server_config_from_pem(
        pki.server_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        Some(pki.ca_pem.as_bytes()),
    )?;
    let device = tunnel_transport::load_server_config_from_pem(
        pki.server_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        Some(pki.ca_pem.as_bytes()),
    )?;
    // The same bare server resumes with the consumer configuration, so the
    // `Full` answers below are the configuration's, not the fixture's.
    let anonymous = tunnel_transport::load_consumer_server_config_from_pem(
        pki.server_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        None,
    )?;
    let address = serve_bare(anonymous).await?;
    let client = resuming_client(&pki, false)?;
    assert_eq!(
        bare_handshake(address, client.clone()).await?,
        HandshakeKind::Full
    );
    assert_eq!(
        bare_handshake(address, client).await?,
        HandshakeKind::Resumed
    );

    for (name, config) in [("mTLS consumer", mtls_consumer), ("device", device)] {
        let address = serve_bare(config).await?;
        let client = resuming_client(&pki, true)?;
        for attempt in 0..3 {
            assert_eq!(
                bare_handshake(address, client.clone()).await?,
                HandshakeKind::Full,
                "{name} listener resumed on attempt {attempt}"
            );
        }
    }
    Ok(())
}
