//! Server-side CPU cost of one TLS 1.3 handshake on the relay's listener
//! configuration, by server key type and by full versus resumed handshake
//! (task row M6-C194, options (b) and (e)).
//!
//! Handshakes run in memory (no sockets) on one thread; only the time spent
//! inside the **server's** rustls calls is counted, so the client's own cost
//! and any network are excluded.
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
//!     -addext subjectAltName=DNS:localhost -keyout rsa.key -out rsa.pem -days 2
//! cargo run --release --locked -p tunnel-transport --example handshake_cost -- rsa.pem rsa.key
//! ```
//!
//! Without arguments only the ECDSA P-256 rows (an `rcgen` key) are printed;
//! a third argument labels the key from files (default `RSA-2048`).  The key material
//! is synthetic and never printed.

use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::{ClientConnection, RootCertStore, ServerConnection};

const WARMUP: usize = 200;
const ROUNDS: usize = 2_000;

fn client_config(certificate_pem: &[u8], resume: bool) -> Arc<rustls::ClientConfig> {
    let roots: RootCertStore =
        tunnel_transport::require_root_certificates(certificate_pem).expect("roots");
    let mut config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("tls13")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    if !resume {
        config.resumption = rustls::client::Resumption::disabled();
    }
    Arc::new(config)
}

/// One handshake; returns the time spent in server calls and whether it
/// resumed.
fn handshake(
    server_config: &Arc<rustls::ServerConfig>,
    client_config: &Arc<rustls::ClientConfig>,
) -> (Duration, bool) {
    let mut client =
        ClientConnection::new(client_config.clone(), "localhost".try_into().expect("name"))
            .expect("client");
    let mut server_time = Duration::ZERO;
    let started = Instant::now();
    let mut server = ServerConnection::new(server_config.clone()).expect("server");
    server_time += started.elapsed();
    let mut buffer = Vec::with_capacity(16 * 1024);
    for _ in 0..16 {
        buffer.clear();
        while client.wants_write() {
            client.write_tls(&mut buffer).expect("client write");
        }
        if !buffer.is_empty() {
            let started = Instant::now();
            let mut reader = Cursor::new(&buffer[..]);
            while (reader.position() as usize) < buffer.len() {
                server.read_tls(&mut reader).expect("server read");
                server.process_new_packets().expect("server process");
            }
            server_time += started.elapsed();
        }
        buffer.clear();
        let started = Instant::now();
        while server.wants_write() {
            server.write_tls(&mut buffer).expect("server write");
        }
        server_time += started.elapsed();
        if !buffer.is_empty() {
            let mut reader = Cursor::new(&buffer[..]);
            while (reader.position() as usize) < buffer.len() {
                client.read_tls(&mut reader).expect("client read");
                client.process_new_packets().expect("client process");
            }
        }
        if !client.is_handshaking() && !server.is_handshaking() && !server.wants_write() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    let resumed = client.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
    (server_time, resumed)
}

fn measure(
    label: &str,
    server_config: &Arc<rustls::ServerConfig>,
    client_config: &Arc<rustls::ClientConfig>,
    expect_resumed: bool,
) {
    for _ in 0..WARMUP {
        handshake(server_config, client_config);
    }
    let mut samples = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let (spent, resumed) = handshake(server_config, client_config);
        assert_eq!(
            resumed, expect_resumed,
            "{label}: unexpected handshake kind"
        );
        samples.push(spent);
    }
    samples.sort();
    let total: Duration = samples.iter().sum();
    let mean = total / ROUNDS as u32;
    let p50 = samples[ROUNDS / 2];
    let p99 = samples[ROUNDS * 99 / 100];
    println!(
        "{label:<40} rounds={ROUNDS} server_cpu_mean_us={:.1} p50_us={:.1} p99_us={:.1} handshakes_per_core_s={:.0}",
        mean.as_secs_f64() * 1e6,
        p50.as_secs_f64() * 1e6,
        p99.as_secs_f64() * 1e6,
        1.0 / mean.as_secs_f64()
    );
}

fn run(label: &str, certificate_pem: &[u8], key_pem: &[u8]) {
    let full = tunnel_transport::load_server_config_from_pem(certificate_pem, key_pem, None)
        .expect("server config");
    measure(
        &format!("{label} full"),
        &full,
        &client_config(certificate_pem, false),
        false,
    );
    let consumer =
        tunnel_transport::load_consumer_server_config_from_pem(certificate_pem, key_pem, None)
            .expect("consumer config");
    let resuming = client_config(certificate_pem, true);
    // Prime the client's session store with a ticket.
    handshake(&consumer, &resuming);
    measure(
        &format!("{label} resumed (consumer)"),
        &consumer,
        &resuming,
        true,
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("p256 key");
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("params")
        .self_signed(&key)
        .expect("certificate");
    println!(
        "rustls ring provider, TLS 1.3, server CPU per handshake ({ROUNDS} rounds after {WARMUP} warm-up)"
    );
    run(
        "ECDSA P-256",
        certificate.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
    );
    // A certificate and key from files, labelled by the optional third
    // argument (default `RSA-2048`, the key the soak harness uses).
    if let [certificate_path, key_path, rest @ ..] = args.as_slice() {
        let certificate = std::fs::read(certificate_path).expect("certificate file");
        let key = std::fs::read(key_path).expect("key file");
        let label = rest.first().map_or("RSA-2048", String::as_str);
        run(label, &certificate, &key);
    }
}
