//! M6-C231: the production HTTPS adapter authenticates to a real mTLS server.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tunnel_cluster::membership::{MembershipCheckpoint, MembershipIssuer};
use tunnel_relay::{
    ClusterConfig,
    membership_runtime::{
        CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, HttpsCheckpointAuthority,
        MAX_CHECKPOINT_BYTES,
    },
};
use tunnel_transport::load_server_config_from_pem_with_alpn;

const NONCE: &str = "checkpoint-test-nonce-0001";

struct Ca {
    certificate: Certificate,
    key: KeyPair,
}

impl Ca {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self {
            certificate: params.self_signed(&key).unwrap(),
            key,
        }
    }

    fn leaf(&self, client: bool, expired: bool) -> (Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![if client {
            ExtendedKeyUsagePurpose::ClientAuth
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        if expired {
            params.not_before = rcgen::date_time_ymd(2000, 1, 1);
            params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        (
            params
                .signed_by(&key, &self.certificate, &self.key)
                .unwrap(),
            key,
        )
    }
}

struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("checkpoint-mtls-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        // macOS temp_dir commonly begins with the /var symlink. Production
        // TLS material rejects symlink ancestors, so use the resolved fixture
        // directory without weakening that rule.
        Self(fs::canonicalize(path).unwrap())
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(endpoint: &str, ca: &Path) -> ClusterConfig {
    let mut value: toml::Value = toml::from_str(
        r#"
deployment_id = "deployment-a"
peer_bind = "127.0.0.1:8443"
peer_tls_cert_chain = "peer.pem"
peer_tls_private_key = "peer.key"
peer_tls_client_ca = "peer-ca.pem"
membership_signer_trust_path = "signers.json"
checkpoint_authority_endpoint = "https://localhost/checkpoint"
checkpoint_authority_trust_path = "ca.pem"
membership_version_state_path = "state.json"
"#,
    )
    .unwrap();
    value["checkpoint_authority_endpoint"] = endpoint.into();
    value["checkpoint_authority_trust_path"] = ca.to_str().unwrap().into();
    value.try_into().unwrap()
}

fn request() -> CheckpointRequest {
    CheckpointRequest {
        deployment_id: "deployment-a".into(),
        deployment_incarnation: "incarnation-a".into(),
        nonce: NONCE.into(),
    }
}

struct Server {
    endpoint: String,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(ca: &Ca, allowed_client: &Certificate, body: Vec<u8>, delay: Duration) -> Self {
        let (certificate, key) = ca.leaf(false, false);
        let tls = load_server_config_from_pem_with_alpn(
            certificate.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            Some(ca.certificate.pem().as_bytes()),
            &[b"http/1.1"],
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(tls);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}/checkpoint",
            listener.local_addr().unwrap().port()
        );
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&requests);
        let allowed_client = allowed_client.der().to_vec();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    Some(result) = connections.join_next() => { result.unwrap(); }
                    accepted = listener.accept(), if connections.len() < 8 => {
                        let (socket, _) = accepted.unwrap();
                        let acceptor = acceptor.clone();
                        let allowed = allowed_client.clone();
                        let body = body.clone();
                        let observed = Arc::clone(&observed);
                        connections.spawn(async move {
                            let _ = tokio::time::timeout(Duration::from_secs(3), async move {
                                let Ok(tls) = acceptor.accept(socket).await else { return; };
                                let authorized = tls.get_ref().1.peer_certificates().unwrap()[0].as_ref() == allowed;
                                let service = service_fn(move |incoming: Request<Incoming>| {
                                    let body = body.clone();
                                    let observed = Arc::clone(&observed);
                                    async move {
                                        observed.fetch_add(1, Ordering::SeqCst);
                                        assert_eq!(incoming.method(), "POST");
                                        assert_eq!(incoming.uri().path(), "/checkpoint");
                                        let input = incoming.into_body().collect().await.unwrap().to_bytes();
                                        let input: serde_json::Value = serde_json::from_slice(&input).unwrap();
                                        assert_eq!(input, serde_json::to_value(request()).unwrap());
                                        tokio::time::sleep(delay).await;
                                        Ok::<_, Infallible>(Response::builder()
                                            .status(if authorized { 200 } else { 403 })
                                            .body(Full::new(Bytes::from(body))).unwrap())
                                    }
                                });
                                let _ = http1::Builder::new().serve_connection(TokioIo::new(tls), service).await;
                            }).await;
                        });
                    }
                }
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }
}

#[tokio::test]
async fn configured_mtls_requires_trusted_client_and_server_without_fallback() {
    let ca = Ca::new();
    let (client, key) = ca.leaf(true, false);
    let (issuer, _) = MembershipIssuer::generate("authority-a").unwrap();
    let now = Utc::now();
    let signed = issuer
        .sign_checkpoint_bytes(MembershipCheckpoint {
            schema_version: 1,
            deployment_id: "deployment-a".into(),
            deployment_incarnation: "incarnation-a".into(),
            checkpoint_version: 1,
            nonce: NONCE.into(),
            minimum_versions: BTreeMap::from([("node-a".into(), 1)]),
            issued_at: now,
            not_before: now,
            expires_at: now + chrono::Duration::seconds(60),
        })
        .unwrap();
    let server = Server::start(&ca, &client, signed.clone(), Duration::ZERO).await;
    let files = Files::new();
    let mut cfg = config(
        &server.endpoint,
        &files.write("ca.pem", ca.certificate.pem().as_bytes()),
    );
    cfg.checkpoint_authority_client_cert_chain =
        Some(files.write("client.pem", client.pem().as_bytes()));
    cfg.checkpoint_authority_client_private_key =
        Some(files.write("client.key", key.serialize_pem().as_bytes()));
    cfg.validate().unwrap();
    let authority = HttpsCheckpointAuthority::from_cluster_config(&cfg).unwrap();
    assert_eq!(
        authority
            .fetch_checkpoint(request())
            .await
            .unwrap()
            .as_bytes(),
        signed
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);

    // Omitting the optional pair retains the legacy constructor, but cannot
    // get past a server that requires mTLS. There is no server-side downgrade.
    cfg.checkpoint_authority_client_cert_chain = None;
    cfg.checkpoint_authority_client_private_key = None;
    let anonymous = HttpsCheckpointAuthority::from_cluster_config(&cfg).unwrap();
    assert_eq!(
        anonymous.fetch_checkpoint(request()).await.unwrap_err(),
        CheckpointAuthorityError::Transport
    );
    let foreign = Ca::new();
    let (wrong, wrong_key) = foreign.leaf(true, false);
    let (expired, expired_key) = ca.leaf(true, true);
    for (certificate, private_key) in [(&wrong, &wrong_key), (&expired, &expired_key)] {
        let client = HttpsCheckpointAuthority::new_with_client_identity(
            &server.endpoint,
            ca.certificate.pem().as_bytes(),
            certificate.pem().as_bytes(),
            private_key.serialize_pem().as_bytes(),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            client.fetch_checkpoint(request()).await.unwrap_err(),
            CheckpointAuthorityError::Transport
        );
    }
    assert_eq!(
        server.requests.load(Ordering::SeqCst),
        1,
        "untrusted clients reached HTTP"
    );
    let (unapproved, unapproved_key) = ca.leaf(true, false);
    let unapproved = HttpsCheckpointAuthority::new_with_client_identity(
        &server.endpoint,
        ca.certificate.pem().as_bytes(),
        unapproved.pem().as_bytes(),
        unapproved_key.serialize_pem().as_bytes(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(
        unapproved.fetch_checkpoint(request()).await.unwrap_err(),
        CheckpointAuthorityError::HttpStatus(403)
    );
    assert!(!CheckpointAuthorityError::HttpStatus(403).is_shared_outage());

    for (endpoint, trust) in [
        (server.endpoint.clone(), foreign.certificate.pem()),
        (
            server.endpoint.replace("localhost", "127.0.0.1"),
            ca.certificate.pem(),
        ),
    ] {
        let invalid_server = HttpsCheckpointAuthority::new_with_client_identity(
            endpoint,
            trust.as_bytes(),
            client.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            invalid_server
                .fetch_checkpoint(request())
                .await
                .unwrap_err(),
            CheckpointAuthorityError::Transport
        );
    }
    assert_eq!(
        authority
            .fetch_checkpoint(request())
            .await
            .unwrap()
            .as_bytes(),
        signed
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn authenticated_checkpoint_retains_deadline_and_response_bound() {
    let ca = Ca::new();
    let (client, key) = ca.leaf(true, false);
    for (body, delay, expected) in [
        (
            vec![0; MAX_CHECKPOINT_BYTES + 1],
            Duration::ZERO,
            CheckpointAuthorityError::BodyTooLarge,
        ),
        (
            vec![0],
            Duration::from_secs(2),
            CheckpointAuthorityError::DeadlineExceeded,
        ),
    ] {
        let server = Server::start(&ca, &client, body, delay).await;
        let authority = HttpsCheckpointAuthority::new_with_client_identity(
            &server.endpoint,
            ca.certificate.pem().as_bytes(),
            client.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            if delay.is_zero() {
                Duration::from_secs(2)
            } else {
                Duration::from_secs(1)
            },
        )
        .unwrap();
        assert_eq!(
            authority.fetch_checkpoint(request()).await.unwrap_err(),
            expected
        );
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn configured_invalid_identity_is_rejected_without_anonymous_fallback() {
    let ca = Ca::new();
    let (client, key) = ca.leaf(true, false);
    let files = Files::new();
    let mut cfg = config(
        "https://localhost/checkpoint",
        &files.write("ca.pem", ca.certificate.pem().as_bytes()),
    );
    let certificate = files.write("client.pem", client.pem().as_bytes());
    let private_key = files.write("client.key", key.serialize_pem().as_bytes());
    cfg.validate().unwrap();
    assert!(HttpsCheckpointAuthority::from_cluster_config(&cfg).is_ok());
    for (chain, key) in [
        (Some(certificate.clone()), None),
        (None, Some(private_key.clone())),
    ] {
        cfg.checkpoint_authority_client_cert_chain = chain;
        cfg.checkpoint_authority_client_private_key = key;
        assert!(cfg.validate().is_err());
        assert_eq!(
            HttpsCheckpointAuthority::from_cluster_config(&cfg).unwrap_err(),
            CheckpointAuthorityError::InvalidClientIdentity
        );
    }
    cfg.checkpoint_authority_client_cert_chain = Some(certificate);
    for path in [
        files.0.join("missing.key"),
        files.write("malformed.key", b"synthetic-invalid-key"),
        files.write(
            "mismatched.key",
            KeyPair::generate().unwrap().serialize_pem().as_bytes(),
        ),
    ] {
        cfg.checkpoint_authority_client_private_key = Some(path);
        assert_eq!(
            HttpsCheckpointAuthority::from_cluster_config(&cfg).unwrap_err(),
            CheckpointAuthorityError::InvalidClientIdentity
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let link = files.0.join("symlink.key");
        symlink(&private_key, &link).unwrap();
        cfg.checkpoint_authority_client_private_key = Some(link);
        assert_eq!(
            HttpsCheckpointAuthority::from_cluster_config(&cfg).unwrap_err(),
            CheckpointAuthorityError::InvalidClientIdentity
        );
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o644)).unwrap();
        cfg.checkpoint_authority_client_private_key = Some(private_key);
        assert_eq!(
            HttpsCheckpointAuthority::from_cluster_config(&cfg).unwrap_err(),
            CheckpointAuthorityError::InvalidClientIdentity
        );
    }
    assert!(!CheckpointAuthorityError::InvalidClientIdentity.is_shared_outage());
}
