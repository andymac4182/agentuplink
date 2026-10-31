//! M6-C234: the real authority process publishes to TLS Redis and serves three
//! configured relay processes over mandatory, independently approved mTLS.
//! This is localhost process acceptance, not an external deployment proof.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tunnel_catalog::{Catalog, OwnerToken, RedisCatalog};
use tunnel_client::{
    ConnectConfig, ConnectOptions, ConnectionHandle, CredentialConfig, LimitsConfig, LocalExport,
    LocalExportKind, SessionInfo, connect,
};
use tunnel_cluster::membership::{
    MembershipPolicy, MembershipVerifier, MembershipVersionState, PrivateEndpointPolicy,
    SignedMembershipCheckpoint, TrustedPublisherKey,
};
use tunnel_relay::membership_runtime::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, HttpsCheckpointAuthority,
};
use tunnel_test_harness::{
    CertificateMaterial, ClusterFixture, FixturePki, FixtureTopology, ManagedProcess, OidcFixture,
    ProcessSpec,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/authority_fault_proxy.rs"]
mod authority_fault_proxy;
#[path = "common/m7_deployment.rs"]
mod common;
#[path = "m6_online_authority/recovery.rs"]
mod recovery;
use authority_fault_proxy::FaultProxy;
use common::{
    FixtureFiles, ProcessConfigFixture, RedisTlsProxy, free_tcp_addr, jwks_json,
    parse_plaintext_upstream, relay_binary_path, toml_path, toml_string, wait_for_exit,
    wait_for_ready,
};

type GateResult<T = ()> = Result<T, &'static str>;
const IO_BOUND: Duration = Duration::from_secs(2);
const PROCESS_BOUND: Duration = Duration::from_secs(8);
const PUBLISH_BOUND: Duration = Duration::from_secs(25);
const SCENARIO_BOUND: Duration = Duration::from_secs(240);
const CANARY: &str = "m6-online-authority-device-canary";
const EXCHANGE_BOUND: Duration = Duration::from_secs(8);

fn require(condition: bool, message: &'static str) -> GateResult {
    if condition { Ok(()) } else { Err(message) }
}

fn authority_binary() -> GateResult<PathBuf> {
    if let Some(path) = env::var_os("TUNNEL_AUTHORITY_BIN") {
        let path = PathBuf::from(path);
        return if path.is_file() {
            Ok(path)
        } else {
            Err("TUNNEL_AUTHORITY_BIN is not a file")
        };
    }
    let executable = env::current_exe().map_err(|_| "test executable path")?;
    let directory = executable.parent().ok_or("test executable directory")?;
    [
        directory.join("tunnel-authority"),
        directory
            .parent()
            .ok_or("test target directory")?
            .join("tunnel-authority"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or("build tunnel-authority before running this gate")
}

async fn command(binary: &Path, args: &[String]) -> GateResult {
    let mut spec = ProcessSpec::new(binary);
    for arg in args {
        spec = spec.arg(arg);
    }
    let mut process = ManagedProcess::spawn("m6-authority-offline-command", spec)
        .await
        .map_err(|_| "start offline command")?;
    let status = wait_for_exit(&mut process, PROCESS_BOUND)
        .await
        .map_err(|_| "offline command deadline");
    let safe = !process
        .stdout()
        .windows(10)
        .any(|part| part == b"-----BEGIN")
        && !process
            .stderr()
            .windows(10)
            .any(|part| part == b"-----BEGIN");
    process
        .shutdown(Duration::from_millis(100))
        .await
        .map_err(|_| "reap offline command")?;
    require(
        status?.success() && safe,
        "offline authority or relay command refused or leaked key material",
    )
}

struct Relay {
    node_id: String,
    config: PathBuf,
    version_state: PathBuf,
    consumer: SocketAddr,
    device: SocketAddr,
    identity: CertificateMaterial,
}

struct Fixture {
    files: FixtureFiles,
    pki: FixturePki,
    authority_binary: PathBuf,
    relay_binary: PathBuf,
    config: PathBuf,
    state: PathBuf,
    inventory: Value,
    endpoint: String,
    deployment: String,
    incarnation: String,
    redis_run: String,
    trusted_key: TrustedPublisherKey,
    peer_ports: Vec<u16>,
    relays: Vec<Relay>,
    authority: Option<ManagedProcess>,
    relay_processes: Vec<ManagedProcess>,
    proxy: Option<RedisTlsProxy>,
    client_config: ConnectConfig,
    connector: Option<ConnectionHandle>,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    consumer_token: String,
    // Retain the exact seeded identities for the separate recovery drill;
    // regenerating catalog_fixture would allocate different credential IDs.
    topology: FixtureTopology,
    oidc: OidcFixture,
    records: tunnel_catalog::CatalogFixture,
}

#[derive(PartialEq, Eq)]
struct SessionEvidence {
    owner: OwnerToken,
    session: SessionInfo,
    connection_id: String,
    relay_pids: Vec<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayVersionEnvelope {
    schema_version: u16,
    deployment_id: String,
    deployment_incarnation: String,
    node_id: String,
    state: MembershipVersionState,
}

impl Fixture {
    async fn create(
        upstream: SocketAddr,
        namespace: &str,
        username: &str,
        password: &str,
        redis_run: String,
        catalog: &RedisCatalog,
    ) -> GateResult<Self> {
        let authority_binary = authority_binary()?;
        let relay_binary =
            relay_binary_path().map_err(|_| "build tunnel-relay before running this gate")?;
        let files = FixtureFiles::new().map_err(|_| "private fixture directory")?;
        let pki = FixturePki::new().map_err(|_| "fixture PKI")?;
        let deployment = format!("authority-deployment-{}", Uuid::new_v4().simple());
        let incarnation = "authority-incarnation-a".to_owned();
        let mut cluster = ClusterFixture::with_deployment(&pki, &deployment, &incarnation)
            .map_err(|_| "three relay fixture")?;
        let peer_ports: Vec<_> = cluster
            .nodes
            .iter()
            .map(|node| node.addresses.udp.port())
            .collect();
        let state = files.state_path().map_err(|_| "authority state path")?;
        let signing = state.with_file_name("membership-signing.der");
        let trust = state.with_file_name("membership-trust.json");
        command(
            &authority_binary,
            &[
                "generate-key".into(),
                "--key-id".into(),
                "online-authority-test".into(),
                "--private-key".into(),
                signing.display().to_string(),
                "--public-keys".into(),
                trust.display().to_string(),
                "--purpose".into(),
                "membership".into(),
            ],
        )
        .await?;
        let trust_document: Value =
            serde_json::from_slice(&fs::read(&trust).map_err(|_| "read emitted public trust")?)
                .map_err(|_| "decode emitted public trust")?;
        require(
            trust_document.get("schema_version").is_none(),
            "membership trust used recovery document shape",
        )?;
        let public = trust_document["keys"][0]["public_key"]
            .as_str()
            .ok_or("emitted public key")?;
        require(public.len() == 64, "emitted public key length")?;
        let decoded: Vec<u8> = (0..public.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&public[offset..offset + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(|_| "emitted key encoding")?;
        let trusted_key = TrustedPublisherKey::new(
            "online-authority-test",
            decoded
                .try_into()
                .map_err(|_| "emitted public key length")?,
        )
        .map_err(|_| "emitted publisher trust")?;
        let now = Utc::now();
        let mut nodes = Vec::new();
        for node in &cluster.nodes {
            let spki = node
                .peer_spki_fingerprint()
                .map_err(|_| "relay peer SPKI")?;
            nodes.push(json!({
                "node_id": node.node_id, "peer_endpoint": node.addresses.udp.to_string(), "server_name": "localhost",
                "keys": [{"key_id": format!("{}-key", node.node_id), "spki_sha256": spki,
                    "not_before": now - chrono::Duration::minutes(1), "expires_at": now + chrono::Duration::hours(1), "revoked": false}],
                "checkpoint_client_spkis": [spki],
            }));
        }
        let inventory = json!({"schema_version": 1, "deployment_id": deployment, "redis_namespace": namespace,
            "deployment_incarnation": incarnation, "revision": 1, "publisher_key_id": "online-authority-test",
            "publisher_public_key": public, "nodes": nodes});
        let redis_leaf = pki
            .issue_server("online-authority-redis")
            .map_err(|_| "Redis TLS leaf")?;
        let redis_tls = load_server_config_from_pem(
            redis_leaf.certificate_pem.as_bytes(),
            redis_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|_| "Redis TLS server")?;
        let proxy = RedisTlsProxy::bind(upstream, redis_tls)
            .await
            .map_err(|_| "Redis TLS proxy")?;
        let relay_redis = proxy.url();
        let authority_redis =
            relay_redis.replacen("rediss://", &format!("rediss://{username}:{password}@"), 1);
        let redis_url = files
            .write("redis-url.txt", authority_redis.as_bytes())
            .map_err(|_| "private Redis credential file")?;
        let ca = files
            .write("server-ca.pem", pki.server_ca.certificate_pem.as_bytes())
            .map_err(|_| "server CA file")?;
        let peer_ca = files
            .write("peer-ca.pem", pki.peer_ca.certificate_pem.as_bytes())
            .map_err(|_| "peer CA file")?;
        let device_ca = files
            .write("device-ca.pem", pki.device_ca.certificate_pem.as_bytes())
            .map_err(|_| "device CA file")?;
        let server = pki
            .issue_server("online-authority")
            .map_err(|_| "authority TLS identity")?;
        let authority_cert = files
            .write("authority.pem", server.certificate_pem.as_bytes())
            .map_err(|_| "authority certificate file")?;
        let authority_key = files
            .write("authority.key", server.private_key_pem.as_bytes())
            .map_err(|_| "authority TLS key file")?;
        let bind = free_tcp_addr();
        let endpoint = format!("https://localhost:{}/v1/checkpoint", bind.port());
        let ports = peer_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "schema_version = 1\nbind = {}\nstate_path = {}\nsigning_key_path = {}\nredis_url_path = {}\nredis_ca_path = {}\ntls_cert_chain = {}\ntls_private_key = {}\ntls_client_ca = {}\n[endpoint_policy]\nallowed_hosts = [\"127.0.0.1\"]\nallowed_server_names = [\"localhost\"]\nallowed_ports = [{ports}]\n",
            toml_string(&bind.to_string()),
            toml_path(&state),
            toml_path(&signing),
            toml_path(&redis_url),
            toml_path(&ca),
            toml_path(&authority_cert),
            toml_path(&authority_key),
            toml_path(&peer_ca)
        );
        let config = files
            .write("authority.toml", config.as_bytes())
            .map_err(|_| "authority config file")?;

        let oidc = OidcFixture::new("https://online-authority-oidc.invalid", "agent-tunnel")
            .map_err(|_| "OIDC fixture")?;
        let topology = FixtureTopology::new(&pki).map_err(|_| "device and consumer fixture")?;
        let records = topology
            .catalog_fixture(&oidc)
            .map_err(|_| "authorized catalog fixture")?;
        catalog
            .seed_fixture(&records)
            .await
            .map_err(|_| "seed actual device and consumer authorization")?;
        let device = topology.devices_a.first().ok_or("device fixture missing")?;
        let service_id = *topology
            .service_ids
            .get(&device.id)
            .ok_or("device service missing")?;
        let consumer = topology
            .consumers_a
            .first()
            .ok_or("consumer fixture missing")?;
        let consumer_token = oidc
            .issue_for_tenant(&consumer.name, consumer.tenant_id)
            .map_err(|_| "consumer token")?;
        let jwks = files
            .write(
                "jwks.json",
                jwks_json(&oidc).map_err(|_| "fixture JWKS")?.as_bytes(),
            )
            .map_err(|_| "JWKS file")?;
        let server = pki
            .issue_server("online-authority-relay")
            .map_err(|_| "relay server identity")?;
        let server_cert = files
            .write("relay-server.pem", server.certificate_pem.as_bytes())
            .map_err(|_| "relay certificate")?;
        let server_key = files
            .write("relay-server.key", server.private_key_pem.as_bytes())
            .map_err(|_| "relay private key")?;
        let mut relays = Vec::new();
        for node in &mut cluster.nodes {
            let peer_cert = files
                .write(
                    &format!("{}-peer.pem", node.node_id),
                    node.peer_certificate_chain_pem().as_bytes(),
                )
                .map_err(|_| "peer certificate file")?;
            let peer_key = files
                .write(
                    &format!("{}-peer.key", node.node_id),
                    node.peer_certificate.private_key_pem.as_bytes(),
                )
                .map_err(|_| "peer key file")?;
            let relay_state = state.with_file_name(format!("{}-versions.json", node.node_id));
            let consumer = node.addresses.tcp;
            let device = free_tcp_addr();
            let config = ProcessConfigFixture {
                consumer_bind: consumer, device_bind: device, peer_bind: node.addresses.udp,
                redis_url: &relay_redis, namespace, deployment_id: &deployment, deployment_incarnation: &incarnation,
                oidc: &oidc, oidc_jwks_path: &jwks, server_chain_path: &server_cert, server_key_path: &server_key,
                server_ca_path: &ca, device_ca_path: &device_ca, peer_chain_path: &peer_cert, peer_key_path: &peer_key,
                peer_ca_path: &peer_ca, signer_trust_path: &trust, state_path: &relay_state,
                checkpoint_endpoint: &endpoint, node_id: &node.node_id,
            }.render().replace("[cluster.endpoint_policy]", &format!("checkpoint_authority_client_cert_chain = {}\ncheckpoint_authority_client_private_key = {}\n\n[cluster.endpoint_policy]", toml_path(&peer_cert), toml_path(&peer_key)))
                .replace(&format!("allowed_ports = [{}]", node.addresses.udp.port()), &format!("allowed_ports = [{ports}]"));
            let config = files
                .write(&format!("{}.toml", node.node_id), config.as_bytes())
                .map_err(|_| "relay config file")?;
            relays.push(Relay {
                node_id: node.node_id.clone(),
                config,
                version_state: relay_state,
                consumer,
                device,
                identity: node.peer_certificate.clone(),
            });
            node.release_ports();
        }
        let client_certificate = files
            .write(
                "device.pem",
                format!(
                    "{}{}",
                    device.certificate.certificate_pem, pki.device_ca.certificate_pem
                )
                .as_bytes(),
            )
            .map_err(|_| "device certificate file")?;
        let client_key = files
            .write("device.key", device.certificate.private_key_pem.as_bytes())
            .map_err(|_| "device key file")?;
        let client_config = ConnectConfig {
            device_id: device.id.to_string(),
            relay_url: format!(
                "wss://localhost:{}/v1/tunnel/control",
                relays[1].device.port()
            ),
            credentials: CredentialConfig {
                client_certificate,
                client_key,
                server_ca: ca,
                pinned: None,
            },
            exports: BTreeMap::from([(
                service_id.to_string(),
                LocalExport {
                    kind: LocalExportKind::Echo,
                    device_canary: Some(CANARY.into()),
                    mcp: None,
                    acp: None,
                    fs: None,
                    cua: None,
                },
            )]),
            limits: LimitsConfig::default(),
            rotation: Default::default(),
            reconnect: Default::default(),
            supervisor: Default::default(),
        };
        client_config
            .validate()
            .map_err(|_| "device connector config")?;
        let fixture = Self {
            files,
            pki,
            authority_binary,
            relay_binary,
            config,
            state,
            inventory,
            endpoint,
            deployment,
            incarnation,
            redis_run,
            trusted_key,
            peer_ports,
            relays,
            authority: None,
            relay_processes: Vec::new(),
            proxy: Some(proxy),
            client_config,
            connector: None,
            tenant_id: device.tenant_id,
            device_id: device.id,
            service_id,
            consumer_token,
            topology,
            oidc,
            records,
        };
        fixture.approve(true, 0).await?;
        command(
            &fixture.authority_binary,
            &[
                "check-config".into(),
                "--config".into(),
                fixture.config.display().to_string(),
            ],
        )
        .await?;
        Ok(fixture)
    }

    async fn approve(&self, initial: bool, expected_revision: u64) -> GateResult {
        let inventory = self
            .files
            .write(
                "inventory.json",
                &serde_json::to_vec(&self.inventory).map_err(|_| "inventory encoding")?,
            )
            .map_err(|_| "independent inventory file")?;
        let mut args = vec![
            if initial {
                "initialize-membership"
            } else {
                "approve-membership"
            }
            .into(),
            "--config".into(),
            self.config.display().to_string(),
            "--inventory".into(),
            inventory.display().to_string(),
            "--expected-redis-run-id".into(),
            self.redis_run.clone(),
        ];
        if !initial {
            args.extend(["--expected-revision".into(), expected_revision.to_string()]);
        }
        command(&self.authority_binary, &args).await
    }

    fn client(&self, identity: &CertificateMaterial) -> GateResult<HttpsCheckpointAuthority> {
        HttpsCheckpointAuthority::new_with_client_identity(
            &self.endpoint,
            self.pki.server_ca.certificate_pem.as_bytes(),
            identity.certificate_pem.as_bytes(),
            identity.private_key_pem.as_bytes(),
            IO_BOUND,
        )
        .map_err(|_| "checkpoint client identity")
    }

    fn request(&self) -> CheckpointRequest {
        CheckpointRequest {
            deployment_id: self.deployment.clone(),
            deployment_incarnation: self.incarnation.clone(),
            nonce: Uuid::new_v4().simple().to_string(),
        }
    }

    async fn checkpoint(
        &self,
        client: &HttpsCheckpointAuthority,
    ) -> GateResult<Option<SignedMembershipCheckpoint>> {
        let request = self.request();
        let nonce = request.nonce.clone();
        let bytes = match client.fetch_checkpoint(request).await {
            Ok(bytes) => bytes,
            Err(CheckpointAuthorityError::HttpStatus(503 | 429)) => return Ok(None),
            Err(_) => return Err("checkpoint transport or unexpected HTTP refusal"),
        };
        let endpoints = PrivateEndpointPolicy::allowlisted(
            ["127.0.0.1"],
            ["localhost"],
            self.peer_ports.clone(),
        )
        .map_err(|_| "verification endpoints")?;
        let policy = MembershipPolicy::new(&self.deployment, &self.incarnation, endpoints)
            .map_err(|_| "verification policy")?;
        MembershipVerifier::new(policy, [self.trusted_key.clone()])
            .map_err(|_| "independent verifier")?
            .verify_checkpoint(bytes.as_bytes(), &nonce, Utc::now())
            .map_err(|_| "service checkpoint failed existing verifier")?;
        serde_json::from_slice(bytes.as_bytes())
            .map(Some)
            .map_err(|_| "signed checkpoint shape")
    }

    async fn wait_checkpoint(
        &self,
        client: &HttpsCheckpointAuthority,
    ) -> GateResult<SignedMembershipCheckpoint> {
        timeout(PUBLISH_BOUND, async {
            loop {
                if let Some(checkpoint) = self.checkpoint(client).await? {
                    return Ok(checkpoint);
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "publication did not become usable before bound")?
    }

    fn state(&self) -> GateResult<Value> {
        serde_json::from_slice(&fs::read(&self.state).map_err(|_| "read independent state")?)
            .map_err(|_| "decode independent state")
    }

    async fn start_authority(&mut self) -> GateResult {
        require(self.authority.is_none(), "authority process already owned")?;
        self.authority = Some(
            ManagedProcess::spawn(
                "m6-online-authority",
                ProcessSpec::new(&self.authority_binary)
                    .arg("serve")
                    .arg("--config")
                    .arg(self.config.display().to_string()),
            )
            .await
            .map_err(|_| "start authority process")?,
        );
        let process = self.authority.as_mut().ok_or("owned authority missing")?;
        timeout(PROCESS_BOUND, async {
            loop {
                if process
                    .try_wait()
                    .map_err(|_| "authority process status")?
                    .is_some()
                {
                    return Err("authority exited before listener start");
                }
                if String::from_utf8_lossy(&process.stderr()).contains("authority_started") {
                    return Ok::<(), &'static str>(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "authority startup deadline")?
    }

    async fn stop_authority(&mut self) -> GateResult {
        let Some(mut process) = self.authority.take() else {
            return Ok::<(), &'static str>(());
        };
        let signal = process
            .request_stop()
            .await
            .map_err(|_| "signal authority stop");
        let status = process
            .shutdown(PROCESS_BOUND)
            .await
            .map_err(|_| "authority stop/reap")?;
        signal?;
        require(status.success(), "authority did not stop successfully")
    }

    async fn start_relays(&mut self) -> GateResult {
        for relay in &self.relays {
            command(
                &self.relay_binary,
                &[
                    "initialize".into(),
                    "--config".into(),
                    relay.config.display().to_string(),
                ],
            )
            .await?;
            let process = ManagedProcess::spawn(
                "m6-authority-relay",
                common::relay_serve_process_spec(&self.relay_binary)
                    .arg("--config")
                    .arg(relay.config.display().to_string()),
            )
            .await
            .map_err(|_| "start real relay")?;
            self.relay_processes.push(process);
        }
        // Required peer-route readiness depends on every approved node. All
        // three listeners must be running before any readiness wait starts.
        for (relay, process) in self.relays.iter().zip(&mut self.relay_processes) {
            wait_for_ready(process, relay.consumer, &self.pki.server_ca.certificate_der)
                .await
                .map_err(|_| "real relay failed mTLS authority readiness")?;
        }
        require(
            self.relay_processes.len() == 3,
            "three relay processes did not reach readiness",
        )
    }

    async fn stop_relays(&mut self) -> GateResult {
        let mut failed = false;
        for mut process in self.relay_processes.drain(..) {
            failed |= process.request_stop().await.is_err();
            failed |= !process
                .shutdown(PROCESS_BOUND)
                .await
                .is_ok_and(|status| status.success());
        }
        require(!failed, "relay process cleanup failed")
    }

    async fn connect_device(&mut self) -> GateResult {
        self.connector = Some(
            timeout(
                PROCESS_BOUND,
                connect(ConnectOptions::new(self.client_config.clone())),
            )
            .await
            .map_err(|_| "device connection deadline")?
            .map_err(|_| "device connection")?,
        );
        let session = timeout(
            PROCESS_BOUND,
            self.connector
                .as_mut()
                .ok_or("device handle missing")?
                .wait_ready(),
        )
        .await
        .map_err(|_| "device readiness deadline")?
        .map_err(|_| "device readiness")?;
        require(
            session.generation > 0,
            "device started without active data generation",
        )
    }

    async fn session_evidence(&self, catalog: &RedisCatalog) -> GateResult<SessionEvidence> {
        let owner = catalog
            .current_owner(self.tenant_id, self.device_id, Utc::now())
            .await
            .map_err(|_| "read real device owner")?
            .ok_or("device owner lease disappeared")?
            .token;
        require(
            owner.node_id == "relay-b" && owner.deployment_incarnation == self.incarnation,
            "device ownership did not stay on the non-ingress relay",
        )?;
        let status = self
            .connector
            .as_ref()
            .ok_or("device connector missing")?
            .status_snapshot();
        let session = SessionInfo {
            session_id: status.session_id.ok_or("device session closed")?,
            epoch: status.epoch.ok_or("device epoch missing")?,
            generation: status
                .active_generation
                .ok_or("device data generation closed")?,
        };
        require(
            owner.session_id == session.session_id
                && owner.epoch == session.epoch
                && session.generation > 0,
            "catalog ownership and actual device session differ",
        )?;
        Ok(SessionEvidence {
            owner,
            session,
            connection_id: status
                .active_connection_id
                .ok_or("active device socket identity missing")?,
            relay_pids: self
                .relay_processes
                .iter()
                .map(|process| {
                    process
                        .id()
                        .ok_or("relay process exited during continuity check")
                })
                .collect::<GateResult<_>>()?,
        })
    }

    fn relays_adopted(&self, target: &SignedMembershipCheckpoint) -> GateResult<bool> {
        const MAX_BYTES: usize =
            tunnel_relay::membership_version_state::MAX_MEMBERSHIP_VERSION_STATE_BYTES;
        let mut adopted = true;
        for relay in &self.relays {
            // The running relay owns the exclusive writer lock. Read only
            // its atomically replaced, bounded public version envelope.
            let mut bytes = Vec::new();
            fs::File::open(&relay.version_state)
                .map_err(|_| "open relay version evidence")?
                .take((MAX_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "read relay version evidence")?;
            require(
                bytes.len() <= MAX_BYTES,
                "relay version evidence exceeded its byte bound",
            )?;
            let envelope: RelayVersionEnvelope =
                serde_json::from_slice(&bytes).map_err(|_| "relay version evidence schema")?;
            require(
                envelope.schema_version == 1
                    && envelope.deployment_id == self.deployment
                    && envelope.deployment_incarnation == self.incarnation
                    && envelope.node_id == relay.node_id,
                "relay version evidence identity mismatch",
            )?;
            // A checkpoint fence is saved before the Redis records are read.
            // Requiring every node fence too proves verified record adoption,
            // rather than merely a successful new checkpoint fetch.
            adopted &= envelope
                .state
                .checkpoint_version
                .is_some_and(|version| version >= target.checkpoint_version)
                && target.minimum_versions.iter().all(|(node, minimum)| {
                    envelope
                        .state
                        .node_versions
                        .get(node)
                        .is_some_and(|version| version >= minimum)
                });
        }
        Ok(adopted)
    }

    async fn wait_relay_adoption(
        &mut self,
        target: &SignedMembershipCheckpoint,
        catalog: &RedisCatalog,
        original: &SessionEvidence,
    ) -> GateResult {
        timeout(PUBLISH_BOUND, async {
            loop {
                self.canary("relay-adoption-after-authority-restart")
                    .await?;
                require(
                    &self.session_evidence(catalog).await? == original,
                    "device continuity changed while relays adopted recovered authority trust",
                )?;
                if self.relays_adopted(target)? {
                    break;
                }
                sleep(Duration::from_millis(250)).await;
            }
            for (relay, process) in self.relays.iter().zip(&mut self.relay_processes) {
                wait_for_ready(process, relay.consumer, &self.pki.server_ca.certificate_der)
                    .await
                    .map_err(|_| "relay was not ready after persisting recovered trust")?;
            }
            self.canary("all-three-relays-adopted-recovered-trust")
                .await?;
            require(
                &self.session_evidence(catalog).await? == original,
                "device continuity changed after every relay adopted recovered trust",
            )
        })
        .await
        .map_err(|_| "three-relay adoption exceeded the refresh bound")?
    }

    async fn canary(&self, phase: &str) -> GateResult {
        self.canary_with_token(phase, &self.consumer_token, false)
            .await
    }

    async fn canary_with_token(&self, phase: &str, token: &str, denied: bool) -> GateResult {
        let mut payload = vec![0, 0xff, 0x80, 0x7f];
        payload.extend_from_slice(phase.as_bytes());
        payload.extend_from_slice(Uuid::new_v4().as_bytes());
        let mut expected = CANARY.as_bytes().to_vec();
        expected.extend_from_slice(&payload);
        let exchange = async {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(
                    self.pki.server_ca.certificate_der.clone(),
                ))
                .map_err(|_| "canary server root")?;
            let mut tls = ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "canary TLS policy")?
            .with_root_certificates(roots)
            .with_no_client_auth();
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            let socket = tokio::net::TcpStream::connect(self.relays[0].consumer)
                .await
                .map_err(|_| "non-owner consumer TCP")?;
            let socket = TlsConnector::from(Arc::new(tls))
                .connect(
                    ServerName::try_from("localhost").map_err(|_| "canary server name")?,
                    socket,
                )
                .await
                .map_err(|_| "non-owner consumer TLS")?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(socket))
                    .await
                    .map_err(|_| "canary HTTP handshake")?;
            let task = EchoTask(Some(tokio::spawn(async move {
                let _ = connection.await;
            })));
            let result = async {
                let request = Request::builder()
                    .method("POST")
                    .uri(format!(
                        "https://localhost/v1/devices/{}/services/{}/echo",
                        self.device_id, self.service_id
                    ))
                    .header("host", "localhost")
                    .header("connection", "close")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/octet-stream")
                    .body(Full::new(Bytes::from(payload)))
                    .map_err(|_| "canary HTTP request")?;
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(|_| "canary HTTP response")?;
                let status = response.status().as_u16();
                let body = Limited::new(response.into_body(), 4096)
                    .collect()
                    .await
                    .map_err(|_| "bounded canary response body")?
                    .to_bytes();
                if denied {
                    require(
                        matches!(status, 403 | 404) && body.as_ref() != expected,
                        "revoked grant did not produce an authorization denial",
                    )
                } else {
                    require(status == 200, "non-owner public canary was refused")?;
                    require(
                        body.as_ref() == expected,
                        "non-owner public canary differed from exact binary request and device prefix",
                    )
                }
            }
            .await;
            let cleanup = task.shutdown().await;
            result.and(cleanup)
        };
        timeout(EXCHANGE_BOUND, exchange)
            .await
            .map_err(|_| "non-owner public canary exceeded exchange deadline")?
    }

    async fn stop_device(&mut self) -> GateResult {
        if let Some(connector) = self.connector.take() {
            timeout(PROCESS_BOUND, connector.stop())
                .await
                .map_err(|_| "device shutdown deadline")?
                .map_err(|_| "device did not stop cleanly")?;
        }
        Ok(())
    }

    async fn cleanup(mut self) -> GateResult {
        let device = self.stop_device().await;
        let relays = self.stop_relays().await;
        let authority = self.stop_authority().await;
        let proxy = if let Some(proxy) = self.proxy.take() {
            proxy
                .shutdown()
                .await
                .map_err(|_| "Redis TLS proxy cleanup")
        } else {
            Ok(())
        };
        device.and(relays).and(authority).and(proxy)
    }
}

struct EchoTask(Option<tokio::task::JoinHandle<()>>);

impl EchoTask {
    async fn shutdown(mut self) -> GateResult {
        let Some(task) = self.0.take() else {
            return Ok::<(), &'static str>(());
        };
        task.abort();
        match timeout(IO_BOUND, task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            _ => Err("canary connection task did not join"),
        }
    }
}

impl Drop for EchoTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

async fn publication_permission(
    admin: &mut redis::aio::MultiplexedConnection,
    username: &str,
    allowed: bool,
) -> GateResult {
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(username)
        .arg(if allowed { "+hset" } else { "-hset" })
        .query_async::<()>(admin)
        .await
        .map_err(|_| "change isolated publisher write permission")
}

async fn wait_spent_round(fixture: &Fixture, previous: u64) -> GateResult {
    timeout(PUBLISH_BOUND, async {
        loop {
            if fixture.state()?["membership_high_water"]
                .as_u64()
                .is_some_and(|current| current > previous)
            {
                return Ok::<(), &'static str>(());
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "failed publication did not spend a durable round")?
}

async fn run_scenario(
    fixture: &mut Fixture,
    admin: &mut redis::aio::MultiplexedConnection,
    username: &str,
    catalog: &RedisCatalog,
) -> GateResult {
    fixture.start_authority().await?;
    let client = fixture.client(&fixture.relays[0].identity)?;
    let first = fixture.wait_checkpoint(&client).await?;
    require(
        first.minimum_versions.len() == 3,
        "checkpoint omitted approved relay",
    )?;
    let memberships = catalog
        .read_signed_memberships()
        .await
        .map_err(|_| "read actual published memberships")?;
    require(
        memberships.len() == 3
            && memberships.iter().all(|record| {
                first
                    .minimum_versions
                    .values()
                    .all(|version| *version == record.version)
            }),
        "checkpoint did not confirm all Redis memberships",
    )?;

    let anonymous = HttpsCheckpointAuthority::new(
        &fixture.endpoint,
        fixture.pki.server_ca.certificate_pem.as_bytes(),
        IO_BOUND,
    )
    .map_err(|_| "anonymous client fixture")?;
    require(
        matches!(
            anonymous.fetch_checkpoint(fixture.request()).await,
            Err(CheckpointAuthorityError::Transport)
        ),
        "anonymous client bypassed mandatory mTLS",
    )?;
    let foreign = FixturePki::new()
        .map_err(|_| "foreign PKI")?
        .issue_peer("relay-a")
        .map_err(|_| "foreign client")?;
    require(
        matches!(
            fixture
                .client(&foreign)?
                .fetch_checkpoint(fixture.request())
                .await,
            Err(CheckpointAuthorityError::Transport)
        ),
        "foreign CA client reached HTTP",
    )?;
    for identity in [
        fixture
            .pki
            .issue_peer("unknown-relay")
            .map_err(|_| "unknown-node client")?,
        fixture
            .pki
            .issue_peer("relay-a")
            .map_err(|_| "wrong-SPKI client")?,
        fixture
            .pki
            .issue_device_signed_by_peer_ca(Uuid::new_v4(), Uuid::new_v4())
            .map_err(|_| "wrong-role client")?,
    ] {
        require(
            matches!(
                fixture
                    .client(&identity)?
                    .fetch_checkpoint(fixture.request())
                    .await,
                Err(CheckpointAuthorityError::HttpStatus(403))
            ),
            "current node, role or SPKI authorization was bypassed",
        )?;
    }
    fixture.start_relays().await?;
    fixture.connect_device().await?;
    let original_session = fixture.session_evidence(catalog).await?;
    fixture.canary("initial-public-through-relay-a").await?;
    eprintln!(
        "online authority: three real relays ready; exact public canary entered relay-a and reached device owned by relay-b"
    );

    // Keep one actual control/data session across two complete publication
    // refreshes. A fresh request body is required at every observation; a
    // recreated connector, owner epoch, socket or relay process cannot pass.
    let before_refreshes = fixture.wait_checkpoint(&client).await?;
    let mut last_confirmed_minimum = before_refreshes.minimum_versions["relay-a"];
    let mut observed_refreshes = 0;
    let refreshed = timeout(Duration::from_secs(55), async {
        loop {
            fixture
                .canary("continuous-two-publication-refreshes")
                .await?;
            require(
                fixture.session_evidence(catalog).await? == original_session,
                "device owner/session/socket or relay process changed across refreshes",
            )?;
            if let Some(response) = fixture.checkpoint(&client).await? {
                let minimum = response.minimum_versions["relay-a"];
                require(
                    minimum >= last_confirmed_minimum,
                    "confirmed membership minimum rolled back",
                )?;
                if minimum > last_confirmed_minimum {
                    last_confirmed_minimum = minimum;
                    observed_refreshes += 1;
                    if observed_refreshes == 2 {
                        return Ok::<_, &'static str>(response);
                    }
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(
        |_| "continuous publisher did not confirm two refreshes with a live device session",
    )??;

    // Healthy authority restart: the relays and connector remain untouched.
    // Cached bounded trust carries a fresh cross-relay exchange while the
    // authority is stopped; new publication then restores the authority.
    fixture.stop_authority().await?;
    fixture
        .canary("authority-stopped-same-device-session")
        .await?;
    require(
        fixture.session_evidence(catalog).await? == original_session,
        "healthy authority stop changed device ownership or carrier",
    )?;
    fixture.start_authority().await?;
    let after_healthy_restart = fixture.wait_checkpoint(&client).await?;
    require(
        after_healthy_restart.minimum_versions["relay-a"] > refreshed.minimum_versions["relay-a"]
            && after_healthy_restart.checkpoint_version > refreshed.checkpoint_version,
        "healthy authority restart did not produce fresh publication and checkpoint",
    )?;
    fixture
        .canary("authority-recovered-same-device-session")
        .await?;
    require(
        fixture.session_evidence(catalog).await? == original_session,
        "healthy authority recovery recreated device owner/session/socket or relay process",
    )?;
    fixture
        .wait_relay_adoption(&after_healthy_restart, catalog, &original_session)
        .await?;
    eprintln!(
        "online authority: exact public canaries survived two refreshes, authority stop, and persisted new-checkpoint/all-node adoption by all3 ready relays with unchanged owner/session/epoch/generation/socket and three relay PIDs"
    );
    fixture.stop_device().await?;
    fixture.stop_relays().await?;

    // Adoption may span the next continuous publication. Fence the outage
    // against the latest confirmed snapshot after the live traffic phase.
    let before_failed_refresh = fixture.wait_checkpoint(&client).await?;
    publication_permission(admin, username, false).await?;
    wait_spent_round(fixture, before_failed_refresh.minimum_versions["relay-a"]).await?;
    let bounded = fixture.wait_checkpoint(&client).await?;
    require(
        bounded.expires_at == before_failed_refresh.expires_at
            && bounded.minimum_versions == before_failed_refresh.minimum_versions,
        "failed publish extended or advanced confirmed authorization",
    )?;

    // Restart while the old signed trust is still temporally usable. Its
    // persisted confirmation alone must never restore process freshness.
    require(
        bounded.expires_at - Utc::now() > chrono::Duration::seconds(12),
        "restart probe missed the old confirmation's usable window",
    )?;
    let before_restart = fixture.state()?;
    fixture.stop_authority().await?;
    fixture.start_authority().await?;
    require(
        matches!(
            client.fetch_checkpoint(fixture.request()).await,
            Err(CheckpointAuthorityError::HttpStatus(503))
        ),
        "restart reused persisted checkpoint freshness",
    )?;
    publication_permission(admin, username, true).await?;
    let recovered = fixture.wait_checkpoint(&client).await?;
    require(
        recovered.checkpoint_version
            > before_restart["checkpoint_high_water"]
                .as_u64()
                .ok_or("checkpoint counter")?
            && recovered.minimum_versions["relay-a"]
                > before_restart["membership_high_water"]
                    .as_u64()
                    .ok_or("membership counter")?,
        "restart reused a spent allocator version",
    )?;

    // A sustained write outage may serve nonce-fresh responses only with the
    // original confirmed expiry. It must become unavailable before that
    // expiry, despite repeated successful durable reservations and requests.
    publication_permission(admin, username, false).await?;
    let outage_started = Instant::now();
    let mut observed_success = false;
    timeout(Duration::from_secs(62), async {
        loop {
            match fixture.checkpoint(&client).await? {
                Some(response) => {
                    require(
                        response.expires_at == recovered.expires_at
                            && response.minimum_versions == recovered.minimum_versions,
                        "outage checkpoint extended old publication",
                    )?;
                    observed_success = true;
                }
                None => {
                    require(
                        observed_success
                            && recovered.expires_at - Utc::now() <= chrono::Duration::seconds(8),
                        "outage refused before the bounded confirmed window",
                    )?;
                    return Ok::<(), &'static str>(());
                }
            }
            sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .map_err(|_| "checkpoint outlived the fixed signed publication window")??;
    require(
        fixture.state()?["membership_high_water"]
            .as_u64()
            .is_some_and(|version| version > recovered.minimum_versions["relay-a"]),
        "outage did not exercise attempted publications",
    )?;
    eprintln!(
        "online authority: failed publications retained original expiry and became unavailable after {}ms",
        outage_started.elapsed().as_millis()
    );

    // Offline approval revokes the old certificate immediately on restart,
    // even while the new inventory has no confirmed publication.
    fixture.stop_authority().await?;
    let replacement = fixture
        .pki
        .issue_peer("relay-a")
        .map_err(|_| "replacement client identity")?;
    fixture.inventory["revision"] = json!(2);
    fixture.inventory["nodes"][0]["checkpoint_client_spkis"] = json!([replacement
        .spki_fingerprint_sha256()
        .map_err(|_| "replacement SPKI")?]);
    let counters = fixture.state()?;
    fixture.approve(false, 1).await?;
    require(
        fixture.state()?["confirmed"].is_null(),
        "inventory approval retained old confirmed snapshot",
    )?;
    fixture.start_authority().await?;
    require(
        matches!(
            client.fetch_checkpoint(fixture.request()).await,
            Err(CheckpointAuthorityError::HttpStatus(403))
        ),
        "revoked client was not forbidden while inventory pending",
    )?;
    let replacement_client = fixture.client(&replacement)?;
    require(
        matches!(
            replacement_client.fetch_checkpoint(fixture.request()).await,
            Err(CheckpointAuthorityError::HttpStatus(503))
        ),
        "pending inventory returned an old successful checkpoint",
    )?;
    publication_permission(admin, username, true).await?;
    let approved = fixture.wait_checkpoint(&replacement_client).await?;
    require(
        approved.checkpoint_version
            > counters["checkpoint_high_water"]
                .as_u64()
                .ok_or("old checkpoint counter")?
            && approved.minimum_versions["relay-a"]
                > counters["membership_high_water"]
                    .as_u64()
                    .ok_or("old membership counter")?,
        "inventory approval reset an allocator",
    )?;
    require(
        matches!(
            client.fetch_checkpoint(fixture.request()).await,
            Err(CheckpointAuthorityError::HttpStatus(403))
        ),
        "publication restored a revoked client",
    )?;

    // Exercise the exact changed-run startup fence without restarting or
    // mutating a shared Redis daemon. Explicit offline approval pins a
    // different synthetic run with a new incarnation; the actual observed
    // run must cause fatal exit before reservation or membership writes.
    fixture.stop_authority().await?;
    fixture.inventory["revision"] = json!(3);
    fixture.incarnation = "authority-incarnation-b".into();
    fixture.inventory["deployment_incarnation"] = json!(fixture.incarnation);
    fixture.redis_run = if fixture.redis_run == "a".repeat(40) {
        "b".repeat(40)
    } else {
        "a".repeat(40)
    };
    fixture.approve(false, 2).await?;
    let before_mismatch = fs::read(&fixture.state).map_err(|_| "state before run mismatch")?;
    let before_records = catalog
        .read_signed_memberships()
        .await
        .map_err(|_| "memberships before run mismatch")?;
    let mut rejected = ManagedProcess::spawn(
        "m6-authority-run-mismatch",
        ProcessSpec::new(&fixture.authority_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config.display().to_string()),
    )
    .await
    .map_err(|_| "start mismatched-run authority")?;
    let status = wait_for_exit(&mut rejected, PROCESS_BOUND)
        .await
        .map_err(|_| "changed Redis run did not terminate authority");
    let refusal = String::from_utf8_lossy(&rejected.stderr())
        .contains("Redis run differs from independent durable approval");
    rejected
        .shutdown(Duration::from_millis(100))
        .await
        .map_err(|_| "reap mismatched-run authority")?;
    require(
        !status?.success() && refusal,
        "changed Redis run was not rejected by the expected fence",
    )?;
    require(
        fs::read(&fixture.state).map_err(|_| "state after run mismatch")? == before_mismatch,
        "run mismatch consumed or rewrote independent state",
    )?;
    require(
        catalog
            .read_signed_memberships()
            .await
            .map_err(|_| "memberships after run mismatch")?
            == before_records,
        "run mismatch changed Redis membership",
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable loopback TEST_REDIS_URL with ACL administration and built authority/relay binaries"]
async fn online_authority_publishes_for_three_relays_and_fails_closed_across_lifecycle() {
    let upstream_url = env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required");
    let upstream = parse_plaintext_upstream(&upstream_url).expect("disposable loopback Redis");
    let suffix = Uuid::new_v4().simple().to_string();
    let namespace = format!("test-m6-authority-{suffix}");
    let username = format!("authority-{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    let mut admin = redis::Client::open(upstream_url.as_str())
        .expect("admin Redis client")
        .get_multiplexed_async_connection()
        .await
        .expect("admin Redis connection");
    let mut catalog = None;
    // Retain every allocated resource before the next fallible setup step.
    // Even an ambiguous ACL write or failed catalog activation reaches the
    // isolated-user cleanup below; no early assertion bypasses it.
    let setup: GateResult = async {
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&username)
            .arg("reset")
            .arg("on")
            .arg(format!(">{password}"))
            .arg(format!("~tunnel-catalog:{namespace}:membership:operator:*"))
            .arg(&[
                "+ping", "+info", "+eval", "+hget", "+hlen", "+hset", "+expire",
            ])
            .query_async::<()>(&mut admin)
            .await
            .map_err(|_| "create isolated publisher ACL")?;
        catalog = Some(
            RedisCatalog::connect_for_recovery(
                &upstream_url,
                &namespace,
                "authority-incarnation-a",
            )
            .await
            .map_err(|_| "connect isolated fixture catalog")?,
        );
        catalog
            .as_ref()
            .ok_or("fixture catalog missing")?
            .activate_deployment_incarnation()
            .await
            .map_err(|_| "activate explicit fixture incarnation")?;
        Ok(())
    }
    .await;
    let setup_succeeded = setup.is_ok();
    let outcome: GateResult = match (setup, catalog.as_ref()) {
        (Ok(()), Some(catalog)) => {
            let run_catalog = catalog.clone();
            let run_namespace = namespace.clone();
            let run_username = username.clone();
            let mut run_admin = admin.clone();
            tokio::spawn(async move {
                let mut fixture = Fixture::create(
                    upstream,
                    &run_namespace,
                    &run_username,
                    &password,
                    run_catalog.bound_redis_run_id(),
                    &run_catalog,
                )
                .await?;
                let outcome = timeout(
                    SCENARIO_BOUND,
                    run_scenario(&mut fixture, &mut run_admin, &run_username, &run_catalog),
                )
                .await
                .map_err(|_| "online authority scenario exceeded shared deadline")
                .and_then(|result| result);
                let cleanup = fixture.cleanup().await;
                outcome.and(cleanup)
            })
            .await
            .map_err(|_| "authority lifecycle task panicked")
            .and_then(|result| result)
        }
        (Err(error), _) => Err(error),
        _ => Err("fixture setup completed without a catalog"),
    };
    let keys = if let Some(catalog) = catalog {
        catalog
            .cleanup_fixture_namespace()
            .await
            .map_err(|_| "remove fixture namespace")
    } else {
        Ok(())
    };
    let users: redis::RedisResult<i64> = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&username)
        .query_async(&mut admin)
        .await;
    keys.expect("remove only fixture namespace");
    let removed = users.expect("remove fixture publisher ACL");
    if setup_succeeded {
        assert_eq!(removed, 1);
    } else {
        assert!((0..=1).contains(&removed));
    }
    outcome.expect("online authority real-process acceptance");
}

// These two faults share only the disposable wrapper-owned Redis daemon.
// Serialize them even when someone omits the wrapper's --test-threads=1.
static FAULT_TEST_SERIALIZER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct OwnedRedis {
    container_id: String,
    name: String,
    owner: String,
    address: SocketAddr,
}

async fn docker_output(args: &[String]) -> GateResult<Vec<u8>> {
    let mut spec = ProcessSpec::new("docker");
    for arg in args {
        spec = spec.arg(arg);
    }
    let mut child = ManagedProcess::spawn("m6-owned-redis-command", spec)
        .await
        .map_err(|_| "start owned Redis command")?;
    let status = wait_for_exit(&mut child, PROCESS_BOUND)
        .await
        .map_err(|_| "owned Redis command deadline");
    let output = child.stdout();
    child
        .shutdown(Duration::from_millis(100))
        .await
        .map_err(|_| "reap owned Redis command")?;
    require(status?.success(), "owned Redis Docker command failed")?;
    Ok(output)
}

impl OwnedRedis {
    async fn from_environment(address: SocketAddr) -> GateResult<Self> {
        let name = env::var("TUNNEL_AUTHORITY_REDIS_CONTAINER")
            .map_err(|_| "isolated authority Redis wrapper is required")?;
        let owner = env::var("TUNNEL_AUTHORITY_REDIS_OWNER")
            .map_err(|_| "isolated Redis ownership token is required")?;
        require(
            owner.len() == 32
                && owner
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid isolated Redis ownership token",
        )?;
        require(
            name == format!("agentuplink-authority-faults-{owner}")
                && address.ip().is_loopback()
                && address.port() != 16379,
            "refusing an unowned or shared Redis fault target",
        )?;
        let mut owned = Self {
            container_id: String::new(),
            name,
            owner,
            address,
        };
        owned.container_id = owned.inspect().await?;
        Ok(owned)
    }

    async fn inspect(&self) -> GateResult<String> {
        // Read only selected public identity fields, never Docker's complete
        // environment/configuration. Bind the Redis URL to this exact owned
        // container's published6379 port before ACL SAVE or any restart.
        let format = "{{.Id}}\n{{index .Config.Labels \"agentuplink.authority-fault-owner\"}}\n{{.Name}}\n{{range (index .NetworkSettings.Ports \"6379/tcp\")}}{{.HostIp}}:{{.HostPort}}{{end}}";
        let bytes = docker_output(&[
            "inspect".into(),
            "--type".into(),
            "container".into(),
            "--format".into(),
            format.into(),
            self.name.clone(),
        ])
        .await?;
        let output = std::str::from_utf8(&bytes).map_err(|_| "owned Redis inspection encoding")?;
        let fields: Vec<_> = output.trim().lines().collect();
        require(fields.len() == 4, "owned Redis inspection shape")?;
        require(
            fields[0].len() == 64
                && fields[0].bytes().all(|byte| byte.is_ascii_hexdigit())
                && fields[1] == self.owner
                && fields[2] == format!("/{}", self.name)
                && fields[3] == self.address.to_string(),
            "Redis container ownership or published port did not match the fixture URL",
        )?;
        Ok(fields[0].to_owned())
    }

    async fn restart(&self, admin: &mut redis::aio::MultiplexedConnection) -> GateResult {
        require(
            self.inspect().await? == self.container_id,
            "owned Redis container was replaced",
        )?;
        redis::cmd("ACL")
            .arg("SAVE")
            .query_async::<()>(admin)
            .await
            .map_err(|_| "persist fixture ACL before owned Redis restart")?;
        // Use the inspected immutable ID, so a same-name replacement cannot
        // turn the name guard into a restart of another container.
        docker_output(&[
            "restart".into(),
            "--time".into(),
            "1".into(),
            self.container_id.clone(),
        ])
        .await?;
        Ok(())
    }
}

async fn admin_connection(url: &str) -> GateResult<redis::aio::MultiplexedConnection> {
    let client = redis::Client::open(url).map_err(|_| "fixture Redis URL")?;
    timeout(IO_BOUND, client.get_multiplexed_async_connection())
        .await
        .map_err(|_| "fixture Redis connection deadline")?
        .map_err(|_| "fixture Redis connection")
}

async fn reconnect_admin(url: &str) -> GateResult<redis::aio::MultiplexedConnection> {
    timeout(Duration::from_secs(12), async {
        loop {
            if let Ok(connection) = admin_connection(url).await {
                return Ok::<_, &'static str>(connection);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "restarted fixture Redis did not return")?
}

async fn redis_run(admin: &mut redis::aio::MultiplexedConnection) -> GateResult<String> {
    let info: String = redis::cmd("INFO")
        .arg("SERVER")
        .query_async(admin)
        .await
        .map_err(|_| "read actual Redis run identity")?;
    let run = info
        .lines()
        .find_map(|line| line.strip_prefix("run_id:"))
        .ok_or("Redis run identity absent")?
        .trim();
    require(
        run.len() == 40 && run.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid actual Redis run identity",
    )?;
    Ok(run.to_owned())
}

async fn raw_memberships(
    admin: &mut redis::aio::MultiplexedConnection,
    namespace: &str,
) -> GateResult<BTreeMap<String, Vec<u8>>> {
    let entries: Vec<(String, Vec<u8>)> = redis::cmd("HGETALL")
        .arg(format!(
            "tunnel-catalog:{namespace}:membership:operator:directory"
        ))
        .query_async(admin)
        .await
        .map_err(|_| "read isolated membership directory")?;
    require(
        entries.len() <= 32 && entries.iter().all(|(_, bytes)| bytes.len() <= 256 * 1024),
        "membership evidence exceeded fixture bounds",
    )?;
    Ok(entries.into_iter().collect())
}

async fn committed_reply_fault(
    fixture: &mut Fixture,
    proxy: &FaultProxy,
    catalog: &RedisCatalog,
) -> GateResult {
    proxy.arm_next_committed_publish()?;
    fixture.start_authority().await?;
    proxy.wait_committed_cut().await?;
    require(
        proxy.cut_count() == 1,
        "lost-reply fault did not cut exactly one committed reply",
    )?;
    let attempts = proxy.attempts();
    let spent = attempts
        .first()
        .ok_or("no observed real membership EVAL")?
        .1;
    let state = fixture.state()?;
    require(
        state["membership_high_water"].as_u64() == Some(spent) && state["confirmed"].is_null(),
        "initial lost-reply round was not durably spent and unconfirmed",
    )?;
    let committed = catalog
        .read_signed_memberships()
        .await
        .map_err(|_| "read committed lost-reply membership")?;
    require(
        !committed.is_empty() && committed.len() < fixture.relays.len(),
        "fault did not prove a committed partial inventory round",
    )?;
    for record in &committed {
        let signed: tunnel_cluster::membership::SignedMembershipRecord =
            serde_json::from_slice(&record.bytes)
                .map_err(|_| "committed membership signed shape")?;
        require(
            record.version == spent
                && signed.record_version == spent
                && signed.deployment_id == fixture.deployment
                && signed.deployment_incarnation == fixture.incarnation
                && attempts.contains(&(signed.node_id, spent)),
            "actual committed bytes did not match the spent publication attempt",
        )?;
    }
    let client = fixture.client(&fixture.relays[0].identity)?;
    require(
        matches!(
            client.fetch_checkpoint(fixture.request()).await,
            Err(CheckpointAuthorityError::HttpStatus(503))
        ),
        "partial or lost-reply publication produced a successful checkpoint",
    )?;
    let recovered = fixture.wait_checkpoint(&client).await?;
    require(
        recovered.minimum_versions.len() == 3
            && recovered
                .minimum_versions
                .values()
                .all(|version| *version > spent),
        "recovery reused the ambiguously committed record version",
    )?;
    let final_records = catalog
        .read_signed_memberships()
        .await
        .map_err(|_| "read higher recovered membership round")?;
    require(
        final_records.len() == 3 && final_records.iter().all(|record| record.version > spent),
        "recovery did not replace every partial-round record with higher versions",
    )?;
    fixture.stop_authority().await?;
    let attempts = proxy.attempts();
    let unique: BTreeSet<_> = attempts.iter().collect();
    require(
        unique.len() == attempts.len(),
        "daemon retried a node publication at a spent version",
    )?;
    require(
        proxy.cut_count() == 1,
        "fault proxy cut an unarmed recovery reply",
    )?;
    eprintln!(
        "online authority fault: real committed partial round stayed unconfirmed; every retry used a higher durable version; cut_count=1"
    );
    Ok(())
}

async fn actual_redis_restart_fault(
    fixture: &mut Fixture,
    owned: &OwnedRedis,
    url: &str,
    username: &str,
    password: &str,
    namespace: &str,
    admin: &mut redis::aio::MultiplexedConnection,
) -> GateResult {
    fixture.start_authority().await?;
    let client = fixture.client(&fixture.relays[0].identity)?;
    let confirmed = fixture.wait_checkpoint(&client).await?;
    let before = fixture.state()?;
    let prior_run = redis_run(admin).await?;
    require(
        prior_run == fixture.redis_run,
        "fixture did not pin the actual original Redis process",
    )?;
    let prior_records = raw_memberships(admin, namespace).await?;
    require(
        prior_records.len() == 3,
        "initial publication did not reach actual Redis",
    )?;
    owned.restart(admin).await?;
    *admin = reconnect_admin(url).await?;
    let next_run = redis_run(admin).await?;
    require(
        next_run != prior_run,
        "owned Redis restart did not change process run identity",
    )?;
    let mut credential_check = admin_connection(url).await?;
    redis::cmd("AUTH")
        .arg(username)
        .arg(password)
        .query_async::<()>(&mut credential_check)
        .await
        .map_err(|_| "persisted publisher ACL did not survive Redis restart")?;
    let pong: String = redis::cmd("PING")
        .query_async(&mut credential_check)
        .await
        .map_err(|_| "publisher ACL after restart")?;
    require(pong == "PONG", "publisher ACL was unusable after restart")?;

    let mut process = fixture
        .authority
        .take()
        .ok_or("live authority process missing during Redis fault")?;
    // One reserved publication can discover the broken old connection; the
    // next20s tick reconnects, observes the new run and fatally refuses it.
    let status = wait_for_exit(&mut process, Duration::from_secs(50))
        .await
        .map_err(|_| "daemon did not fail closed after actual Redis restart");
    let diagnostic = String::from_utf8_lossy(&process.stderr()).into_owned();
    let refusal = diagnostic.contains("Redis run differs from independent durable approval")
        || diagnostic.contains(
            "membership publication conflict; independent authority state review required",
        );
    process
        .shutdown(Duration::from_millis(100))
        .await
        .map_err(|_| "reap authority after actual Redis restart")?;
    require(
        !status?.success() && refusal,
        "actual Redis restart did not hit the independent run fence",
    )?;
    require(
        client.fetch_checkpoint(fixture.request()).await.is_err(),
        "authority served a checkpoint after fatal Redis-run detection",
    )?;
    let after = fixture.state()?;
    require(
        after["expected_redis_run_id"] == before["expected_redis_run_id"]
            && after["inventory"] == before["inventory"]
            && after["confirmed"] == before["confirmed"],
        "daemon silently reapproved new Redis run or confirmed a new publication",
    )?;
    require(
        after["membership_high_water"]
            .as_u64()
            .ok_or("post-restart membership counter")?
            >= before["membership_high_water"]
                .as_u64()
                .ok_or("pre-restart membership counter")?
            && after["checkpoint_high_water"] == before["checkpoint_high_water"],
        "Redis restart reset or spuriously advanced authority allocators",
    )?;
    require(
        raw_memberships(admin, namespace).await? == prior_records,
        "unapproved new Redis process received a new membership publication",
    )?;
    require(
        after["confirmed"]["membership_version"].as_u64()
            == Some(confirmed.minimum_versions["relay-a"]),
        "failed daemon changed its last confirmed membership floor",
    )?;
    eprintln!(
        "online authority fault: owned Redis changed run while daemon lived; persisted ACL remained usable; daemon exited without reapproval or new membership writes"
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum FaultCase {
    CommittedReply,
    RedisRestart,
}

async fn run_owned_fault(case: FaultCase) -> GateResult {
    let url = env::var("TEST_REDIS_URL").map_err(|_| "TEST_REDIS_URL required")?;
    let upstream = parse_plaintext_upstream(&url)
        .map_err(|_| "fault gate requires disposable loopback Redis")?;
    let owned = OwnedRedis::from_environment(upstream).await?;
    let mut admin = admin_connection(&url).await?;
    let suffix = Uuid::new_v4().simple().to_string();
    let namespace = format!("test-authority-fault-{suffix}");
    let username = format!("fault-publisher-{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    let mut catalog = None;
    let mut fixture = None;
    let mut proxy = None;
    let outcome = timeout(Duration::from_secs(90), async {
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&username)
            .arg("reset")
            .arg("on")
            .arg(format!(">{password}"))
            .arg(format!("~tunnel-catalog:{namespace}:membership:operator:*"))
            .arg(&[
                "+ping", "+info", "+eval", "+hget", "+hlen", "+hset", "+expire",
            ])
            .query_async::<()>(&mut admin)
            .await
            .map_err(|_| "create isolated fault publisher ACL")?;
        catalog = Some(
            RedisCatalog::connect_for_recovery(&url, &namespace, "authority-incarnation-a")
                .await
                .map_err(|_| "fault fixture catalog")?,
        );
        let catalog = catalog.as_ref().ok_or("fault catalog missing")?;
        catalog
            .activate_deployment_incarnation()
            .await
            .map_err(|_| "fault fixture incarnation activation")?;
        let proxied_upstream = if matches!(case, FaultCase::CommittedReply) {
            proxy = Some(FaultProxy::start(upstream).await?);
            proxy.as_ref().ok_or("fault proxy missing")?.address()
        } else {
            upstream
        };
        fixture = Some(
            Fixture::create(
                proxied_upstream,
                &namespace,
                &username,
                &password,
                catalog.bound_redis_run_id(),
                catalog,
            )
            .await?,
        );
        let fixture = fixture.as_mut().ok_or("fault authority fixture missing")?;
        match case {
            FaultCase::CommittedReply => {
                committed_reply_fault(
                    fixture,
                    proxy.as_ref().ok_or("lost-reply proxy missing")?,
                    catalog,
                )
                .await
            }
            FaultCase::RedisRestart => {
                actual_redis_restart_fault(
                    fixture, &owned, &url, &username, &password, &namespace, &mut admin,
                )
                .await
            }
        }
    })
    .await
    .map_err(|_| "owned authority fault scenario deadline")
    .and_then(|result| result);

    let fixture_cleanup = if let Some(fixture) = fixture {
        fixture.cleanup().await
    } else {
        Ok(())
    };
    let proxy_cleanup = if let Some(proxy) = proxy {
        proxy.shutdown().await
    } else {
        Ok(())
    };
    // The old catalog is deliberately pinned to the pre-restart process.
    // Teardown opens an explicitly fresh handle only to the isolated test
    // namespace; the authority never gets that new run's handle or approval.
    let keys_cleanup = if catalog.is_some() {
        match RedisCatalog::connect(&url, &namespace).await {
            Ok(fresh) => fresh
                .cleanup_fixture_namespace()
                .await
                .map_err(|_| "remove isolated fault namespace"),
            Err(_) => Err("connect for isolated fault namespace cleanup"),
        }
    } else {
        Ok(())
    };
    let user_cleanup = async {
        require(
            owned.inspect().await? == owned.container_id,
            "owned Redis changed before ACL cleanup",
        )?;
        let mut fresh = reconnect_admin(&url).await?;
        redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&username)
            .query_async::<i64>(&mut fresh)
            .await
            .map_err(|_| "remove isolated fault publisher ACL")?;
        redis::cmd("ACL")
            .arg("SAVE")
            .query_async::<()>(&mut fresh)
            .await
            .map_err(|_| "persist isolated fault ACL cleanup")?;
        Ok::<_, &'static str>(())
    }
    .await;
    outcome
        .and(fixture_cleanup)
        .and(proxy_cleanup)
        .and(keys_cleanup)
        .and(user_cleanup)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run scripts/m6-authority-faults-verify.sh; requires its owned isolated Redis container"]
async fn online_authority_fault_committed_publish_reply_uses_a_higher_round() {
    let _serial = FAULT_TEST_SERIALIZER.lock().await;
    run_owned_fault(FaultCase::CommittedReply)
        .await
        .expect("actual daemon committed lost-reply acceptance");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run scripts/m6-authority-faults-verify.sh; never restart a shared Redis instance"]
async fn online_authority_fault_actual_redis_restart_requires_independent_approval() {
    let _serial = FAULT_TEST_SERIALIZER.lock().await;
    run_owned_fault(FaultCase::RedisRestart)
        .await
        .expect("actual daemon owned Redis restart acceptance");
}
