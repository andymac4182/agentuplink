//! M6-C243: a local, explicitly fenced operator recovery drill. The retained
//! catalog snapshot is synthetic external reconciliation evidence, not a new
//! production reconciler or a source of authority inferred from restored Redis.
use super::*;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};
use tunnel_catalog::RecoveryApproval;

#[path = "../common/recovery_fixture_snapshot.rs"]
mod snapshot;

const CANDIDATE: &str = "authority-incarnation-recovered";
const LABEL: &str = "agentuplink.authority-recovery-owner";
const KEY_ID: &str = "c243-offline-recovery";
const NONCE: &str = "c243-independent-operator-challenge";
const QUIESCENCE: Duration =
    Duration::from_secs(60).saturating_add(tunnel_catalog::clock::MAX_CLUSTER_CLOCK_SKEW);
const DRILL_BOUND: Duration = Duration::from_secs(360);

struct Capture {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn capture(binary: &Path, args: &[String]) -> GateResult<Capture> {
    let name = format!("c243-cli-{}", Uuid::new_v4().simple());
    let directory = env::var_os("TUNNEL_HARNESS_PROCESS_LOG_DIR")
        .map(PathBuf::from)
        .ok_or("private managed-process capture directory required")?;
    let mut spec = ProcessSpec::new(binary);
    for arg in args {
        spec = spec.arg(arg);
    }
    let mut child = ManagedProcess::spawn(&name, spec)
        .await
        .map_err(|_| "spawn bounded recovery command")?;
    let pid = child.id().ok_or("recovery command PID missing")?;
    let status = wait_for_exit(&mut child, Duration::from_secs(20))
        .await
        .map_err(|_| "recovery command deadline");
    // Join both drains before reading, including on a refused command.
    let cleanup = child
        .shutdown(Duration::from_millis(100))
        .await
        .map_err(|_| "reap recovery command and output drains");
    cleanup?;
    // shutdown consumes ManagedProcess and joins its bounded output drains.
    // Read its existing opt-in capture only after that join, avoiding an early
    // stdout snapshot race without changing the shared process implementation.
    let read_stream = |extension: &str| -> GateResult<Vec<u8>> {
        let suffix = format!("-{name}-{pid}-shutdown.{extension}");
        let mut matched = None;
        for (index, entry) in fs::read_dir(&directory)
            .map_err(|_| "private capture directory")?
            .enumerate()
        {
            require(index < 512, "managed-process capture directory bound")?;
            let entry = entry.map_err(|_| "managed-process capture entry")?;
            if entry.file_name().to_string_lossy().ends_with(&suffix) {
                require(
                    matched.is_none()
                        && entry
                            .file_type()
                            .map_err(|_| "capture file type")?
                            .is_file(),
                    "ambiguous or nonregular managed-process capture",
                )?;
                let mut bytes = Vec::new();
                fs::File::open(entry.path())
                    .map_err(|_| "open joined capture")?
                    .take(64 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "read joined capture")?;
                matched = Some(bytes);
            }
        }
        matched.ok_or("joined managed-process capture missing")
    };
    let stdout = read_stream("stdout")?;
    let stderr = read_stream("stderr")?;
    require(
        stdout.len() <= 64 * 1024
            && stderr.len() <= 64 * 1024
            && !stdout.windows(10).any(|part| part == b"-----BEGIN")
            && !stderr.windows(10).any(|part| part == b"-----BEGIN"),
        "recovery command output exceeded bounds or exposed private PEM",
    )?;
    Ok(Capture {
        success: status?.success(),
        stdout,
        stderr,
    })
}

fn refusal(output: &Capture, marker: &str) -> GateResult {
    require(
        !output.success && String::from_utf8_lossy(&output.stderr).contains(marker),
        "negative control did not reach its required refusal cause",
    )
}

fn fingerprint(bytes: &[u8]) -> String {
    common::hex_encode(&Sha256::digest(bytes))
}

struct Container {
    id: String,
    name: String,
    owner: String,
    image: String,
    address: SocketAddr,
}

impl Container {
    async fn from_environment(role: &str, address: SocketAddr) -> GateResult<Self> {
        let owner = env::var("TUNNEL_C22_REDIS_OWNER").map_err(|_| "owned wrapper required")?;
        let id = env::var(format!("TUNNEL_C22_REDIS_{}_ID", role.to_ascii_uppercase()))
            .map_err(|_| "immutable owned container ID required")?;
        let image = env::var("TUNNEL_C22_REDIS_IMAGE_ID")
            .map_err(|_| "exact Redis image identity required")?;
        require(
            owner.len() == 32
                && owner
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                && id.len() == 64
                && id.bytes().all(|byte| byte.is_ascii_hexdigit())
                && image.starts_with("sha256:")
                && image.len() == 71
                && address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
                && address.port() != 16379,
            "refusing an unowned, non-loopback or shared Redis target",
        )?;
        let value = Self {
            id,
            name: format!("agentuplink-authority-recovery-{owner}-{role}"),
            owner,
            image,
            address,
        };
        value.inspect().await?;
        Ok(value)
    }

    // HostConfig retains the configured port binding even while created or
    // stopped. Verify by immutable ID before every lifecycle/copy operation;
    // the wrapper applies the same guard before final removal.
    async fn inspect(&self) -> GateResult<(bool, u32)> {
        let format = format!(
            "{{{{.Id}}}}\n{{{{.Name}}}}\n{{{{index .Config.Labels \"{LABEL}\"}}}}\n{{{{.Image}}}}\n{{{{json .HostConfig.PortBindings}}}}\n{{{{.State.Running}}}}\n{{{{.State.Pid}}}}"
        );
        let output = docker_output(&[
            "inspect".into(),
            "--type".into(),
            "container".into(),
            "--format".into(),
            format,
            self.id.clone(),
        ])
        .await?;
        let text = std::str::from_utf8(&output).map_err(|_| "container inspection encoding")?;
        let fields: Vec<_> = text.trim().lines().collect();
        require(fields.len() == 7, "container inspection shape")?;
        let bindings: Value = serde_json::from_str(fields[4]).map_err(|_| "owned port bindings")?;
        require(
            fields[0] == self.id
                && fields[1] == format!("/{}", self.name)
                && fields[2] == self.owner
                && fields[3] == self.image
                && bindings
                    == json!({"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": self.address.port().to_string()}]}),
            "container identity, owner, image or exact loopback binding changed",
        )?;
        let running = match fields[5] {
            "true" => true,
            "false" => false,
            _ => return Err("container running shape"),
        };
        let pid = fields[6].parse().map_err(|_| "container process ID")?;
        Ok((running, pid))
    }

    async fn stop(&self) -> GateResult {
        require(
            self.inspect().await?.0,
            "old Redis was not running before its fence",
        )?;
        docker_output(&["stop".into(), "--time".into(), "5".into(), self.id.clone()]).await?;
        require(
            self.inspect().await? == (false, 0),
            "old Redis process survived its fence",
        )?;
        require(
            std::net::TcpListener::bind(self.address).is_ok(),
            "old Redis endpoint was not released",
        )
    }

    async fn copy_out(&self, source: &str, target: &Path) -> GateResult {
        self.inspect().await?;
        docker_output(&[
            "cp".into(),
            format!("{}:{source}", self.id),
            target.display().to_string(),
        ])
        .await?;
        Ok(())
    }

    async fn copy_in(&self, source: &Path, target: &str) -> GateResult {
        require(
            self.inspect().await? == (false, 0),
            "restore target is already running",
        )?;
        docker_output(&[
            "cp".into(),
            source.display().to_string(),
            format!("{}:{target}", self.id),
        ])
        .await?;
        Ok(())
    }

    async fn start(&self) -> GateResult {
        require(
            self.inspect().await? == (false, 0),
            "candidate was already running",
        )?;
        docker_output(&["start".into(), self.id.clone()]).await?;
        require(self.inspect().await?.0, "candidate Redis did not start")
    }
}

async fn bounded_redis<T: redis::FromRedisValue>(
    admin: &mut redis::aio::MultiplexedConnection,
    command: &mut redis::Cmd,
) -> GateResult<T> {
    timeout(IO_BOUND, command.query_async(admin))
        .await
        .map_err(|_| "owned Redis command deadline")?
        .map_err(|_| "owned Redis command refused")
}

async fn publisher_acl(
    admin: &mut redis::aio::MultiplexedConnection,
    namespace: &str,
    username: &str,
    password: &str,
) -> GateResult {
    bounded_redis::<()>(
        admin,
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg(username)
            .arg("reset")
            .arg("on")
            .arg(format!(">{password}"))
            .arg(format!("~tunnel-catalog:{namespace}:membership:operator:*"))
            .arg(&[
                "+ping", "+info", "+eval", "+hget", "+hlen", "+hset", "+expire",
            ]),
    )
    .await
}

fn candidate_configs(
    fixture: &mut Fixture,
    recovery_trust: &Path,
    fence: &Path,
) -> GateResult<PathBuf> {
    // TOML fields have one exact occurrence in this fixture renderer. Check
    // before replacement; do not silently edit a different setting.
    let original =
        fs::read_to_string(&fixture.relays[0].config).map_err(|_| "read relay recovery config")?;
    let recovery = format!(
        "{original}\n[recovery]\nfence_path = {}\ntrusted_keys_path = {}\ndeployment_incarnation = {}\n",
        toml_path(fence),
        toml_path(recovery_trust),
        toml_string(CANDIDATE)
    );
    fixture
        .files
        .write("recovery.toml", recovery.as_bytes())
        .map_err(|_| "write recovery config")
}

fn move_to_candidate(fixture: &mut Fixture) -> GateResult {
    for relay in &mut fixture.relays {
        let old = fs::read_to_string(&relay.config).map_err(|_| "read old relay config")?;
        let old_identity = format!(
            "deployment_incarnation = {}",
            toml_string(&fixture.incarnation)
        );
        let old_path = format!(
            "membership_version_state_path = {}",
            toml_path(&relay.version_state)
        );
        require(
            old.matches(&old_identity).count() == 1 && old.matches(&old_path).count() == 1,
            "candidate fixture config replacement is ambiguous",
        )?;
        let state = fixture
            .state
            .with_file_name(format!("{}-recovered-versions.json", relay.node_id));
        require(!state.exists(), "candidate membership state already exists")?;
        let config = old
            .replace(
                &old_identity,
                &format!("deployment_incarnation = {}", toml_string(CANDIDATE)),
            )
            .replace(
                &old_path,
                &format!("membership_version_state_path = {}", toml_path(&state)),
            );
        relay.config = fixture
            .files
            .write(
                &format!("{}-recovered.toml", relay.node_id),
                config.as_bytes(),
            )
            .map_err(|_| "write separate candidate config")?;
        relay.version_state = state;
    }
    fixture.incarnation = CANDIDATE.into();
    fixture.inventory["deployment_incarnation"] = CANDIDATE.into();
    fixture.inventory["revision"] = 2.into();
    Ok(())
}

async fn observe(fixture: &Fixture, config: &Path) -> GateResult<Value> {
    let output = capture(
        &fixture.relay_binary,
        &[
            "recovery-observe".into(),
            "--config".into(),
            config.display().to_string(),
        ],
    )
    .await?;
    require(output.success, "actual recovery-observe refused")?;
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "recovery observation JSON")?;
    require(
        value["quiescence"] == "unproven" && value["deployment_incarnation"] == CANDIDATE,
        "observation invented quiescence or changed candidate scope",
    )?;
    Ok(value)
}

async fn sign(
    fixture: &Fixture,
    offline: &FixtureFiles,
    observed: &Value,
    private: &Path,
    label: &str,
) -> GateResult<PathBuf> {
    let now = Utc::now();
    let string = |key: &str| {
        observed[key]
            .as_str()
            .map(str::to_owned)
            .ok_or("observation field missing")
    };
    let approval = RecoveryApproval {
        schema_version: 1,
        deployment_id: string("deployment_id")?,
        redis_namespace: string("redis_namespace")?,
        redis_run_id: string("redis_run_id")?,
        deployment_incarnation: string("deployment_incarnation")?,
        approval_version: 1,
        nonce: NONCE.into(),
        catalog_digest: string("catalog_digest")?,
        issued_at: now,
        not_before: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    let observation = offline
        .write(
            &format!("{label}-observation.json"),
            &serde_json::to_vec(observed).map_err(|_| "encode observation")?,
        )
        .map_err(|_| "private observation file")?;
    let unsigned = offline
        .write(
            &format!("{label}-unsigned.json"),
            &serde_json::to_vec(&approval).map_err(|_| "encode approval")?,
        )
        .map_err(|_| "private unsigned approval file")?;
    let signed = private.with_file_name(format!("{label}-signed.json"));
    command(
        &fixture.authority_binary,
        &[
            "sign-recovery-approval".into(),
            "--key".into(),
            private.display().to_string(),
            "--key-id".into(),
            KEY_ID.into(),
            "--observation".into(),
            observation.display().to_string(),
            "--approval".into(),
            unsigned.display().to_string(),
            "--expected-nonce".into(),
            NONCE.into(),
            "--output".into(),
            signed.display().to_string(),
        ],
    )
    .await?;
    Ok(signed)
}

async fn recover(
    fixture: &Fixture,
    config: &Path,
    approval: &Path,
    nonce: &str,
    flags: bool,
) -> GateResult<Capture> {
    let mut args = vec![
        "recover".into(),
        "--config".into(),
        config.display().to_string(),
        "--approval".into(),
        approval.display().to_string(),
        "--expected-nonce".into(),
        nonce.into(),
        "--acknowledgement-id".into(),
        "c243-verified-process-fences".into(),
    ];
    if flags {
        args.extend(["--old-primary-fenced".into(), "--old-relays-fenced".into()]);
    }
    capture(&fixture.relay_binary, &args).await
}

fn fence_bytes(path: &Path, highest: Option<u64>) -> GateResult<Vec<u8>> {
    let bytes = fs::read(path).map_err(|_| "read independent recovery fence")?;
    require(bytes.len() <= 4096, "recovery fence evidence bound")?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "recovery fence evidence JSON")?;
    require(
        value["highest_approval_version"].as_u64() == highest,
        "unexpected consumed approval version",
    )?;
    Ok(bytes)
}

struct Revocations {
    config: ConnectConfig,
    credential: tunnel_catalog::CredentialRecord,
    principal: Uuid,
    token: String,
}

impl Revocations {
    fn new(fixture: &Fixture) -> GateResult<Self> {
        let device = fixture
            .topology
            .devices_a
            .get(1)
            .ok_or("second device missing")?;
        let credential = fixture
            .records
            .credentials
            .iter()
            .find(|record| record.device_id == device.id)
            .ok_or("exact seeded credential missing")?
            .clone();
        let consumer = fixture
            .topology
            .consumers_a
            .get(1)
            .ok_or("second consumer missing")?;
        let token = fixture
            .oidc
            .issue_for_tenant(&consumer.name, consumer.tenant_id)
            .map_err(|_| "revocation consumer token")?;
        let mut config = fixture.client_config.clone();
        config.device_id = device.id.to_string();
        config.credentials.client_certificate = fixture
            .files
            .write(
                "revoked-device.pem",
                format!(
                    "{}{}",
                    device.certificate.certificate_pem, fixture.pki.device_ca.certificate_pem
                )
                .as_bytes(),
            )
            .map_err(|_| "second device certificate")?;
        config.credentials.client_key = fixture
            .files
            .write(
                "revoked-device.key",
                device.certificate.private_key_pem.as_bytes(),
            )
            .map_err(|_| "second device key")?;
        let service = fixture
            .topology
            .service_ids
            .get(&device.id)
            .ok_or("second device service missing")?;
        let export = config
            .exports
            .values()
            .next()
            .ok_or("echo export missing")?
            .clone();
        config.exports = BTreeMap::from([(service.to_string(), export)]);
        Ok(Self {
            config,
            credential,
            principal: consumer.id,
            token,
        })
    }

    async fn credential_probe(&self, denied: bool) -> GateResult {
        let connected = timeout(
            PROCESS_BOUND,
            connect(ConnectOptions::new(self.config.clone())),
        )
        .await
        .map_err(|_| "credential probe deadline")?;
        match connected {
            Err(tunnel_client::ClientError::Credential(_)) if denied => Ok(()),
            Err(_) => Err("credential probe did not reach required authenticated outcome"),
            Ok(mut handle) => {
                let ready = timeout(PROCESS_BOUND, handle.wait_ready()).await;
                timeout(PROCESS_BOUND, handle.stop())
                    .await
                    .map_err(|_| "credential probe stop deadline")?
                    .map_err(|_| "credential probe stop")?;
                require(
                    !denied && ready.is_ok_and(|result| result.is_ok()),
                    "revoked credential established or valid credential failed",
                )
            }
        }
    }

    async fn revoke(&self, fixture: &Fixture) -> GateResult {
        let base = [
            "--config".into(),
            fixture.relays[0].config.display().to_string(),
            "--tenant".into(),
            fixture.tenant_id.to_string(),
        ];
        let mut credential = vec!["revoke-credential".into()];
        credential.extend(base.clone());
        credential.extend([
            "--device".into(),
            self.credential.device_id.to_string(),
            "--credential".into(),
            self.credential.credential_id.to_string(),
        ]);
        command(&fixture.relay_binary, &credential).await?;
        let mut grant = vec!["revoke-grant".into()];
        grant.extend(base);
        grant.extend([
            "--user".into(),
            self.principal.to_string(),
            "--device".into(),
            fixture.device_id.to_string(),
            "--service".into(),
            fixture.service_id.to_string(),
        ]);
        command(&fixture.relay_binary, &grant).await
    }

    async fn raw_flags(
        &self,
        fixture: &Fixture,
        admin: &mut redis::aio::MultiplexedConnection,
        namespace: &str,
        active: bool,
    ) -> GateResult {
        let prefix = format!("tunnel-catalog:{namespace}:");
        let credential = format!(
            "{prefix}credential:{}:{}:{}",
            fixture.tenant_id, self.credential.device_id, self.credential.credential_id
        );
        let grant = format!(
            "{prefix}grant:{}:{}:{}:{}",
            fixture.tenant_id, self.principal, fixture.device_id, fixture.service_id
        );
        for key in [credential, grant] {
            let value: String =
                bounded_redis(admin, redis::cmd("HGET").arg(key).arg("active")).await?;
            require(
                value == if active { "1" } else { "0" },
                "restored/reconciled revocation flags differ from external fixture evidence",
            )?;
        }
        Ok(())
    }

    async fn denied(&self, fixture: &Fixture) -> GateResult {
        // Positive traffic immediately adjacent to the negatives rules out
        // dependency unavailability masquerading as authorization denial.
        fixture.canary("revocation-positive-control").await?;
        self.credential_probe(true).await?;
        fixture
            .canary_with_token("revoked-grant", &self.token, true)
            .await
    }
}

async fn fence_processes(fixture: &mut Fixture) -> GateResult {
    fixture.stop_device().await?;
    fixture.stop_authority().await?;
    fixture.stop_relays().await?;
    for (relay, port) in fixture.relays.iter().zip(&fixture.peer_ports) {
        common::wait_for_ports_released(
            relay.consumer,
            relay.device,
            SocketAddr::from(([127, 0, 0, 1], *port)),
        )
        .await
        .map_err(|_| "old relay listeners remained bound")?;
    }
    let port: u16 = fixture
        .endpoint
        .strip_prefix("https://localhost:")
        .and_then(|text| text.split('/').next())
        .and_then(|text| text.parse().ok())
        .ok_or("authority endpoint fixture shape")?;
    require(
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "old authority listener remained bound",
    )
}

async fn confirm_next(
    fixture: &mut Fixture,
    catalog: &RedisCatalog,
    evidence: &SessionEvidence,
    previous: u64,
) -> GateResult<u64> {
    let client = fixture.client(&fixture.relays[0].identity)?;
    let next = timeout(PUBLISH_BOUND, async {
        loop {
            let checkpoint = fixture.wait_checkpoint(&client).await?;
            if checkpoint
                .minimum_versions
                .values()
                .all(|value| *value > previous)
            {
                return Ok::<_, &'static str>(checkpoint);
            }
            fixture.canary("waiting-next-publication").await?;
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| "new confirmed publication deadline")??;
    fixture
        .wait_relay_adoption(&next, catalog, evidence)
        .await?;
    next.minimum_versions
        .values()
        .copied()
        .min()
        .ok_or("empty checkpoint")
}

async fn drill(
    fixture: &mut Fixture,
    url: &str,
    namespace: &str,
    old: &Container,
    candidate: &Container,
    catalog: RedisCatalog,
) -> GateResult {
    let mut admin = admin_connection(url).await?;
    let prefix = format!("tunnel-catalog:{namespace}:");
    let revocations = Revocations::new(fixture)?;
    // A separate private root can be mounted only for offline CLI invocations.
    // The online authority fixture root never contains recovery private keys.
    let offline = FixtureFiles::new().map_err(|_| "offline operator directory")?;
    let private = offline
        .state_path()
        .map_err(|_| "offline operator state directory")?
        .with_file_name("offline-recovery.der");
    let offline_trust = private.with_file_name("offline-recovery-public.json");
    let fence = fixture
        .state
        .with_file_name("independent-recovery-fence.json");
    command(
        &fixture.authority_binary,
        &[
            "generate-key".into(),
            "--key-id".into(),
            KEY_ID.into(),
            "--private-key".into(),
            private.display().to_string(),
            "--public-keys".into(),
            offline_trust.display().to_string(),
        ],
    )
    .await?;
    let trust = fixture
        .files
        .write(
            "recovery-public.json",
            &fs::read(&offline_trust).map_err(|_| "offline public trust")?,
        )
        .map_err(|_| "install public recovery trust")?;
    let recovery_config = candidate_configs(fixture, &trust, &fence)?;
    command(
        &fixture.relay_binary,
        &[
            "recovery-initialize".into(),
            "--config".into(),
            recovery_config.display().to_string(),
        ],
    )
    .await?;
    let empty_fence = fence_bytes(&fence, None)?;

    // Capture the old physical backup before any device sessions/tickets.
    // The named publisher ACL is control-plane input, copied separately.
    bounded_redis::<()>(&mut admin, redis::cmd("ACL").arg("SAVE")).await?;
    bounded_redis::<()>(&mut admin, &mut redis::cmd("SAVE")).await?;
    old.inspect().await?;
    let size = docker_output(&[
        "exec".into(),
        old.id.clone(),
        "stat".into(),
        "-c".into(),
        "%s".into(),
        "/data/dump.rdb".into(),
    ])
    .await?;
    let size: u64 = std::str::from_utf8(&size)
        .map_err(|_| "RDB size encoding")?
        .trim()
        .parse()
        .map_err(|_| "RDB size")?;
    require(
        size > 0 && size <= 8 * 1024 * 1024,
        "physical backup exceeds fixture bound",
    )?;
    let backup = fixture.state.with_file_name("older.rdb");
    let acl = fixture.state.with_file_name("publisher-users.acl");
    old.copy_out("/data/dump.rdb", &backup).await?;
    old.copy_out("/data/users.acl", &acl).await?;
    require(
        fs::metadata(&backup).map_err(|_| "backup metadata")?.len() == size,
        "backup size changed during copy",
    )?;
    let old_durable = snapshot::capture(old.address, &prefix)
        .await
        .map_err(|_| "capture old independent durable snapshot")?;
    println!(
        "c243 phase=old-backup rdb_bytes={size} rdb_sha256={}",
        fingerprint(&fs::read(&backup).map_err(|_| "read bounded RDB")?)
    );

    fixture.start_authority().await?;
    let initial = fixture
        .wait_checkpoint(&fixture.client(&fixture.relays[0].identity)?)
        .await?;
    fixture.start_relays().await?;
    fixture.connect_device().await?;
    let old_session = fixture.session_evidence(&catalog).await?;
    drop(catalog);
    let old_authority_pid = fixture
        .authority
        .as_ref()
        .and_then(ManagedProcess::id)
        .ok_or("old authority PID missing")?;
    let (old_redis_running, old_redis_pid) = old.inspect().await?;
    require(
        old_redis_running && old_redis_pid != 0,
        "old Redis PID evidence missing",
    )?;
    fixture.canary("before-recovery").await?;
    fixture
        .canary_with_token("grant-before-revocation", &revocations.token, false)
        .await?;
    revocations.credential_probe(false).await?;
    revocations.revoke(fixture).await?;
    revocations.denied(fixture).await?;
    println!("c243 phase=live-three-relays positive_canary=true credential_and_grant_revoked=true");
    fence_processes(fixture).await?;
    let old_state = fixture.state()?;
    let old_relay_states: Vec<_> = fixture
        .relays
        .iter()
        .map(|relay| {
            fs::read(&relay.version_state)
                .map(|bytes| (relay.version_state.clone(), fingerprint(&bytes)))
                .map_err(|_| "old relay state evidence")
        })
        .collect::<GateResult<_>>()?;
    let old_configs: Vec<_> = fixture
        .relays
        .iter()
        .map(|relay| relay.config.clone())
        .collect();
    revocations
        .raw_flags(fixture, &mut admin, namespace, false)
        .await?;
    // Only after all serving writers exited: this latest snapshot is the
    // independently retained operator evidence for reconciliation, not Redis
    // discovering whether its subsequently restored backup is complete.
    let reconciled = snapshot::capture(old.address, &prefix)
        .await
        .map_err(|_| "capture independent latest revoked catalog")?;
    let (records, bytes, hash) = reconciled.summary();
    println!(
        "c243 phase=independent-revocation-evidence records={records} bytes={bytes} sha256={hash}"
    );
    old.stop().await?;
    let fenced_at = Instant::now();
    println!(
        "c243 phase=old-processes-fenced relay_pids={:?} authority_pid={old_authority_pid} redis_pid={old_redis_pid} listeners_released=true",
        old_session.relay_pids
    );
    candidate.copy_in(&backup, "/data/dump.rdb").await?;
    candidate.copy_in(&acl, "/data/users.acl").await?;
    candidate.start().await?;
    admin = reconnect_admin(url).await?;
    let new_run = redis_run(&mut admin).await?;
    require(
        new_run != fixture.redis_run,
        "restored Redis reused old process run identity",
    )?;
    bounded_redis::<()>(
        &mut admin,
        redis::cmd("CONFIG")
            .arg("SET")
            .arg("appendfsync")
            .arg("always"),
    )
    .await?;
    bounded_redis::<()>(
        &mut admin,
        redis::cmd("CONFIG").arg("SET").arg("appendonly").arg("yes"),
    )
    .await?;
    timeout(Duration::from_secs(20), async {
        loop {
            let info: String =
                bounded_redis(&mut admin, redis::cmd("INFO").arg("PERSISTENCE")).await?;
            if info.lines().any(|line| line.trim() == "aof_enabled:1")
                && info
                    .lines()
                    .any(|line| line.trim() == "aof_rewrite_in_progress:0")
                && info
                    .lines()
                    .any(|line| line.trim() == "aof_rewrite_scheduled:0")
                && info
                    .lines()
                    .any(|line| line.trim() == "aof_last_bgrewrite_status:ok")
                && info
                    .lines()
                    .any(|line| line.trim() == "aof_last_write_status:ok")
            {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, &'static str>(())
    })
    .await
    .map_err(|_| "restored AOF durability deadline")??;
    revocations
        .raw_flags(fixture, &mut admin, namespace, true)
        .await?;
    sleep(QUIESCENCE.saturating_sub(fenced_at.elapsed())).await;
    require(
        old.inspect().await? == (false, 0) && fenced_at.elapsed() >= QUIESCENCE,
        "old primary restarted or quiescence boundary was shortened",
    )?;
    println!(
        "c243 phase=older-rdb-restored changed_run=true omitted_revocations=true quiescence_ms={}",
        fenced_at.elapsed().as_millis()
    );

    reconciled
        .restore(candidate.address, &prefix)
        .await
        .map_err(|_| "apply independent reconciled catalog")?;
    revocations
        .raw_flags(fixture, &mut admin, namespace, false)
        .await?;
    let observed = observe(fixture, &recovery_config).await?;
    require(
        observed["redis_run_id"] == new_run,
        "observation did not bind independently checked candidate run",
    )?;
    let signed = sign(fixture, &offline, &observed, &private, "reviewed").await?;
    refusal(
        &recover(fixture, &recovery_config, &signed, NONCE, false).await?,
        "recover requires",
    )?;
    require(
        fence_bytes(&fence, None)? == empty_fence,
        "missing acknowledgements mutated fence",
    )?;
    refusal(
        &recover(
            fixture,
            &recovery_config,
            &signed,
            "c243-different-operator-challenge",
            true,
        )
        .await?,
        "recovery approval was rejected",
    )?;
    require(
        fence_bytes(&fence, None)? == empty_fence,
        "wrong nonce mutated fence",
    )?;
    old_durable
        .restore(candidate.address, &prefix)
        .await
        .map_err(|_| "restore stale catalog negative control")?;
    revocations
        .raw_flags(fixture, &mut admin, namespace, true)
        .await?;
    refusal(
        &recover(fixture, &recovery_config, &signed, NONCE, true).await?,
        "recovery approval does not match the live catalog observation",
    )?;
    require(
        fence_bytes(&fence, None)? == empty_fence,
        "stale digest consumed fence",
    )?;
    println!(
        "c243 phase=negative-controls missing_fences=true wrong_nonce=true stale_digest=true fence_unchanged=true"
    );
    reconciled
        .restore(candidate.address, &prefix)
        .await
        .map_err(|_| "reapply independently reconciled catalog")?;
    let fresh = observe(fixture, &recovery_config).await?;
    require(
        fresh["catalog_digest"] == observed["catalog_digest"],
        "reconciliation did not restore reviewed digest",
    )?;
    let final_signed = sign(fixture, &offline, &fresh, &private, "fresh").await?;
    let accepted = recover(fixture, &recovery_config, &final_signed, NONCE, true).await?;
    require(
        accepted.success,
        "actual signed recovery CLI refused reconciled candidate",
    )?;
    let consumed = fence_bytes(&fence, Some(1))?;
    refusal(
        &recover(fixture, &recovery_config, &final_signed, NONCE, true).await?,
        "recovery approval was rejected",
    )?;
    require(
        fence_bytes(&fence, Some(1))? == consumed,
        "replay changed durable recovery fence",
    )?;
    println!("c243 phase=actual-cli-recovery consumed_version=1 replay_refused=true");

    // Old configuration must refuse at startup, before new inventory is
    // approved. A bound run or active-incarnation cause is independently
    // asserted; general readiness failure is insufficient evidence.
    let active: String = bounded_redis(
        &mut admin,
        redis::cmd("GET").arg(format!("{prefix}meta:active_incarnation")),
    )
    .await?;
    let bound_run: String = bounded_redis(
        &mut admin,
        redis::cmd("GET").arg(format!("{prefix}meta:redis_run_id")),
    )
    .await?;
    require(
        active == CANDIDATE && bound_run == new_run,
        "recovery did not activate the exact reviewed incarnation/run",
    )?;
    for config in &old_configs {
        let output = capture(
            &fixture.relay_binary,
            &[
                "serve".into(),
                "--config".into(),
                config.display().to_string(),
            ],
        )
        .await?;
        require(
            !output.success
                && String::from_utf8_lossy(&output.stderr).contains("stage=authority_identity")
                && String::from_utf8_lossy(&output.stderr).contains("class=catalog"),
            "old relay configuration did not reach an incarnation/run refusal",
        )?;
    }
    let unchanged_authority = capture(
        &fixture.authority_binary,
        &[
            "serve".into(),
            "--config".into(),
            fixture.config.display().to_string(),
        ],
    )
    .await?;
    refusal(
        &unchanged_authority,
        "Redis run differs from independent durable approval; recovery required",
    )?;
    let before_approval = fixture.state()?;
    for field in ["membership_high_water", "checkpoint_high_water"] {
        require(
            before_approval[field] == old_state[field],
            "old inventory start altered authority high-water",
        )?;
    }
    fixture.redis_run = new_run;
    move_to_candidate(fixture)?;
    fixture.approve(false, 1).await?;
    let approved = fixture.state()?;
    for field in ["membership_high_water", "checkpoint_high_water"] {
        require(
            approved[field] == old_state[field],
            "new incarnation reset an independent allocator",
        )?;
    }
    require(
        approved["confirmed"].is_null(),
        "approval retained old confirmation",
    )?;
    fixture.start_authority().await?;
    let first = fixture
        .wait_checkpoint(&fixture.client(&fixture.relays[0].identity)?)
        .await?;
    let membership_high = old_state["membership_high_water"]
        .as_u64()
        .ok_or("old membership high-water missing")?;
    let checkpoint_high = old_state["checkpoint_high_water"]
        .as_u64()
        .ok_or("old checkpoint high-water missing")?;
    require(
        first.checkpoint_version > checkpoint_high
            && first.minimum_versions.len() == 3
            && first
                .minimum_versions
                .values()
                .all(|value| *value > membership_high),
        "candidate reused old authority allocations",
    )?;
    fixture.start_relays().await?;
    fixture.connect_device().await?;
    let fresh_catalog =
        RedisCatalog::connect_with_deployment_incarnation(url, namespace, CANDIDATE)
            .await
            .map_err(|_| "fresh recovered catalog connection")?;
    let new_session = fixture.session_evidence(&fresh_catalog).await?;
    require(
        new_session.session.session_id != old_session.session.session_id
            && new_session.connection_id != old_session.connection_id
            && new_session.owner.deployment_incarnation == CANDIDATE,
        "recovery reused the old device session or incarnation",
    )?;
    fixture
        .wait_relay_adoption(&first, &fresh_catalog, &new_session)
        .await?;
    revocations.denied(fixture).await?;
    let minimum = first
        .minimum_versions
        .values()
        .copied()
        .min()
        .ok_or("first candidate membership floor missing")?;
    let second = confirm_next(fixture, &fresh_catalog, &new_session, minimum).await?;
    confirm_next(fixture, &fresh_catalog, &new_session, second).await?;
    revocations.denied(fixture).await?;
    for (path, hash) in old_relay_states {
        require(
            fingerprint(&fs::read(path).map_err(|_| "retained old relay state missing")?) == hash,
            "candidate initialization overwrote old relay state",
        )?;
    }
    require(
        fence_bytes(&fence, Some(1))? == consumed && old.inspect().await? == (false, 0),
        "recovery fence or old primary changed after acceptance",
    )?;
    require(
        initial.minimum_versions.len() == 3,
        "initial checkpoint omitted a relay",
    )?;
    println!(
        "c243 phase=PASS three_relays=3 nonowner_exact_canary=true revoked_credential_denied=true revoked_grant_denied=true fresh_session=true confirmed_refreshes=2 allocators_preserved=true independent_fence_preserved=true device=production-library"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run scripts/m6-authority-recovery-verify.sh; requires both precisely owned Redis containers"]
async fn online_authority_three_relay_cli_recovery_preserves_reconciled_revocations() {
    let url = env::var("TEST_REDIS_URL").expect("owned recovery wrapper Redis URL");
    let address = parse_plaintext_upstream(&url).expect("owned loopback Redis URL");
    let old = Container::from_environment("old", address)
        .await
        .expect("old Redis identity");
    let candidate = Container::from_environment("candidate", address)
        .await
        .expect("candidate Redis identity");
    assert_ne!(old.id, candidate.id);
    assert_eq!(
        candidate.inspect().await.expect("candidate starts stopped"),
        (false, 0)
    );
    let suffix = Uuid::new_v4().simple().to_string();
    let namespace = format!("test-authority-recovery-{suffix}");
    let username = format!("recovery-publisher-{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    let mut fixture = None;
    let outcome = timeout(DRILL_BOUND, async {
        let mut admin = admin_connection(&url).await?;
        publisher_acl(&mut admin, &namespace, &username, &password).await?;
        let catalog =
            RedisCatalog::connect_for_recovery(&url, &namespace, "authority-incarnation-a")
                .await
                .map_err(|_| "initial fixture catalog")?;
        catalog
            .activate_deployment_incarnation()
            .await
            .map_err(|_| "initial fixture activation")?;
        fixture = Some(
            Fixture::create(
                address,
                &namespace,
                &username,
                &password,
                catalog.bound_redis_run_id(),
                &catalog,
            )
            .await?,
        );
        drill(
            fixture.as_mut().ok_or("recovery fixture missing")?,
            &url,
            &namespace,
            &old,
            &candidate,
            catalog,
        )
        .await
    })
    .await
    .map_err(|_| "three-relay recovery drill deadline")
    .and_then(|result| result);
    // Dedicated containers own all catalog/ACL state; the wrapper removes only
    // their verified immutable IDs after this process has reaped its children.
    let cleanup = if let Some(fixture) = fixture {
        fixture.cleanup().await
    } else {
        Ok(())
    };
    outcome
        .and(cleanup)
        .expect("actual three-relay operator recovery drill");
}
