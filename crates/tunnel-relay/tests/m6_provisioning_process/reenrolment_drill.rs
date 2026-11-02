//! M6-C233: the approved replacement-device workaround, through shipped
//! commands and a single configured relay. This is not same-device renewal,
//! CA rollover, multi-relay failover, or evidence about a live tester's keys.
//!
//! The issuer is the fixture's external OpenSSL CA. The OLD certificate really
//! expires after 120 seconds; no catalog clock/expiry is edited. Revocation
//! must close its live session before that expiry. NEW has a separate key,
//! device/service/credential IDs and a one-day certificate. Two existing users
//! retain exactly their supported grant policy; an ungranted member stays out.

use super::*;
use chrono::{DateTime, Timelike, Utc};

const OLD_LIFETIME: chrono::Duration = chrono::Duration::seconds(120);
const REVOCATION_BOUND: Duration = Duration::from_secs(5);
const OLD_CANARY: &str = "m6c233-old-device";
const NEW_CANARY: &str = "m6c233-new-device";

struct Identity {
    device: Uuid,
    service: Uuid,
    credential: Uuid,
    config: PathBuf,
    certificate: PathBuf,
    expires: DateTime<Utc>,
    canary: &'static str,
}

struct Connector {
    process: Running,
    log: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Session {
    id: String,
    epoch: u64,
}

/// Bound new command steps by the shared 20-second command/readiness bound.
/// Files avoid waiting on a full stdout pipe; Running reaps on every failure.
fn command(fixture: &Provisioned, name: &str, command: &mut Command) -> Output {
    let stem = fixture.work.join(format!("command-{}", Uuid::new_v4()));
    let out = stem.with_extension("out");
    let err = stem.with_extension("err");
    let mut child = Running(
        command
            .stdout(fs::File::create(&out).expect("command stdout"))
            .stderr(fs::File::create(&err).expect("command stderr"))
            .spawn()
            .unwrap_or_else(|error| panic!("step {name}: spawn failed: {error}")),
    );
    let deadline = Instant::now() + STEP_DEADLINE;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll command") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "step {name}: command exceeded {STEP_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = Output {
        status,
        stdout: fs::read(out).expect("command stdout"),
        stderr: fs::read(err).expect("command stderr"),
    };
    assert!(
        output.status.success(),
        "step {name}: exit {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(4096)
            .collect::<String>()
    );
    output
}

fn change(fixture: &Provisioned, name: &str, args: &[&str]) -> String {
    stdout(&command(
        fixture,
        name,
        Command::new(&fixture.relay_bin)
            .args(args)
            .arg("--config")
            .arg(&fixture.relay_config),
    ))
}

fn records(fixture: &Provisioned, action: &str, path: &Path, contents: String) -> String {
    fs::write(path, contents).expect("write operator records");
    change(
        fixture,
        action,
        &[action, "--records", path.to_str().expect("records path")],
    )
}

fn prepare(fixture: &Provisioned, label: &str, canary: &'static str, short: bool) -> Identity {
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let dir = fixture.work.join(label);
    fs::create_dir(&dir).expect("device profile directory");
    let config = dir.join("client.toml");
    let profile = fs::read_to_string(&fixture.client_config)
        .expect("profile template")
        .replace(&fixture.device.to_string(), &device.to_string())
        .replace(&fixture.service.to_string(), &service.to_string())
        .replace(CANARY, canary);
    fs::write(&config, profile).expect("new profile");
    command(
        fixture,
        "credentials create",
        Command::new(&fixture.client_bin)
            .args(["credentials", "create", "--config"])
            .arg(&config)
            .args(["--csr-out", "device.csr"]),
    );

    // `openssl ca` supports an explicit notAfter, unlike x509 -req -days.
    // Each identity has its own issuer database; neither is relay state.
    let issued = Utc::now().with_nanosecond(0).expect("whole seconds");
    let expires = issued
        + if short {
            OLD_LIFETIME
        } else {
            chrono::Duration::days(1)
        };
    let issuer = dir.join("issuer.cnf");
    fs::write(dir.join("index.txt"), "").expect("issuer index");
    fs::write(dir.join("serial"), format!("{}\n", Uuid::new_v4().simple())).expect("issuer serial");
    fs::write(
        &issuer,
        format!(
            "[ca]\ndefault_ca = issuer\n[issuer]\n\
         database = {}\nserial = {}\nnew_certs_dir = {}\n\
         certificate = {}\nprivate_key = {}\ndefault_md = sha256\n\
         policy = subject\nx509_extensions = device\nunique_subject = no\n\
         [subject]\ncommonName = supplied\n[device]\nbasicConstraints = CA:FALSE\n\
         keyUsage = digitalSignature\nextendedKeyUsage = clientAuth\n\
         subjectAltName = URI:urn:agent-tunnel:device:{device}\n",
            dir.join("index.txt").display(),
            dir.join("serial").display(),
            dir.display(),
            fixture.device_ca.display(),
            fixture.device_ca_key.display()
        ),
    )
    .expect("issuer configuration");
    let certificate = dir.join("device-cert.pem");
    command(
        fixture,
        "issue real-expiry certificate",
        Command::new("openssl")
            .args(["ca", "-batch", "-notext", "-config"])
            .arg(issuer)
            .arg("-startdate")
            .arg(
                (issued - chrono::Duration::seconds(5))
                    .format("%y%m%d%H%M%SZ")
                    .to_string(),
            )
            .arg("-enddate")
            .arg(expires.format("%y%m%d%H%M%SZ").to_string())
            .arg("-in")
            .arg(dir.join("device.csr"))
            .arg("-out")
            .arg(&certificate),
    );
    let dates = stdout(&command(
        fixture,
        "read actual certificate expiry",
        Command::new("openssl")
            .args(["x509", "-noout", "-enddate", "-in"])
            .arg(&certificate),
    ));
    let actual = chrono::NaiveDateTime::parse_from_str(
        dates
            .trim()
            .strip_prefix("notAfter=")
            .expect("certificate notAfter"),
        "%b %e %H:%M:%S %Y GMT",
    )
    .expect("parse certificate notAfter")
    .and_utc();
    assert_eq!(
        actual, expires,
        "issuer must write the requested real deadline"
    );
    command(
        fixture,
        "credentials import",
        Command::new(&fixture.client_bin)
            .args(["credentials", "import", "--config"])
            .arg(&config)
            .args(["--certificate", "device-cert.pem", "--server-ca"])
            .arg(&fixture.server_ca),
    );
    Identity {
        device,
        service,
        credential: Uuid::nil(),
        config,
        certificate,
        expires,
        canary,
    }
}

fn enrol(fixture: &Provisioned, identity: &mut Identity, tenant: Uuid, user: Uuid) {
    let dir = identity.config.parent().expect("profile directory");
    let added = records(
        fixture,
        "add-device",
        &dir.join("device.toml"),
        format!(
            "[device]\ntenant = \"{tenant}\"\nowner = \"{user}\"\nid = \"{}\"\n\
         display_name = \"Re-enrolment fixture\"\ncertificate = {}\n",
            identity.device,
            toml_string(&identity.certificate)
        ),
    );
    identity.credential = added
        .split_whitespace()
        .find_map(|field| field.strip_prefix("credential="))
        .and_then(|id| id.parse().ok())
        .expect("actual add-device credential ID");
    records(
        fixture,
        "add-service",
        &dir.join("service.toml"),
        format!(
            "[service]\ntenant = \"{tenant}\"\ndevice = \"{}\"\nid = \"{}\"\n\
         type = \"echo\"\ndisplay_name = \"Re-enrolment echo\"\noperations = [\"echo:invoke\"]\n",
            identity.device, identity.service
        ),
    );
    let key = credential_key(tenant, identity);
    assert_eq!(
        field(fixture, &key, "expires_at_us"),
        Some(identity.expires.timestamp_micros().to_string()),
        "catalog expiry must derive from this certificate, not the old identity"
    );
}

fn grant(
    fixture: &Provisioned,
    tenant: Uuid,
    user: Uuid,
    identity: &Identity,
    expires: Option<DateTime<Utc>>,
) {
    let expiry = expires
        .map(|at| format!("expires_at = \"{}\"\n", at.to_rfc3339()))
        .unwrap_or_default();
    records(
        fixture,
        "set-grant",
        &identity
            .config
            .parent()
            .expect("profile directory")
            .join(format!("grant-{user}.toml")),
        format!(
            "[grant]\ntenant = \"{tenant}\"\nuser = \"{user}\"\ndevice = \"{}\"\n\
         service = \"{}\"\noperations = [\"echo:invoke\"]\n{expiry}",
            identity.device, identity.service
        ),
    );
}

/// Only read-only Redis commands are used for witnesses; all writes are CLI.
fn field(fixture: &Provisioned, key: &str, field: &str) -> Option<String> {
    let reply = redis_command(
        fixture.upstream,
        fixture.database,
        &[
            "HGET",
            &format!("tunnel-catalog:{}:{key}", fixture.namespace),
            field,
        ],
    );
    let reply = std::str::from_utf8(&reply).expect("UTF-8 metadata RESP");
    let bulk = reply
        .strip_prefix("+OK\r\n$")
        .expect("SELECT and bulk response");
    let (length, value) = bulk.split_once("\r\n").expect("bulk header");
    if length == "-1" {
        assert_eq!(value, "");
        None
    } else {
        let length: usize = length.parse().expect("bulk length");
        assert_eq!(value.len(), length + 2, "complete metadata reply");
        Some(value[..length].to_owned())
    }
}

fn credential_key(tenant: Uuid, identity: &Identity) -> String {
    format!(
        "credential:{tenant}:{}:{}",
        identity.device, identity.credential
    )
}

fn grant_key(tenant: Uuid, user: Uuid, identity: &Identity) -> String {
    format!(
        "grant:{tenant}:{user}:{}:{}",
        identity.device, identity.service
    )
}

fn owner_key(fixture: &Provisioned, tenant: Uuid, identity: &Identity) -> String {
    // This fixture's incarnation is namespace, containing only safe ASCII.
    assert!(
        fixture
            .namespace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    );
    format!(
        "coord:owner:{}:{tenant}:{}",
        fixture.namespace, identity.device
    )
}

fn start(fixture: &Provisioned, identity: &Identity, label: &str) -> Connector {
    let log = fixture.work.join(format!("connect-{label}.log"));
    let process = Running(
        Command::new(&fixture.client_bin)
            .args(["connect", "--config"])
            .arg(&identity.config)
            .arg("--json")
            .stdout(fs::File::create(&log).expect("connector log"))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connector"),
    );
    Connector { process, log }
}

async fn ready(connector: &mut Connector, previous: Option<&Session>, bound: Duration) -> Session {
    let deadline = Instant::now() + bound;
    loop {
        assert!(
            connector
                .process
                .0
                .try_wait()
                .expect("poll connector")
                .is_none(),
            "replacement connector exited before a fresh ready session"
        );
        for line in fs::read_to_string(&connector.log)
            .unwrap_or_default()
            .lines()
            .rev()
        {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let result = &value["result"];
            if result["state"] != "ready" {
                continue;
            }
            let session = Session {
                id: result["session_id"]
                    .as_str()
                    .expect("ready session")
                    .to_owned(),
                epoch: result["epoch"].as_u64().expect("ready epoch"),
            };
            if previous.is_none_or(|old| old.id != session.id && session.epoch > old.epoch) {
                return session;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no fresh ready session within {bound:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn assert_owner(
    fixture: &Provisioned,
    tenant: Uuid,
    identity: &Identity,
    session: &Session,
    boot: &str,
) {
    let key = owner_key(fixture, tenant, identity);
    assert_eq!(
        field(fixture, &key, "session_id").as_deref(),
        Some(session.id.as_str())
    );
    assert_eq!(
        field(fixture, &key, "owner_epoch"),
        Some(session.epoch.to_string())
    );
    assert_eq!(field(fixture, &key, "boot_id").as_deref(), Some(boot));
}

async fn echo(fixture: &Provisioned, token: &str, identity: &Identity, phase: &str) {
    let payload = format!("m6c233-{phase}-{}", fixture.nonce);
    let deadline = tokio::time::Instant::now() + STEP_DEADLINE;
    loop {
        let (status, body) = tokio::time::timeout_at(
            deadline,
            echo_once(fixture, token, identity.device, identity.service, &payload),
        )
        .await
        .expect("echo command deadline");
        if status == 200 {
            assert!(
                body == format!("{}{payload}", identity.canary).as_bytes(),
                "replacement canary and request bytes must match exactly: phase={phase}"
            );
            return;
        }
        let error = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default();
        assert!(
            status == 503
                && error["execution"] == "not_dispatched"
                && error["code"].as_str().is_some_and(|code| !code.is_empty()),
            "phase={phase}: non-retryable HTTP {status}; authorization/ambiguous failures are never retried"
        );
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_millis(50)).min(deadline),
        )
        .await;
    }
}

async fn denied(fixture: &Provisioned, token: &str, device: Uuid, service: Uuid) {
    let (status, _) = echo_once(fixture, token, device, service, "m6c233-denied").await;
    assert!(
        matches!(status, 403 | 404),
        "known member without matching grant must be denied, HTTP {status}"
    );
}

async fn stop(fixture: &Provisioned, identity: &Identity, connector: &mut Connector) {
    command(
        fixture,
        "disconnect replacement profile",
        Command::new(&fixture.client_bin)
            .args(["disconnect", "--config"])
            .arg(&identity.config)
            .arg("--json"),
    );
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        if let Some(status) = connector
            .process
            .0
            .try_wait()
            .expect("poll stopped connector")
        {
            assert_eq!(
                status.code(),
                Some(0),
                "disconnect must drain and exit cleanly"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "disconnect left a running connector"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable TEST_REDIS_URL and fresh TUNNEL_CLIENT_BIN; m6-provisioning-verify.sh and Linux acceptance"]
async fn m6c233_reenrolment_preserves_access_and_retires_old_identity() {
    tokio::time::timeout(Duration::from_secs(300), drill())
        .await
        .expect("bounded re-enrolment drill");
}

async fn drill() {
    let mut fixture = provision_and_serve_with(
        "m6c233-reenrolment",
        None,
        ServiceKind::Echo,
        ProvisionOptions {
            skip_stage_cases: true,
            ..ProvisionOptions::default()
        },
    )
    .await;
    let catalog: toml::Value = toml::from_str(
        &fs::read_to_string(repository().join("examples/m6-catalog.toml")).expect("example"),
    )
    .expect("catalog example");
    let tenant: Uuid = catalog["tenant"]["id"]
        .as_str()
        .expect("tenant")
        .parse()
        .expect("tenant UUID");
    let user: Uuid = catalog["user"]["id"]
        .as_str()
        .expect("user")
        .parse()
        .expect("user UUID");
    let delegated = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let mut tokens = vec![access_token(&fixture.issuer_key, &fixture.subject)];
    for (id, label) in [(delegated, "delegated"), (stranger, "ungranted")] {
        let subject = format!("m6c233-{label}-{}", fixture.nonce);
        records(
            &fixture,
            "add-user",
            &fixture.work.join(format!("{label}.toml")),
            format!(
                "[user]\ntenant = \"{tenant}\"\nid = \"{id}\"\ndisplay_name = \"{label}\"\noidc_subject = \"{subject}\"\n"
            ),
        );
        tokens.push(access_token(&fixture.issuer_key, &subject));
    }
    let policies = [
        (user, None),
        (
            delegated,
            Some(
                Utc::now().with_nanosecond(0).expect("whole seconds")
                    + chrono::Duration::minutes(30),
            ),
        ),
    ];
    let incarnation = namespace_get(&fixture, "meta:active_incarnation");
    let redis_run = namespace_get(&fixture, "meta:redis_run_id");
    let seed = namespace_get(&fixture, "meta:fixture_seeded");
    let initial_pid = fixture.relay.0.id();
    let initial_boot = format!("m6c21-boot-{}", fixture.nonce);
    let mut old = prepare(&fixture, "old", OLD_CANARY, true);
    enrol(&fixture, &mut old, tenant, user);
    for (user, expiry) in policies {
        grant(&fixture, tenant, user, &old, expiry);
    }
    let mut old_client = start(&fixture, &old, "old");
    let old_session = ready(&mut old_client, None, STEP_DEADLINE).await;
    assert_owner(&fixture, tenant, &old, &old_session, &initial_boot);
    for token in &tokens[..2] {
        echo(&fixture, token, &old, "old-positive").await;
    }

    let mut new = prepare(&fixture, "new", NEW_CANARY, false);
    // Local validity alone is not enrollment: a valid but unknown key is refused.
    expect_identity_refusal(
        "m6c233 replacement before add-device",
        &fixture.client_bin,
        &new.config,
    );
    enrol(&fixture, &mut new, tenant, user);
    assert_ne!(old.device, new.device);
    assert_ne!(old.service, new.service);
    assert_ne!(old.credential, new.credential);
    assert_ne!(
        field(&fixture, &credential_key(tenant, &old), "spki_fingerprint"),
        field(&fixture, &credential_key(tenant, &new), "spki_fingerprint"),
        "new identity must have a fresh key"
    );
    assert!(new.expires > old.expires);
    let mut new_client = start(&fixture, &new, "new-first");
    let first = ready(&mut new_client, None, STEP_DEADLINE).await;
    for token in &tokens[..2] {
        denied(&fixture, token, new.device, new.service).await;
    }
    for (user, expiry) in policies {
        grant(&fixture, tenant, user, &new, expiry);
        for property in ["permissions", "constraints", "expires_at_us", "active"] {
            let before = field(&fixture, &grant_key(tenant, user, &old), property);
            assert!(before.is_some(), "old grant policy must exist");
            assert_eq!(
                before,
                field(&fixture, &grant_key(tenant, user, &new), property),
                "migration must preserve every supported grant field: {property}"
            );
        }
    }
    for token in &tokens[..2] {
        echo(&fixture, token, &new, "migrated").await;
        denied(&fixture, token, old.device, new.service).await;
        denied(&fixture, token, new.device, old.service).await;
    }
    denied(&fixture, &tokens[2], old.device, old.service).await;
    denied(&fixture, &tokens[2], new.device, new.service).await;
    assert_owner(&fixture, tenant, &new, &first, &initial_boot);
    assert_eq!(
        fixture.relay.0.id(),
        initial_pid,
        "migration requires no relay restart"
    );
    // Keep OLD genuinely live until revoke; TTL or certificate expiry cannot be its witness.
    echo(&fixture, &tokens[0], &old, "before-revoke").await;
    assert!(
        Utc::now() + chrono::Duration::seconds(25) < old.expires,
        "setup must leave time to prove revocation independently of expiry"
    );
    while fixture.relay_log.try_recv().is_ok() {}
    change(
        &fixture,
        "revoke old device",
        &[
            "revoke-device",
            "--tenant",
            &tenant.to_string(),
            "--device",
            &old.device.to_string(),
        ],
    );
    let revoked_at = Instant::now();
    let mut reason = None;
    let mut ended = false;
    while reason.is_none() || !ended {
        while let Ok(line) = fixture.relay_log.try_recv() {
            if line.contains("owner_check_failed") && line.contains(&old.device.to_string()) {
                reason = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|value| value["fields"]["reason"].as_str().map(str::to_owned));
            }
        }
        ended |= fs::read_to_string(&old_client.log)
            .unwrap_or_default()
            .contains("\"state\":\"disconnected\"")
            || old_client
                .process
                .0
                .try_wait()
                .expect("poll old client")
                .is_some();
        assert!(
            revoked_at.elapsed() < REVOCATION_BOUND,
            "revocation must close the live old identity within 5 seconds: reason={reason:?} ended={ended}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let revoke_ms = revoked_at.elapsed().as_millis();
    assert_eq!(reason.as_deref(), Some("AUTHORIZATION_REVOKED"));
    assert!(
        Utc::now() < old.expires,
        "live revocation witness must precede real expiry"
    );
    assert_eq!(
        field(
            &fixture,
            &format!("device:{tenant}:{}", old.device),
            "active"
        )
        .as_deref(),
        Some("0")
    );
    for key in std::iter::once(credential_key(tenant, &old))
        .chain(policies.map(|(u, _)| grant_key(tenant, u, &old)))
    {
        assert_eq!(
            field(&fixture, &key, "active").as_deref(),
            Some("0"),
            "old credential/grants must all be revoked"
        );
        assert!(field(&fixture, &key, "revoked_at_us").is_some_and(|at| !at.is_empty()));
    }
    assert!(field(&fixture, &owner_key(&fixture, tenant, &old), "session_id").is_none());
    let terminal_deadline = Instant::now() + STEP_DEADLINE;
    loop {
        if let Some(status) = old_client
            .process
            .0
            .try_wait()
            .expect("poll revoked client")
        {
            assert_eq!(
                status.code(),
                Some(3),
                "revoked old client must stop with identity refusal"
            );
            break;
        }
        assert!(
            Instant::now() < terminal_deadline,
            "revoked old client kept retrying"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    expect_identity_refusal(
        "m6c233 revoked old profile",
        &fixture.client_bin,
        &old.config,
    );
    assert!(
        Utc::now() < old.expires,
        "fresh old reconnect must be refused before expiry"
    );
    for token in &tokens[..2] {
        denied(&fixture, token, old.device, old.service).await;
        echo(&fixture, token, &new, "after-revoke").await;
    }

    // Explicit device restart uses the on-disk NEW profile, not a still-pinned process.
    stop(&fixture, &new, &mut new_client).await;
    let previous_pid = new_client.process.0.id();
    new_client = start(&fixture, &new, "new-restarted");
    assert_ne!(new_client.process.0.id(), previous_pid);
    let second = ready(&mut new_client, Some(&first), M6C65_RECOVERY_DEADLINE).await;
    assert_owner(&fixture, tenant, &new, &second, &initial_boot);
    for token in &tokens[..2] {
        echo(&fixture, token, &new, "client-restarted").await;
    }

    // Then restart the relay with a fresh boot ID. The SAME new client must reconnect.
    let connector_pid = new_client.process.0.id();
    m6c65_stop_relay(&mut fixture.relay);
    let replacement_boot = format!("m6c233-restarted-{}", fixture.nonce);
    let config = set_key(
        &fs::read_to_string(&fixture.relay_config).expect("relay config"),
        "boot_id",
        &format!("\"{replacement_boot}\""),
    );
    fs::write(&fixture.relay_config, config).expect("fresh relay boot config");
    (fixture.relay, fixture.relay_log) = start_serve(&fixture.relay_bin, &fixture.relay_config);
    assert_ne!(fixture.relay.0.id(), initial_pid);
    let third = ready(&mut new_client, Some(&second), M6C65_RECOVERY_DEADLINE).await;
    assert_eq!(new_client.process.0.id(), connector_pid);
    assert_owner(&fixture, tenant, &new, &third, &replacement_boot);
    for token in &tokens[..2] {
        echo(&fixture, token, &new, "relay-restarted").await;
    }
    denied(&fixture, &tokens[2], new.device, new.service).await;
    assert_eq!(
        namespace_get(&fixture, "meta:active_incarnation"),
        incarnation
    );
    assert_eq!(namespace_get(&fixture, "meta:redis_run_id"), redis_run);
    assert_eq!(namespace_get(&fixture, "meta:fixture_seeded"), seed);

    // Cross the real OLD notAfter, retaining NEW's same ready session and grant policy.
    while Utc::now() <= old.expires {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for token in &tokens[..2] {
        echo(&fixture, token, &new, "past-old-expiry").await;
    }
    assert_owner(&fixture, tenant, &new, &third, &replacement_boot);
    assert_eq!(
        field(&fixture, &credential_key(tenant, &new), "active").as_deref(),
        Some("1")
    );
    assert_eq!(
        field(&fixture, &credential_key(tenant, &new), "expires_at_us"),
        Some(new.expires.timestamp_micros().to_string())
    );
    for token in &tokens[..2] {
        denied(&fixture, token, old.device, old.service).await;
    }
    stop(&fixture, &new, &mut new_client).await;
    m6c65_stop_relay(&mut fixture.relay);
    assert!(
        field(&fixture, &owner_key(&fixture, tenant, &new), "session_id").is_none(),
        "clean stop releases the replacement owner"
    );
    println!(
        "m6c233-reenrolment ok nonce={} namespace={} scope=single-relay migrated_users=2 \
        old_revocation_ms={revoke_ms} old_identity_exit=3 old_expiry_crossed=true \
        fresh_key=true fresh_sessions=3 client_restarts=1 relay_restarts=1 \
        grant_policy_preserved=true ungranted_denied=true clean_stop=true",
        fixture.nonce, fixture.namespace
    );
}
