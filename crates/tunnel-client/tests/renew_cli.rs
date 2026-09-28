//! Task row M0-07, `tunnel-client credentials renew`, on the real binary.
//!
//! * **The two steps.** `--csr-out` writes a pending key and a CSR and
//!   leaves the current pair byte-for-byte; the issued certificate is then
//!   completed with `--certificate`, which swaps the pair in.
//! * **Every exit.** Success `0`; a malformed invocation, a pending renewal
//!   (`RENEWAL_PENDING`), nothing pending (`RENEWAL_NOT_PENDING`) and a
//!   layout rename cannot renew (`CONFIG_ERROR`) `2`; a certificate for
//!   another key, from another issuer, or no current pair
//!   (`CREDENTIAL_ERROR`) `3`, each leaving the old pair; a held renewal
//!   lock (`RENEWAL_LOCKED`) `7`.
//! * **Killed between renames.** A debug build aborts after a named swap
//!   step when `TUNNEL_CLIENT_TEST_RENEW_ABORT_AFTER` names it -- SIGABRT, no
//!   cleanup, as a kill. After every step, `doctor` reports the state
//!   without changing it, and a following `connect` (or `renew`) resolves it
//!   to exactly one valid pair.
//! * **Redaction.** `--json` output carries no path (the credential
//!   directory's name is a canary), no key and no certificate body.
//!
//! Every key and certificate is generated per test; nothing is committed.

#![cfg(unix)]

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyIdMethod, KeyPair, SanType};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::{TempDir, tempdir};

const DEVICE: &str = "6a6b6c6d-6e6f-4a6b-8c6d-6e6f6a6b6c6d";

/// The swap's steps, in order, as `tunnel_client::renewal::SwapStep::name`.
const STEPS: [&str; 7] = [
    "certificate_staged",
    "previous_key_cleared",
    "previous_certificate_cleared",
    "previous_key_kept",
    "previous_certificate_kept",
    "certificate_installed",
    "key_installed",
];

fn client_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-client"))
}

fn toml_string(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

struct Issuer {
    key: KeyPair,
    certificate: rcgen::Certificate,
}

impl Issuer {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().expect("issuer key");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_identifier_method = KeyIdMethod::Sha256;
        let certificate = params.self_signed(&key).expect("issuer certificate");
        Self { key, certificate }
    }

    fn issue(&self, key_pem: &str) -> String {
        let subject = KeyPair::from_pem(key_pem).expect("subject key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("device/{DEVICE}"));
        params.subject_alt_names = vec![SanType::URI(
            format!("urn:agent-tunnel:device:{DEVICE}")
                .try_into()
                .expect("device role SAN"),
        )];
        params.use_authority_key_identifier_extension = true;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        params
            .signed_by(&subject, &self.certificate, &self.key)
            .expect("device certificate")
            .pem()
    }
}

/// A profile with a current pair from `issuer`, whose relay is a refused
/// loopback port so `connect` fails fast after its startup.
struct Profile {
    root: TempDir,
    dir: PathBuf,
    config: PathBuf,
    key: PathBuf,
    certificate: PathBuf,
    pending_key: PathBuf,
    canary: String,
}

impl Profile {
    fn new(issuer: &Issuer) -> Self {
        let root = tempdir().expect("fixture root");
        let canary = format!("cnry-renew-{}", std::process::id());
        let dir = root.path().join(&canary);
        fs::create_dir(&dir).expect("credential directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let key = dir.join("client-key.pem");
        let certificate = dir.join("client-cert.pem");
        let server_ca = dir.join("server-ca.pem");
        let current = KeyPair::generate().expect("current key");
        fs::write(&key, current.serialize_pem()).expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod key");
        fs::write(&certificate, issuer.issue(&current.serialize_pem())).expect("certificate");
        fs::write(&server_ca, issuer.certificate.pem()).expect("server CA");
        let config = dir.join("client.toml");
        fs::write(
            &config,
            format!(
                "device_id = \"{DEVICE}\"\n\
                 relay_url = \"wss://127.0.0.1:1/control\"\n\
                 client_cert = {}\nprivate_key = {}\nserver_ca = {}\n",
                toml_string(&certificate),
                toml_string(&key),
                toml_string(&server_ca),
            ),
        )
        .expect("configuration");
        Self {
            pending_key: dir.join("client-key.pem.renew-pending"),
            root,
            dir,
            config,
            key,
            certificate,
            canary,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(client_binary());
        command.args(args);
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("run tunnel-client")
    }

    fn renew(&self, step: &[&str]) -> Output {
        let config = self.config.display().to_string();
        let mut args = vec!["credentials", "renew", "--config", &config];
        args.extend_from_slice(step);
        self.run(&args)
    }

    /// `renew --csr-out`, returning the pending key's PEM.
    fn request(&self) -> String {
        let csr = self.path("renew.csr").display().to_string();
        let _ = fs::remove_file(&csr);
        let output = self.renew(&["--csr-out", &csr, "--json"]);
        assert_eq!(output.status.code(), Some(0), "{}", text(&output));
        fs::read_to_string(&self.pending_key).expect("pending key")
    }

    /// In the canary directory, so a message naming its path is caught.
    fn write_issued(&self, pem: &str) -> String {
        let path = self.dir.join("issued.pem");
        fs::write(&path, pem).expect("issued certificate");
        path.display().to_string()
    }

    fn pair(&self) -> (Vec<u8>, Vec<u8>) {
        (
            fs::read(&self.key).expect("key"),
            fs::read(&self.certificate).expect("certificate"),
        )
    }

    fn pair_matches(&self) -> bool {
        let (Ok(key), Ok(chain)) = (
            tunnel_client::credentials::load_private_key(&self.key),
            tunnel_client::credentials::load_certificates(&self.certificate),
        ) else {
            return false;
        };
        tunnel_client::credentials::verify_certificate_key(&chain, key).is_ok()
    }

    fn doctor(&self) -> (Option<i32>, Value) {
        let config = self.config.display().to_string();
        let output = self.run(&["doctor", "--config", &config, "--json"]);
        (output.status.code(), json(&output))
    }

    fn assert_redacted(&self, output: &Output) {
        let all = text(output);
        for forbidden in [
            self.canary.as_str(),
            "PRIVATE KEY",
            "BEGIN CERTIFICATE",
            "CERTIFICATE REQUEST",
        ] {
            assert!(!all.contains(forbidden), "{forbidden:?} printed: {all}");
        }
    }
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout {}\nstderr {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().last().unwrap_or_default();
    serde_json::from_str(line).unwrap_or_else(|_| panic!("JSON: {}", text(output)))
}

fn error_code(output: &Output) -> String {
    json(output)["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_renewal_requests_then_swaps_in_the_new_pair() {
    let issuer = Issuer::new("synthetic renew-cli issuer");
    let profile = Profile::new(&issuer);
    let before = profile.pair();

    let csr = profile.path("renew.csr").display().to_string();
    let requested = profile.renew(&["--csr-out", &csr, "--json"]);
    assert_eq!(requested.status.code(), Some(0), "{}", text(&requested));
    profile.assert_redacted(&requested);
    let result = &json(&requested)["result"];
    assert_eq!(result["state"], "pending", "{result}");
    assert_eq!(result["discarded_pending"], false);
    assert_eq!(
        profile.pair(),
        before,
        "requesting touched the current pair"
    );
    let pending = fs::read_to_string(&profile.pending_key).expect("pending key");
    let mode = |path: &Path| fs::metadata(path).expect("mode").permissions().mode() & 0o777;
    assert_eq!(mode(&profile.pending_key), 0o600);
    assert_eq!(mode(&profile.dir), 0o700);
    assert!(
        fs::read_to_string(&csr)
            .expect("CSR")
            .contains("BEGIN CERTIFICATE REQUEST")
    );

    let (status, report) = profile.doctor();
    assert_eq!(status, Some(0), "{report}");
    assert_eq!(report["result"]["renewal"]["status"], "pending", "{report}");
    assert_eq!(report["result"]["renewal"]["code"], "RENEWAL_PENDING");
    assert!(report["result"]["renewal"]["pending_since_unix"].is_i64());

    let issued = profile.write_issued(&issuer.issue(&pending));
    let completed = profile.renew(&["--certificate", &issued, "--json"]);
    assert_eq!(completed.status.code(), Some(0), "{}", text(&completed));
    profile.assert_redacted(&completed);
    let result = &json(&completed)["result"];
    assert_eq!(result["state"], "renewed", "{result}");
    assert_eq!(result["restart_required"], true);
    assert_eq!(result["already_installed"], false);
    assert_eq!(result["certificate_count"], 1);
    assert!(result["recovered"].is_null());
    assert_eq!(fs::read_to_string(&profile.key).expect("key"), pending);
    assert_eq!(mode(&profile.key), 0o600);
    assert!(profile.pair_matches());
    assert!(!profile.pending_key.exists());

    let (status, report) = profile.doctor();
    assert_eq!(status, Some(0), "{report}");
    assert_eq!(report["result"]["renewal"]["status"], "none", "{report}");
    assert_eq!(report["result"]["credential_key_match"]["status"], "ok");

    // Text mode, and a re-run of the same completion is answered.
    let again = profile.renew(&["--certificate", &issued]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("Already installed"),
        "{}",
        text(&again)
    );
    assert!(String::from_utf8_lossy(&again.stdout).contains("stopped and started"));
}

#[test]
fn every_renew_exit_follows_the_published_table() {
    let issuer = Issuer::new("synthetic renew-cli issuer");
    let other = Issuer::new("another synthetic issuer");
    let profile = Profile::new(&issuer);
    let config = profile.config.display().to_string();
    let csr = profile.path("x.csr").display().to_string();
    let missing = profile.path("absent.toml").display().to_string();

    for args in [
        vec!["credentials", "renew"],
        vec!["credentials", "renew", "--config", &config],
        vec!["credentials", "renew", "--csr-out", &csr],
        vec![
            "credentials",
            "renew",
            "--config",
            &missing,
            "--csr-out",
            &csr,
        ],
        vec![
            "credentials",
            "renew",
            "--config",
            &config,
            "--csr-out",
            &csr,
            "--certificate",
            &csr,
        ],
        vec![
            "credentials",
            "renew",
            "--config",
            &config,
            "--certificate",
            &csr,
            "--discard-pending",
        ],
        vec!["credentials", "renew", "--config", &config, "--csr-out"],
        vec![
            "credentials",
            "renew",
            "--config",
            &config,
            "--config",
            &config,
        ],
        vec!["credentials", "renew", "--config", &config, "--frobnicate"],
    ] {
        let output = profile.run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", text(&output));
        assert!(!profile.pending_key.exists(), "{args:?} wrote a key");
    }

    let before = profile.pair();
    // Nothing pending.
    let issued =
        profile.write_issued(&issuer.issue(&KeyPair::generate().expect("k").serialize_pem()));
    let output = profile.renew(&["--certificate", &issued, "--json"]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert_eq!(error_code(&output), "RENEWAL_NOT_PENDING");
    profile.assert_redacted(&output);

    // A pending renewal is never silently replaced.
    let pending = profile.request();
    let output = profile.renew(&[
        "--csr-out",
        &profile.path("y.csr").display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert_eq!(error_code(&output), "RENEWAL_PENDING");
    assert_eq!(json(&output)["error"]["retryable"], false);
    assert_eq!(
        fs::read_to_string(&profile.pending_key).expect("pending"),
        pending
    );

    // Refusals of the issued certificate: exit 3, old pair untouched.
    for (label, pem) in [
        (
            "another key",
            issuer.issue(&KeyPair::generate().expect("k").serialize_pem()),
        ),
        ("another issuer", other.issue(&pending)),
        ("not a certificate", "not PEM at all\n".to_owned()),
    ] {
        let issued = profile.write_issued(&pem);
        let output = profile.renew(&["--certificate", &issued, "--json"]);
        assert_eq!(output.status.code(), Some(3), "{label}: {}", text(&output));
        assert_eq!(error_code(&output), "CREDENTIAL_ERROR", "{label}");
        assert!(
            json(&output)["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("current credential is unchanged"),
            "{label}: {}",
            text(&output)
        );
        profile.assert_redacted(&output);
        assert_eq!(profile.pair(), before, "{label}: the old pair changed");
        assert_eq!(
            fs::read_to_string(&profile.pending_key).expect("pending"),
            pending,
            "{label}: the pending key was lost"
        );
    }

    // A held renewal lock: 7, retryable, after the bounded wait.
    {
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(profile.dir.join("client-key.pem.renew-lock"))
            .expect("the lock file a renewal created");
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("hold the renewal lock");
        let issued = profile.write_issued(&issuer.issue(&pending));
        let output = profile.renew(&["--certificate", &issued, "--json"]);
        assert_eq!(output.status.code(), Some(7), "{}", text(&output));
        assert_eq!(error_code(&output), "RENEWAL_LOCKED");
        assert_eq!(json(&output)["error"]["retryable"], true);
        assert_eq!(profile.pair(), before);
    }

    // No valid current pair: 3.
    let stray = KeyPair::generate().expect("k");
    fs::write(&profile.key, stray.serialize_pem()).expect("break the pair");
    let output = profile.renew(&[
        "--csr-out",
        &profile.path("z.csr").display().to_string(),
        "--discard-pending",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", text(&output));
    assert_eq!(error_code(&output), "CREDENTIAL_ERROR");
    profile.assert_redacted(&output);

    // A layout rename cannot renew: 2, CONFIG_ERROR.
    let linked = Profile::new(&issuer);
    let target = linked.dir.join("real-key.pem");
    fs::rename(&linked.key, &target).expect("move key");
    std::os::unix::fs::symlink(&target, &linked.key).expect("link key");
    let output = linked.renew(&[
        "--csr-out",
        &linked.path("l.csr").display().to_string(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert_eq!(error_code(&output), "CONFIG_ERROR");
}

/// Killed after each swap step: `doctor` reports without changing, and the
/// next `connect` resolves the profile to one valid pair before its first
/// attempt -- the old pair before the certificate rename, the new one from
/// it on.
#[test]
fn a_renewal_killed_at_any_swap_step_recovers_to_one_valid_pair() {
    for (index, step) in STEPS.into_iter().enumerate() {
        let issuer = Issuer::new("synthetic renew-cli issuer");
        let profile = Profile::new(&issuer);
        let old = profile.pair();
        let pending = profile.request();
        let issued_pem = issuer.issue(&pending);
        let issued = profile.write_issued(&issued_pem);
        let config = profile.config.display().to_string();
        let killed = profile.run_with(
            &[
                "credentials",
                "renew",
                "--config",
                &config,
                "--certificate",
                &issued,
            ],
            &[("TUNNEL_CLIENT_TEST_RENEW_ABORT_AFTER", step)],
        );
        assert_eq!(
            killed.status.code(),
            None,
            "{step}: not killed: {}",
            text(&killed)
        );
        assert!(
            String::from_utf8_lossy(&killed.stderr).contains(&format!("aborting after {step}")),
            "{step}: {}",
            text(&killed)
        );

        let mismatched = step == "certificate_installed";
        assert_eq!(profile.pair_matches(), !mismatched, "{step}: at rest");
        let (status, report) = profile.doctor();
        let expected = match (mismatched, step) {
            (true, _) => "interrupted",
            (false, "key_installed") => "none",
            (false, _) => "pending",
        };
        assert_eq!(
            report["result"]["renewal"]["status"], expected,
            "{step}: {report}"
        );
        assert_eq!(
            status,
            Some(if mismatched { 3 } else { 0 }),
            "{step}: {report}"
        );
        assert_eq!(
            profile.pair_matches(),
            !mismatched,
            "{step}: doctor changed files"
        );

        let connect = profile.run(&["connect", "--config", &config, "--no-reconnect"]);
        assert_eq!(connect.status.code(), Some(4), "{step}: {}", text(&connect));
        assert_eq!(
            String::from_utf8_lossy(&connect.stderr)
                .contains("resolved an interrupted credential renewal (rolled_forward)"),
            mismatched,
            "{step}: {}",
            text(&connect)
        );
        assert!(
            profile.pair_matches(),
            "{step}: no valid pair after connect"
        );
        if index >= 5 {
            assert_eq!(
                fs::read_to_string(&profile.key).expect("key"),
                pending,
                "{step}"
            );
            assert_eq!(
                fs::read_to_string(&profile.certificate).expect("certificate"),
                issued_pem,
                "{step}"
            );
        } else {
            assert_eq!(profile.pair(), old, "{step}: the old pair changed");
            // Still pending: the same completion, re-run, finishes it.
            let rerun = profile.renew(&["--certificate", &issued, "--json"]);
            assert_eq!(rerun.status.code(), Some(0), "{step}: {}", text(&rerun));
            assert_eq!(json(&rerun)["result"]["already_installed"], false);
            assert!(profile.pair_matches(), "{step}");
            assert_eq!(fs::read_to_string(&profile.key).expect("key"), pending);
        }
    }
}

/// The same interruption resolved by `renew` itself rather than `connect`:
/// the re-run reports that it rolled the swap forward.
#[test]
fn a_rerun_of_renew_completes_a_swap_killed_between_the_renames() {
    let issuer = Issuer::new("synthetic renew-cli issuer");
    let profile = Profile::new(&issuer);
    let pending = profile.request();
    let issued = profile.write_issued(&issuer.issue(&pending));
    let config = profile.config.display().to_string();
    let killed = profile.run_with(
        &[
            "credentials",
            "renew",
            "--config",
            &config,
            "--certificate",
            &issued,
        ],
        &[(
            "TUNNEL_CLIENT_TEST_RENEW_ABORT_AFTER",
            "certificate_installed",
        )],
    );
    assert_eq!(killed.status.code(), None, "{}", text(&killed));
    assert!(!profile.pair_matches());
    let rerun = profile.renew(&["--certificate", &issued, "--json"]);
    assert_eq!(rerun.status.code(), Some(0), "{}", text(&rerun));
    let result = &json(&rerun)["result"];
    assert_eq!(result["recovered"], "rolled_forward", "{result}");
    assert_eq!(result["already_installed"], true, "{result}");
    assert!(profile.pair_matches());
}

/// A running `connect` keeps the pair it started with: a renewal completed
/// under it, and then a key file made unreadable as PEM, change nothing for
/// it -- its next attempts still fail only for the refused relay port, as
/// transport errors, where a re-read of the files would end it with exit
/// `3`. The new pair is used only after a stop and a start.
#[test]
fn a_running_connect_keeps_the_pair_it_started_with() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;

    let issuer = Issuer::new("synthetic renew-cli issuer");
    let profile = Profile::new(&issuer);
    let config = profile.config.display().to_string();
    let mut child = Command::new(client_binary())
        .args(["connect", "--config", &config, "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn connect");
    let stdout = child.stdout.take().expect("stdout");
    let (events, received) = mpsc::channel::<Value>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(event) = serde_json::from_str::<Value>(&line)
                && events.send(event).is_err()
            {
                return;
            }
        }
    });
    let backoffs = |count: usize| {
        let mut seen = 0;
        while seen < count {
            let event = received
                .recv_timeout(Duration::from_secs(20))
                .expect("a connect event before the deadline");
            let result = &event["result"];
            if result["state"] == "backoff" {
                assert_eq!(result["code"], "TRANSPORT_ERROR", "{event}");
                seen += 1;
            }
            assert_ne!(event["ok"], false, "connect ended: {event}");
        }
    };
    backoffs(1);

    let pending = profile.request();
    let issued = profile.write_issued(&issuer.issue(&pending));
    let completed = profile.renew(&["--certificate", &issued]);
    assert_eq!(completed.status.code(), Some(0), "{}", text(&completed));
    fs::write(&profile.key, "not a key\n").expect("make the key file unreadable as PEM");
    backoffs(3);
    assert!(
        child.try_wait().expect("poll connect").is_none(),
        "connect re-read its credentials and exited"
    );
    let _ = child.kill();
    let _ = child.wait();

    // A fresh start reads the files again: the unreadable key is terminal.
    let restarted = profile.run(&["connect", "--config", &config, "--no-reconnect", "--json"]);
    assert_eq!(restarted.status.code(), Some(3), "{}", text(&restarted));
}
