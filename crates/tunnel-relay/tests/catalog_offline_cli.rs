//! Actual executable coverage for the two offline commands. No Redis fixture.
#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BUNDLE: &[u8] = include_bytes!("fixtures/offline_catalog_bundle.json");
const CONFIG: &[u8] = include_bytes!("fixtures/offline_catalog_config.toml");

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary root")
            .join(format!("catalog-cli-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
        Self(root)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        use std::io::Write;
        let path = self.0.join(name);
        let mut file = private_file(&path);
        file.write_all(bytes).expect("write");
        path
    }

    fn run(&self, command: &str, args: &[(&str, &Path)]) -> (Option<i32>, String, String) {
        let stdout = self.0.join(format!("{}.stdout", uuid::Uuid::new_v4()));
        let stderr = self.0.join(format!("{}.stderr", uuid::Uuid::new_v4()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_tunnel-relay"))
            .arg(command)
            .args(
                args.iter()
                    .flat_map(|(flag, value)| [Path::new(flag), *value]),
            )
            .stdin(Stdio::null())
            .stdout(private_file(&stdout))
            .stderr(private_file(&stderr))
            .spawn()
            .expect("spawn offline CLI");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut timed_out = false;
        let status = 'wait: loop {
            if let Some(status) = child.try_wait().expect("wait offline CLI") {
                break status;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                let reap_deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    if let Some(status) = child.try_wait().expect("reap offline CLI") {
                        break 'wait status;
                    }
                    assert!(Instant::now() < reap_deadline, "offline CLI did not reap");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!timed_out, "offline CLI exceeded its test deadline");
        (
            status.code(),
            fs::read_to_string(stdout).expect("stdout"),
            fs::read_to_string(stderr).expect("stderr"),
        )
    }
}

fn private_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("private file")
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn catalog_offline_cli_dispatches_strict_private_checks_and_create_only_drafts() {
    let directory = Directory::new();
    let config = directory.write("config", CONFIG);
    let bundle = directory.write("bundle", BUNDLE);
    let hash = tunnel_catalog::recovery::durable_catalog_digest(BUNDLE);
    let check = [
        ("--config", config.as_path()),
        ("--bundle", bundle.as_path()),
        ("--expected-bundle-sha256", Path::new(&hash)),
    ];
    let (success, stdout, stderr) = directory.run("catalog-bundle-check", &check);
    assert_eq!(success, Some(0), "offline check failed: {stderr}");
    let summary: serde_json::Value = serde_json::from_str(&stdout).expect("summary JSON");
    assert_eq!(summary["status"], "schema_valid_only");
    assert_eq!(summary["apply_authorized"], false);
    assert_eq!(summary["custody"], "unproven");
    let output = directory.0.join("plan");
    let plan = [
        ("--config", config.as_path()),
        ("--baseline", bundle.as_path()),
        ("--expected-baseline-sha256", Path::new(&hash)),
        ("--target", bundle.as_path()),
        ("--expected-target-sha256", Path::new(&hash)),
        ("--output", output.as_path()),
    ];
    let (success, stdout, stderr) = directory.run("catalog-reconcile-plan", &plan);
    assert_eq!(success, Some(0), "offline plan failed: {stderr}");
    let summary: serde_json::Value = serde_json::from_str(&stdout).expect("summary JSON");
    assert_eq!(summary["status"], "offline_draft");
    assert_eq!(summary["apply_authorized"], false);
    let bytes = fs::read(&output).expect("private plan");
    assert_eq!(
        summary["plan_sha256"],
        tunnel_catalog::recovery::durable_catalog_digest(&bytes)
    );
    let (success, stdout, _) = directory.run("catalog-reconcile-plan", &plan);
    assert_eq!(success, Some(1));
    assert!(stdout.is_empty());
    assert_eq!(fs::read(&output).expect("preserved plan"), bytes);
    let bad_hash = "0".repeat(64);
    let mut wrong = check;
    wrong[2].1 = Path::new(&bad_hash);
    let (success, stdout, stderr) = directory.run("catalog-bundle-check", &wrong);
    assert_eq!(success, Some(1));
    assert!(stdout.is_empty());
    assert!(!stderr.contains("synthetic tenant"));
    assert!(stderr.contains("expected hash does not match"));
}
