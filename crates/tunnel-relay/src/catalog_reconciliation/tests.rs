use super::*;

#[test]
fn offline_arguments_require_each_exact_flag_once_without_echoing_values() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    let required = ["--config", "--bundle", "--expected-bundle-sha256"];
    let valid = args(&[
        "--bundle",
        "b",
        "--expected-bundle-sha256",
        "hash",
        "--config",
        "c",
    ]);
    let parsed = Arguments::parse(&valid, &required).expect("arguments");
    assert_eq!(parsed.get("--config").expect("config"), OsStr::new("c"));
    for invalid in [
        args(&[]),
        args(&["--config", "secret-sentinel", "--bundle"]),
        args(&[
            "--config",
            "secret-sentinel",
            "--bundle",
            "b",
            "--config",
            "c",
        ]),
        args(&[
            "--config",
            "c",
            "--bundle",
            "b",
            "--unknown-secret-sentinel",
            "x",
        ]),
        args(&[
            "--config",
            "",
            "--bundle",
            "b",
            "--expected-bundle-sha256",
            "x",
        ]),
    ] {
        let error = Arguments::parse(&invalid, &required).err().expect("refused");
        assert!(!error.to_string().contains("secret-sentinel"));
    }
}

#[cfg(unix)]
mod files {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use super::*;

    const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/offline_catalog_bundle.json");
    const CONFIG: &[u8] = include_bytes!("../../tests/fixtures/offline_catalog_config.toml");

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let parent = std::env::temp_dir().canonicalize().expect("temporary root");
            let root = parent.join(format!("catalog-offline-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).expect("directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
            let fixture = Self(root);
            fixture.write("config", CONFIG);
            fixture.write("bundle", BUNDLE);
            fixture
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            let mut file = private_files::NewFile::create(&self.0.join(name)).expect("create");
            file.write_and_sync(bytes).expect("sync");
            file.commit();
        }

        fn check_args(&self) -> Vec<OsString> {
            vec![
                "--config".into(),
                self.0.join("config").into_os_string(),
                "--bundle".into(),
                self.0.join("bundle").into_os_string(),
                "--expected-bundle-sha256".into(),
                tunnel_catalog::recovery::durable_catalog_digest(BUNDLE).into(),
            ]
        }

        fn plan_args(&self) -> Vec<OsString> {
            vec![
                "--config".into(),
                self.0.join("config").into_os_string(),
                "--baseline".into(),
                self.0.join("bundle").into_os_string(),
                "--expected-baseline-sha256".into(),
                tunnel_catalog::recovery::durable_catalog_digest(BUNDLE).into(),
                "--target".into(),
                self.0.join("bundle").into_os_string(),
                "--expected-target-sha256".into(),
                tunnel_catalog::recovery::durable_catalog_digest(BUNDLE).into(),
                "--output".into(),
                self.0.join("plan").into_os_string(),
            ]
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn offline_commands_validate_and_plan_without_reading_absent_keys_or_connecting() {
        let fixture = Fixture::new();
        let summary = bundle_check(&fixture.check_args()).expect("bundle check");
        let summary: serde_json::Value = serde_json::from_str(&summary).expect("summary");
        assert_eq!(summary["status"], "schema_valid_only");
        assert_eq!(summary["custody"], "unproven");
        assert_eq!(summary["key_count"], 11);
        assert_eq!(summary["apply_authorized"], false);
        let output = reconcile_plan(&fixture.plan_args()).expect("draft");
        let output: serde_json::Value = serde_json::from_str(&output).expect("summary");
        assert_eq!(output["status"], "offline_draft");
        assert_eq!(output["difference_count"], 0);
        assert_eq!(output["apply_authorized"], false);
        assert!(output.get("differences").is_none());
        let bytes =
            private_files::read(&fixture.0.join("plan"), MAX_CATALOG_BUNDLE_BYTES).expect("plan");
        assert_eq!(
            output["plan_sha256"],
            tunnel_catalog::recovery::durable_catalog_digest(&bytes)
        );
        let plan: serde_json::Value = serde_json::from_slice(&bytes).expect("draft JSON");
        assert_eq!(plan["historical_completeness"], "unproven");
        assert_eq!(plan["external_anchors_verified"], false);
        assert_eq!(plan["apply_authorized"], false);
        assert_eq!(
            fs::metadata(fixture.0.join("plan")).expect("mode").mode() & 0o7777,
            0o600
        );
        assert!(reconcile_plan(&fixture.plan_args()).is_err());
        assert_eq!(fs::read(fixture.0.join("plan")).expect("preserved"), bytes);
    }

    #[test]
    fn offline_config_identity_hash_and_private_input_fail_before_output() {
        let fixture = Fixture::new();
        let mut args = fixture.plan_args();
        args[9] = "0".repeat(64).into();
        assert!(reconcile_plan(&args).is_err());
        assert!(!fixture.0.join("plan").exists());
        fs::set_permissions(
            fixture.0.join("bundle"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("mode");
        assert!(bundle_check(&fixture.check_args()).is_err());
        fs::set_permissions(
            fixture.0.join("bundle"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("mode");
        let foreign = String::from_utf8(CONFIG.to_vec())
            .expect("text")
            .replace("deployment-a", "foreign");
        fixture.write("foreign-config", foreign.as_bytes());
        let mut args = fixture.plan_args();
        args[1] = fixture.0.join("foreign-config").into_os_string();
        assert!(reconcile_plan(&args).is_err());
        assert!(!fixture.0.join("plan").exists());
    }
}

#[cfg(not(unix))]
#[test]
fn offline_cli_files_fail_closed_on_unsupported_platforms() {
    assert!(private_files::read(Path::new("unused"), 1).is_err());
    assert!(private_files::NewFile::create(Path::new("unused")).is_err());
}
