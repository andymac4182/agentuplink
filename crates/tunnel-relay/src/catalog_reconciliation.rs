//! Offline catalog checks and conservative drafts. No Redis adapter is used.
//! Local configuration selects the identity; input hashes establish neither
//! historical completeness nor permission to apply or activate anything.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;

use tunnel_catalog::{
    CatalogBundle, CatalogBundleError, CatalogBundleIdentity, MAX_CATALOG_BUNDLE_BYTES,
    plan_catalog_reconciliation,
};

use crate::config::ServeConfig;

mod private_files;

const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// All diagnostics are closed strings; arguments, records and paths are private.
#[derive(Debug)]
pub enum OfflineCatalogError {
    Input(&'static str),
    Bundle(CatalogBundleError),
}

impl fmt::Display for OfflineCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(message) => f.write_str(message),
            Self::Bundle(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for OfflineCatalogError {}

impl From<&'static str> for OfflineCatalogError {
    fn from(value: &'static str) -> Self {
        Self::Input(value)
    }
}

impl From<CatalogBundleError> for OfflineCatalogError {
    fn from(value: CatalogBundleError) -> Self {
        Self::Bundle(value)
    }
}

struct Arguments<'a>(BTreeMap<&'a str, &'a OsStr>);

impl<'a> Arguments<'a> {
    fn parse(args: &'a [OsString], required: &[&str]) -> Result<Self, OfflineCatalogError> {
        if args.len() != required.len() * 2 {
            return Err("offline catalog command requires exactly the documented options".into());
        }
        let mut fields = BTreeMap::new();
        for pair in args.chunks_exact(2) {
            let flag = pair[0].to_str().ok_or("offline catalog option is not UTF-8")?;
            if !required.contains(&flag)
                || pair[1].is_empty()
                || pair[1].len() > 4096
                || fields.insert(flag, pair[1].as_os_str()).is_some()
            {
                return Err("offline catalog option is unknown, duplicate or invalid".into());
            }
        }
        if fields.len() != required.len() {
            return Err("offline catalog command is missing an option".into());
        }
        Ok(Self(fields))
    }

    fn get(&self, flag: &str) -> Result<&'a OsStr, OfflineCatalogError> {
        self.0
            .get(flag)
            .copied()
            .ok_or_else(|| "offline catalog option is missing".into())
    }

    fn hash(&self, flag: &str) -> Result<&'a str, OfflineCatalogError> {
        self.get(flag)?
            .to_str()
            .ok_or_else(|| "expected SHA-256 is not UTF-8".into())
    }
}

fn checked_identity(path: &Path) -> Result<CatalogBundleIdentity, OfflineCatalogError> {
    let bytes = private_files::read(path, MAX_CONFIG_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "offline catalog config is not UTF-8")?;
    // This parser validates values only. No TLS material, fence, socket or
    // catalog is opened, including when the configuration names absent files.
    let config = ServeConfig::parse(text).map_err(|_| "offline catalog config refused")?;
    let cluster = config
        .cluster
        .as_ref()
        .ok_or("offline catalog config requires cluster identity")?;
    Ok(CatalogBundleIdentity::new(
        &cluster.deployment_id,
        &config.redis_namespace,
    )?)
}

fn read_bundle(
    path: &Path,
    expected_sha256: &str,
    identity: &CatalogBundleIdentity,
) -> Result<CatalogBundle, OfflineCatalogError> {
    let bytes = private_files::read(path, MAX_CATALOG_BUNDLE_BYTES)?;
    Ok(CatalogBundle::parse(&bytes, expected_sha256, identity)?)
}

/// Validate a supplied private bundle without opening Redis or authorizing apply.
pub fn bundle_check(args: &[OsString]) -> Result<String, OfflineCatalogError> {
    let args = Arguments::parse(
        args,
        &["--config", "--bundle", "--expected-bundle-sha256"],
    )?;
    let identity = checked_identity(Path::new(args.get("--config")?))?;
    let bundle = read_bundle(
        Path::new(args.get("--bundle")?),
        args.hash("--expected-bundle-sha256")?,
        &identity,
    )?;
    serde_json::to_string(&bundle.summary())
        .map_err(|_| "cannot encode offline catalog summary".into())
}

/// Write one private create-only draft; no export, apply or activation follows.
pub fn reconcile_plan(args: &[OsString]) -> Result<String, OfflineCatalogError> {
    let args = Arguments::parse(
        args,
        &[
            "--config",
            "--baseline",
            "--expected-baseline-sha256",
            "--target",
            "--expected-target-sha256",
            "--output",
        ],
    )?;
    let identity = checked_identity(Path::new(args.get("--config")?))?;
    let baseline = read_bundle(
        Path::new(args.get("--baseline")?),
        args.hash("--expected-baseline-sha256")?,
        &identity,
    )?;
    let target = read_bundle(
        Path::new(args.get("--target")?),
        args.hash("--expected-target-sha256")?,
        &identity,
    )?;
    let plan = plan_catalog_reconciliation(&baseline, &target)?;
    let bytes = plan.canonical_bytes()?;
    let summary = serde_json::json!({
        "schema_version": 1,
        "status": "offline_draft",
        "plan_sha256": tunnel_catalog::recovery::durable_catalog_digest(&bytes),
        "difference_count": plan.difference_count(),
        "historical_completeness": "unproven",
        "custody": "unproven",
        "quiescence": "unproven",
        "external_anchors_verified": false,
        "apply_authorized": false,
    });
    let summary =
        serde_json::to_string(&summary).map_err(|_| "cannot encode offline catalog summary")?;
    let mut output = private_files::NewFile::create(Path::new(args.get("--output")?))?;
    output.write_and_sync(&bytes)?;
    output.commit();
    Ok(summary)
}

#[cfg(test)]
mod tests;
