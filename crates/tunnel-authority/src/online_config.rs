//! Independent operator approval. No authorization is learned from Redis.
use crate::{Result, private_files};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tunnel_catalog::RedisTlsOptions;
use tunnel_cluster::membership::{
    MembershipCheckpoint, MembershipIssuer, MembershipPolicy, MembershipRecord, MembershipVerifier,
    PrivateEndpointPolicy, RelayKey, TrustedPublisherKey,
};
use zeroize::Zeroizing;

pub const LIFETIME_SECONDS: i64 = 60;
pub const MAX_INVENTORY_BYTES: usize = 128 * 1024;
pub const MAX_TLS_BYTES: usize = 1024 * 1024;
pub const VALIDATION_NONCE: &str = "authority-validation-nonce-v1";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u16,
    pub bind: SocketAddr,
    pub state_path: PathBuf,
    pub signing_key_path: PathBuf,
    pub redis_url_path: PathBuf,
    pub redis_ca_path: PathBuf,
    pub redis_client_cert_path: Option<PathBuf>,
    pub redis_client_key_path: Option<PathBuf>,
    pub tls_cert_chain: PathBuf,
    pub tls_private_key: PathBuf,
    pub tls_client_ca: PathBuf,
    pub endpoint_policy: EndpointPolicy,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicy {
    pub allowed_hosts: Vec<String>,
    pub allowed_server_names: Vec<String>,
    pub allowed_ports: Vec<u16>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = private_files::read(path, 32 * 1024)?;
        let config: Self =
            toml::from_str(std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?)
                .map_err(|_| "invalid authority configuration")?;
        if config.schema_version != 1 || config.bind.port() == 0 {
            return Err("unsupported configuration schema or zero listener port");
        }
        if config.redis_client_cert_path.is_some() != config.redis_client_key_path.is_some() {
            return Err("Redis client certificate and key must be supplied together");
        }
        config.endpoint_policy.policy()?;
        Ok(config)
    }

    pub fn issuer(&self, inventory: &Inventory) -> Result<Arc<MembershipIssuer>> {
        let key = Zeroizing::new(private_files::read(&self.signing_key_path, 4096)?);
        let issuer = MembershipIssuer::from_pkcs8(&inventory.publisher_key_id, &key)
            .map_err(|_| "invalid membership signing key")?;
        if hex(&issuer
            .public_key()
            .map_err(|_| "invalid signing public key")?)
            != inventory.publisher_public_key
        {
            return Err("signing key does not match independent approval");
        }
        Ok(Arc::new(issuer))
    }

    pub fn tls(&self) -> Result<Arc<rustls::ServerConfig>> {
        let cert = private_files::read(&self.tls_cert_chain, MAX_TLS_BYTES)?;
        let key = Zeroizing::new(private_files::read(&self.tls_private_key, MAX_TLS_BYTES)?);
        let ca = private_files::read(&self.tls_client_ca, MAX_TLS_BYTES)?;
        tunnel_transport::load_server_config_from_pem_with_alpn(
            &cert,
            &key,
            Some(&ca),
            &[b"http/1.1"],
        )
        .map_err(|_| "invalid authority mandatory-mTLS identity or client trust")
    }

    pub fn redis(&self) -> Result<(Zeroizing<String>, RedisTlsOptions)> {
        let bytes = Zeroizing::new(private_files::read(&self.redis_url_path, 4096)?);
        let url = Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| "Redis credential file is not UTF-8")?
                .trim()
                .to_owned(),
        );
        let credentials = url
            .strip_prefix("rediss://")
            .and_then(|rest| rest.split_once('@'))
            .map(|(credentials, _)| credentials);
        if !credentials.is_some_and(|credentials| {
            credentials
                .split_once(':')
                .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty())
        }) {
            return Err("Redis requires verified rediss with a named ACL user and password");
        }
        let mut tls = RedisTlsOptions::with_root_cert_pem(private_files::read(
            &self.redis_ca_path,
            MAX_TLS_BYTES,
        )?);
        if let (Some(cert), Some(key)) = (&self.redis_client_cert_path, &self.redis_client_key_path)
        {
            tls = tls.with_client_identity_pem(
                private_files::read(cert, MAX_TLS_BYTES)?,
                private_files::read(key, MAX_TLS_BYTES)?,
            );
        }
        Ok((url, tls))
    }
}

impl EndpointPolicy {
    pub fn policy(&self) -> Result<PrivateEndpointPolicy> {
        if self.allowed_server_names.is_empty() {
            return Err("explicit peer certificate names are required");
        }
        PrivateEndpointPolicy::allowlisted(
            self.allowed_hosts.clone(),
            self.allowed_server_names.clone(),
            self.allowed_ports.clone(),
        )
        .map_err(|_| "invalid independent peer endpoint allowlist")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub schema_version: u16,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub deployment_incarnation: String,
    pub revision: u64,
    pub publisher_key_id: String,
    pub publisher_public_key: String,
    pub nodes: Vec<Node>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub node_id: String,
    pub peer_endpoint: String,
    pub server_name: String,
    pub keys: Vec<RelayKey>,
    pub checkpoint_client_spkis: Vec<String>,
}

impl Inventory {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = private_files::read(path, MAX_INVENTORY_BYTES)?;
        let inventory: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid independent inventory")?;
        inventory.shape()?;
        Ok(inventory)
    }

    pub fn shape(&self) -> Result<()> {
        if self.schema_version != 1 || self.revision == 0 || self.nodes.len() > 32 {
            return Err("invalid inventory schema, revision or node bound");
        }
        identifier(&self.deployment_id)?;
        identifier(&self.deployment_incarnation)?;
        identifier(&self.publisher_key_id)?;
        tunnel_catalog::validate_redis_namespace(&self.redis_namespace)
            .map_err(|_| "invalid inventory Redis namespace")?;
        digest(&self.publisher_public_key)?;
        let mut nodes = BTreeSet::new();
        for node in &self.nodes {
            identifier(&node.node_id)?;
            if !nodes.insert(&node.node_id)
                || node.checkpoint_client_spkis.is_empty()
                || node.checkpoint_client_spkis.len() > 2
            {
                return Err("duplicate node or invalid checkpoint client pin bound");
            }
            let mut pins = BTreeSet::new();
            for pin in &node.checkpoint_client_spkis {
                digest(pin)?;
                if !pins.insert(pin) {
                    return Err("duplicate checkpoint client pin");
                }
            }
        }
        Ok(())
    }

    pub fn policy(&self, config: &Config) -> Result<MembershipPolicy> {
        MembershipPolicy::new(
            &self.deployment_id,
            &self.deployment_incarnation,
            config.endpoint_policy.policy()?,
        )
        .map_err(|_| "invalid membership approval policy")
    }

    pub fn validate(
        &self,
        config: &Config,
        issuer: &MembershipIssuer,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.shape()?;
        let mut verifier = MembershipVerifier::new(
            self.policy(config)?,
            [TrustedPublisherKey::new(
                &self.publisher_key_id,
                issuer.public_key().map_err(|_| "invalid publisher key")?,
            )
            .map_err(|_| "invalid publisher identity")?],
        )
        .map_err(|_| "invalid membership verifier policy")?;
        let checkpoint = self.checkpoint(
            1,
            1,
            VALIDATION_NONCE.to_owned(),
            now,
            now + chrono::Duration::seconds(LIFETIME_SECONDS),
        );
        let bytes = issuer
            .sign_checkpoint_bytes(checkpoint)
            .map_err(|_| "cannot validate checkpoint encoding")?;
        verifier
            .verify_checkpoint(&bytes, VALIDATION_NONCE, now)
            .map_err(|_| "inventory checkpoint rejected")?;
        for node in &self.nodes {
            let record = self.record(node, 1, now);
            let bytes = issuer
                .sign_membership_bytes(record)
                .map_err(|_| "cannot validate membership encoding")?;
            let verified = verifier
                .verify_membership(&bytes, now)
                .map_err(|_| "inventory endpoint, role, key window or record bound rejected")?;
            // Structural verification permits a just-expired key within the
            // record skew window. Publication uses the relay's actual active
            // key rule, whose expiry stays strict.
            if verified.active_key(now).is_none() {
                return Err("inventory node has no active relay key");
            }
        }
        Ok(())
    }

    pub fn record(&self, node: &Node, version: u64, now: DateTime<Utc>) -> MembershipRecord {
        MembershipRecord {
            schema_version: 1,
            deployment_id: self.deployment_id.clone(),
            deployment_incarnation: self.deployment_incarnation.clone(),
            node_id: node.node_id.clone(),
            record_version: version,
            roles: vec!["relay_peer".into()],
            peer_endpoint: node.peer_endpoint.clone(),
            server_name: node.server_name.clone(),
            keys: node.keys.clone(),
            issued_at: now,
            not_before: now,
            expires_at: now + chrono::Duration::seconds(LIFETIME_SECONDS),
        }
    }

    pub fn checkpoint(
        &self,
        checkpoint_version: u64,
        record_version: u64,
        nonce: String,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> MembershipCheckpoint {
        MembershipCheckpoint {
            schema_version: 1,
            deployment_id: self.deployment_id.clone(),
            deployment_incarnation: self.deployment_incarnation.clone(),
            checkpoint_version,
            nonce,
            minimum_versions: self
                .nodes
                .iter()
                .map(|node| (node.node_id.clone(), record_version))
                .collect::<BTreeMap<_, _>>(),
            issued_at: now,
            not_before: now,
            expires_at,
        }
    }

    pub fn permits_client(&self, node_id: &str, spki: &str) -> bool {
        self.nodes.iter().any(|node| {
            node.node_id == node_id && node.checkpoint_client_spkis.iter().any(|pin| pin == spki)
        })
    }
}

pub fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err("invalid authority identifier");
    }
    Ok(())
}
pub fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid lower-case public key or digest");
    }
    Ok(())
}
pub fn run_id(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid independently approved Redis run identifier");
    }
    Ok(())
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
