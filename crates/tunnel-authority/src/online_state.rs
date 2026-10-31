//! Durable allocation is independent of Redis, signed responses and delivery.
use crate::{
    Result,
    online_config::{Config, Inventory, LIFETIME_SECONDS, run_id},
    state_store::StateStore,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tunnel_catalog::SignedMembershipRecord;
use tunnel_cluster::membership::{MembershipIssuer, MembershipVerifier, TrustedPublisherKey};

const STATE_IO_BUDGET: Duration = Duration::from_secs(1);
// Every older HTTP waiter expires within one second; the last admitted
// operation then holds the serializer for at most one more healthy second.
// Keep the publisher in that fair queue, with one second of scheduling margin.
const PUBLISHER_QUEUE_BUDGET: Duration = Duration::from_secs(3);
pub const RESPONSE_MARGIN: Duration = Duration::from_secs(7);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u16,
    inventory: Inventory,
    expected_redis_run_id: String,
    membership_high_water: u64,
    checkpoint_high_water: u64,
    // Redis's bounded membership directory retains removed names even across
    // incarnation changes. Never discard their slots or counters implicitly.
    known_node_ids: BTreeSet<String>,
    confirmed: Option<Confirmation>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    inventory_revision: u64,
    membership_version: u64,
    expires_at: DateTime<Utc>,
}

impl State {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let state: Self = serde_json::from_slice(bytes).map_err(|_| "corrupt authority state")?;
        state.validate()?;
        Ok(state)
    }
    fn validate(&self) -> Result<()> {
        self.inventory.shape()?;
        run_id(&self.expected_redis_run_id)?;
        if self.schema_version != 1
            || self.known_node_ids.len() > 32
            || self
                .inventory
                .nodes
                .iter()
                .any(|n| !self.known_node_ids.contains(&n.node_id))
        {
            return Err("invalid authority state identity or node history");
        }
        for node in &self.known_node_ids {
            crate::online_config::identifier(node)?;
        }
        if self.confirmed.as_ref().is_some_and(|c| {
            c.inventory_revision != self.inventory.revision
                || c.membership_version == 0
                || c.membership_version > self.membership_high_water
        }) {
            return Err("invalid authority confirmed publication fence");
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "cannot encode authority state")?;
        if bytes.len() > crate::state_store::MAX_STATE_BYTES {
            return Err("authority state exceeds its byte bound");
        }
        Ok(bytes)
    }
}

pub fn initialize(config: &Config, inventory_path: &Path, expected_run: &str) -> Result<()> {
    run_id(expected_run)?;
    let inventory = Inventory::load(inventory_path)?;
    if inventory.revision != 1 {
        return Err("initial inventory revision must be one");
    }
    inventory.validate(config, config.issuer(&inventory)?.as_ref(), Utc::now())?;
    let state = State {
        schema_version: 1,
        expected_redis_run_id: expected_run.into(),
        membership_high_water: 0,
        checkpoint_high_water: 0,
        known_node_ids: inventory.nodes.iter().map(|n| n.node_id.clone()).collect(),
        inventory,
        confirmed: None,
    };
    StateStore::initialize(&config.state_path, &state.bytes()?)?;
    Ok(())
}

pub fn approve(
    config: &Config,
    inventory_path: &Path,
    expected_revision: u64,
    expected_run: &str,
) -> Result<()> {
    run_id(expected_run)?;
    let mut store = StateStore::open(&config.state_path)?;
    let mut state = State::decode(&store.load()?)?;
    let inventory = Inventory::load(inventory_path)?;
    inventory.validate(config, config.issuer(&inventory)?.as_ref(), Utc::now())?;
    if state.inventory.revision != expected_revision
        || inventory.revision
            != expected_revision
                .checked_add(1)
                .ok_or("inventory revision exhausted")?
    {
        return Err("inventory revision compare-and-replace refused");
    }
    if inventory.deployment_id != state.inventory.deployment_id
        || inventory.redis_namespace != state.inventory.redis_namespace
    {
        return Err("approval cannot change deployment or durable Redis namespace");
    }
    if expected_run != state.expected_redis_run_id
        && inventory.deployment_incarnation == state.inventory.deployment_incarnation
    {
        return Err("a changed Redis run requires independently recovered new incarnation");
    }
    state
        .known_node_ids
        .extend(inventory.nodes.iter().map(|node| node.node_id.clone()));
    state.inventory = inventory;
    state.expected_redis_run_id = expected_run.into();
    state.confirmed = None;
    // Both high-water counters deliberately survive every approval transition.
    store.replace(&state.bytes()?)
}

pub struct Round {
    pub records: Vec<(String, SignedMembershipRecord)>,
    version: u64,
    revision: u64,
    expires_at: DateTime<Utc>,
    deadline: Instant,
}

pub struct Engine {
    store: StateStore,
    state: State,
    config: Config,
    issuer: Arc<MembershipIssuer>,
    // Persisted confirmation never reconstitutes monotonic freshness after
    // process restart. Only a newly acknowledged publication installs this.
    fresh_deadline: Option<Instant>,
    fatal: Arc<AtomicBool>,
}

impl Engine {
    pub fn open(config: Config, fatal: Arc<AtomicBool>) -> Result<Self> {
        let store = StateStore::open(&config.state_path)?;
        let state = State::decode(&store.load()?)?;
        let issuer = config.issuer(&state.inventory)?;
        state.inventory.validate(&config, &issuer, Utc::now())?;
        Ok(Self {
            store,
            state,
            config,
            issuer,
            fresh_deadline: None,
            fatal,
        })
    }
    pub fn inventory(&self) -> Inventory {
        self.state.inventory.clone()
    }
    pub fn expected_run(&self) -> String {
        self.state.expected_redis_run_id.clone()
    }
    fn persist(&mut self, candidate: State) -> Result<()> {
        let result = candidate
            .bytes()
            .and_then(|bytes| self.store.replace(&bytes));
        if result.is_err() {
            self.fatal.store(true, Ordering::SeqCst);
        }
        result?;
        self.state = candidate;
        Ok(())
    }

    pub fn reserve_round(&mut self) -> Result<Round> {
        let now = Utc::now();
        let deadline = Instant::now() + Duration::from_secs(LIFETIME_SECONDS as u64);
        self.state
            .inventory
            .validate(&self.config, &self.issuer, now)?;
        let version = self
            .state
            .membership_high_water
            .checked_add(1)
            .ok_or("membership allocator exhausted")?;
        let mut records = Vec::new();
        for node in &self.state.inventory.nodes {
            let bytes = self
                .issuer
                .sign_membership_bytes(self.state.inventory.record(node, version, now))
                .map_err(|_| "cannot encode membership")?;
            records.push((
                node.node_id.clone(),
                SignedMembershipRecord { version, bytes },
            ));
        }
        let mut candidate = self.state.clone();
        candidate.membership_high_water = version;
        self.persist(candidate)?;
        Ok(Round {
            records,
            version,
            revision: self.state.inventory.revision,
            expires_at: now + chrono::Duration::seconds(LIFETIME_SECONDS),
            deadline,
        })
    }

    pub fn confirm(&mut self, round: Round) -> Result<()> {
        if round.revision != self.state.inventory.revision
            || round.version > self.state.membership_high_water
            || self
                .state
                .confirmed
                .as_ref()
                .is_some_and(|old| old.membership_version >= round.version)
            || Instant::now() + RESPONSE_MARGIN >= round.deadline
        {
            return Err("publication confirmation is stale or outside its fixed lifetime");
        }
        let mut candidate = self.state.clone();
        candidate.confirmed = Some(Confirmation {
            inventory_revision: round.revision,
            membership_version: round.version,
            expires_at: round.expires_at,
        });
        self.persist(candidate)?;
        self.fresh_deadline = Some(round.deadline);
        Ok(())
    }

    fn fresh_confirmation(&self) -> Result<(Confirmation, DateTime<Utc>)> {
        let confirmation = self
            .state
            .confirmed
            .clone()
            .ok_or("no confirmed publication")?;
        if self
            .fresh_deadline
            .is_none_or(|deadline| Instant::now() + RESPONSE_MARGIN >= deadline)
            || confirmation.inventory_revision != self.state.inventory.revision
        {
            return Err("no fresh publication for this process and inventory");
        }
        let now = Utc::now();
        let remaining = confirmation.expires_at.signed_duration_since(now);
        if remaining < chrono::Duration::seconds(RESPONSE_MARGIN.as_secs() as i64)
            || remaining > chrono::Duration::seconds(LIFETIME_SECONDS)
        {
            return Err("confirmed publication window or authority clock is unusable");
        }
        Ok((confirmation, now))
    }

    pub fn ready(&self) -> bool {
        self.fresh_confirmation().is_ok()
    }

    pub fn checkpoint(&mut self, nonce: String) -> Result<Vec<u8>> {
        validate_nonce(&nonce)?;
        let (confirmation, now) = self.fresh_confirmation()?;
        let version = self
            .state
            .checkpoint_high_water
            .checked_add(1)
            .ok_or("checkpoint allocator exhausted")?;
        let checkpoint = self.state.inventory.checkpoint(
            version,
            confirmation.membership_version,
            nonce.clone(),
            now,
            confirmation.expires_at,
        );
        let bytes = self
            .issuer
            .sign_checkpoint_bytes(checkpoint)
            .map_err(|_| "cannot encode checkpoint")?;
        let mut verifier = MembershipVerifier::new(
            self.state.inventory.policy(&self.config)?,
            [TrustedPublisherKey::new(
                &self.state.inventory.publisher_key_id,
                self.issuer
                    .public_key()
                    .map_err(|_| "invalid signing public key")?,
            )
            .map_err(|_| "invalid signer")?],
        )
        .map_err(|_| "invalid verification policy")?;
        verifier
            .verify_checkpoint(&bytes, &nonce, now)
            .map_err(|_| "checkpoint rejected by signing policy")?;
        let mut candidate = self.state.clone();
        candidate.checkpoint_high_water = version;
        self.persist(candidate)?;
        Ok(bytes)
    }
}

pub fn validate_nonce(nonce: &str) -> Result<()> {
    if !(16..=128).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid checkpoint nonce");
    }
    Ok(())
}

/// At most one blocking state task exists. HTTP admission has a bounded async
/// wait queue; the publisher joins the fair serializer without competing for
/// an HTTP admission slot, so new requests cannot continually overtake it.
#[derive(Clone)]
pub struct Coordinator {
    engine: Arc<Mutex<Engine>>,
    permit: Arc<Semaphore>,
    admission: Arc<Semaphore>,
    pub fatal: Arc<AtomicBool>,
}

impl Coordinator {
    pub fn new(engine: Engine, fatal: Arc<AtomicBool>) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
            permit: Arc::new(Semaphore::new(1)),
            admission: Arc::new(Semaphore::new(32)),
            fatal,
        }
    }
    pub async fn call<T: Send + 'static>(
        &self,
        wait: bool,
        operation: impl FnOnce(&mut Engine) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        if self.fatal.load(Ordering::SeqCst) {
            return Err("authority persistence is unavailable");
        }
        let _admission = if wait {
            None
        } else {
            Some(
                Arc::clone(&self.admission)
                    .try_acquire_owned()
                    .map_err(|_| "state admission limit")?,
            )
        };
        let permit = tokio::time::timeout(
            if wait {
                PUBLISHER_QUEUE_BUDGET
            } else {
                STATE_IO_BUDGET
            },
            Arc::clone(&self.permit).acquire_owned(),
        )
        .await
        .map_err(|_| "state allocator is busy")?
        .map_err(|_| "state allocator closed")?;
        let engine = Arc::clone(&self.engine);
        let fatal = Arc::clone(&self.fatal);
        let task = tokio::task::spawn_blocking(move || {
            // Keep the permit in the actual blocking task, including after its
            // HTTP caller times out or disconnects. Never overlap durable I/O.
            let _permit = permit;
            if fatal.load(Ordering::SeqCst) {
                return Err("authority persistence is unavailable");
            }
            let mut engine = engine.lock().map_err(|_| "authority state lock failed")?;
            operation(&mut engine)
        });
        // This watchdog must outlive the request that allocated the task.
        // Dropping a request's JoinHandle detaches this supervisor; it still
        // latches an actual I/O timeout, without treating cancellation itself
        // as a global authority failure.
        let fatal = Arc::clone(&self.fatal);
        let supervisor = tokio::spawn(async move {
            match tokio::time::timeout(STATE_IO_BUDGET, task).await {
                Ok(Ok(result)) => result,
                _ => {
                    fatal.store(true, Ordering::SeqCst);
                    Err("authority durable operation failed or timed out")
                }
            }
        });
        match supervisor.await {
            Ok(result) if !self.fatal.load(Ordering::SeqCst) => result,
            Ok(_) => Err("authority persistence is unavailable"),
            Err(_) => {
                self.fatal.store(true, Ordering::SeqCst);
                Err("authority durable supervisor failed")
            }
        }
    }
}

#[cfg(test)]
#[path = "online_state_tests.rs"]
mod tests;
