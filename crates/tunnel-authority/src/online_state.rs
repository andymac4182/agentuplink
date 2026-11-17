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
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tunnel_catalog::SignedMembershipRecord;
use tunnel_cluster::membership::{MembershipIssuer, MembershipVerifier, TrustedPublisherKey};

const STATE_IO_BUDGET: Duration = Duration::from_secs(1);
// Every older HTTP waiter expires within one second; the last admitted
// operation then holds the serializer for at most one more healthy second.
// Keep the publisher in that fair queue, with one second of scheduling margin.
const PUBLISHER_QUEUE_BUDGET: Duration = Duration::from_secs(3);
pub const RESPONSE_MARGIN: Duration = Duration::from_secs(7);
/// Bound of the engine actor's command queue: the 32 admitted HTTP waiters,
/// the publisher, and headroom for waiters that left the queue before the
/// actor reached them (those entries are skipped without running). A caller
/// that finds the queue full waits inside its own queue budget and is then
/// refused as busy; nothing is queued without a bound.
const ENGINE_QUEUE_BOUND: usize = 64;
const PERSISTENCE_UNAVAILABLE: &str = "authority persistence is unavailable";

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

/// The durable allocator and approval fields the engine mutates in memory:
/// the persisted [`State`] without its confirmation, which lives in the
/// engine's [`Publication`] phase instead.
#[derive(Clone)]
struct Ledger {
    schema_version: u16,
    inventory: Inventory,
    expected_redis_run_id: String,
    membership_high_water: u64,
    checkpoint_high_water: u64,
    known_node_ids: BTreeSet<String>,
}

/// What this process may assert about its confirmed publication.
///
/// A persisted confirmation never reconstitutes monotonic freshness after a
/// process restart: only a publication acknowledged by this process carries a
/// monotonic deadline, so a deadline without a confirmation cannot exist.
/// `Fresh` means "holds this process's deadline"; whether that deadline and
/// the wall-clock expiry still leave the response margin is a clock reading
/// taken by each checkpoint, not a phase.
enum Publication {
    /// No confirmed round for the approved inventory.
    Unpublished,
    /// A confirmation persisted by an earlier process. It is kept on disk
    /// unchanged but authorizes nothing here.
    ConfirmedButStale(Confirmation),
    /// A round this process published and durably confirmed.
    Fresh {
        confirmation: Confirmation,
        deadline: Instant,
    },
    /// A durable write failed. Absorbing: this engine releases nothing more.
    Fatal,
}

enum PublicationEvent {
    /// Every node acknowledged a reserved round inside its fixed lifetime.
    Confirmed {
        confirmation: Confirmation,
        deadline: Instant,
    },
    /// A durable state replacement failed.
    PersistenceFailed,
}

/// The event is not allowed in the current publication phase.
#[derive(Debug, PartialEq, Eq)]
struct IllegalTransition;

impl Publication {
    /// The phase a newly opened engine starts in.
    fn restored(confirmed: Option<Confirmation>) -> Self {
        match confirmed {
            None => Self::Unpublished,
            Some(confirmation) => Self::ConfirmedButStale(confirmation),
        }
    }

    /// The confirmation the durable state carries in this phase.
    fn confirmation(&self) -> Option<&Confirmation> {
        match self {
            Self::Unpublished | Self::Fatal => None,
            Self::ConfirmedButStale(confirmation) | Self::Fresh { confirmation, .. } => {
                Some(confirmation)
            }
        }
    }

    /// The only place the publication phase changes.
    fn transition(
        &mut self,
        event: PublicationEvent,
    ) -> std::result::Result<(), IllegalTransition> {
        let next = match (&*self, event) {
            (Self::Fatal, _) => return Err(IllegalTransition),
            (_, PublicationEvent::PersistenceFailed) => Self::Fatal,
            (
                current,
                PublicationEvent::Confirmed {
                    confirmation,
                    deadline,
                },
            ) => {
                // A confirmation never moves backwards or repeats a version.
                if current
                    .confirmation()
                    .is_some_and(|old| old.membership_version >= confirmation.membership_version)
                {
                    return Err(IllegalTransition);
                }
                Self::Fresh {
                    confirmation,
                    deadline,
                }
            }
        };
        *self = next;
        Ok(())
    }
}

impl State {
    fn compose(ledger: Ledger, confirmed: Option<Confirmation>) -> Self {
        Self {
            schema_version: ledger.schema_version,
            inventory: ledger.inventory,
            expected_redis_run_id: ledger.expected_redis_run_id,
            membership_high_water: ledger.membership_high_water,
            checkpoint_high_water: ledger.checkpoint_high_water,
            known_node_ids: ledger.known_node_ids,
            confirmed,
        }
    }
    fn split(self) -> (Ledger, Option<Confirmation>) {
        (
            Ledger {
                schema_version: self.schema_version,
                inventory: self.inventory,
                expected_redis_run_id: self.expected_redis_run_id,
                membership_high_water: self.membership_high_water,
                checkpoint_high_water: self.checkpoint_high_water,
                known_node_ids: self.known_node_ids,
            },
            self.confirmed,
        )
    }
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
    state: Ledger,
    config: Config,
    issuer: Arc<MembershipIssuer>,
    publication: Publication,
    fatal: Arc<AtomicBool>,
}

impl Engine {
    pub fn open(config: Config, fatal: Arc<AtomicBool>) -> Result<Self> {
        let store = StateStore::open(&config.state_path)?;
        let state = State::decode(&store.load()?)?;
        let issuer = config.issuer(&state.inventory)?;
        state.inventory.validate(&config, &issuer, Utc::now())?;
        let (state, confirmed) = state.split();
        Ok(Self {
            store,
            state,
            config,
            issuer,
            publication: Publication::restored(confirmed),
            fatal,
        })
    }
    pub fn inventory(&self) -> Inventory {
        self.state.inventory.clone()
    }
    pub fn expected_run(&self) -> String {
        self.state.expected_redis_run_id.clone()
    }
    fn refuse_after_failure(&self) -> Result<()> {
        match self.publication {
            Publication::Fatal => Err(PERSISTENCE_UNAVAILABLE),
            _ => Ok(()),
        }
    }
    /// Durably replace the state with `candidate` and the confirmation of the
    /// current publication phase. A failure latches the process-wide fatal
    /// flag and moves this engine to its absorbing phase.
    fn persist(&mut self, candidate: Ledger) -> Result<()> {
        self.refuse_after_failure()?;
        let state = State::compose(candidate, self.publication.confirmation().cloned());
        let result = state.bytes().and_then(|bytes| self.store.replace(&bytes));
        if result.is_err() {
            self.fatal.store(true, Ordering::SeqCst);
            let _ = self
                .publication
                .transition(PublicationEvent::PersistenceFailed);
        }
        result?;
        (self.state, _) = state.split();
        Ok(())
    }

    pub fn reserve_round(&mut self) -> Result<Round> {
        self.refuse_after_failure()?;
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
        const STALE: &str = "publication confirmation is stale or outside its fixed lifetime";
        self.refuse_after_failure()?;
        if round.revision != self.state.inventory.revision
            || round.version > self.state.membership_high_water
            || Instant::now() + RESPONSE_MARGIN >= round.deadline
        {
            return Err(STALE);
        }
        // The phase refuses a confirmation that does not advance the version.
        // It then holds the new confirmation, which the durable write below
        // carries; if that write fails the phase is `Fatal` and nothing reads
        // the unpersisted confirmation.
        self.publication
            .transition(PublicationEvent::Confirmed {
                confirmation: Confirmation {
                    inventory_revision: round.revision,
                    membership_version: round.version,
                    expires_at: round.expires_at,
                },
                deadline: round.deadline,
            })
            .map_err(|IllegalTransition| STALE)?;
        self.persist(self.state.clone())
    }

    fn fresh_confirmation(&self) -> Result<(Confirmation, DateTime<Utc>)> {
        const NOT_FRESH: &str = "no fresh publication for this process and inventory";
        let (confirmation, deadline) = match &self.publication {
            Publication::Fatal => return Err(PERSISTENCE_UNAVAILABLE),
            Publication::Unpublished => return Err("no confirmed publication"),
            Publication::ConfirmedButStale(_) => return Err(NOT_FRESH),
            Publication::Fresh {
                confirmation,
                deadline,
            } => (confirmation, *deadline),
        };
        if Instant::now() + RESPONSE_MARGIN >= deadline
            || confirmation.inventory_revision != self.state.inventory.revision
        {
            return Err(NOT_FRESH);
        }
        let now = Utc::now();
        let remaining = confirmation.expires_at.signed_duration_since(now);
        if remaining < chrono::Duration::seconds(RESPONSE_MARGIN.as_secs() as i64)
            || remaining > chrono::Duration::seconds(LIFETIME_SECONDS)
        {
            return Err("confirmed publication window or authority clock is unusable");
        }
        Ok((confirmation.clone(), now))
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

type Operation = Box<dyn FnOnce(&mut Engine) + Send>;

/// One admitted state operation waiting for the engine.
struct Job {
    /// Tells the caller its operation is about to run. A caller that left
    /// the queue (its wait budget passed, or it was cancelled) has closed or
    /// dropped the receiving half, and its operation is then never run.
    grant: oneshot::Sender<()>,
    operation: Operation,
    /// Resolved when the operation finished inside its I/O budget, and
    /// dropped as soon as that budget passes or the operation is refused.
    done: oneshot::Sender<()>,
}

enum Command {
    Operate(Job),
    /// Read the engine without admission, budgets or the fatal latch.
    #[cfg(test)]
    Inspect(Box<dyn FnOnce(&Engine) + Send>),
}

/// The engine has exactly one owner: the actor task [`Coordinator::new`]
/// starts. Serialization follows from that ownership. The actor takes one
/// queued operation at a time, in arrival order, and lends the engine to at
/// most one blocking task. HTTP admission has a bounded wait queue; the
/// publisher joins the same fair queue without competing for an HTTP
/// admission slot, so new requests cannot continually overtake it.
#[derive(Clone)]
pub struct Coordinator {
    commands: mpsc::Sender<Command>,
    admission: Arc<Semaphore>,
    pub fatal: Arc<AtomicBool>,
    /// Whether the actor's blocking operation is still running.
    #[cfg(test)]
    operating: Arc<AtomicBool>,
}

impl Coordinator {
    /// Start the engine's owning actor. Must be called inside a Tokio runtime.
    pub fn new(engine: Engine, fatal: Arc<AtomicBool>) -> Self {
        let (commands, queue) = mpsc::channel(ENGINE_QUEUE_BOUND);
        let operating = Arc::new(AtomicBool::new(false));
        tokio::spawn(run_engine(
            engine,
            queue,
            Arc::clone(&fatal),
            Arc::clone(&operating),
        ));
        Self {
            commands,
            admission: Arc::new(Semaphore::new(32)),
            fatal,
            #[cfg(test)]
            operating,
        }
    }
    pub async fn call<T: Send + 'static>(
        &self,
        wait: bool,
        operation: impl FnOnce(&mut Engine) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        if self.fatal.load(Ordering::SeqCst) {
            return Err(PERSISTENCE_UNAVAILABLE);
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
        let (grant, mut granted) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        let (result, mut outcome) = oneshot::channel();
        let job = Job {
            grant,
            operation: Box::new(move |engine| {
                let _ = result.send(operation(engine));
            }),
            done,
        };
        let queued = tokio::time::timeout(
            if wait {
                PUBLISHER_QUEUE_BUDGET
            } else {
                STATE_IO_BUDGET
            },
            async {
                self.commands
                    .send(Command::Operate(job))
                    .await
                    .map_err(|_| ())?;
                (&mut granted).await.map_err(|_| ())
            },
        )
        .await;
        match queued {
            Ok(Ok(())) => {}
            // The actor is gone: an operation panicked and latched fatal.
            Ok(Err(())) if self.fatal.load(Ordering::SeqCst) => {
                return Err(PERSISTENCE_UNAVAILABLE);
            }
            Ok(Err(())) => return Err("state allocator closed"),
            Err(_) => {
                // Leave the queue. Closing first makes the decision atomic:
                // either the actor already granted this operation and it
                // runs, or it can no longer be granted and never runs.
                granted.close();
                if granted.try_recv().is_err() {
                    return Err("state allocator is busy");
                }
            }
        }
        // From here the operation belongs to the actor. It runs to completion
        // under the actor's watchdog even if this caller times out or
        // disconnects; cancellation itself is never a global failure.
        let _ = finished.await;
        if self.fatal.load(Ordering::SeqCst) {
            return Err(PERSISTENCE_UNAVAILABLE);
        }
        outcome
            .try_recv()
            .unwrap_or(Err("authority durable operation failed or timed out"))
    }

    #[cfg(test)]
    async fn inspect<T: Send + 'static>(
        &self,
        read: impl FnOnce(&Engine) -> T + Send + 'static,
    ) -> T {
        let (reply, value) = oneshot::channel();
        self.commands
            .send(Command::Inspect(Box::new(move |engine| {
                let _ = reply.send(read(engine));
            })))
            .await
            .expect("engine actor is running");
        value.await.expect("engine actor answered")
    }

    #[cfg(test)]
    fn operating(&self) -> bool {
        self.operating.load(Ordering::SeqCst)
    }
}

/// The engine's owning actor. It never overlaps durable I/O: the engine moves
/// into one blocking task and comes back before the next operation starts.
async fn run_engine(
    mut engine: Engine,
    mut queue: mpsc::Receiver<Command>,
    fatal: Arc<AtomicBool>,
    operating: Arc<AtomicBool>,
) {
    while let Some(command) = queue.recv().await {
        // Outside tests `Operate` is the only command.
        #[cfg_attr(not(test), allow(clippy::infallible_destructuring_match))]
        let job = match command {
            Command::Operate(job) => job,
            #[cfg(test)]
            Command::Inspect(read) => {
                read(&engine);
                continue;
            }
        };
        if job.grant.send(()).is_err() || fatal.load(Ordering::SeqCst) {
            // Dropping the job tells a caller that is still there; with the
            // latch set it reports the persistence failure.
            continue;
        }
        operating.store(true, Ordering::SeqCst);
        let Job {
            operation, done, ..
        } = job;
        let mut task = tokio::task::spawn_blocking(move || {
            operation(&mut engine);
            engine
        });
        // This watchdog belongs to the actor, so it outlives the request that
        // queued the operation. A stuck operation latches fatal at its budget
        // and still keeps the engine until it actually returns.
        let joined = match tokio::time::timeout(STATE_IO_BUDGET, &mut task).await {
            Ok(joined) => joined,
            Err(_) => {
                fatal.store(true, Ordering::SeqCst);
                drop(done);
                let joined = task.await;
                operating.store(false, Ordering::SeqCst);
                match joined {
                    Ok(returned) => engine = returned,
                    Err(_) => return,
                }
                continue;
            }
        };
        match joined {
            Ok(returned) => engine = returned,
            Err(_) => {
                // The operation panicked and took the engine with it.
                fatal.store(true, Ordering::SeqCst);
                operating.store(false, Ordering::SeqCst);
                return;
            }
        }
        operating.store(false, Ordering::SeqCst);
        let _ = done.send(());
    }
}

#[cfg(test)]
#[path = "online_state_tests.rs"]
mod tests;
