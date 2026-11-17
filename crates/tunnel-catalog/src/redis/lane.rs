//! Verified physical lanes to the Redis authority.
//!
//! The catalog keeps a plain redis-rs `MultiplexedConnection` per lane and
//! never hides a transport failure behind a generic reconnecting pool.  The
//! command that observes the failure returns it, so authorization, ownership
//! and recovery callers keep their fail-closed and unknown-outcome semantics;
//! nothing is replayed.  A lane re-establishes its connection only when a
//! *later* command needs it, and only after repeating the bounded PING/INFO
//! identity check used at startup.
//!
//! **Reconnect budget (M6-C74).**  That reconnect has the full
//! `REDIS_CONNECT_TIMEOUT` for DNS, TCP, TLS and `AUTH` -- a cold lookup on a
//! fresh machine alone can exceed the two-second command deadline -- so it
//! runs as one single-flight task per lane, started for the command that found
//! the lane without a connection, and the lane's bookkeeping never waits for
//! it to connect.  Every caller, the one that started it included, waits for it at
//! most its own `REDIS_OPERATION_TIMEOUT` and otherwise fails closed with the
//! ordinary timeout; the task keeps going and installs its connection for the
//! next command, but only while the lane still has no connection and the
//! attempt is still the lane's current one.  At most one reconnect is in
//! flight per lane, and its whole run is bounded by [`LANE_RECONNECT_BUDGET`].
//!
//! A primary whose `run_id` differs from the one the catalog is bound to has
//! restarted, been restored or been replaced.  The lanes of one catalog share
//! one [`RunBinding`].  A catalog that did not opt in (every `[cluster]`
//! catalog, every library caller) refuses any other run, as before task row
//! M6-C65.  A single relay's catalog (`enable_run_rebinding`) decides with one
//! atomic script on the new connection, before any caller command runs there:
//!
//! * it adopts the new run when the namespace's stored run binding already
//!   names it -- an operator re-attested it (`tunnel-relay rebind-redis-run`)
//!   or a sibling lane has just re-bound it -- and its incarnation is the
//!   configured one, which is exactly what a relay started now would accept;
//!   except that a run this process already refused for continuity stays
//!   refused, whatever an operator later declares;
//! * with a continuity witness (`redis_restart_continuity_seconds`), it moves
//!   the binding when the namespace's continuity token is one this process
//!   wrote and Redis acknowledged (or one whose write outcome it could not
//!   learn), the last acknowledgement was at most one token interval plus the
//!   command deadlines before this process's last reply from the old run, and
//!   `CONFIG GET` on the new run shows `appendonly yes`, `appendfsync always`
//!   and `no-appendfsync-on-rewrite no`.
//!
//! **What the token proves, and what it does not.**  It is sound for one
//! Redis restarting from its own AOF: AOF replay restores a prefix of the
//! command history, so a Redis holding this process's last acknowledged token
//! holds every write acknowledged before it, and with `appendfsync always`
//! nothing acknowledged after it was lost.  It only detects a copy **older
//! than the last token**: an empty Redis, or a snapshot, backup or replica
//! taken before it.  It is **not** sound across failover or replica
//! promotion: an asynchronous replica usually holds the last token and can
//! still lack writes the old primary acknowledged after it.  Likewise a
//! restore or a replica taken within about one interval before Redis went
//! away (plus any time the token loop was failing while Redis still
//! answered) holds the token and can lack writes acknowledged after it,
//! including operator-CLI revocations.  Anything that is not an in-place
//! restart must go through recovery or a new namespace.
//!
//! Lanes of one catalog share a loss generation.  When one lane observes a
//! transport loss, every sibling lane probes its own connection with the same
//! startup `PING` before its next caller command: a connection severed by the
//! same event reconnects there instead of failing one more caller closed,
//! while a live connection keeps its place.  The probe is never the caller's
//! command.
//!
//! A lane does not serialize its callers.  Each lane's connection phase is
//! owned by one actor task that only does bookkeeping: it performs no I/O, so
//! it never waits for the probe that verifies the physical connection
//! (M6-C95) nor for a reconnect (M6-C74, see above);
//! every caller then runs its own command on a handle to that multiplexed
//! connection, so concurrent commands pipeline on one socket and the
//! per-command deadline measures the authority's reply, never the time spent
//! waiting behind other callers.  A queueing delay therefore cannot be
//! reported as an authority timeout, while a stalled or severed authority
//! still fails exactly the commands that observed it.

use std::{
    collections::VecDeque,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use redis::{FromRedisValue, RedisError, aio::MultiplexedConnection};
use tokio::sync::{mpsc, oneshot, watch};

use super::{
    BOUND_RUN_MARKER, REDIS_CONNECT_TIMEOUT, REDIS_OPERATION_TIMEOUT, bound_run_id,
    connection_config, eval_command, open_verified_connection_with, redis_timeout,
};
use crate::{CatalogConnectionError, CatalogError, UnknownWriteCause};

/// The closed conflict label returned when a reconnect reaches a primary
/// whose `run_id` differs from the bound identity and the namespace does not
/// allow the new run to be adopted.
pub(super) const RUN_ID_CONFLICT: &str = "Redis server run id";

/// Run re-binding was already enabled for this catalog with a different
/// incarnation or different namespace keys.
pub(super) const REBIND_SCOPE_CONFLICT: &str = "Redis run re-binding scope";

/// The namespace has no deployment incarnation or no run binding: it was
/// never activated, or Redis came back without its data (M6-C65).
pub(crate) const NAMESPACE_UNBOUND: &str =
    "namespace has no deployment incarnation or Redis run binding";

/// The namespace is bound to an earlier Redis server run: Redis restarted
/// since the binding was written, and nothing re-attested it (M6-C65).
pub(crate) const RUN_BINDING_CHANGED: &str = "namespace is bound to an earlier Redis server run";

/// The namespace's continuity token is not one this relay wrote: Redis came
/// back without this relay's last acknowledged write (M6-C65).
pub(crate) const CONTINUITY_MISMATCH: &str = "Redis authority continuity token";

/// The restarted Redis does not prove its acknowledged writes are durable
/// (`appendonly yes`, `appendfsync always`, `no-appendfsync-on-rewrite no`,
/// read with `CONFIG GET`), so a continuity token proves nothing (M6-C65).
pub(crate) const PERSISTENCE_UNSOUND: &str =
    "Redis persistence does not make acknowledged writes durable";

/// The whole of one lane reconnect: opening the connection within
/// [`REDIS_CONNECT_TIMEOUT`], the PING/INFO identity check, and the run
/// re-binding decision, each of the last three bounded by
/// [`REDIS_OPERATION_TIMEOUT`] (M6-C74).
const LANE_RECONNECT_BUDGET: Duration = REDIS_CONNECT_TIMEOUT
    .saturating_add(REDIS_OPERATION_TIMEOUT)
    .saturating_add(REDIS_OPERATION_TIMEOUT)
    .saturating_add(REDIS_OPERATION_TIMEOUT);

/// Outcome of one lane reconnect: `None` while in flight.
type ReconnectOutcome = Option<Result<(), CatalogError>>;

/// Bound of a lane actor's and of the binding actor's command queue.  Neither
/// actor waits on anything while handling a command, so the queue only
/// absorbs bursts.  A caller that finds it full waits for room inside its own
/// command deadline and then fails closed with the ordinary timeout.
const ACTOR_QUEUE_BOUND: usize = 64;

/// The event is not allowed in the current phase; nothing changed.
#[derive(Debug, PartialEq, Eq)]
struct IllegalTransition;

/// The owning actor is not running: its runtime has shut down.
fn actor_gone(what: &'static str) -> CatalogError {
    CatalogError::Database(RedisError::from(std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        what,
    )))
}

/// Most continuity tokens whose write outcome is unknown that a witness keeps
/// as candidates.  Beyond it the oldest is forgotten, which can only make a
/// later re-binding refuse.
const MAX_CONTINUITY_CANDIDATES: usize = 8;

/// Most Redis runs a binding remembers having refused for continuity.
const MAX_CONTINUITY_REFUSED_RUNS: usize = 8;

/// The Redis persistence a token re-binding requires, read with `CONFIG GET`
/// on the new run: every acknowledged write is on disk before the reply,
/// including while the AOF is being rewritten.
const REQUIRED_PERSISTENCE: [(&str, &str); 3] = [
    ("appendonly", "yes"),
    ("appendfsync", "always"),
    ("no-appendfsync-on-rewrite", "no"),
];

/// One atomic re-binding decision on a connection to a new Redis run.
///
/// KEYS[1] active incarnation, [2] run binding, [3] continuity token.
/// ARGV[1] configured incarnation, [2] the new run id, [3] `1` when a
/// continuity witness may re-bind, [4..] the witness's candidate tokens.
const SCRIPT_REBIND_RUN: &str = r#"
local incarnation = redis.call('GET', KEYS[1])
local run = redis.call('GET', KEYS[2])
if not incarnation or not run then return {'unbound'} end
if incarnation ~= ARGV[1] then return {'incarnation'} end
if run == ARGV[2] then return {'ok'} end
if ARGV[3] ~= '1' then return {'run'} end
local token = redis.call('GET', KEYS[3])
if not token then return {'continuity'} end
for index = 4, #ARGV do
  if token == ARGV[index] then
    redis.call('SET', KEYS[2], ARGV[2])
    return {'rebound'}
  end
end
return {'continuity'}
"#;

/// The keys and incarnation a lane needs to decide a re-binding on its own
/// connection.  Set only for a single relay (`enable_run_rebinding`); a
/// catalog without it refuses every other run, as before M6-C65.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RebindScope {
    pub(super) incarnation: String,
    pub(super) incarnation_key: String,
    pub(super) run_key: String,
    pub(super) continuity_key: String,
}

/// Continuity tokens this process wrote: the last one Redis acknowledged and
/// any written since whose outcome is unknown.  Only these can be in Redis
/// if Redis still holds this process's acknowledged writes.
struct ContinuityWitness {
    candidates: VecDeque<String>,
    /// The token interval the relay runs, which bounds how stale the last
    /// acknowledged token may be when Redis went away.
    interval: Duration,
    /// When Redis last acknowledged a token, in the binding's clock.
    last_ack_ms: Option<u64>,
}

/// How far a catalog's run binding may move.  The witness exists only on top
/// of a re-binding scope, so a witness without a scope cannot be represented.
enum BindingMode {
    /// Never opted in: any run but the bound one is refused.
    Pinned,
    /// `enable_run_rebinding`: adopt a run the namespace's stored binding
    /// already names.
    Rebindable(RebindScope),
    /// Rebindable, and a continuity witness may move the stored binding.
    Witnessed {
        scope: RebindScope,
        witness: ContinuityWitness,
    },
}

enum BindingEvent {
    ScopeConfigured(RebindScope),
    WitnessEnabled(Duration),
    WitnessDisabled,
}

impl BindingMode {
    /// The only place the binding mode changes.  A refused event leaves the
    /// mode as it was: enabling an enabled witness keeps its tokens, and a
    /// scope is configured once.
    fn transition(&mut self, event: BindingEvent) -> Result<(), IllegalTransition> {
        let (next, result) = match (std::mem::replace(self, Self::Pinned), event) {
            (Self::Pinned, BindingEvent::ScopeConfigured(scope)) => {
                (Self::Rebindable(scope), Ok(()))
            }
            (Self::Rebindable(scope), BindingEvent::WitnessEnabled(interval)) => (
                Self::Witnessed {
                    scope,
                    witness: ContinuityWitness {
                        candidates: VecDeque::new(),
                        interval,
                        last_ack_ms: None,
                    },
                },
                Ok(()),
            ),
            (Self::Witnessed { scope, .. }, BindingEvent::WitnessDisabled) => {
                (Self::Rebindable(scope), Ok(()))
            }
            (unchanged, _) => (unchanged, Err(IllegalTransition)),
        };
        *self = next;
        result
    }

    fn scope(&self) -> Option<&RebindScope> {
        match self {
            Self::Pinned => None,
            Self::Rebindable(scope) | Self::Witnessed { scope, .. } => Some(scope),
        }
    }

    fn witness(&self) -> Option<&ContinuityWitness> {
        match self {
            Self::Witnessed { witness, .. } => Some(witness),
            Self::Pinned | Self::Rebindable(_) => None,
        }
    }

    fn witness_mut(&mut self) -> Option<&mut ContinuityWitness> {
        match self {
            Self::Witnessed { witness, .. } => Some(witness),
            Self::Pinned | Self::Rebindable(_) => None,
        }
    }
}

/// The run a catalog is bound to and how often that has moved, published by
/// the binding actor for callers that cannot wait.
#[derive(Clone, Default)]
struct BoundRun {
    /// The adopted run; meaningful once `rebinds` is not zero.  Until then
    /// the catalog is bound to the run its first lane connected to.
    run_id: String,
    /// Advanced every time the binding moves to a new run.
    rebinds: u64,
}

/// What callers that cannot wait hand to, or read past, the binding actor.
struct BindingShared {
    /// The binding's clock origin.
    origin: Instant,
    /// Milliseconds since `origin` of the last reply any lane received from
    /// the bound run.  Updated on every successful command.
    last_contact_ms: AtomicU64,
    /// The run the catalog's first lane connected to.  Set once.
    initial_run: OnceLock<String>,
    /// The re-binding scope, configured at most once.
    scope: OnceLock<RebindScope>,
    /// Advanced by every request to stop the witness.
    witness_disables: AtomicU64,
}

impl BindingShared {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// What a re-binding decision needs from the binding, read in one step.
enum RebindPlan {
    /// The catalog is already bound to that run.
    AlreadyBound,
    Decide {
        keys: Vec<String>,
        incarnation: String,
        /// The witness's candidate tokens, when its last acknowledged token
        /// is fresh enough to re-bind on.
        candidates: Option<Vec<String>>,
    },
}

/// Everything about a catalog's run binding that changes, owned by the
/// binding actor.
struct BindingState {
    shared: Arc<BindingShared>,
    mode: BindingMode,
    run: BoundRun,
    published: watch::Sender<BoundRun>,
    /// The `witness_disables` value already applied to `mode`.
    witness_disables_seen: u64,
    /// Runs refused for continuity; they stay refused in this process even if
    /// an operator later re-attests them (M6-C65 review).
    continuity_refused: VecDeque<String>,
}

impl BindingState {
    /// Apply what callers that cannot wait have asked for since the last
    /// command: a configured scope and requests to stop the witness.  The
    /// actor runs this before every command, so each command sees them.
    fn absorb(&mut self) {
        if matches!(self.mode, BindingMode::Pinned)
            && let Some(scope) = self.shared.scope.get()
        {
            let _ = self
                .mode
                .transition(BindingEvent::ScopeConfigured(scope.clone()));
        }
        let disables = self.shared.witness_disables.load(Ordering::Acquire);
        if disables != self.witness_disables_seen {
            self.witness_disables_seen = disables;
            // Refused when no witness is kept: there is nothing to stop.
            let _ = self.mode.transition(BindingEvent::WitnessDisabled);
        }
    }

    fn bound_run_is(&self, run_id: &str) -> bool {
        if self.run.rebinds == 0 {
            self.shared
                .initial_run
                .get()
                .is_some_and(|run| run == run_id)
        } else {
            self.run.run_id == run_id
        }
    }

    fn plan(&self, run_id: &str) -> Result<RebindPlan, CatalogError> {
        if self.bound_run_is(run_id) {
            return Ok(RebindPlan::AlreadyBound);
        }
        let Some(scope) = self.mode.scope() else {
            return Err(CatalogError::Conflict(RUN_ID_CONFLICT));
        };
        if self.continuity_refused.iter().any(|run| run == run_id) {
            return Err(CatalogError::Conflict(CONTINUITY_MISMATCH));
        }
        let candidates = self.mode.witness().and_then(|witness| {
            token_is_fresh(
                witness.last_ack_ms,
                self.shared.last_contact_ms.load(Ordering::Acquire),
                witness.interval,
            )
            .then(|| witness.candidates.iter().cloned().collect::<Vec<_>>())
        });
        Ok(RebindPlan::Decide {
            keys: vec![
                scope.incarnation_key.clone(),
                scope.run_key.clone(),
                scope.continuity_key.clone(),
            ],
            incarnation: scope.incarnation.clone(),
            candidates,
        })
    }

    fn adopt(&mut self, run_id: &str) {
        if !self.bound_run_is(run_id) {
            run_id.clone_into(&mut self.run.run_id);
            self.run.rebinds += 1;
            self.published.send_replace(self.run.clone());
        }
    }

    fn refuse_for_continuity(&mut self, run_id: &str) {
        if !self.continuity_refused.iter().any(|run| run == run_id) {
            self.continuity_refused.push_back(run_id.to_owned());
            while self.continuity_refused.len() > MAX_CONTINUITY_REFUSED_RUNS {
                self.continuity_refused.pop_front();
            }
        }
    }
}

type BindingCommand = Box<dyn FnOnce(&mut BindingState) + Send>;

async fn run_binding(mut state: BindingState, mut commands: mpsc::Receiver<BindingCommand>) {
    while let Some(command) = commands.recv().await {
        state.absorb();
        command(&mut state);
    }
}

/// Whether a token re-binding is still sound: the last acknowledged token
/// was written at most one interval plus the command deadlines before the
/// last reply this process had from the bound Redis run.  A token loop that
/// stopped or kept failing while Redis still answered leaves a larger gap,
/// in which writes the witness never saw may have been acknowledged.
pub(super) fn token_is_fresh(
    last_ack_ms: Option<u64>,
    last_contact_ms: u64,
    interval: Duration,
) -> bool {
    let Some(last_ack_ms) = last_ack_ms else {
        return false;
    };
    let bound = interval + 2 * REDIS_OPERATION_TIMEOUT + Duration::from_secs(1);
    let bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
    last_contact_ms.saturating_sub(last_ack_ms) <= bound_ms
}

/// Whether `CONFIG GET` pairs show the persistence a token re-binding needs.
pub(super) fn persistence_is_sound(pairs: &[String]) -> bool {
    REQUIRED_PERSISTENCE.iter().all(|(name, required)| {
        pairs
            .chunks(2)
            .any(|pair| pair.len() == 2 && pair[0] == *name && pair[1] == *required)
    })
}

/// Read the persistence settings on `connection` (M6-C65).  A refused
/// `CONFIG GET` (for example an ACL user without `+config|get`) is unsound,
/// not an error: nothing proves the writes are durable.
pub(super) async fn persistence_verified(connection: &mut MultiplexedConnection) -> bool {
    let mut command = redis::cmd("CONFIG");
    command.arg("GET");
    for (name, _) in REQUIRED_PERSISTENCE {
        command.arg(name);
    }
    match command.query_async::<Vec<String>>(connection).await {
        Ok(pairs) => persistence_is_sound(&pairs),
        Err(_) => false,
    }
}

/// The Redis server run a catalog is bound to, shared by all of its lanes.
///
/// Everything that changes is owned by one actor task, started on the Tokio
/// runtime the binding is created on; the binding must not outlive that
/// runtime, after which re-binding fails closed.  Callers that cannot wait
/// read the published bound run, and hand the actor a scope (once) or a
/// request to stop the witness, which it applies before its next command.
pub(super) struct RunBinding {
    shared: Arc<BindingShared>,
    bound: watch::Receiver<BoundRun>,
    commands: mpsc::Sender<BindingCommand>,
}

impl Default for RunBinding {
    /// Must be called inside a Tokio runtime.
    fn default() -> Self {
        let shared = Arc::new(BindingShared {
            origin: Instant::now(),
            last_contact_ms: AtomicU64::new(0),
            initial_run: OnceLock::new(),
            scope: OnceLock::new(),
            witness_disables: AtomicU64::new(0),
        });
        let (published, bound) = watch::channel(BoundRun::default());
        let (commands, queue) = mpsc::channel(ACTOR_QUEUE_BOUND);
        tokio::spawn(run_binding(
            BindingState {
                shared: Arc::clone(&shared),
                mode: BindingMode::Pinned,
                run: BoundRun::default(),
                published,
                witness_disables_seen: 0,
                continuity_refused: VecDeque::new(),
            },
            queue,
        ));
        Self {
            shared,
            bound,
            commands,
        }
    }
}

impl RunBinding {
    /// Run `operation` on the binding actor and return its result, or `None`
    /// when the actor is no longer running.
    async fn ask<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut BindingState) -> T + Send + 'static,
    ) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Box::new(move |state| {
                let _ = reply.send(operation(state));
            }))
            .await
            .ok()?;
        answer.await.ok()
    }

    /// A lane received a reply from the bound run.
    pub(super) fn contact(&self) {
        self.shared
            .last_contact_ms
            .fetch_max(self.shared.now_ms(), Ordering::AcqRel);
    }

    /// The run the catalog is currently bound to.
    pub(super) fn run_id(&self) -> String {
        let bound = self.bound.borrow();
        if bound.rebinds == 0 {
            self.shared.initial_run.get().cloned().unwrap_or_default()
        } else {
            bound.run_id.clone()
        }
    }

    /// How many times the binding has moved to a new run in this process.
    pub(super) fn rebinds(&self) -> u64 {
        self.bound.borrow().rebinds
    }

    fn initialize(&self, run_id: &str) {
        let _ = self.shared.initial_run.set(run_id.to_owned());
    }

    /// Configure the re-binding scope.  It is derived from the catalog's
    /// namespace and incarnation and is set once: a later call with the same
    /// scope changes nothing, and one with a different scope is refused and
    /// keeps the first.
    pub(super) fn set_scope(&self, scope: RebindScope) -> Result<(), CatalogError> {
        match self.shared.scope.set(scope) {
            Ok(()) => Ok(()),
            Err(scope) if self.shared.scope.get() == Some(&scope) => Ok(()),
            Err(_) => Err(CatalogError::Conflict(REBIND_SCOPE_CONFLICT)),
        }
    }

    pub(super) fn has_scope(&self) -> bool {
        self.shared.scope.get().is_some()
    }

    /// Start keeping a continuity witness.  Idempotent.  A request to stop
    /// the witness made after this call began wins, even if the actor reaches
    /// this call's command later: the witness then stays off.
    pub(super) async fn enable_witness(&self, interval: Duration) {
        let disables = self.shared.witness_disables.load(Ordering::Acquire);
        self.ask(move |state| {
            if state.shared.witness_disables.load(Ordering::Acquire) == disables {
                let _ = state
                    .mode
                    .transition(BindingEvent::WitnessEnabled(interval));
            }
        })
        .await;
    }

    /// Stop re-binding on tokens: the token loop is gone (M6-C65 review).
    /// Takes effect before the binding's next command.
    pub(super) fn disable_witness(&self) {
        self.shared.witness_disables.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) async fn witness_enabled(&self) -> bool {
        self.ask(|state| state.mode.witness().is_some())
            .await
            .unwrap_or(false)
    }

    /// Record a token about to be written, before it is dispatched, so a
    /// re-binding that races the write still recognizes it.
    pub(super) async fn continuity_dispatching(&self, token: &str) {
        let token = token.to_owned();
        self.ask(move |state| {
            if let Some(witness) = state.mode.witness_mut() {
                witness.candidates.push_back(token);
                while witness.candidates.len() > MAX_CONTINUITY_CANDIDATES {
                    witness.candidates.pop_front();
                }
            }
        })
        .await;
    }

    /// Redis acknowledged `token`: it is now the only candidate.
    pub(super) async fn continuity_acknowledged(&self, token: &str) {
        let now = self.shared.now_ms();
        self.contact();
        let token = token.to_owned();
        self.ask(move |state| {
            if let Some(witness) = state.mode.witness_mut() {
                witness.candidates.clear();
                witness.candidates.push_back(token);
                witness.last_ack_ms = Some(now);
            }
        })
        .await;
    }

    /// The write of `token` definitely did not happen.
    pub(super) async fn continuity_not_written(&self, token: &str) {
        let token = token.to_owned();
        self.ask(move |state| {
            if let Some(witness) = state.mode.witness_mut() {
                witness.candidates.retain(|candidate| *candidate != token);
            }
        })
        .await;
    }

    /// Decide on `connection`, already verified to be Redis run `run_id`,
    /// whether the catalog may move its binding there.
    async fn rebind(
        &self,
        connection: &mut MultiplexedConnection,
        run_id: &str,
    ) -> Result<(), CatalogError> {
        const GONE: &str = "Redis run binding is not running";
        // Decide, in one step on the actor, whether a token re-binding is
        // even possible; the persistence read happens after it.
        let planned = run_id.to_owned();
        let (keys, incarnation, candidates) = match self
            .ask(move |state| state.plan(&planned))
            .await
            .ok_or_else(|| actor_gone(GONE))??
        {
            RebindPlan::AlreadyBound => return Ok(()),
            RebindPlan::Decide {
                keys,
                incarnation,
                candidates,
            } => (keys, incarnation, candidates),
        };
        let mut persistence_unsound = false;
        let candidates = match candidates {
            Some(candidates) if persistence_verified(connection).await => Some(candidates),
            Some(_) => {
                persistence_unsound = true;
                None
            }
            None => None,
        };
        let mut args = vec![incarnation, run_id.to_owned()];
        match candidates {
            Some(candidates) => {
                args.push("1".to_owned());
                args.extend(candidates);
            }
            None => args.push("0".to_owned()),
        }
        let reply: Vec<String> = eval_command(SCRIPT_REBIND_RUN, &keys, &args)
            .query_async(connection)
            .await
            .map_err(CatalogError::Database)?;
        match reply.first().map(String::as_str) {
            Some("ok" | "rebound") => {
                let adopted = run_id.to_owned();
                self.ask(move |state| state.adopt(&adopted))
                    .await
                    .ok_or_else(|| actor_gone(GONE))
            }
            Some("unbound") => Err(CatalogError::Conflict(NAMESPACE_UNBOUND)),
            Some("continuity") => {
                let refused = run_id.to_owned();
                self.ask(move |state| state.refuse_for_continuity(&refused))
                    .await;
                Err(CatalogError::Conflict(CONTINUITY_MISMATCH))
            }
            Some("incarnation") => Err(CatalogError::Conflict(
                "active deployment incarnation or Redis authority run",
            )),
            // No token re-binding was attempted: why not decides the class.
            Some("run") if persistence_unsound => Err(CatalogError::Conflict(PERSISTENCE_UNSOUND)),
            Some("run") => Err(CatalogError::Conflict(RUN_BINDING_CHANGED)),
            _ => Err(CatalogError::Serialization(
                "invalid Redis run binding reply".into(),
            )),
        }
    }
}

/// Transport-loss signal and run binding shared by every lane of one catalog.
#[derive(Default)]
pub(super) struct LaneGroup {
    loss_generation: AtomicU64,
    binding: RunBinding,
}

impl LaneGroup {
    pub(super) fn binding(&self) -> &RunBinding {
        &self.binding
    }
}

/// One lane's connection phase.  `C` is the connection handle; it is a type
/// parameter only so the transition table can be tested without a socket.
enum LanePhase<C> {
    /// The lane holds a connection verified against a Redis run.
    Connected {
        connection: C,
        /// The Redis run the connection was verified against.
        verified_run_id: String,
        /// The group loss generation it was last verified against.
        verified_generation: u64,
    },
    /// No connection and no reconnect: the next command starts one.
    Disconnected,
    /// No connection, and the lane's single reconnect is in flight (M6-C74).
    Reconnecting(ReconnectAttempt<C>),
}

/// One single-flight lane reconnect, running as its own task while the lane
/// actor keeps answering callers.
struct ReconnectAttempt<C> {
    task: tokio::task::JoinHandle<Result<(C, String), CatalogError>>,
    /// `None` while in flight; the attempt's outcome once it has finished
    /// and, on success, the lane holds its connection.
    outcome: watch::Sender<ReconnectOutcome>,
    /// The group loss generation current when the attempt started: a loss
    /// observed since then makes the next command probe its connection.
    loss_generation: u64,
}

enum LaneEvent<C> {
    /// A command found the lane disconnected and started its reconnect.
    ReconnectStarted(ReconnectAttempt<C>),
    ReconnectSucceeded {
        connection: C,
        run_id: String,
    },
    ReconnectFailed,
    /// A command or a probe observed a transport loss on the connection.
    ConnectionLost,
    /// The connection answered a probe for this group loss generation.
    ProbePassed {
        loss_generation: u64,
    },
}

struct LaneState<C> {
    phase: LanePhase<C>,
    /// Advanced whenever a connection is released or installed, so a caller
    /// that observed a loss on an older connection cannot release one that a
    /// sibling caller has since re-established.
    connection_generation: u64,
}

impl<C> LaneState<C> {
    /// The only place the lane's connection phase changes.  Returns the
    /// reconnect attempt the event ended, whose outcome the caller publishes.
    fn transition(
        &mut self,
        event: LaneEvent<C>,
    ) -> Result<Option<ReconnectAttempt<C>>, IllegalTransition> {
        let (next, result) = match (
            std::mem::replace(&mut self.phase, LanePhase::Disconnected),
            event,
        ) {
            (LanePhase::Disconnected, LaneEvent::ReconnectStarted(attempt)) => {
                (LanePhase::Reconnecting(attempt), Ok(None))
            }
            (
                LanePhase::Reconnecting(attempt),
                LaneEvent::ReconnectSucceeded { connection, run_id },
            ) => {
                self.connection_generation += 1;
                (
                    LanePhase::Connected {
                        connection,
                        verified_run_id: run_id,
                        verified_generation: attempt.loss_generation,
                    },
                    Ok(Some(attempt)),
                )
            }
            (LanePhase::Reconnecting(attempt), LaneEvent::ReconnectFailed) => {
                (LanePhase::Disconnected, Ok(Some(attempt)))
            }
            (LanePhase::Connected { .. }, LaneEvent::ConnectionLost) => {
                self.connection_generation += 1;
                (LanePhase::Disconnected, Ok(None))
            }
            (
                LanePhase::Connected {
                    connection,
                    verified_run_id,
                    ..
                },
                LaneEvent::ProbePassed { loss_generation },
            ) => (
                LanePhase::Connected {
                    connection,
                    verified_run_id,
                    verified_generation: loss_generation,
                },
                Ok(None),
            ),
            (unchanged, _) => (unchanged, Err(IllegalTransition)),
        };
        self.phase = next;
        result
    }

    /// Whether the lane still holds the connection a caller was handed.
    fn holds(&self, connection_generation: u64) -> bool {
        self.connection_generation == connection_generation
            && matches!(self.phase, LanePhase::Connected { .. })
    }
}

/// What the lane actor tells a caller to do next.
enum Verified {
    Ready(Admitted),
    /// A sibling lane observed a transport loss since this connection was
    /// last verified: probe this handle, away from the lane actor, before
    /// the caller's command (M6-C95).
    Probe {
        connection: MultiplexedConnection,
        connection_generation: u64,
        loss_generation: u64,
    },
    /// The lane has no connection and a reconnect is in flight.
    Reconnecting(watch::Receiver<ReconnectOutcome>),
}

/// What a caller's probe of a connection found.
struct ProbeReport {
    connection_generation: u64,
    loss_generation: u64,
    passed: bool,
}

enum LaneCommand {
    /// Record the caller's probe, if it made one, and decide what it does
    /// next.
    Admit {
        probed: Option<ProbeReport>,
        reply: oneshot::Sender<Verified>,
    },
    /// The caller observed a transport loss on the connection it was handed.
    ReleaseLost {
        connection_generation: u64,
        done: oneshot::Sender<()>,
    },
    #[cfg(test)]
    Inspect(oneshot::Sender<LaneSnapshot>),
}

/// The lane's bookkeeping as a test reads it.
#[cfg(test)]
struct LaneSnapshot {
    connected: bool,
    reconnecting: bool,
    connection_generation: u64,
    /// Of the connection the lane holds, if it holds one.
    verified_generation: Option<u64>,
    verified_run_id: Option<String>,
}

/// Everything a lane's actor owns.
struct LaneActor {
    client: redis::Client,
    /// The redis-rs configuration a reconnect uses: production is
    /// `connection_config(REDIS_CONNECT_TIMEOUT)`.
    connect_config: redis::AsyncConnectionConfig,
    group: Arc<LaneGroup>,
    state: LaneState<MultiplexedConnection>,
}

impl LaneActor {
    /// The lane's owning task.  It performs no I/O: it answers callers, and
    /// records the end of the reconnect it started.  When the lane is dropped
    /// it abandons an in-flight reconnect instead of leaving a task to finish
    /// a connection nobody will use.
    async fn run(mut self, mut commands: mpsc::Receiver<LaneCommand>) {
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.handle(command),
                    None => break,
                },
                finished = reconnect_finished(&mut self.state) => self.reconnected(finished),
            }
        }
        if let LanePhase::Reconnecting(attempt) = &self.state.phase {
            attempt.task.abort();
        }
    }

    fn handle(&mut self, command: LaneCommand) {
        match command {
            LaneCommand::Admit { probed, reply } => {
                // Record the result only for the connection it probed: a
                // sibling caller may have released or replaced it since.
                if let Some(report) = probed
                    && self.state.holds(report.connection_generation)
                {
                    let _ = self.state.transition(if report.passed {
                        LaneEvent::ProbePassed {
                            loss_generation: report.loss_generation,
                        }
                    } else {
                        LaneEvent::ConnectionLost
                    });
                }
                let _ = reply.send(self.verify());
            }
            LaneCommand::ReleaseLost {
                connection_generation,
                done,
            } => {
                // Only the first observer of one loss releases the connection
                // and advances the group loss generation; a connection a
                // sibling caller already released or replaced is left alone.
                if self.state.holds(connection_generation)
                    && self.state.transition(LaneEvent::ConnectionLost).is_ok()
                {
                    self.group.loss_generation.fetch_add(1, Ordering::AcqRel);
                }
                let _ = done.send(());
            }
            #[cfg(test)]
            LaneCommand::Inspect(reply) => {
                let (verified_generation, verified_run_id) = match &self.state.phase {
                    LanePhase::Connected {
                        verified_generation,
                        verified_run_id,
                        ..
                    } => (Some(*verified_generation), Some(verified_run_id.clone())),
                    _ => (None, None),
                };
                let _ = reply.send(LaneSnapshot {
                    connected: matches!(self.state.phase, LanePhase::Connected { .. }),
                    reconnecting: matches!(self.state.phase, LanePhase::Reconnecting(_)),
                    connection_generation: self.state.connection_generation,
                    verified_generation,
                    verified_run_id,
                });
            }
        }
    }

    /// Decide, without I/O, what the caller does next.
    fn verify(&mut self) -> Verified {
        let loss_generation = self.group.loss_generation.load(Ordering::Acquire);
        match &self.state.phase {
            LanePhase::Connected {
                connection,
                verified_generation,
                ..
            } if *verified_generation != loss_generation => {
                // A sibling lane observed a transport loss since this
                // connection was last verified.  Probe before the caller's
                // command so a connection severed by the same event
                // reconnects here instead of failing this caller closed.
                Verified::Probe {
                    connection: connection.clone(),
                    connection_generation: self.state.connection_generation,
                    loss_generation,
                }
            }
            LanePhase::Connected {
                connection,
                verified_run_id,
                ..
            } => Verified::Ready(Admitted {
                connection: connection.clone(),
                connection_generation: self.state.connection_generation,
                run_id: verified_run_id.clone(),
            }),
            LanePhase::Reconnecting(attempt) => Verified::Reconnecting(attempt.outcome.subscribe()),
            LanePhase::Disconnected => {
                let attempt = self.start_reconnect(loss_generation);
                let outcome = attempt.outcome.subscribe();
                let _ = self.state.transition(LaneEvent::ReconnectStarted(attempt));
                Verified::Reconnecting(outcome)
            }
        }
    }

    /// Start the lane's single reconnect with the full connect budget
    /// (M6-C74).  It runs as its own task, bounded by
    /// [`LANE_RECONNECT_BUDGET`]; the actor learns its result in
    /// [`Self::reconnected`].
    fn start_reconnect(&self, loss_generation: u64) -> ReconnectAttempt<MultiplexedConnection> {
        let client = self.client.clone();
        let config = self.connect_config.clone();
        let group = Arc::clone(&self.group);
        let task = tokio::spawn(async move {
            tokio::time::timeout(LANE_RECONNECT_BUDGET, reconnect(&client, &config, &group))
                .await
                .unwrap_or_else(|_| Err(CatalogError::Database(redis_timeout())))
        });
        ReconnectAttempt {
            task,
            outcome: watch::channel(None).0,
            loss_generation,
        }
    }

    /// The lane's reconnect ended: install its connection, then publish the
    /// outcome so waiting callers verify the lane as it now is.
    fn reconnected(&mut self, finished: Result<(MultiplexedConnection, String), CatalogError>) {
        let (event, outcome) = match finished {
            Ok((connection, run_id)) => {
                (LaneEvent::ReconnectSucceeded { connection, run_id }, Ok(()))
            }
            Err(error) => (LaneEvent::ReconnectFailed, Err(error)),
        };
        if let Ok(Some(attempt)) = self.state.transition(event) {
            attempt.outcome.send_replace(Some(outcome));
        }
    }
}

/// Resolves when the lane's in-flight reconnect has ended; never while the
/// lane has none.  The lane actor applies the result at once, so a finished
/// task is never polled again.
async fn reconnect_finished<C>(state: &mut LaneState<C>) -> Result<(C, String), CatalogError> {
    match &mut state.phase {
        LanePhase::Reconnecting(attempt) => (&mut attempt.task)
            .await
            .unwrap_or_else(|_| Err(actor_gone("Redis authority lane reconnect abandoned"))),
        LanePhase::Connected { .. } | LanePhase::Disconnected => std::future::pending().await,
    }
}

pub(super) struct AuthorityLane {
    group: Arc<LaneGroup>,
    commands: mpsc::Sender<LaneCommand>,
}

/// A verified connection handed to one caller, and the run it belongs to.
struct Admitted {
    connection: MultiplexedConnection,
    connection_generation: u64,
    run_id: String,
}

impl AuthorityLane {
    /// Start the lane's owning actor around a verified startup connection.
    /// Must be called inside a Tokio runtime, which the lane must not
    /// outlive: afterwards every command fails closed.
    pub(super) fn new(
        client: redis::Client,
        connection: MultiplexedConnection,
        verified_run_id: String,
        group: Arc<LaneGroup>,
    ) -> Self {
        Self::with_connect_config(
            client,
            connection,
            verified_run_id,
            group,
            connection_config(REDIS_CONNECT_TIMEOUT),
        )
    }

    /// [`Self::new`], reconnecting with `connect_config` instead of the
    /// production configuration, for example with a slow resolver.
    fn with_connect_config(
        client: redis::Client,
        connection: MultiplexedConnection,
        verified_run_id: String,
        group: Arc<LaneGroup>,
        connect_config: redis::AsyncConnectionConfig,
    ) -> Self {
        group.binding.initialize(&verified_run_id);
        let verified_generation = group.loss_generation.load(Ordering::Acquire);
        let (commands, queue) = mpsc::channel(ACTOR_QUEUE_BOUND);
        tokio::spawn(
            LaneActor {
                client,
                connect_config,
                group: Arc::clone(&group),
                state: LaneState {
                    phase: LanePhase::Connected {
                        connection,
                        verified_run_id,
                        verified_generation,
                    },
                    connection_generation: 0,
                },
            }
            .run(queue),
        );
        Self { group, commands }
    }

    #[cfg(test)]
    async fn inspect(&self) -> LaneSnapshot {
        let (reply, snapshot) = oneshot::channel();
        self.commands
            .send(LaneCommand::Inspect(reply))
            .await
            .expect("lane actor is running");
        snapshot.await.expect("lane actor answered")
    }

    /// Run one bounded command on this lane.
    ///
    /// A transport failure releases the lane's connection so the *next*
    /// command reconnects; the failed command itself is never retried and its
    /// error is returned unchanged.
    pub(super) async fn query<T: FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection, _run_id| command.query_async::<T>(connection).await,
            DispatchedFailure::Definite,
        )
        .await
    }

    /// Run one bounded write command on this lane.
    ///
    /// Same transport contract as [`Self::query`], except that once the
    /// command has been dispatched a lost reply (a reply timeout or a severed
    /// connection) is the typed [`CatalogError::WriteOutcomeUnknown`]: the
    /// write may have committed on the authority, for example when it was
    /// written into a stalled socket that later delivered it (M7-C189).  A
    /// failure before dispatch and an actual authority reply keep their
    /// definite shapes, and the write is never replayed.
    pub(super) async fn query_write<T: FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection, _run_id| command.query_async::<T>(connection).await,
            DispatchedFailure::Unknown,
        )
        .await
    }

    /// Run one script on this lane.  Every argument equal to
    /// `bound_run_id()` is replaced, after the lane has verified its
    /// connection, by the run that connection was verified against, so a
    /// script's run fence always names the run it executes on -- including
    /// the first command after the lane adopted a new run.
    ///
    /// With `owner_write` the script is an owner-affecting write.  Once it
    /// has been dispatched, a lost reply no longer proves the write failed:
    /// the script may have committed on the authority before the reply
    /// deadline passed or the connection was severed.  Those two failures are
    /// reported as the typed [`CatalogError::WriteOutcomeUnknown`] so the
    /// caller can stay unready until it re-reads the authority; a failure
    /// before dispatch (lane admission) and an actual authority reply keep
    /// their definite shapes.  The write itself is never replayed.
    pub(super) async fn query_eval<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
        owner_write: bool,
    ) -> Result<T, CatalogError> {
        let dispatched = if owner_write {
            DispatchedFailure::Unknown
        } else {
            DispatchedFailure::Definite
        };
        let placeholder = bound_run_id();
        // Only the catalog's own placeholder may start with the marker, so no
        // caller-supplied value is ever taken for it.
        if args
            .iter()
            .any(|arg| arg.starts_with(BOUND_RUN_MARKER) && arg != placeholder)
        {
            return Err(CatalogError::InvalidInput(
                "script argument starts with a reserved control character",
            ));
        }
        self.execute(
            async |connection, run_id| {
                let args: Vec<String> = args
                    .iter()
                    .map(|arg| {
                        if arg == placeholder {
                            run_id.to_owned()
                        } else {
                            arg.clone()
                        }
                    })
                    .collect();
                eval_command(script, keys, &args)
                    .query_async::<T>(connection)
                    .await
            },
            dispatched,
        )
        .await
    }

    /// Run one bounded pipeline on this lane with the same failure contract
    /// as [`Self::query`].
    pub(super) async fn query_pipeline<T: FromRedisValue>(
        &self,
        pipeline: &redis::Pipeline,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection, _run_id| pipeline.query_async::<T>(connection).await,
            DispatchedFailure::Definite,
        )
        .await
    }

    async fn execute<T>(
        &self,
        operation: impl AsyncFnOnce(&mut MultiplexedConnection, &str) -> Result<T, RedisError>,
        dispatched: DispatchedFailure,
    ) -> Result<T, CatalogError> {
        let Admitted {
            mut connection,
            connection_generation,
            run_id,
        } = self.admit().await?;
        // Admission is over: this deadline covers only the authority's
        // handling of the caller's own command.  From here on the
        // command may have reached the authority, so `dispatched` decides
        // how a lost reply is reported.
        match tokio::time::timeout(REDIS_OPERATION_TIMEOUT, operation(&mut connection, &run_id))
            .await
        {
            Ok(Ok(value)) => {
                self.group.binding.contact();
                Ok(value)
            }
            // A reply that missed the deadline is a timeout however it was
            // observed.  redis-rs's own response timeout (set to the same
            // bound, and surfacing as an I/O `TimedOut`) and this outer
            // deadline race for the same instant; which one wins used to
            // decide whether the lane kept a connection that still owes the
            // stalled reply (M7-C113).  Both now release it, so the next
            // command re-verifies the primary on a fresh connection instead
            // of queueing its reply behind the stalled one, and both report
            // the typed timeout rather than, for an owner write, a lost
            // connection.  The command itself is never replayed.
            Ok(Err(error)) if error.is_timeout() => {
                self.release_lost(connection_generation).await;
                Err(dispatched.timeout())
            }
            Ok(Err(error)) => {
                let lost = lane_lost(&error);
                if lost {
                    // Release the dead connection and tell sibling lanes to
                    // probe theirs.  This command stays failed and is never
                    // replayed.
                    self.release_lost(connection_generation).await;
                }
                Err(dispatched.classify(error, lost))
            }
            Err(_) => {
                self.release_lost(connection_generation).await;
                Err(dispatched.timeout())
            }
        }
    }

    /// Hand out a handle to this lane's verified physical connection.
    ///
    /// The caller has [`REDIS_OPERATION_TIMEOUT`] in total, from its arrival:
    /// for the lane actor's answers, the sibling-loss probe and waiting on a
    /// reconnect in flight.  The actor only does bookkeeping -- the probe
    /// (M6-C95) and the reconnect (M6-C74) run away from it -- so a caller
    /// never queues behind another caller's probe; concurrent callers each
    /// probe the same multiplexed connection under their own deadline.  A
    /// probe that exceeds it leaves the lane state as it found it, and a
    /// reconnect that exceeds it keeps running for the next command; a
    /// caller's command that times out releases the connection (see
    /// [`Self::execute`]).
    async fn admit(&self) -> Result<Admitted, CatalogError> {
        let deadline = tokio::time::Instant::now() + REDIS_OPERATION_TIMEOUT;
        let timed_out = |_| CatalogError::Database(redis_timeout());
        let mut probed = None;
        loop {
            let verified = tokio::time::timeout_at(deadline, self.verify(probed.take()))
                .await
                .map_err(timed_out)??;
            let mut outcome = match verified {
                Verified::Ready(admitted) => return Ok(admitted),
                Verified::Probe {
                    mut connection,
                    connection_generation,
                    loss_generation,
                } => {
                    // The lane actor is not involved while the probe waits
                    // for the authority's reply.
                    let passed = match tokio::time::timeout_at(
                        deadline,
                        redis::cmd("PING").query_async::<String>(&mut connection),
                    )
                    .await
                    .map_err(timed_out)?
                    {
                        Ok(_) => true,
                        Err(error) if lane_lost(&error) => false,
                        Err(error) => return Err(CatalogError::Database(error)),
                    };
                    probed = Some(ProbeReport {
                        connection_generation,
                        loss_generation,
                        passed,
                    });
                    continue;
                }
                Verified::Reconnecting(outcome) => outcome,
            };
            // The lane actor keeps answering while the reconnect connects.
            let finished: Result<(), CatalogError> =
                match tokio::time::timeout_at(deadline, outcome.wait_for(Option::is_some)).await {
                    Err(elapsed) => Err(timed_out(elapsed)),
                    // The attempt ended without an outcome: the lane is gone.
                    Ok(Err(_)) => Err(actor_gone("Redis authority lane reconnect abandoned")),
                    Ok(Ok(outcome)) => outcome.clone().unwrap_or(Ok(())),
                };
            finished?;
            // The reconnect installed its connection: verify again, which
            // normally hands it out at once.
        }
    }

    /// Ask the lane actor what this caller does next, reporting the probe it
    /// just made, if any.
    async fn verify(&self, probed: Option<ProbeReport>) -> Result<Verified, CatalogError> {
        const GONE: &str = "Redis authority lane is not running";
        let (reply, verified) = oneshot::channel();
        self.commands
            .send(LaneCommand::Admit { probed, reply })
            .await
            .map_err(|_| actor_gone(GONE))?;
        verified.await.map_err(|_| actor_gone(GONE))
    }

    /// Release the connection a caller observed a transport loss on, unless a
    /// sibling caller already released or replaced it.  Only the first
    /// observer of one loss advances the group loss generation.  Returns once
    /// the lane has recorded it.
    async fn release_lost(&self, connection_generation: u64) {
        let (done, released) = oneshot::channel();
        if self
            .commands
            .send(LaneCommand::ReleaseLost {
                connection_generation,
                done,
            })
            .await
            .is_ok()
        {
            let _ = released.await;
        }
    }
}

/// Open and verify one replacement connection, and decide whether the
/// catalog may be bound to the run it reached.
async fn reconnect(
    client: &redis::Client,
    config: &redis::AsyncConnectionConfig,
    group: &LaneGroup,
) -> Result<(MultiplexedConnection, String), CatalogError> {
    let (mut connection, run_id) = open_verified_connection_with(client, config)
        .await
        .map_err(CatalogConnectionError::into_catalog_error)?;
    // A different run is adopted only when the namespace proves it may
    // (see the module documentation); until then no caller command runs
    // on this connection.
    tokio::time::timeout(
        REDIS_OPERATION_TIMEOUT,
        group.binding.rebind(&mut connection, &run_id),
    )
    .await
    .map_err(|_| CatalogError::Database(redis_timeout()))??;
    Ok((connection, run_id))
}

/// How a failure observed after the command was handed to the connection is
/// reported.  Reads and non-owner writes keep the definite `Database` shape;
/// owner-affecting writes report a lost reply as the typed unknown outcome.
#[derive(Clone, Copy)]
enum DispatchedFailure {
    Definite,
    Unknown,
}

impl DispatchedFailure {
    fn classify(self, error: RedisError, lost: bool) -> CatalogError {
        match self {
            Self::Definite => CatalogError::Database(error),
            Self::Unknown if lost => {
                CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ConnectionLost)
            }
            Self::Unknown if error.is_timeout() => {
                CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout)
            }
            // An actual authority reply (server error, parse failure) is a
            // definite outcome even for an owner write.
            Self::Unknown => CatalogError::Database(error),
        }
    }

    fn timeout(self) -> CatalogError {
        match self {
            Self::Definite => CatalogError::Database(redis_timeout()),
            Self::Unknown => CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout),
        }
    }
}

/// Whether a command failure means the physical connection is gone.  Server
/// replies and parse failures keep the connection; a reply timeout is
/// classified before this is consulted and releases it.
fn lane_lost(error: &RedisError) -> bool {
    error.is_io_error() || error.is_connection_dropped()
}

#[cfg(test)]
mod tests {
    use super::super::open_verified_connection;
    use super::*;
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinSet,
    };

    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    const MAX_REQUEST_BYTES: usize = 16 * 1024;
    const MAX_PENDING_REPLIES: usize = 1_024;
    /// Concurrent callers on one lane in the queueing regression.  With the
    /// per-reply delay below, serializing them takes three seconds while any
    /// single reply arrives well inside the two-second operation deadline.
    const QUEUED_CALLERS: usize = 20;
    const QUEUED_REPLY_DELAY: Duration = Duration::from_millis(150);
    /// A stalled authority: one reply takes longer than the operation
    /// deadline even with no other caller queued.
    const STALLED_REPLY_DELAY: Duration = Duration::from_millis(2_600);

    /// A bounded RESP2 authority double: answers the redis-rs handshake,
    /// `PING`, and `INFO` with a configurable `run_id`, and can sever any
    /// accepted connection while keeping its listener.
    struct FakeAuthority {
        port: u16,
        /// The `run_id` every later `INFO` reply reports.
        run_id: watch::Sender<String>,
        /// Delay applied to every reply, measured from the command's arrival.
        /// Replies stay in command order but are delayed concurrently, like a
        /// network path that adds latency to each reply rather than a server
        /// that spends that long on each command.
        reply_delay_ms: Arc<AtomicU64>,
        /// Connections accepted so far.
        accepted: Arc<AtomicUsize>,
        /// Sever requests for the accept task, which owns the connections.
        severs: mpsc::Sender<Sever>,
        active: Arc<AtomicUsize>,
        shutdown: Option<oneshot::Sender<()>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    /// Which accepted connections to sever.  The reply says whether the
    /// request named connections that could be severed.
    enum Sever {
        One(usize, oneshot::Sender<bool>),
        All(oneshot::Sender<bool>),
    }

    impl FakeAuthority {
        async fn start(run_id: &str) -> Self {
            Self::start_with_reply_delay(run_id, Duration::ZERO).await
        }

        async fn start_with_reply_delay(run_id: &str, reply_delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake authority");
            let port = listener
                .local_addr()
                .expect("fake authority address")
                .port();
            let (run_id, served_run_id) = watch::channel(run_id.to_owned());
            let reply_delay_ms = Arc::new(AtomicU64::new(
                u64::try_from(reply_delay.as_millis()).expect("bounded reply delay"),
            ));
            let accepted = Arc::new(AtomicUsize::new(0));
            let (severs, sever_requests) = mpsc::channel(8);
            let active = Arc::new(AtomicUsize::new(0));
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(run_fake_authority(
                listener,
                served_run_id,
                Arc::clone(&reply_delay_ms),
                Arc::clone(&accepted),
                sever_requests,
                Arc::clone(&active),
                shutdown_rx,
            ));
            Self {
                port,
                run_id,
                reply_delay_ms,
                accepted,
                severs,
                active,
                shutdown: Some(shutdown_tx),
                task: Some(task),
            }
        }

        fn set_reply_delay(&self, reply_delay: Duration) {
            self.reply_delay_ms.store(
                u64::try_from(reply_delay.as_millis()).expect("bounded reply delay"),
                Ordering::Release,
            );
        }

        fn url(&self) -> String {
            format!("redis://127.0.0.1:{}/", self.port)
        }

        /// Connections accepted so far, in accept order.
        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::Acquire)
        }

        async fn set_run_id(&self, run_id: &str) {
            self.run_id.send_replace(run_id.to_owned());
        }

        /// Sever the connection with this accept index and wait until the
        /// server has dropped it.  The listener keeps accepting.
        async fn sever(&self, index: usize) {
            let before = self.active.load(Ordering::Acquire);
            let (reply, severed) = oneshot::channel();
            self.severs
                .send(Sever::One(index, reply))
                .await
                .expect("fake authority is running");
            assert!(
                severed.await.expect("fake authority answered"),
                "connection index was accepted, not yet severed, and its task is live"
            );
            self.wait_active(before - 1).await;
        }

        /// Sever every live connection and wait until all are dropped.
        async fn sever_all(&self) {
            let (reply, severed) = oneshot::channel();
            self.severs
                .send(Sever::All(reply))
                .await
                .expect("fake authority is running");
            severed.await.expect("fake authority answered");
            self.wait_active(0).await;
        }

        async fn wait_active(&self, expected: usize) {
            let deadline = tokio::time::Instant::now() + TEST_DEADLINE;
            while self.active.load(Ordering::Acquire) != expected {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "fake authority did not sever its connections"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn shutdown(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(task) = self.task.take() {
                tokio::time::timeout(TEST_DEADLINE, task)
                    .await
                    .expect("fake authority shutdown deadline")
                    .expect("fake authority task");
            }
        }
    }

    async fn run_fake_authority(
        listener: TcpListener,
        run_id: watch::Receiver<String>,
        reply_delay_ms: Arc<AtomicU64>,
        accepted: Arc<AtomicUsize>,
        mut sever_requests: mpsc::Receiver<Sever>,
        active: Arc<AtomicUsize>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        let mut connections = JoinSet::new();
        // One sever handle per accepted connection, in accept order.
        let mut severs: Vec<Option<oneshot::Sender<()>>> = Vec::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    return;
                }
                accepted_stream = listener.accept() => {
                    let Ok((stream, _)) = accepted_stream else { return; };
                    let (sever_tx, sever_rx) = oneshot::channel();
                    active.fetch_add(1, Ordering::AcqRel);
                    severs.push(Some(sever_tx));
                    accepted.store(severs.len(), Ordering::Release);
                    connections.spawn(serve_fake_connection(
                        stream,
                        run_id.clone(),
                        Arc::clone(&reply_delay_ms),
                        sever_rx,
                        Arc::clone(&active),
                    ));
                }
                Some(request) = sever_requests.recv() => match request {
                    Sever::One(index, reply) => {
                        let severed = severs
                            .get_mut(index)
                            .and_then(Option::take)
                            .is_some_and(|sever| sever.send(()).is_ok());
                        let _ = reply.send(severed);
                    }
                    Sever::All(reply) => {
                        let mut severed = false;
                        for sever in severs.iter_mut().filter_map(Option::take) {
                            severed |= sever.send(()).is_ok();
                        }
                        let _ = reply.send(severed);
                    }
                },
                Some(_) = connections.join_next() => {}
            }
        }
    }

    async fn serve_fake_connection(
        mut stream: TcpStream,
        run_id: watch::Receiver<String>,
        reply_delay_ms: Arc<AtomicU64>,
        mut sever: oneshot::Receiver<()>,
        active: Arc<AtomicUsize>,
    ) {
        let mut pending = Vec::new();
        let mut buffer = [0_u8; 1024];
        // Replies due in command order; each is written once its own delay,
        // counted from the command's arrival, has elapsed.
        let mut due: VecDeque<(tokio::time::Instant, Vec<u8>)> = VecDeque::new();
        loop {
            let next_due = due.front().map(|(at, _)| *at);
            tokio::select! {
                // Dropping the stream is the injected transport loss.
                _ = &mut sever => break,
                read = stream.read(&mut buffer) => {
                    let read = match read {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    pending.extend_from_slice(&buffer[..read]);
                    if pending.len() > MAX_REQUEST_BYTES {
                        break;
                    }
                    let delay = Duration::from_millis(reply_delay_ms.load(Ordering::Acquire));
                    let arrived = tokio::time::Instant::now();
                    while let Some((command, consumed)) = parse_command(&pending) {
                        pending.drain(..consumed);
                        let reply = match command.as_str() {
                            "CLIENT" => b"+OK\r\n".to_vec(),
                            "PING" => b"+PONG\r\n".to_vec(),
                            "INFO" => {
                                let body =
                                    format!("# Server\r\nrun_id:{}\r\n", *run_id.borrow());
                                format!("${}\r\n{body}\r\n", body.len()).into_bytes()
                            }
                            _ => b"-ERR unsupported fake authority command\r\n".to_vec(),
                        };
                        due.push_back((arrived + delay, reply));
                    }
                    if due.len() > MAX_PENDING_REPLIES {
                        break;
                    }
                }
                _ = async {
                    match next_due {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let Some((_, reply)) = due.pop_front() else { continue };
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            }
        }
        active.fetch_sub(1, Ordering::AcqRel);
    }

    /// Parse one complete RESP2 command array, returning its upper-cased
    /// name and the consumed byte count, or `None` while incomplete.
    fn parse_command(bytes: &[u8]) -> Option<(String, usize)> {
        let (count_line, mut offset) = resp_line(bytes, 0)?;
        let count: usize = std::str::from_utf8(count_line.strip_prefix(b"*")?)
            .ok()?
            .parse()
            .ok()?;
        let mut name = None;
        for index in 0..count {
            let (length_line, next) = resp_line(bytes, offset)?;
            let length: usize = std::str::from_utf8(length_line.strip_prefix(b"$")?)
                .ok()?
                .parse()
                .ok()?;
            let end = next.checked_add(length)?;
            if bytes.len() < end.checked_add(2)? {
                return None;
            }
            if index == 0 {
                name = Some(String::from_utf8_lossy(&bytes[next..end]).to_ascii_uppercase());
            }
            offset = end + 2;
        }
        Some((name?, offset))
    }

    fn resp_line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
        let rest = bytes.get(start..)?;
        let end = rest.windows(2).position(|window| window == b"\r\n")?;
        Some((&rest[..end], start + end + 2))
    }

    async fn verified_lane(
        client: &redis::Client,
        expected_run_id: &str,
        group: &Arc<LaneGroup>,
    ) -> AuthorityLane {
        let (connection, run_id) =
            tokio::time::timeout(TEST_DEADLINE, open_verified_connection(client))
                .await
                .expect("bounded startup connection")
                .expect("verified startup connection");
        assert_eq!(run_id, expected_run_id);
        AuthorityLane::new(client.clone(), connection, run_id, Arc::clone(group))
    }

    /// A lane whose startup connection has no redis-rs response timeout, so
    /// a stalled reply can only be observed by the lane's own outer deadline
    /// in [`AuthorityLane::execute`].  With the production configuration the
    /// two deadlines are equal and which one fires is decided by timer ticks
    /// and scheduling (M7-C113, M5-C17); this makes the outer one certain.
    /// The lane's own reconnects still use the production configuration.
    async fn lane_with_outer_deadline_only(
        client: &redis::Client,
        run_id: &str,
        group: &Arc<LaneGroup>,
    ) -> AuthorityLane {
        let config = redis::AsyncConnectionConfig::new().set_response_timeout(None);
        let connection = tokio::time::timeout(
            TEST_DEADLINE,
            client.get_multiplexed_async_connection_with_config(&config),
        )
        .await
        .expect("bounded startup connection")
        .expect("startup connection without a response timeout");
        AuthorityLane::new(
            client.clone(),
            connection,
            run_id.to_owned(),
            Arc::clone(group),
        )
    }

    /// Queue [`QUEUED_CALLERS`] pings behind a reply that takes
    /// [`QUEUED_REPLY_DELAY`] and require that every one succeeds, well
    /// inside the authority deadline, on the one connection the lane holds.
    ///
    /// Run twice by the test below: on the outer-deadline-only startup
    /// connection, and again on the lane's own reconnected connection, which
    /// carries the **production** redis-rs response timeout. The second run is
    /// the review follow-up to M5-C17: the rewrite had moved the whole
    /// queued-caller phase onto a connection with no redis-rs timeout, so the
    /// production configuration's queueing was no longer measured.
    async fn assert_queued_callers_share_one_connection(
        server: &FakeAuthority,
        lane: &Arc<AuthorityLane>,
        context: &str,
    ) {
        let accepted = server.accepted();
        server.set_reply_delay(QUEUED_REPLY_DELAY);
        let started = tokio::time::Instant::now();
        let mut callers = JoinSet::new();
        for _ in 0..QUEUED_CALLERS {
            let lane = Arc::clone(lane);
            callers.spawn(async move { ping(&lane).await });
        }
        let mut replies = Vec::with_capacity(QUEUED_CALLERS);
        while let Some(joined) = callers.join_next().await {
            replies.push(joined.expect("queued caller task"));
        }
        let elapsed = started.elapsed();
        let failures: Vec<String> = replies
            .iter()
            .filter_map(|reply| reply.as_ref().err().map(ToString::to_string))
            .collect();
        assert!(
            failures.is_empty(),
            "{context}: {} of {QUEUED_CALLERS} queued callers failed after {elapsed:?} \
             although every reply took {QUEUED_REPLY_DELAY:?}: {failures:?}",
            failures.len()
        );
        assert!(
            elapsed < REDIS_OPERATION_TIMEOUT,
            "{context}: queued callers took {elapsed:?}; the lane serialized them behind \
             each other"
        );
        assert_eq!(
            server.accepted(),
            accepted,
            "{context}: queueing must not open connections"
        );
        server.set_reply_delay(Duration::ZERO);
    }

    /// Drive one stalled command and require that it is reported as a
    /// timeout, is never retried or reconnected in place, and *releases* the
    /// lane: the release is read from the lane itself (the group loss
    /// generation it advances and the empty connection slot), not inferred
    /// from how many connections the fake authority later accepts.
    async fn assert_stall_times_out_and_releases(
        server: &FakeAuthority,
        lane: &AuthorityLane,
        group: &LaneGroup,
        context: &str,
    ) {
        let accepted = server.accepted();
        let generation = group.loss_generation.load(Ordering::Acquire);
        server.set_reply_delay(STALLED_REPLY_DELAY);
        let stalled_started = tokio::time::Instant::now();
        match ping(lane).await {
            Err(CatalogError::Database(error)) => assert!(
                timed_out(&error) && !error.is_connection_dropped(),
                "{context}: stalled authority reported {error} instead of a timeout"
            ),
            other => panic!("{context}: stalled authority reported {other:?} instead of a timeout"),
        }
        assert!(
            stalled_started.elapsed() >= REDIS_OPERATION_TIMEOUT,
            "{context}: the authority deadline fired before the documented bound"
        );
        assert_eq!(
            group.loss_generation.load(Ordering::Acquire),
            generation + 1,
            "{context}: the timed-out command must release the lane's connection"
        );
        assert!(
            !lane.inspect().await.connected,
            "{context}: the lane kept a connection that still owes the stalled reply"
        );
        assert_eq!(
            server.accepted(),
            accepted,
            "{context}: a timeout never reconnects in place"
        );
        server.set_reply_delay(Duration::ZERO);
        assert_eq!(
            ping(lane).await.unwrap_or_else(|error| panic!(
                "{context}: the command after a timeout must re-verify the primary: {error}"
            )),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            accepted + 1,
            "{context}: exactly one fresh connection replaces the released one"
        );
    }

    async fn ping(lane: &AuthorityLane) -> Result<String, CatalogError> {
        tokio::time::timeout(TEST_DEADLINE, lane.query::<String>(&redis::cmd("PING")))
            .await
            .expect("bounded lane command")
    }

    fn assert_lost(result: Result<String, CatalogError>, context: &str) {
        match result {
            Err(CatalogError::Database(error)) if lane_lost(&error) => {}
            Err(other) => panic!("{context}: reported {other} instead of a transport loss"),
            Ok(reply) => panic!("{context}: succeeded with {reply} on a severed connection"),
        }
    }

    #[tokio::test]
    async fn severed_lane_fails_once_then_reconnects_only_to_the_same_primary() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = verified_lane(&client, "lane-run-a", &group).await;
        assert_eq!(ping(&lane).await.expect("healthy lane"), "PONG");
        assert_eq!(server.accepted(), 1);

        server.sever_all().await;
        assert_lost(ping(&lane).await, "severed lane");
        assert_eq!(
            server.accepted(),
            1,
            "the failed command must neither retry nor reconnect"
        );

        server.set_run_id("lane-run-b").await;
        for _ in 0..2 {
            let refused = ping(&lane)
                .await
                .expect_err("a changed primary identity must be refused");
            assert!(
                matches!(refused, CatalogError::Conflict(RUN_ID_CONFLICT)),
                "changed primary reported {refused}"
            );
        }
        assert_eq!(
            server.accepted(),
            3,
            "each refused reconnect verifies identity on a fresh connection"
        );

        server.set_run_id("lane-run-a").await;
        assert_eq!(ping(&lane).await.expect("same primary reconnects"), "PONG");
        assert_eq!(
            ping(&lane).await.expect("reconnected lane is reused"),
            "PONG"
        );
        assert_eq!(server.accepted(), 4);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn sibling_lanes_probe_after_a_loss_without_failing_their_callers() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let discovering = verified_lane(&client, "lane-run-a", &group).await;
        let severed_sibling = verified_lane(&client, "lane-run-a", &group).await;
        let live_sibling = verified_lane(&client, "lane-run-a", &group).await;
        assert_eq!(server.accepted(), 3);

        // Connections 0 and 1 are lost by the same event; connection 2 stays.
        server.sever(0).await;
        server.sever(1).await;
        assert_lost(ping(&discovering).await, "discovering lane");
        assert_eq!(server.accepted(), 3, "discovery never reconnects in place");

        assert_eq!(
            ping(&severed_sibling)
                .await
                .expect("a severed sibling reconnects before its caller's command"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            4,
            "the severed sibling opened one connection"
        );
        assert_eq!(
            ping(&live_sibling)
                .await
                .expect("a live sibling passes its probe and keeps its connection"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            4,
            "the live sibling opened no connection"
        );

        assert_eq!(
            ping(&discovering)
                .await
                .expect("the discovering lane reconnects on its next command"),
            "PONG"
        );
        assert_eq!(server.accepted(), 5);
        for lane in [&discovering, &severed_sibling, &live_sibling] {
            assert_eq!(ping(lane).await.expect("verified lanes are reused"), "PONG");
        }
        assert_eq!(server.accepted(), 5, "no further probe reconnects");
        server.shutdown().await;
    }

    fn timed_out(error: &RedisError) -> bool {
        error.is_timeout()
    }

    /// M7-C32 regression: callers queued on one lane must be measured
    /// against the authority's reply, not against each other.  Twenty
    /// callers whose replies each take 150 ms would take three seconds if the
    /// lane served them one at a time, so the last of them would report a
    /// two-second "authority timeout" that Redis never caused.  A genuinely
    /// stalled reply and a severed connection must still fail closed, with
    /// distinguishable transport classes and no reconnect in place.
    ///
    /// M5-C17: the stalled reply is driven twice.  First on a startup
    /// connection without a redis-rs response timeout, so the lane's outer
    /// deadline is certain to be the one that fires -- the path that kept the
    /// connection before f3aaba9 and failed this test only when load let the
    /// outer timer win a tick race.  Then on the lane's own reconnected
    /// connection, where the production configuration makes the two
    /// deadlines equal and either may fire.  Each stall must release the lane.
    #[tokio::test]
    async fn queued_callers_are_measured_against_the_authority_not_the_queue() {
        let server = FakeAuthority::start_with_reply_delay("lane-run-a", QUEUED_REPLY_DELAY).await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(lane_with_outer_deadline_only(&client, "lane-run-a", &group).await);
        assert_eq!(server.accepted(), 1);

        assert_queued_callers_share_one_connection(
            &server,
            &lane,
            "outer-deadline-only connection",
        )
        .await;

        // A reply that genuinely exceeds the deadline is a timeout, reported
        // as such rather than as a severed connection.  The stalled command
        // is never retried; the lane releases the connection so the next
        // command re-verifies the primary before it is trusted again.
        assert_stall_times_out_and_releases(&server, &lane, &group, "outer deadline").await;
        assert_eq!(server.accepted(), 2);
        assert_stall_times_out_and_releases(&server, &lane, &group, "production deadlines").await;
        assert_eq!(server.accepted(), 3);
        // The lane now holds its own reconnected connection, which carries the
        // production redis-rs response timeout: queueing is measured there too.
        assert_queued_callers_share_one_connection(&server, &lane, "production connection").await;
        assert_eq!(server.accepted(), 3);

        // A severed connection is a transport loss, never a timeout, and the
        // discovering command fails closed exactly once.
        server.sever_all().await;
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                lane_lost(&error) && !timed_out(&error),
                "severed lane reported {error} instead of a transport loss"
            ),
            other => panic!("severed lane reported {other:?} instead of a transport loss"),
        }
        assert_eq!(
            server.accepted(),
            3,
            "the discovering command never reconnects"
        );
        assert_eq!(
            ping(&lane).await.expect("the next command reconnects"),
            "PONG"
        );
        assert_eq!(server.accepted(), 4);
        server.shutdown().await;
    }

    /// Callers that observe the same loss concurrently release the lane once
    /// and advance the group loss generation once; a sibling that has already
    /// reconnected is never released by a late observer.
    #[tokio::test]
    async fn concurrent_loss_observers_release_the_lane_once() {
        let server = FakeAuthority::start_with_reply_delay("lane-run-a", QUEUED_REPLY_DELAY).await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(verified_lane(&client, "lane-run-a", &group).await);

        let mut callers = JoinSet::new();
        for _ in 0..QUEUED_CALLERS {
            let lane = Arc::clone(&lane);
            callers.spawn(async move { ping(&lane).await });
        }
        // Every caller is in flight behind the delayed replies when the
        // connection is severed, so all of them observe the same loss.
        tokio::time::sleep(QUEUED_REPLY_DELAY / 3).await;
        server.sever_all().await;
        while let Some(joined) = callers.join_next().await {
            assert_lost(joined.expect("queued caller task"), "concurrent observer");
        }
        assert_eq!(
            group.loss_generation.load(Ordering::Acquire),
            1,
            "one loss event advances the group generation once"
        );
        assert_eq!(server.accepted(), 1, "no observer reconnects in place");
        assert_eq!(
            ping(&lane).await.expect("the next command reconnects once"),
            "PONG"
        );
        assert_eq!(server.accepted(), 2);
        server.shutdown().await;
    }

    fn attempt(loss_generation: u64) -> ReconnectAttempt<&'static str> {
        ReconnectAttempt {
            task: tokio::spawn(std::future::pending()),
            outcome: watch::channel(None).0,
            loss_generation,
        }
    }

    fn connected(verified_generation: u64) -> LaneState<&'static str> {
        LaneState {
            phase: LanePhase::Connected {
                connection: "startup",
                verified_run_id: "run-a".to_owned(),
                verified_generation,
            },
            connection_generation: 0,
        }
    }

    /// Every lane event against every lane phase: the legal transitions do
    /// exactly what the lane relies on, and every other pair is refused and
    /// changes nothing.
    #[tokio::test]
    async fn lane_phase_allows_exactly_its_transition_table() {
        // Connected -> Connected: a passed probe records its generation and
        // keeps the connection and its generation.
        let mut lane = connected(3);
        assert!(matches!(
            lane.transition(LaneEvent::ProbePassed { loss_generation: 5 }),
            Ok(None)
        ));
        assert!(matches!(
            lane.phase,
            LanePhase::Connected {
                connection: "startup",
                verified_generation: 5,
                ..
            }
        ));
        assert_eq!(lane.connection_generation, 0);
        assert!(lane.holds(0));

        // Connected refuses every reconnect event.
        for event in [
            LaneEvent::ReconnectStarted(attempt(0)),
            LaneEvent::ReconnectSucceeded {
                connection: "other",
                run_id: "run-b".to_owned(),
            },
            LaneEvent::ReconnectFailed,
        ] {
            assert!(matches!(lane.transition(event), Err(IllegalTransition)));
            assert!(matches!(
                lane.phase,
                LanePhase::Connected {
                    connection: "startup",
                    verified_generation: 5,
                    ..
                }
            ));
            assert_eq!(lane.connection_generation, 0);
        }

        // Connected -> Disconnected: the connection slot changed.
        assert!(matches!(
            lane.transition(LaneEvent::ConnectionLost),
            Ok(None)
        ));
        assert!(matches!(lane.phase, LanePhase::Disconnected));
        assert_eq!(lane.connection_generation, 1);
        assert!(!lane.holds(0) && !lane.holds(1));

        // Disconnected refuses everything but the start of a reconnect.
        for event in [
            LaneEvent::ConnectionLost,
            LaneEvent::ProbePassed { loss_generation: 9 },
            LaneEvent::ReconnectSucceeded {
                connection: "other",
                run_id: "run-b".to_owned(),
            },
            LaneEvent::ReconnectFailed,
        ] {
            assert!(matches!(lane.transition(event), Err(IllegalTransition)));
            assert!(matches!(lane.phase, LanePhase::Disconnected));
            assert_eq!(lane.connection_generation, 1);
        }

        // Disconnected -> Reconnecting -> Disconnected: a failed attempt is
        // handed back for its outcome and installs nothing.
        assert!(matches!(
            lane.transition(LaneEvent::ReconnectStarted(attempt(7))),
            Ok(None)
        ));
        assert!(matches!(lane.phase, LanePhase::Reconnecting(_)));
        // Reconnecting refuses a second attempt, a loss and a probe result.
        for event in [
            LaneEvent::ReconnectStarted(attempt(8)),
            LaneEvent::ConnectionLost,
            LaneEvent::ProbePassed { loss_generation: 9 },
        ] {
            assert!(matches!(lane.transition(event), Err(IllegalTransition)));
            assert!(matches!(
                &lane.phase,
                LanePhase::Reconnecting(current) if current.loss_generation == 7
            ));
            assert_eq!(lane.connection_generation, 1);
        }
        let ended = lane
            .transition(LaneEvent::ReconnectFailed)
            .expect("a reconnect in flight may fail")
            .expect("the failed attempt is handed back");
        assert_eq!(ended.loss_generation, 7);
        assert!(matches!(lane.phase, LanePhase::Disconnected));
        assert_eq!(lane.connection_generation, 1);

        // Disconnected -> Reconnecting -> Connected: the connection is
        // verified against the generation current when the attempt started,
        // and the slot changed once more.
        lane.transition(LaneEvent::ReconnectStarted(attempt(11)))
            .expect("a disconnected lane may reconnect");
        let ended = lane
            .transition(LaneEvent::ReconnectSucceeded {
                connection: "replacement",
                run_id: "run-b".to_owned(),
            })
            .expect("a reconnect in flight may succeed")
            .expect("the finished attempt is handed back");
        assert_eq!(ended.loss_generation, 11);
        assert!(matches!(
            &lane.phase,
            LanePhase::Connected {
                connection: "replacement",
                verified_run_id,
                verified_generation: 11,
            } if verified_run_id == "run-b"
        ));
        assert_eq!(lane.connection_generation, 2);
        assert!(lane.holds(2) && !lane.holds(1));
    }

    fn scope(incarnation: &str) -> RebindScope {
        RebindScope {
            incarnation: incarnation.to_owned(),
            incarnation_key: "incarnation-key".to_owned(),
            run_key: "run-key".to_owned(),
            continuity_key: "continuity-key".to_owned(),
        }
    }

    /// Every binding event against every binding mode.
    #[test]
    fn binding_mode_allows_exactly_its_transition_table() {
        let interval = Duration::from_secs(5);
        let events = || {
            [
                BindingEvent::ScopeConfigured(scope("other")),
                BindingEvent::WitnessEnabled(interval),
                BindingEvent::WitnessDisabled,
            ]
        };

        // Pinned: only a scope is accepted; a witness needs one.
        let mut mode = BindingMode::Pinned;
        for event in events().into_iter().skip(1) {
            assert_eq!(mode.transition(event), Err(IllegalTransition));
            assert!(matches!(mode, BindingMode::Pinned));
            assert!(mode.scope().is_none() && mode.witness().is_none());
        }
        assert_eq!(
            mode.transition(BindingEvent::ScopeConfigured(scope("first"))),
            Ok(())
        );

        // Rebindable: the scope is set once; there is no witness to stop.
        for event in [
            BindingEvent::ScopeConfigured(scope("other")),
            BindingEvent::WitnessDisabled,
        ] {
            assert_eq!(mode.transition(event), Err(IllegalTransition));
            assert!(matches!(mode, BindingMode::Rebindable(_)));
            assert_eq!(mode.scope().expect("scope").incarnation, "first");
            assert!(mode.witness().is_none());
        }
        assert_eq!(
            mode.transition(BindingEvent::WitnessEnabled(interval)),
            Ok(())
        );
        let witness = mode.witness().expect("a fresh witness");
        assert!(witness.candidates.is_empty() && witness.last_ack_ms.is_none());
        assert_eq!(witness.interval, interval);

        // Witnessed: enabling again keeps the witness and its tokens.
        let witness = mode.witness_mut().expect("witness");
        witness.candidates.push_back("token".to_owned());
        witness.last_ack_ms = Some(42);
        for event in [
            BindingEvent::ScopeConfigured(scope("other")),
            BindingEvent::WitnessEnabled(Duration::from_secs(1)),
        ] {
            assert_eq!(mode.transition(event), Err(IllegalTransition));
            let witness = mode.witness().expect("the witness is kept");
            assert_eq!(witness.candidates, ["token"]);
            assert_eq!(witness.last_ack_ms, Some(42));
            assert_eq!(witness.interval, interval);
            assert_eq!(mode.scope().expect("scope").incarnation, "first");
        }

        // Witnessed -> Rebindable keeps the scope; a later witness is fresh.
        assert_eq!(mode.transition(BindingEvent::WitnessDisabled), Ok(()));
        assert!(matches!(mode, BindingMode::Rebindable(_)));
        assert_eq!(mode.scope().expect("scope").incarnation, "first");
        assert_eq!(
            mode.transition(BindingEvent::WitnessEnabled(interval)),
            Ok(())
        );
        let witness = mode.witness().expect("a fresh witness");
        assert!(witness.candidates.is_empty() && witness.last_ack_ms.is_none());
    }

    /// A request to stop the witness that arrives after an enable was queued
    /// but before the actor reached it is the last request, so the witness
    /// ends up off.
    #[tokio::test]
    async fn a_witness_stop_after_a_queued_enable_wins() {
        let binding = RunBinding::default();
        binding.initialize("run-a");
        assert!(binding.set_scope(scope("first")).is_ok());

        // Queue the enable: on this single-threaded runtime the actor cannot
        // run until the test yields, so the command stays queued.
        let mut enable = std::pin::pin!(binding.enable_witness(Duration::from_secs(5)));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(enable.as_mut().poll(&mut context).is_pending());
        binding.disable_witness();
        enable.await;
        assert!(!binding.witness_enabled().await, "the stop came last");

        // An enable requested after the stop is honoured.
        binding.enable_witness(Duration::from_secs(5)).await;
        assert!(binding.witness_enabled().await);
    }

    /// The binding's callers that cannot wait -- configuring the scope and
    /// stopping the witness -- are applied before the binding's next
    /// command, in the order the old single critical section gave.
    #[tokio::test]
    async fn binding_applies_scope_and_witness_stops_before_its_next_command() {
        let binding = RunBinding::default();
        binding.initialize("run-a");
        binding.initialize("run-b");
        assert_eq!(binding.run_id(), "run-a", "the first lane's run is kept");
        assert_eq!(binding.rebinds(), 0);

        // Without a scope a witness cannot be kept and no other run is
        // accepted.
        binding.enable_witness(Duration::from_secs(5)).await;
        assert!(!binding.witness_enabled().await);
        assert!(matches!(
            binding.ask(|state| state.plan("run-b")).await,
            Some(Err(CatalogError::Conflict(RUN_ID_CONFLICT)))
        ));
        assert!(matches!(
            binding.ask(|state| state.plan("run-a")).await,
            Some(Ok(RebindPlan::AlreadyBound))
        ));

        assert!(!binding.has_scope());
        assert!(binding.set_scope(scope("first")).is_ok());
        // The same scope again changes nothing; a different one is refused
        // and the first is kept (asserted below through the plan).
        assert!(binding.set_scope(scope("first")).is_ok());
        assert!(matches!(
            binding.set_scope(scope("second")),
            Err(CatalogError::Conflict(REBIND_SCOPE_CONFLICT))
        ));
        assert!(binding.has_scope());
        binding.enable_witness(Duration::from_secs(5)).await;
        assert!(binding.witness_enabled().await);

        // A token dispatched and acknowledged is the candidate a re-binding
        // offers, under the first scope.
        binding.continuity_dispatching("token-1").await;
        binding.continuity_dispatching("token-2").await;
        binding.continuity_not_written("token-2").await;
        binding.continuity_acknowledged("token-1").await;
        match binding.ask(|state| state.plan("run-b")).await {
            Some(Ok(RebindPlan::Decide {
                incarnation,
                candidates,
                ..
            })) => {
                assert_eq!(incarnation, "first");
                assert_eq!(candidates, Some(vec!["token-1".to_owned()]));
            }
            _ => panic!("a fresh witness offers its acknowledged token"),
        }

        // Stopping the witness cannot wait, and still precedes the next
        // command: the token is no longer offered, and a witness enabled
        // afterwards starts without it.
        binding.disable_witness();
        assert!(!binding.witness_enabled().await);
        binding.continuity_acknowledged("token-3").await;
        binding.disable_witness();
        binding.enable_witness(Duration::from_secs(5)).await;
        assert!(binding.witness_enabled().await);
        assert!(matches!(
            binding.ask(|state| state.plan("run-b")).await,
            Some(Ok(RebindPlan::Decide {
                candidates: None,
                ..
            }))
        ));

        // Adoption moves the published run once per new run; a run refused
        // for continuity stays refused.
        binding.ask(|state| state.adopt("run-b")).await;
        binding.ask(|state| state.adopt("run-b")).await;
        assert_eq!(binding.run_id(), "run-b");
        assert_eq!(binding.rebinds(), 1);
        binding
            .ask(|state| state.refuse_for_continuity("run-c"))
            .await;
        assert!(matches!(
            binding.ask(|state| state.plan("run-c")).await,
            Some(Err(CatalogError::Conflict(CONTINUITY_MISMATCH)))
        ));
        binding.ask(|state| state.adopt("run-a")).await;
        assert_eq!(binding.run_id(), "run-a");
        assert_eq!(binding.rebinds(), 2);
    }

    #[test]
    fn lane_loss_classification_is_transport_only() {
        assert!(lane_lost(&RedisError::from(std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        ))));
        assert!(lane_lost(&RedisError::from(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(!lane_lost(&RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "wrong value type"
        ))));
        assert!(!lane_lost(&RedisError::from((
            redis::ErrorKind::Parse,
            "malformed reply"
        ))));
    }

    /// M6-C65 review: a token re-binding needs a token acknowledged at most
    /// one interval plus the command deadlines (and one second) before the
    /// last reply from Redis; a loop that stopped or kept failing while
    /// Redis answered leaves a larger gap and is refused.
    #[test]
    fn a_token_is_fresh_only_within_one_interval_of_the_last_reply() {
        let interval = Duration::from_secs(5);
        let bound = 5_000 + 2 * 2_000 + 1_000;
        assert!(token_is_fresh(Some(10_000), 10_000, interval));
        assert!(token_is_fresh(Some(10_000), 10_000 + bound, interval));
        assert!(!token_is_fresh(Some(10_000), 10_000 + bound + 1, interval));
        assert!(!token_is_fresh(None, 0, interval), "no acknowledged token");
        // A reply recorded before the acknowledgement is not a gap.
        assert!(token_is_fresh(Some(10_000), 9_000, interval));
    }

    /// M6-C65 review: all three settings, exactly.
    #[test]
    fn persistence_needs_aof_always_and_fsync_during_rewrite() {
        let pairs = |fsync: &str, rewrite: &str, aof: &str| -> Vec<String> {
            [
                "appendonly",
                aof,
                "appendfsync",
                fsync,
                "no-appendfsync-on-rewrite",
                rewrite,
            ]
            .map(str::to_owned)
            .to_vec()
        };
        assert!(persistence_is_sound(&pairs("always", "no", "yes")));
        assert!(!persistence_is_sound(&pairs("everysec", "no", "yes")));
        assert!(!persistence_is_sound(&pairs("no", "no", "yes")));
        assert!(!persistence_is_sound(&pairs("always", "yes", "yes")));
        assert!(!persistence_is_sound(&pairs("always", "no", "no")));
        assert!(!persistence_is_sound(&[]), "a refused or empty CONFIG GET");
    }

    /// M7-C113 regression: a reply timeout reported by the lane's own outer
    /// deadline releases the connection exactly as one reported by redis-rs.
    ///
    /// The startup connection here has no redis-rs response timeout, so the
    /// outer deadline is the only one that can fire.  Before the fix that
    /// branch kept the connection still owed the stalled reply, and the next
    /// command queued behind it instead of re-verifying on a fresh one.
    #[tokio::test]
    async fn an_outer_deadline_timeout_releases_the_connection() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let config = redis::AsyncConnectionConfig::new().set_response_timeout(None);
        let connection = tokio::time::timeout(
            TEST_DEADLINE,
            client.get_multiplexed_async_connection_with_config(&config),
        )
        .await
        .expect("bounded startup connection")
        .expect("startup connection without a response timeout");
        let lane = AuthorityLane::new(
            client.clone(),
            connection,
            "lane-run-a".to_owned(),
            Arc::clone(&group),
        );
        assert_eq!(server.accepted(), 1);

        server.set_reply_delay(STALLED_REPLY_DELAY);
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                timed_out(&error),
                "the outer deadline reported {error} instead of a timeout"
            ),
            other => panic!("stalled authority reported {other:?} instead of a timeout"),
        }
        server.set_reply_delay(Duration::ZERO);
        assert_eq!(
            ping(&lane)
                .await
                .expect("the command after a timeout re-verifies the primary"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            2,
            "the timed-out connection must be replaced, not reused"
        );
    }

    /// A resolver that answers with the fake authority's address only once
    /// the test releases it, standing in for the cold DNS lookup measured on
    /// a fresh Fly machine (M6-C73), and counts its lookups.  The test, not
    /// a wall-clock delay, decides when the reconnect can finish (M6-C117:
    /// a fixed delay let the reconnect land inside a late caller's deadline
    /// on Windows' coarse timers).
    struct GatedResolver {
        release: tokio::sync::watch::Receiver<bool>,
        address: std::net::SocketAddr,
        lookups: Arc<AtomicUsize>,
    }

    impl redis::io::AsyncDNSResolver for GatedResolver {
        fn resolve<'a, 'b: 'a>(
            &'a self,
            _host: &'b str,
            _port: u16,
        ) -> redis::RedisFuture<'a, Box<dyn Iterator<Item = std::net::SocketAddr> + Send + 'a>>
        {
            Box::pin(async move {
                self.lookups.fetch_add(1, Ordering::AcqRel);
                let mut release = self.release.clone();
                let _ = release.wait_for(|released| *released).await;
                Ok(Box::new(std::iter::once(self.address))
                    as Box<dyn Iterator<Item = std::net::SocketAddr> + Send>)
            })
        }
    }

    /// Longer than the per-command deadline, well inside the connect budget.
    const SLOW_RECONNECT: Duration = Duration::from_millis(3_000);
    const _: () = assert!(SLOW_RECONNECT.as_millis() > REDIS_OPERATION_TIMEOUT.as_millis());
    const _: () = assert!(SLOW_RECONNECT.as_millis() < REDIS_CONNECT_TIMEOUT.as_millis());
    /// Scheduling slack allowed on top of the per-command deadline.
    const DEADLINE_SLACK: Duration = Duration::from_millis(500);
    /// Callers that arrive while the slow reconnect is in flight.
    const SIBLING_CALLERS: usize = 5;

    /// A PING whose wall time is measured, with a bound far above any
    /// deadline under test so a queued caller is measured, not cut off.
    async fn timed_ping(lane: &AuthorityLane) -> (Result<String, CatalogError>, Duration) {
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            lane.query::<String>(&redis::cmd("PING")),
        )
        .await
        .expect("measurement bound");
        (result, started.elapsed())
    }

    /// M6-C74 regression: after a severed connection, a lane reconnect that
    /// needs longer than the two-second command deadline (a cold DNS lookup)
    /// but less than `REDIS_CONNECT_TIMEOUT` completes and is installed,
    /// while every caller that arrives during it -- the one that started it
    /// included -- stays bounded at the command deadline and fails closed
    /// with a timeout instead of queueing behind the connect.  Exactly one
    /// reconnect runs, and the next command uses its connection at once.
    ///
    /// Before the fix `admit` cancelled the reconnect at two seconds while
    /// keeping the lane to itself, so the siblings queued one full deadline each
    /// and the lane never reconnected at all.
    #[tokio::test]
    async fn m6c74_slow_lane_reconnect_completes_while_callers_stay_bounded() {
        let server = FakeAuthority::start("lane-run-a").await;
        let direct = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let (connection, run_id) =
            tokio::time::timeout(TEST_DEADLINE, open_verified_connection(&direct))
                .await
                .expect("bounded startup connection")
                .expect("verified startup connection");
        assert_eq!(run_id, "lane-run-a");
        // The lane reconnects by host name through the slow resolver.
        let lookups = Arc::new(AtomicUsize::new(0));
        let slow_client =
            redis::Client::open(format!("redis://m6c74-cold-dns.invalid:{}/", server.port))
                .expect("slow-resolver URL");
        let (release_resolver, release) = tokio::sync::watch::channel(false);
        let config = connection_config(REDIS_CONNECT_TIMEOUT).set_dns_resolver(GatedResolver {
            release,
            address: std::net::SocketAddr::from(([127, 0, 0, 1], server.port)),
            lookups: Arc::clone(&lookups),
        });
        let lane = Arc::new(AuthorityLane::with_connect_config(
            slow_client,
            connection,
            run_id,
            Arc::clone(&group),
            config,
        ));
        assert_eq!(ping(&lane).await.expect("healthy lane"), "PONG");
        assert_eq!(server.accepted(), 1);

        server.sever_all().await;
        assert_lost(ping(&lane).await, "severed lane");
        let generation_after_loss = lane.inspect().await.connection_generation;
        assert_eq!(
            lookups.load(Ordering::Acquire),
            0,
            "discovery never reconnects"
        );

        // Callers arrive while the slow reconnect is in flight: at once, and
        // one second later.  None may wait longer than its own deadline.
        let reconnect_started = tokio::time::Instant::now();
        let mut callers = JoinSet::new();
        for index in 0..SIBLING_CALLERS {
            let lane = Arc::clone(&lane);
            callers.spawn(async move {
                if index + 1 == SIBLING_CALLERS {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                timed_ping(&lane).await
            });
        }
        let mut observed = Vec::with_capacity(SIBLING_CALLERS);
        while let Some(joined) = callers.join_next().await {
            observed.push(joined.expect("caller task"));
        }
        for (result, elapsed) in &observed {
            assert!(
                *elapsed < REDIS_OPERATION_TIMEOUT + DEADLINE_SLACK,
                "a caller waited {elapsed:?} behind the lane reconnect; callers must stay \
                 bounded at {REDIS_OPERATION_TIMEOUT:?}: {observed:?}"
            );
            match result {
                Err(CatalogError::Database(error)) if timed_out(error) => {}
                other => panic!("a caller during the reconnect reported {other:?}, not a timeout"),
            }
        }
        assert_eq!(
            lookups.load(Ordering::Acquire),
            1,
            "concurrent callers share one single-flight reconnect"
        );

        // The reconnect outlives its callers: it is still in flight, held at
        // the resolver, after every caller has given up.  Only now, and not
        // before it has run for SLOW_RECONNECT (longer than any caller's
        // deadline), is the lookup answered (M6-C117).
        tokio::time::sleep_until(reconnect_started + SLOW_RECONNECT).await;
        {
            let state = lane.inspect().await;
            assert!(
                !state.connected,
                "nothing installed before the lookup answers"
            );
            assert!(state.reconnecting, "the reconnect is still in flight");
        }
        release_resolver.send_replace(true);

        // The reconnect then completes and is installed.
        loop {
            if lane.inspect().await.connected {
                break;
            }
            assert!(
                reconnect_started.elapsed() < REDIS_CONNECT_TIMEOUT,
                "the lane never reconnected within REDIS_CONNECT_TIMEOUT \
                 ({REDIS_CONNECT_TIMEOUT:?}) although the reconnect needs only {SLOW_RECONNECT:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            reconnect_started.elapsed() >= SLOW_RECONNECT,
            "the resolver delay applied"
        );
        {
            let state = lane.inspect().await;
            assert!(!state.reconnecting, "the finished attempt is cleared");
            assert_eq!(
                state.connection_generation,
                generation_after_loss + 1,
                "one installed connection advances the connection generation once"
            );
            assert_eq!(
                state.verified_generation,
                Some(group.loss_generation.load(Ordering::Acquire))
            );
            assert_eq!(state.verified_run_id.as_deref(), Some("lane-run-a"));
        }
        assert_eq!(server.accepted(), 2, "exactly one reconnect connection");

        let (reply, elapsed) = timed_ping(&lane).await;
        assert_eq!(reply.expect("the reconnected lane serves"), "PONG");
        assert!(
            elapsed < DEADLINE_SLACK,
            "the next command used the installed connection: {elapsed:?}"
        );
        assert_eq!(server.accepted(), 2);
        assert_eq!(lookups.load(Ordering::Acquire), 1);
        server.shutdown().await;
    }

    /// M6-C95 regression: after a sibling lane observed a transport loss,
    /// the next callers probe this lane's connection before their commands.
    /// With the authority stalled past the command deadline, two concurrent
    /// callers must each fail closed with a timeout within their own
    /// deadline.  Before the fix the probe kept the lane to itself and the
    /// second caller's deadline started only once it had the lane, so it
    /// took about two deadlines.  The stall then clears and the lane keeps
    /// serving on the connection it probed.
    #[tokio::test]
    async fn m6c95_callers_behind_a_stalled_sibling_probe_stay_bounded() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(lane_with_outer_deadline_only(&client, "lane-run-a", &group).await);
        assert_eq!(ping(&lane).await.expect("healthy lane"), "PONG");

        // A sibling lane observed a loss: this lane must probe first.
        group.loss_generation.fetch_add(1, Ordering::AcqRel);
        server.set_reply_delay(STALLED_REPLY_DELAY);
        let mut callers = JoinSet::new();
        for _ in 0..2 {
            let lane = Arc::clone(&lane);
            callers.spawn(async move { timed_ping(&lane).await });
        }
        let mut observed = Vec::with_capacity(2);
        while let Some(joined) = callers.join_next().await {
            observed.push(joined.expect("caller task"));
        }
        for (result, elapsed) in &observed {
            assert!(
                *elapsed < REDIS_OPERATION_TIMEOUT + DEADLINE_SLACK,
                "a caller waited {elapsed:?} behind a stalled probe; each caller must stay \
                 bounded at {REDIS_OPERATION_TIMEOUT:?}: {observed:?}"
            );
            match result {
                Err(CatalogError::Database(error)) if timed_out(error) => {}
                other => panic!("a caller behind the stalled probe reported {other:?}"),
            }
        }

        // The stall clears: the probe passes on the same connection.
        server.set_reply_delay(Duration::ZERO);
        assert_eq!(ping(&lane).await.expect("the probed lane serves"), "PONG");
        assert_eq!(server.accepted(), 1, "no reconnect for a stalled probe");
        assert_eq!(
            lane.inspect().await.verified_generation,
            Some(group.loss_generation.load(Ordering::Acquire)),
            "the passed probe is recorded"
        );
        server.shutdown().await;
    }
}
