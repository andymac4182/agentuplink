//! Bounded readiness state for the private relay-to-relay routes.
//!
//! Membership readiness is necessary but not sufficient for a cluster relay.
//! This module keeps the additional process-local facts which must be true
//! before public work is admitted: the private listener is bound, every
//! verified route required by the current membership snapshot has completed a
//! bounded authenticated probe, and a non-zero amount of peer capacity is
//! available.  It deliberately stores only bounded state and never exposes
//! endpoint or certificate details through its status snapshot.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering::SeqCst},
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot, watch};
use tunnel_cluster::membership::VerifiedMembership;

/// The signed membership policy caps an authorized deployment at 32 nodes.
/// Keep the readiness state no larger than that policy even if a caller is
/// handed an invalid or unbounded route iterator.
pub const MAX_REQUIRED_PEER_ROUTES: usize = 32;

/// The smallest amount of peer capacity that can support a ready relay.
pub const MIN_REQUIRED_PEER_CAPACITY: usize = 1;

/// The maximum number of authenticated probes allowed to be in flight during
/// one refresh pass.  This bounds bootstrap and recovery work independently
/// of the number of signed membership records.
pub const MAX_CONCURRENT_PEER_PROBES: usize = 4;

/// Default monotonic freshness bound for a successful route probe.
pub const DEFAULT_PEER_PROBE_TTL: Duration = Duration::from_secs(15);

/// Absolute deadline for one complete authenticated route probe.
///
/// This covers connection checkout or setup, request-stream reservation,
/// response headers, and the terminating empty-body read.  It is deliberately
/// independent of the transport's per-operation idle timeout so a peer which
/// sends periodic unrelated bytes cannot keep readiness admission alive.
pub const PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Revision of the currently installed verified route and pin set.
pub type PeerReadinessRevision = u64;

/// The state of the private listener relevant to public readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerListenerState {
    /// The private listener has not completed its bind.
    Unbound,
    /// The private listener is accepting authenticated peer connections.
    Bound,
    /// Shutdown or drain has begun; new public work must fail closed.
    Draining,
}

/// The result of one bounded, authenticated route probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerProbeState {
    /// A route is in the required set but has not completed a current probe.
    Pending,
    /// The route completed mTLS, role, pin, and endpoint checks.
    Reachable,
    /// The route could not be reached or failed identity validation.
    Unreachable,
    /// The route could not obtain bounded transport capacity.
    CapacityExhausted,
}

/// Redacted state for one uniquely identified signed peer route.
///
/// The accessor intentionally returns only the signed node identifier and the
/// bounded probe state.  Endpoint, server-name, and SPKI values remain
/// private so diagnostics cannot turn route evidence into trust material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRouteReadiness {
    pub node_id: String,
    pub state: PeerProbeState,
}

/// A route target derived from one verified signed membership record.
///
/// A signed membership record does not contain a boot ID.  The boot ID is
/// therefore intentionally absent here and is checked later when an owner
/// binding is selected.  The authenticated probe still verifies the relay
/// node role and one of the currently approved SPKI keys from this record.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerRouteTarget {
    node_id: String,
    peer_endpoint: String,
    server_name: String,
    approved_spki_sha256: Vec<String>,
}

impl fmt::Debug for PeerRouteTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRouteTarget")
            .field("node_id", &self.node_id)
            .field("approved_key_count", &self.approved_spki_sha256.len())
            .finish_non_exhaustive()
    }
}

impl PeerRouteTarget {
    #[cfg(test)]
    pub(crate) fn for_test(
        node_id: impl Into<String>,
        peer_endpoint: impl Into<String>,
        server_name: impl Into<String>,
        approved_spki_sha256: Vec<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            peer_endpoint: peer_endpoint.into(),
            server_name: server_name.into(),
            approved_spki_sha256,
        }
    }

    /// Build a target from a membership record which has already passed the
    /// signed verifier.  Expired, revoked, and not-yet-active keys are
    /// excluded from the bounded probe pin set.  Activation honours the
    /// verifier's clock-skew allowance exactly as `bind_peer` does (M7-C171,
    /// option (a)); expiry is strict.
    #[must_use]
    pub fn from_verified_membership(
        membership: &VerifiedMembership,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        if !membership.activated(membership.record().not_before, now)
            || membership.record().expires_at <= now
        {
            return None;
        }
        let mut approved_spki_sha256 = membership
            .keys()
            .iter()
            .filter(|key| {
                !key.revoked && membership.activated(key.not_before, now) && key.expires_at > now
            })
            .map(|key| key.spki_sha256.clone())
            .collect::<Vec<_>>();
        approved_spki_sha256.sort_unstable();
        approved_spki_sha256.dedup();
        if approved_spki_sha256.is_empty() {
            return None;
        }
        Some(Self {
            node_id: membership.node_id().to_owned(),
            peer_endpoint: membership.peer_endpoint().to_owned(),
            server_name: membership.server_name().to_owned(),
            approved_spki_sha256,
        })
    }

    /// Build a one-pin route identity from an already verified binding.  This
    /// is used to mark an established route unavailable after a failed owner
    /// open without accepting caller-provided endpoint or pin strings.
    #[must_use]
    pub fn from_verified_binding(
        binding: &tunnel_cluster::membership::VerifiedPeerBinding,
    ) -> Self {
        Self {
            node_id: binding.node_id().to_owned(),
            peer_endpoint: binding.peer_endpoint().to_owned(),
            server_name: binding.server_name().to_owned(),
            approved_spki_sha256: vec![binding.spki_sha256().to_owned()],
        }
    }

    /// Return the signed node identifier used by the peer certificate role.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Return the signed private endpoint for the transport adapter.
    #[must_use]
    pub fn peer_endpoint(&self) -> &str {
        &self.peer_endpoint
    }

    /// Return the signed TLS server name for the transport adapter.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Return the currently approved SPKI digests for this target.
    #[must_use]
    pub fn approved_spki_sha256(&self) -> &[String] {
        &self.approved_spki_sha256
    }

    fn key(&self) -> PeerRouteKey {
        PeerRouteKey {
            node_id: self.node_id.clone(),
            peer_endpoint: self.peer_endpoint.clone(),
            server_name: self.server_name.clone(),
        }
    }

    fn same_pins(&self, other: &Self) -> bool {
        self.approved_spki_sha256 == other.approved_spki_sha256
    }

    /// Match an observation derived from one authenticated binding to the
    /// signed route target.  Endpoint and node identity must match exactly;
    /// the observed binding pin only needs to be a member of the signed pin
    /// overlap set.
    fn matches_route_observation(&self, observation: &Self) -> bool {
        self.key() == observation.key()
            && observation.approved_spki_sha256.iter().any(|pin| {
                self.approved_spki_sha256
                    .iter()
                    .any(|approved| approved == pin)
            })
    }
}

/// A redacted readiness snapshot suitable for bounded in-process checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerReadinessSnapshot {
    /// Current listener state.
    pub listener: PeerListenerState,
    /// Whether the current verified route set has been installed.
    pub routes_known: bool,
    /// Number of routes required by that set.
    pub required_routes: usize,
    /// Number of routes with a successful current probe.
    pub reachable_routes: usize,
    /// Number of routes with a current successful probe and capacity floor.
    pub capacity_ready_routes: usize,
    /// Current observed/configured available peer capacity.
    pub available_capacity: Option<usize>,
    /// Minimum capacity required for readiness.
    pub required_capacity: usize,
    /// Monotonic revision of the installed route and pin set.
    pub revision: PeerReadinessRevision,
}

/// Bounded readiness errors.  They do not include endpoints, pins, payloads,
/// or backend error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerReadinessError {
    /// The required capacity floor is zero or otherwise invalid.
    InvalidCapacity,
    /// A zero probe freshness bound would immediately make every route stale.
    InvalidProbeTtl,
    /// A route set exceeded the signed deployment bound.
    TooManyRoutes { observed: usize, maximum: usize },
    /// A probe result referred to a route which is not currently required.
    UnknownRoute,
    /// The task owning the route table is gone, so the change was not
    /// applied.  Readiness reads not ready from then on.
    OwnerUnavailable,
}

impl fmt::Display for PeerReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("peer readiness capacity is invalid"),
            Self::InvalidProbeTtl => {
                formatter.write_str("peer readiness probe freshness is invalid")
            }
            Self::TooManyRoutes { observed, maximum } => write!(
                formatter,
                "peer readiness route count exceeds bound: {observed} > {maximum}"
            ),
            Self::UnknownRoute => formatter.write_str("peer readiness route is not required"),
            Self::OwnerUnavailable => formatter.write_str("peer readiness owner is unavailable"),
        }
    }
}

impl std::error::Error for PeerReadinessError {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PeerRouteKey {
    node_id: String,
    peer_endpoint: String,
    server_name: String,
}

/// One required route and its probe evidence.
#[derive(Clone, Debug)]
struct RequiredRoute {
    target: PeerRouteTarget,
    state: PeerProbeState,
    last_probe: Option<Instant>,
    available_capacity: Option<usize>,
    /// The approved SPKI digest the last successful probe authenticated, when
    /// the prober reported it.
    proven_spki: Option<String>,
    /// Unreachable marks issued against this route.  A failed open raises
    /// it synchronously, before it awaits anything, so the mark stands
    /// however the caller is cancelled and however full the owner's queue
    /// is.  The cell follows the route key across route-set replacements.
    marks: Arc<AtomicU64>,
    /// How many of those marks this table already reflects.  A route whose
    /// two counts differ reads unreachable until the owner folds the rest.
    marks_folded: u64,
}

/// Table-wide withdrawals issued so far.  Each is raised synchronously by
/// the withdrawing caller; the table records how many it reflects.
#[derive(Debug, Default)]
struct WithdrawalCounters {
    /// The required route set was replaced by the empty set.
    trust: AtomicU64,
    /// Every probe and capacity observation was withdrawn.
    probe_resets: AtomicU64,
    /// The available peer capacity was withdrawn.
    capacity_clears: AtomicU64,
}

/// One reading of [`WithdrawalCounters`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Withdrawals {
    trust: u64,
    probe_resets: u64,
    capacity_clears: u64,
}

impl WithdrawalCounters {
    fn issued(&self) -> Withdrawals {
        Withdrawals {
            trust: self.trust.load(SeqCst),
            probe_resets: self.probe_resets.load(SeqCst),
            capacity_clears: self.capacity_clears.load(SeqCst),
        }
    }
}

/// Every withdrawal issued against one table at one reading: the
/// table-wide counts and each route's mark count, in route order.
#[derive(Debug, Eq, PartialEq)]
struct Issued {
    withdrawals: Withdrawals,
    marks: Vec<u64>,
}

/// The withdrawals a change had seen when it was issued.  The owner applies
/// a change that would make readiness *more* ready only if no withdrawal it
/// could undo was issued after it, so a queued older observation never
/// erases a newer withdrawal.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    withdrawals: Withdrawals,
    /// The mark count of the change's route, when it names an installed one.
    route_marks: Option<u64>,
}

/// The route, probe and capacity table.  Exactly one task owns the mutable
/// copy; every reader samples an immutable published snapshot of it.
#[derive(Clone, Debug)]
struct RouteTable {
    routes_known: bool,
    routes: BTreeMap<PeerRouteKey, RequiredRoute>,
    available_capacity: Option<usize>,
    required_capacity: usize,
    probe_ttl: Duration,
    revision: PeerReadinessRevision,
    /// The table-wide withdrawals this table reflects.
    folded: Withdrawals,
}

/// One change to the route table.  A change is applied whole by the owning
/// task and published before the caller is answered.
#[derive(Debug)]
enum RouteTableChange {
    /// Nothing but the withdrawals issued so far.  Every withdrawal is
    /// issued synchronously and then asks for this, so losing the request
    /// loses nothing: readers already see the withdrawal, and the owner
    /// folds it in before whatever change it applies next.
    Fold,
    SetAvailableCapacity(usize),
    /// A non-empty, deduplicated route set already checked against the
    /// route bound.
    ReplaceRoutes(Vec<PeerRouteTarget>),
    /// `revision: None` means "whatever revision is installed when the
    /// owner applies this".
    RecordProbe {
        revision: Option<PeerReadinessRevision>,
        target: PeerRouteTarget,
        probe: PeerProbeState,
        proven_spki: Option<String>,
    },
    SetRouteCapacity {
        revision: Option<PeerReadinessRevision>,
        target: PeerRouteTarget,
        available_capacity: usize,
    },
}

/// What one applied change did.
#[derive(Clone, Copy, Debug)]
struct Applied {
    /// The route-set revision after the change.
    revision: PeerReadinessRevision,
    /// `false` when the change was stale -- fenced by its revision, or
    /// issued before a withdrawal it would have undone -- and was ignored.
    published: bool,
}

impl RouteTable {
    /// Read every withdrawal issued against this table.
    fn issued(&self, counters: &WithdrawalCounters) -> Issued {
        Issued {
            withdrawals: counters.issued(),
            marks: self
                .routes
                .values()
                .map(|route| route.marks.load(SeqCst))
                .collect(),
        }
    }

    /// Whether `issued` holds a withdrawal this table does not reflect.
    fn lags(&self, issued: &Issued) -> bool {
        issued.withdrawals != self.folded
            || self
                .routes
                .values()
                .zip(&issued.marks)
                .any(|(route, marks)| route.marks_folded != *marks)
    }

    /// Bring the table up to the withdrawals in `issued`.  The owner does
    /// this before every change; a reader that samples a lagging table does
    /// the same to its own copy, so both see exactly the same result.
    fn fold(&mut self, issued: &Issued) {
        for (route, marks) in self.routes.values_mut().zip(&issued.marks) {
            if route.marks_folded != *marks {
                route.marks_folded = *marks;
                route.state = PeerProbeState::Unreachable;
                route.available_capacity = None;
                route.proven_spki = None;
            }
        }
        if issued.withdrawals.trust != self.folded.trust {
            self.replace_routes(Vec::new());
        }
        if issued.withdrawals.probe_resets != self.folded.probe_resets {
            self.revision = self.revision.saturating_add(1);
            self.available_capacity = None;
            for route in self.routes.values_mut() {
                route.state = PeerProbeState::Pending;
                route.last_probe = None;
                route.available_capacity = None;
                route.proven_spki = None;
            }
        }
        if issued.withdrawals.capacity_clears != self.folded.capacity_clears {
            self.available_capacity = None;
        }
        self.folded = issued.withdrawals;
    }

    /// The only place the route table changes, besides [`Self::fold`], which
    /// the owner always runs first.
    fn apply(
        &mut self,
        change: RouteTableChange,
        stamp: Stamp,
    ) -> Result<Applied, PeerReadinessError> {
        let seen = stamp.withdrawals;
        let mut published = true;
        match change {
            RouteTableChange::Fold => {}
            RouteTableChange::SetAvailableCapacity(available_capacity) => {
                if seen.probe_resets == self.folded.probe_resets
                    && seen.capacity_clears == self.folded.capacity_clears
                {
                    self.available_capacity = Some(available_capacity);
                } else {
                    published = false;
                }
            }
            RouteTableChange::ReplaceRoutes(targets) => {
                if seen.trust == self.folded.trust {
                    self.replace_routes(targets);
                } else {
                    published = false;
                }
            }
            RouteTableChange::RecordProbe {
                revision,
                target,
                probe,
                proven_spki,
            } => {
                // The outcome and its proof, if any, change together, so no
                // interleaved unreachable mark or reset can leave an
                // `Unreachable` route carrying a proof.
                if revision.is_some_and(|revision| revision != self.revision)
                    || seen.trust != self.folded.trust
                    || seen.probe_resets != self.folded.probe_resets
                {
                    published = false;
                } else {
                    let required = self.required_route_mut(&target)?;
                    if probe == PeerProbeState::Reachable
                        && stamp
                            .route_marks
                            .is_some_and(|marks| marks != required.marks_folded)
                    {
                        // The route was marked unreachable after this
                        // success was issued; the mark stands.
                        published = false;
                    } else {
                        required.state = probe;
                        required.proven_spki =
                            proven_spki.filter(|_| probe == PeerProbeState::Reachable);
                        required.last_probe =
                            (probe == PeerProbeState::Reachable).then(Instant::now);
                        required.available_capacity = match probe {
                            PeerProbeState::Reachable => Some(1),
                            PeerProbeState::CapacityExhausted => Some(0),
                            PeerProbeState::Pending | PeerProbeState::Unreachable => None,
                        };
                    }
                }
            }
            RouteTableChange::SetRouteCapacity {
                revision,
                target,
                available_capacity,
            } => {
                if revision.is_some_and(|revision| revision != self.revision)
                    || seen.trust != self.folded.trust
                    || seen.probe_resets != self.folded.probe_resets
                {
                    published = false;
                } else {
                    let required_capacity = self.required_capacity;
                    let required = self.required_route_mut(&target)?;
                    if available_capacity >= required_capacity
                        && stamp
                            .route_marks
                            .is_some_and(|marks| marks != required.marks_folded)
                    {
                        published = false;
                    } else {
                        required.available_capacity = Some(available_capacity);
                        if available_capacity < required_capacity {
                            required.state = PeerProbeState::CapacityExhausted;
                        }
                    }
                }
            }
        }
        Ok(Applied {
            revision: self.revision,
            published,
        })
    }

    fn required_route_mut(
        &mut self,
        target: &PeerRouteTarget,
    ) -> Result<&mut RequiredRoute, PeerReadinessError> {
        self.routes
            .get_mut(&target.key())
            .filter(|required| required.target.same_pins(target))
            .ok_or(PeerReadinessError::UnknownRoute)
    }

    fn replace_routes(&mut self, targets: Vec<PeerRouteTarget>) {
        let mut next = BTreeMap::new();
        for target in targets {
            let key = target.key();
            let installed = self.routes.get(&key);
            // Marks follow the route key, whatever happens to its pins: a
            // failed open that resolved the route just before this
            // replacement still marks the route it meant.
            let (marks, marks_folded) = installed.map_or_else(
                || (Arc::new(AtomicU64::new(0)), 0),
                |installed| (Arc::clone(&installed.marks), installed.marks_folded),
            );
            // Keep a route's probe evidence when the new signed target still
            // approves the key that evidence was proven with. A record that
            // only adds a key -- a staged rotation overlap -- or retires a
            // key the peer is not presenting does not make the proven route
            // any less reachable, and resetting it to `Pending` withdrew
            // public readiness until the next probe pass completed (M8-C30).
            // With no recorded proof, any pin change still resets, as before.
            let previous = installed.filter(|previous| {
                previous.target.same_pins(&target)
                    || previous.proven_spki.as_ref().is_some_and(|proven| {
                        target
                            .approved_spki_sha256()
                            .iter()
                            .any(|pin| pin == proven)
                    })
            });
            let route_state = previous.map_or(PeerProbeState::Pending, |previous| previous.state);
            let last_probe = previous.and_then(|previous| previous.last_probe);
            let available_capacity = previous.and_then(|previous| previous.available_capacity);
            let proven_spki = previous.and_then(|previous| previous.proven_spki.clone());
            next.entry(key).or_insert(RequiredRoute {
                target,
                state: route_state,
                last_probe,
                available_capacity,
                proven_spki,
                marks,
                marks_folded,
            });
        }
        self.routes = next;
        self.routes_known = true;
        self.revision = self.revision.saturating_add(1);
    }

    /// Whether every route and capacity prerequisite holds right now.  Probe
    /// freshness is measured here, at read time, against the stored
    /// monotonic instants, so a stale probe withdraws readiness without any
    /// owner-task tick.
    fn routes_ready(&self) -> bool {
        self.routes_known
            && self.routes.values().all(|route| {
                route.state == PeerProbeState::Reachable
                    && route
                        .last_probe
                        .is_some_and(|last_probe| last_probe.elapsed() <= self.probe_ttl)
                    && route
                        .available_capacity
                        .is_some_and(|available| available >= self.required_capacity)
            })
            && self
                .available_capacity
                .is_some_and(|available| available >= self.required_capacity)
    }
}

/// Bound of the route-table owner's command queue.  A full queue makes the
/// next writer wait for the owner.  A writer cancelled while it waits loses
/// its queued request, which costs nothing fail-open: every withdrawal is
/// already issued in the shared counters by then, and what is lost is at
/// most an observation that would have made readiness more ready.  The
/// bound covers one concurrent probe pass (`MAX_CONCURRENT_PEER_PROBES`)
/// plus one failure mark per required route.
const ROUTE_TABLE_QUEUE: usize = 64;

/// How often a reader re-samples when the route table or a withdrawal moves
/// while it reads the listener state.  Each retry needs a whole owner
/// publication or a fresh withdrawal to land inside a few instructions; an
/// admission reader that exhausts the bound reports not ready.
const MAX_READ_RETRIES: usize = 8;

const LISTENER_UNBOUND: u8 = 0;
const LISTENER_BOUND: u8 = 1;
const LISTENER_DRAINING: u8 = 2;

const fn encode_listener(listener: PeerListenerState) -> u8 {
    match listener {
        PeerListenerState::Unbound => LISTENER_UNBOUND,
        PeerListenerState::Bound => LISTENER_BOUND,
        PeerListenerState::Draining => LISTENER_DRAINING,
    }
}

/// Decode fails closed: anything that is not a known live state is draining.
const fn decode_listener(listener: u8) -> PeerListenerState {
    match listener {
        LISTENER_UNBOUND => PeerListenerState::Unbound,
        LISTENER_BOUND => PeerListenerState::Bound,
        _ => PeerListenerState::Draining,
    }
}

type RouteTableCommand = (
    RouteTableChange,
    Stamp,
    oneshot::Sender<Result<Applied, PeerReadinessError>>,
);

struct ReadinessShared {
    /// The private listener state.  Its one logical writer is the listener
    /// lifecycle (bind, planned drain, shutdown, the serving guard's drop),
    /// which stores it synchronously; it is deliberately not routed through
    /// the route-table owner so a drain can never be queued or lost.
    listener: AtomicU8,
    /// The published route table.  Only the owning task sends on it; this
    /// handle exists so readers can sample it and so the owner can be
    /// started lazily with the table as it stands.
    table: watch::Sender<Arc<RouteTable>>,
    /// Table-wide withdrawals, raised synchronously by their callers.
    withdrawals: Arc<WithdrawalCounters>,
    /// Command channel of the owning task, started by the first writer.
    owner: OnceLock<mpsc::Sender<RouteTableCommand>>,
    /// Latched when a change could not reach the owner (its runtime is
    /// gone).  A table that can no longer be withdrawn must not read ready.
    owner_lost: AtomicBool,
}

impl fmt::Debug for ReadinessShared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadinessShared")
            .field("listener", &decode_listener(self.listener.load(SeqCst)))
            .field("owner_started", &self.owner.get().is_some())
            .field("owner_lost", &self.owner_lost.load(SeqCst))
            .finish_non_exhaustive()
    }
}

/// The task that owns the mutable route table.  For each change it folds in
/// every withdrawal issued so far, applies the change, publishes the
/// resulting snapshot, and only then answers, so a caller that has been
/// answered reads its own write.  It ends when the last readiness handle is
/// dropped.
async fn own_route_table(
    mut table: RouteTable,
    published: watch::Sender<Arc<RouteTable>>,
    withdrawals: Arc<WithdrawalCounters>,
    mut commands: mpsc::Receiver<RouteTableCommand>,
) {
    while let Some((change, stamp, reply)) = commands.recv().await {
        let issued = table.issued(&withdrawals);
        table.fold(&issued);
        let outcome = table.apply(change, stamp);
        published.send_replace(Arc::new(table.clone()));
        let _ = reply.send(outcome);
    }
}

/// Thread-safe process-local peer route readiness.
#[derive(Clone, Debug)]
pub struct PeerReadiness {
    shared: Arc<ReadinessShared>,
}

impl PeerReadiness {
    /// Construct a readiness state with a positive capacity floor.
    pub fn new(required_capacity: usize) -> Result<Self, PeerReadinessError> {
        Self::new_with_probe_ttl(required_capacity, DEFAULT_PEER_PROBE_TTL)
    }

    /// Construct readiness with an explicit monotonic probe freshness bound.
    pub fn new_with_probe_ttl(
        required_capacity: usize,
        probe_ttl: Duration,
    ) -> Result<Self, PeerReadinessError> {
        if required_capacity < MIN_REQUIRED_PEER_CAPACITY {
            return Err(PeerReadinessError::InvalidCapacity);
        }
        if probe_ttl.is_zero() {
            return Err(PeerReadinessError::InvalidProbeTtl);
        }
        let (table, _) = watch::channel(Arc::new(RouteTable {
            routes_known: false,
            routes: BTreeMap::new(),
            available_capacity: None,
            required_capacity,
            probe_ttl,
            revision: 0,
            folded: Withdrawals::default(),
        }));
        Ok(Self {
            shared: Arc::new(ReadinessShared {
                listener: AtomicU8::new(LISTENER_UNBOUND),
                table,
                withdrawals: Arc::new(WithdrawalCounters::default()),
                owner: OnceLock::new(),
                owner_lost: AtomicBool::new(false),
            }),
        })
    }

    /// The withdrawals issued so far, as a change issued now has seen them.
    fn stamp(&self, target: Option<&PeerRouteTarget>) -> Stamp {
        let route_marks = target.and_then(|target| {
            self.shared
                .table
                .borrow()
                .routes
                .get(&target.key())
                .map(|route| route.marks.load(SeqCst))
        });
        Stamp {
            withdrawals: self.shared.withdrawals.issued(),
            route_marks,
        }
    }

    /// Ask the owner to fold in the withdrawal the caller has just issued,
    /// and wait until it is published.
    async fn fold(&self) -> Result<Applied, PeerReadinessError> {
        self.change(RouteTableChange::Fold, None).await
    }

    /// Hand one change to the owning task and wait until it is published.
    ///
    /// The change is stamped and queued before this future first yields
    /// whenever the queue has room.  Must be called inside a Tokio runtime.
    async fn change(
        &self,
        change: RouteTableChange,
        target: Option<&PeerRouteTarget>,
    ) -> Result<Applied, PeerReadinessError> {
        let stamp = self.stamp(target);
        let owner = self.shared.owner.get_or_init(|| {
            let (sender, commands) = mpsc::channel(ROUTE_TABLE_QUEUE);
            let table = RouteTable::clone(&self.shared.table.borrow());
            tokio::spawn(own_route_table(
                table,
                self.shared.table.clone(),
                Arc::clone(&self.shared.withdrawals),
                commands,
            ));
            sender
        });
        let (reply, answer) = oneshot::channel();
        let queued = match owner.try_send((change, stamp, reply)) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(command)) => owner.send(command).await.is_ok(),
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        };
        if queued && let Ok(outcome) = answer.await {
            return outcome;
        }
        self.shared.owner_lost.store(true, SeqCst);
        Err(PeerReadinessError::OwnerUnavailable)
    }

    /// `table` with every withdrawal in `issued` folded in.
    fn folded(table: Arc<RouteTable>, issued: &Issued) -> Arc<RouteTable> {
        if !table.lags(issued) {
            return table;
        }
        let mut folded = RouteTable::clone(&table);
        folded.fold(issued);
        Arc::new(folded)
    }

    /// The published table with every withdrawal issued so far folded in.
    fn current_table(&self) -> Arc<RouteTable> {
        let table = Arc::clone(&self.shared.table.borrow());
        let issued = table.issued(&self.shared.withdrawals);
        Self::folded(table, &issued)
    }

    /// Sample a listener state, a route table and the issued withdrawals
    /// that all coexisted, and return the listener with the table as those
    /// withdrawals leave it.  `None` means the retry bound was exhausted.
    ///
    /// The table and the withdrawals are read, then the listener, then the
    /// withdrawals and the table again.  The owner publishes a fresh
    /// allocation for every change and the withdrawal counts only grow, so
    /// an unchanged pointer and unchanged counts prove that the sampled
    /// table and withdrawals were the current ones at the instant the
    /// listener was read.  The listener is always read after the table it
    /// is paired with, so a drain stored before a read begins is never
    /// paired with an older "ready" table.
    fn sample(&self) -> Option<(PeerListenerState, Arc<RouteTable>)> {
        let mut table = Arc::clone(&self.shared.table.borrow());
        for _ in 0..MAX_READ_RETRIES {
            let issued = table.issued(&self.shared.withdrawals);
            let listener = decode_listener(self.shared.listener.load(SeqCst));
            let unchanged = issued == table.issued(&self.shared.withdrawals);
            let current = Arc::clone(&self.shared.table.borrow());
            if unchanged && Arc::ptr_eq(&table, &current) {
                return Some((listener, Self::folded(table, &issued)));
            }
            table = current;
        }
        None
    }

    /// [`Self::sample`] for an admission decision: an unstable sample, or a
    /// lost owner, is no evidence of readiness.
    fn admission_sample(&self) -> Option<(PeerListenerState, Arc<RouteTable>)> {
        self.sample()
            .filter(|_| !self.shared.owner_lost.load(SeqCst))
    }

    /// Mark the private listener bound or draining.  A draining listener can
    /// never make readiness true again until a new state is installed.
    ///
    /// This is synchronous, immediate and cannot be lost: it is one atomic
    /// store, usable from `Drop` and from non-async drain paths.
    pub fn set_listener_state(&self, listener: PeerListenerState) {
        self.shared
            .listener
            .store(encode_listener(listener), SeqCst);
    }

    /// Record the currently available bounded peer capacity.  Zero is valid
    /// input and deliberately makes readiness fail closed.
    ///
    /// A value below the capacity floor is a withdrawal: the capacity is
    /// withdrawn synchronously first, so it stands even if this call is
    /// cancelled before the value itself is recorded.
    pub async fn set_available_capacity(&self, available_capacity: usize) {
        if available_capacity < self.shared.table.borrow().required_capacity {
            self.shared.withdrawals.capacity_clears.fetch_add(1, SeqCst);
        }
        let _ = self
            .change(
                RouteTableChange::SetAvailableCapacity(available_capacity),
                None,
            )
            .await;
    }

    /// Forget capacity evidence until the next transport/configuration
    /// observation.  This is used when the pool is shut down or revoked.
    ///
    /// The withdrawal takes effect before this first awaits; it cannot be
    /// lost to cancellation or a full owner queue.
    pub async fn clear_available_capacity(&self) {
        self.shared.withdrawals.capacity_clears.fetch_add(1, SeqCst);
        let _ = self.fold().await;
    }

    /// Replace the required route set from current verified membership.
    /// Existing successful state is retained only when the endpoint, server
    /// name, and approved pin set are unchanged.  An explicitly empty set is
    /// valid for a verified one-node deployment; an uninstalled set is not.
    pub async fn replace_required_routes<I>(&self, targets: I) -> Result<(), PeerReadinessError>
    where
        I: IntoIterator<Item = PeerRouteTarget>,
    {
        self.replace_required_routes_with_revision(targets)
            .await
            .map(|_| ())
    }

    /// Replace the required route set and return its new revision.
    ///
    /// Every refresh pass gets a distinct revision, even when the signed
    /// endpoint and pin set is unchanged.  An in-flight result from an older
    /// pass therefore cannot publish into a newer pass merely because it has
    /// the same route key.
    ///
    /// Installing the empty set withdraws every approved peer, so it takes
    /// effect before this first awaits and cannot be lost to cancellation
    /// or a full owner queue.
    pub async fn replace_required_routes_with_revision<I>(
        &self,
        targets: I,
    ) -> Result<PeerReadinessRevision, PeerReadinessError>
    where
        I: IntoIterator<Item = PeerRouteTarget>,
    {
        // Bound and deduplicate before anything is queued, so an unbounded
        // iterator can neither grow the command nor change the table.
        let mut keys = BTreeSet::new();
        let mut bounded = Vec::new();
        for target in targets {
            let key = target.key();
            if keys.len() >= MAX_REQUIRED_PEER_ROUTES && !keys.contains(&key) {
                return Err(PeerReadinessError::TooManyRoutes {
                    observed: keys.len().saturating_add(1),
                    maximum: MAX_REQUIRED_PEER_ROUTES,
                });
            }
            if keys.insert(key) {
                bounded.push(target);
            }
        }
        let applied = if bounded.is_empty() {
            self.shared.withdrawals.trust.fetch_add(1, SeqCst);
            self.fold().await
        } else {
            self.change(RouteTableChange::ReplaceRoutes(bounded), None)
                .await
        };
        applied.map(|applied| applied.revision)
    }

    /// Withdraw every reachability and capacity observation while keeping the
    /// currently installed verified route and pin set.
    ///
    /// This is the readiness withdrawal used when the relay's *own* cluster
    /// prerequisites are lost: readiness becomes false and no stale probe can
    /// keep it true, but the verified route set stays installed so the relay
    /// can still answer an authenticated peer's bounded reachability probe.
    /// Dropping the route set instead would make two relays wait on each
    /// other: each side's probe admission would require the other to already
    /// be ready, and neither readiness could ever converge.
    ///
    /// The revision is bumped so an in-flight probe result from before the
    /// withdrawal cannot publish into the withdrawn state.  The withdrawal
    /// takes effect before this first awaits; it cannot be lost to
    /// cancellation or a full owner queue.
    pub async fn reset_route_probes(&self) {
        self.shared.withdrawals.probe_resets.fetch_add(1, SeqCst);
        let _ = self.fold().await;
    }

    /// Record a bounded probe result for one required route.
    pub async fn record_probe(
        &self,
        target: &PeerRouteTarget,
        probe: PeerProbeState,
    ) -> Result<(), PeerReadinessError> {
        self.change(
            RouteTableChange::RecordProbe {
                revision: None,
                target: target.clone(),
                probe,
                proven_spki: None,
            },
            Some(target),
        )
        .await
        .map(|_| ())
    }

    /// Record a probe only if it belongs to the currently installed route
    /// revision.  `false` means the refresh result was stale and was ignored.
    pub async fn record_probe_at(
        &self,
        revision: PeerReadinessRevision,
        target: &PeerRouteTarget,
        probe: PeerProbeState,
    ) -> Result<bool, PeerReadinessError> {
        self.change(
            RouteTableChange::RecordProbe {
                revision: Some(revision),
                target: target.clone(),
                probe,
                proven_spki: None,
            },
            Some(target),
        )
        .await
        .map(|applied| applied.published)
    }

    /// Record a successful probe together with the approved SPKI digest it
    /// authenticated. The digest must be one of the route's approved pins.
    pub async fn record_probe_proven_at(
        &self,
        revision: PeerReadinessRevision,
        target: &PeerRouteTarget,
        observed_spki: &str,
    ) -> Result<bool, PeerReadinessError> {
        if !target
            .approved_spki_sha256()
            .iter()
            .any(|pin| pin == observed_spki)
        {
            return Err(PeerReadinessError::UnknownRoute);
        }
        self.change(
            RouteTableChange::RecordProbe {
                revision: Some(revision),
                target: target.clone(),
                probe: PeerProbeState::Reachable,
                proven_spki: Some(observed_spki.to_owned()),
            },
            Some(target),
        )
        .await
        .map(|applied| applied.published)
    }

    /// Return the current route-set revision.
    #[must_use]
    pub fn current_revision(&self) -> PeerReadinessRevision {
        self.current_table().revision
    }

    /// Publish a bounded route-specific capacity observation.
    ///
    /// Route capacity is independent: updating one route never clears a
    /// capacity failure recorded for another route.
    pub async fn set_route_capacity(
        &self,
        target: &PeerRouteTarget,
        available_capacity: usize,
    ) -> Result<(), PeerReadinessError> {
        self.change(
            RouteTableChange::SetRouteCapacity {
                revision: None,
                target: target.clone(),
                available_capacity,
            },
            Some(target),
        )
        .await
        .map(|_| ())
    }

    /// Publish route-specific capacity only for the expected route revision.
    pub async fn set_route_capacity_at(
        &self,
        revision: PeerReadinessRevision,
        target: &PeerRouteTarget,
        available_capacity: usize,
    ) -> Result<bool, PeerReadinessError> {
        self.change(
            RouteTableChange::SetRouteCapacity {
                revision: Some(revision),
                target: target.clone(),
                available_capacity,
            },
            Some(target),
        )
        .await
        .map(|applied| applied.published)
    }

    /// Mark a currently required route unavailable after a failed admitted
    /// open.  Unknown routes are ignored because membership may have already
    /// removed them during the same reconciliation pass.
    ///
    /// The mark is one atomic step taken before this first awaits, exactly
    /// as it was when the caller applied it directly: it cannot be lost to
    /// the caller's cancellation or to a full owner queue, and every reader
    /// sees the route unreachable from that step on.  What is awaited is
    /// only the owner writing it into the published table.
    pub async fn mark_route_unreachable(&self, target: &PeerRouteTarget) {
        let marked = self
            .shared
            .table
            .borrow()
            .routes
            .get(&target.key())
            .filter(|required| required.target.matches_route_observation(target))
            .map(|required| required.marks.fetch_add(1, SeqCst))
            .is_some();
        if marked {
            let _ = self.fold().await;
        }
    }

    /// Check whether an authenticated peer certificate belongs to one of the
    /// currently verified route targets.  Probe admission intentionally does
    /// not require the route to have completed its outbound probe: requiring
    /// that would make two relays wait on each other during bootstrap.
    #[must_use]
    pub fn accepts_probe(&self, node_id: &str, spki_sha256: &str) -> bool {
        self.admission_sample().is_some_and(|(listener, table)| {
            listener == PeerListenerState::Bound
                && table.routes_known
                && table.routes.values().any(|route| {
                    route.target.node_id() == node_id
                        && route
                            .target
                            .approved_spki_sha256()
                            .iter()
                            .any(|pin| pin == spki_sha256)
                })
        })
    }

    /// Return a redacted bounded snapshot.
    ///
    /// The listener state and the table are sampled exactly as the
    /// admission readers sample them, and re-sampled until they are a pair
    /// that coexisted; a diagnostic never joins two unrelated readings.
    #[must_use]
    pub fn snapshot(&self) -> PeerReadinessSnapshot {
        let (listener, table) = loop {
            if let Some(sample) = self.sample() {
                break sample;
            }
        };
        PeerReadinessSnapshot {
            listener,
            routes_known: table.routes_known,
            required_routes: table.routes.len(),
            reachable_routes: table
                .routes
                .values()
                .filter(|route| route.state == PeerProbeState::Reachable)
                .count(),
            capacity_ready_routes: table
                .routes
                .values()
                .filter(|route| {
                    route
                        .available_capacity
                        .is_some_and(|available| available >= table.required_capacity)
                })
                .count(),
            available_capacity: table.available_capacity,
            required_capacity: table.required_capacity,
            revision: table.revision,
        }
    }

    /// Return the redacted probe state for one uniquely identified route.
    ///
    /// A duplicate node identifier is treated as ambiguous and returns
    /// `None`; callers must never infer a route result from an arbitrary
    /// endpoint when the verified route set is malformed.
    #[must_use]
    pub fn route_readiness(&self, node_id: &str) -> Option<PeerRouteReadiness> {
        let table = self.current_table();
        let mut matches = table
            .routes
            .values()
            .filter(|route| route.target.node_id() == node_id);
        let route = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(PeerRouteReadiness {
            node_id: route.target.node_id().to_owned(),
            state: route.state,
        })
    }

    /// Return whether all current bounded peer prerequisites hold.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.admission_sample().is_some_and(|(listener, table)| {
            listener == PeerListenerState::Bound && table.routes_ready()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_with_pins(name: &str, pins: &[&str]) -> PeerRouteTarget {
        PeerRouteTarget {
            node_id: name.to_owned(),
            peer_endpoint: format!("10.0.0.{}:8443", name.len()),
            server_name: format!("10.0.0.{}", name.len()),
            approved_spki_sha256: pins.iter().map(|pin| (*pin).to_owned()).collect(),
        }
    }

    async fn ready_with_one_route(proven: bool) -> (PeerReadiness, PeerRouteTarget) {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        let old = target_with_pins("relay-a", &["aa"]);
        let revision = readiness
            .replace_required_routes_with_revision([old.clone()])
            .await
            .expect("route set");
        if proven {
            readiness
                .record_probe_proven_at(revision, &old, "aa")
                .await
                .expect("proven probe");
        } else {
            readiness
                .record_probe_at(revision, &old, PeerProbeState::Reachable)
                .await
                .expect("probe");
        }
        assert!(
            readiness.is_ready(),
            "control: ready after a successful probe"
        );
        (readiness, old)
    }

    /// **M8-C30.** A signed record that only *adds* a key to a peer -- a
    /// staged rotation overlap -- must not withdraw the route's proven
    /// reachability: the key the probe authenticated is still approved.
    #[tokio::test]
    async fn a_pin_addition_keeps_a_route_proven_with_a_still_approved_key() {
        let (readiness, _) = ready_with_one_route(true).await;
        readiness
            .replace_required_routes([target_with_pins("relay-a", &["aa", "bb"])])
            .await
            .expect("overlap route set");
        assert!(
            readiness.is_ready(),
            "M8-C30: staging an overlap key reset a proven route to Pending and \
             withdrew public readiness until the next probe pass"
        );
        // Retiring a key the peer was not presenting keeps it too.
        readiness
            .replace_required_routes([target_with_pins("relay-a", &["aa"])])
            .await
            .expect("restored route set");
        assert!(readiness.is_ready());
    }

    /// The fail-closed side: once the proven key is no longer approved, the
    /// route's evidence is gone and it must be re-probed.
    #[tokio::test]
    async fn retiring_the_proven_key_resets_the_route() {
        let (readiness, _) = ready_with_one_route(true).await;
        readiness
            .replace_required_routes([target_with_pins("relay-a", &["bb"])])
            .await
            .expect("replacement route set");
        assert!(!readiness.is_ready(), "the proven key was retired");
    }

    /// Whether any installed route still carries a probe proof. The proof is
    /// internal state, deliberately absent from every public snapshot.
    fn route_carries_proof(readiness: &PeerReadiness) -> bool {
        readiness
            .current_table()
            .routes
            .values()
            .any(|route| route.proven_spki.is_some())
    }

    /// An unreachable mark withdraws the proof with the reachability: a
    /// later overlap record must not resurrect the route.
    #[tokio::test]
    async fn an_unreachable_route_is_not_revived_by_an_overlap_record() {
        let (readiness, old) = ready_with_one_route(true).await;
        readiness.mark_route_unreachable(&old).await;
        assert!(!readiness.is_ready());
        readiness
            .replace_required_routes([target_with_pins("relay-a", &["aa", "bb"])])
            .await
            .expect("overlap route set");
        assert!(
            !readiness.is_ready(),
            "M8-C30: an overlap record revived a route marked unreachable"
        );
        assert!(
            !route_carries_proof(&readiness),
            "M8-C30: an unreachable route kept its probe proof"
        );
    }

    /// A probe reset withdraws the proof too.
    #[tokio::test]
    async fn a_reset_route_is_not_revived_by_an_overlap_record() {
        let (readiness, _) = ready_with_one_route(true).await;
        readiness.reset_route_probes().await;
        readiness.set_available_capacity(1).await;
        readiness
            .replace_required_routes([target_with_pins("relay-a", &["aa", "bb"])])
            .await
            .expect("overlap route set");
        assert!(!readiness.is_ready(), "a reset route is not ready");
        assert!(
            !route_carries_proof(&readiness),
            "M8-C30: a reset route kept its probe proof"
        );
    }

    /// A proof binds to one route: a record that moves the peer's endpoint is
    /// a different route and must be probed afresh.
    #[tokio::test]
    async fn an_endpoint_change_resets_a_proven_route() {
        let (readiness, _) = ready_with_one_route(true).await;
        let mut moved = target_with_pins("relay-a", &["aa"]);
        moved.peer_endpoint = "10.0.0.99:8443".to_owned();
        readiness
            .replace_required_routes([moved])
            .await
            .expect("moved route set");
        assert!(!readiness.is_ready(), "a moved endpoint kept the old proof");
    }

    /// Without a recorded proof the old rule stands: any pin change resets.
    #[tokio::test]
    async fn a_route_without_a_recorded_proof_still_resets_on_any_pin_change() {
        let (readiness, _) = ready_with_one_route(false).await;
        readiness
            .replace_required_routes([target_with_pins("relay-a", &["aa", "bb"])])
            .await
            .expect("overlap route set");
        assert!(!readiness.is_ready());
    }

    /// A proof must name one of the route's approved pins.
    #[tokio::test]
    async fn a_proof_for_an_unapproved_key_is_refused() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target_with_pins("relay-a", &["aa"]);
        let revision = readiness
            .replace_required_routes_with_revision([route.clone()])
            .await
            .expect("route set");
        assert!(
            readiness
                .record_probe_proven_at(revision, &route, "cc")
                .await
                .is_err()
        );
    }

    fn target(name: &str, pin: &str) -> PeerRouteTarget {
        PeerRouteTarget {
            node_id: name.to_owned(),
            peer_endpoint: format!("10.0.0.{}:8443", name.len()),
            server_name: format!("10.0.0.{}", name.len()),
            approved_spki_sha256: vec![pin.to_owned()],
        }
    }

    #[tokio::test]
    async fn bootstrap_requires_listener_routes_probes_and_capacity() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target("peer-a", "a");
        readiness
            .replace_required_routes([route.clone()])
            .await
            .expect("bounded route set");
        readiness.set_available_capacity(1).await;
        assert!(!readiness.is_ready(), "unbound listener must fail closed");
        readiness.set_listener_state(PeerListenerState::Bound);
        assert!(!readiness.is_ready(), "unprobed route must fail closed");
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .await
            .expect("required route");
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn route_readiness_reports_node_state_without_route_identity_material() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let first = target("peer-a", "a");
        let second = target("peer-b", "b");
        readiness
            .replace_required_routes([first.clone(), second.clone()])
            .await
            .expect("bounded route set");
        readiness
            .record_probe(&first, PeerProbeState::Unreachable)
            .await
            .expect("first route");
        readiness
            .record_probe(&second, PeerProbeState::Reachable)
            .await
            .expect("second route");

        assert_eq!(
            readiness.route_readiness("peer-a"),
            Some(PeerRouteReadiness {
                node_id: "peer-a".to_owned(),
                state: PeerProbeState::Unreachable,
            })
        );
        assert_eq!(
            readiness.route_readiness("peer-b"),
            Some(PeerRouteReadiness {
                node_id: "peer-b".to_owned(),
                state: PeerProbeState::Reachable,
            })
        );
        assert_eq!(readiness.route_readiness("unknown"), None);
    }

    #[tokio::test]
    async fn route_loss_and_capacity_exhaustion_withdraw_readiness_until_recovery() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target("peer-a", "a");
        readiness
            .replace_required_routes([route.clone()])
            .await
            .expect("bounded route set");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .await
            .expect("required route");
        assert!(readiness.is_ready());

        readiness
            .record_probe(&route, PeerProbeState::CapacityExhausted)
            .await
            .expect("required route");
        assert!(!readiness.is_ready());
        readiness.set_available_capacity(0).await;
        assert!(!readiness.is_ready());

        readiness.set_available_capacity(1).await;
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .await
            .expect("fresh probe");
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn explicit_empty_route_set_is_ready_only_after_installation() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        assert!(!readiness.is_ready(), "route set is not yet known");
        readiness
            .replace_required_routes([])
            .await
            .expect("empty one-node route set");
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn route_refresh_resets_state_when_signed_pin_set_changes() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let old = target("peer-a", "a");
        let new = target("peer-a", "b");
        readiness
            .replace_required_routes([old.clone()])
            .await
            .expect("old route");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        readiness
            .record_probe(&old, PeerProbeState::Reachable)
            .await
            .expect("old probe");
        assert!(readiness.is_ready());

        readiness
            .replace_required_routes([new.clone()])
            .await
            .expect("new route");
        assert!(
            !readiness.is_ready(),
            "key replacement requires a fresh probe"
        );
        readiness
            .record_probe(&new, PeerProbeState::Reachable)
            .await
            .expect("new probe");
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn stale_probe_withdraws_readiness_without_a_refresh_task_tick() {
        // The probe is recorded by the owning task, so the control reading
        // below is a task hand-off after the probe instant: the freshness
        // bound has to outlast a hand-off on a loaded machine.
        let readiness = PeerReadiness::new_with_probe_ttl(1, Duration::from_millis(250))
            .expect("short probe freshness");
        let route = target("peer-a", "a");
        readiness
            .replace_required_routes([route.clone()])
            .await
            .expect("bounded route set");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .await
            .expect("route probe");
        assert!(readiness.is_ready());
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !readiness.is_ready(),
            "freshness must be monotonic and fail closed"
        );
    }

    #[tokio::test]
    async fn route_bound_is_capped_without_growing_state() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let routes = (0..=MAX_REQUIRED_PEER_ROUTES)
            .map(|index| target(&format!("peer-{index}"), "a"))
            .collect::<Vec<_>>();
        let error = readiness
            .replace_required_routes(routes)
            .await
            .expect_err("route bound");
        assert_eq!(
            error,
            PeerReadinessError::TooManyRoutes {
                observed: MAX_REQUIRED_PEER_ROUTES + 1,
                maximum: MAX_REQUIRED_PEER_ROUTES,
            }
        );
        assert!(!readiness.snapshot().routes_known);
    }

    #[tokio::test]
    async fn stale_probe_revision_cannot_republish_after_same_target_refresh() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target("peer-a", "a");
        let first = readiness
            .replace_required_routes_with_revision([route.clone()])
            .await
            .expect("first route revision");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        let second = readiness
            .replace_required_routes_with_revision([route.clone()])
            .await
            .expect("second route revision");
        assert!(second > first);
        assert!(
            !readiness
                .record_probe_at(first, &route, PeerProbeState::Reachable)
                .await
                .expect("stale result is handled")
        );
        assert!(!readiness.is_ready(), "stale success must not publish");
        assert!(
            readiness
                .record_probe_at(second, &route, PeerProbeState::Reachable)
                .await
                .expect("current result is handled")
        );
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn route_capacity_failures_are_independent() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let first = target("peer-a", "a");
        let second = target("peer-b", "b");
        readiness
            .replace_required_routes([first.clone(), second.clone()])
            .await
            .expect("routes");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        readiness
            .record_probe(&first, PeerProbeState::Reachable)
            .await
            .expect("first route");
        readiness
            .record_probe(&second, PeerProbeState::Reachable)
            .await
            .expect("second route");
        assert!(readiness.is_ready());

        readiness
            .record_probe(&second, PeerProbeState::CapacityExhausted)
            .await
            .expect("second capacity failure");
        readiness
            .record_probe(&first, PeerProbeState::Reachable)
            .await
            .expect("first route remains healthy");
        assert!(
            !readiness.is_ready(),
            "one route capacity failure must gate all"
        );
        assert_eq!(readiness.snapshot().capacity_ready_routes, 1);

        readiness
            .record_probe(&second, PeerProbeState::Reachable)
            .await
            .expect("second route recovers");
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn rotating_pin_set_fences_old_probe_even_when_route_key_is_same() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let old = target("peer-a", "old");
        let new = target("peer-a", "new");
        let old_revision = readiness
            .replace_required_routes_with_revision([old.clone()])
            .await
            .expect("old route");
        let new_revision = readiness
            .replace_required_routes_with_revision([new.clone()])
            .await
            .expect("rotated route");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        assert!(
            !readiness
                .record_probe_at(old_revision, &old, PeerProbeState::Reachable)
                .await
                .expect("old result is handled")
        );
        assert!(!readiness.is_ready());
        assert!(
            readiness
                .record_probe_at(new_revision, &new, PeerProbeState::Reachable)
                .await
                .expect("new result is handled")
        );
        assert!(readiness.is_ready());
    }

    #[tokio::test]
    async fn binding_failure_matches_one_pin_inside_signed_overlap_without_accepting_wrong_pin() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let signed = PeerRouteTarget::for_test(
            "peer-a",
            "10.0.0.1:8443",
            "peer-a.internal",
            vec!["old-pin".to_owned(), "next-pin".to_owned()],
        );
        let observed_old = PeerRouteTarget::for_test(
            "peer-a",
            "10.0.0.1:8443",
            "peer-a.internal",
            vec!["old-pin".to_owned()],
        );
        let observed_wrong = PeerRouteTarget::for_test(
            "peer-a",
            "10.0.0.1:8443",
            "peer-a.internal",
            vec!["unapproved-pin".to_owned()],
        );
        readiness
            .replace_required_routes([signed.clone()])
            .await
            .expect("signed route");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1).await;
        readiness
            .record_probe(&signed, PeerProbeState::Reachable)
            .await
            .expect("signed route probe");
        assert!(readiness.is_ready());

        readiness.mark_route_unreachable(&observed_wrong).await;
        assert!(readiness.is_ready(), "wrong pin must not mark the route");
        readiness.mark_route_unreachable(&observed_old).await;
        assert!(
            !readiness.is_ready(),
            "overlap binding must mark route loss"
        );
    }

    /// Fill the owner's queue without letting the owner run: each change is
    /// queued on its first poll, and nothing here yields to the runtime.
    macro_rules! fill_owner_queue {
        ($readiness:expr) => {{
            let mut queued = Vec::new();
            for _ in 0..ROUTE_TABLE_QUEUE {
                let mut change = Box::pin($readiness.set_available_capacity(1));
                assert!(futures_util::poll!(change.as_mut()).is_pending());
                queued.push(change);
            }
            queued
        }};
    }

    /// The reviewed interleaving: the owner's queue is full, a failed open
    /// marks its route, and the caller is cancelled while it waits for
    /// room.  The mark must stand at once and after the queue drains.
    #[tokio::test]
    async fn a_mark_cancelled_behind_a_full_queue_still_withdraws_the_route() {
        let (readiness, route) = ready_with_one_route(true).await;
        let queued = fill_owner_queue!(readiness);
        {
            let mut mark = Box::pin(readiness.mark_route_unreachable(&route));
            assert!(
                futures_util::poll!(mark.as_mut()).is_pending(),
                "control: the mark is waiting for room in the full queue"
            );
            // The caller's request future is cancelled here.
        }
        assert!(
            !readiness.is_ready(),
            "a cancelled mark behind a full queue left the route ready"
        );
        assert_eq!(
            readiness
                .route_readiness("relay-a")
                .map(|route| route.state),
            Some(PeerProbeState::Unreachable)
        );
        assert_eq!(readiness.snapshot().reachable_routes, 0);
        for change in queued {
            change.await;
        }
        assert!(
            !readiness.is_ready(),
            "the queued changes issued before the mark erased it"
        );
        assert_eq!(readiness.snapshot().reachable_routes, 0);
        // A probe issued after the mark recovers the route as before.
        let revision = readiness.current_revision();
        assert!(
            readiness
                .record_probe_proven_at(revision, &route, "aa")
                .await
                .expect("fresh probe")
        );
        assert!(readiness.is_ready());
    }

    /// Every other withdrawal survives the same cancellation: capacity,
    /// the probe reset, and the trust (empty route set) withdrawal.
    #[tokio::test]
    async fn withdrawals_cancelled_behind_a_full_queue_still_withdraw() {
        let (readiness, _) = ready_with_one_route(true).await;
        let queued = fill_owner_queue!(readiness);
        drop({
            let mut clear = Box::pin(readiness.clear_available_capacity());
            assert!(futures_util::poll!(clear.as_mut()).is_pending());
            clear
        });
        assert!(!readiness.is_ready(), "capacity withdrawal was lost");
        for change in queued {
            change.await;
        }
        assert!(
            !readiness.is_ready(),
            "an older capacity observation erased a newer withdrawal"
        );
        assert_eq!(readiness.snapshot().available_capacity, None);

        let (readiness, _) = ready_with_one_route(true).await;
        let before = readiness.current_revision();
        let queued = fill_owner_queue!(readiness);
        drop({
            let mut reset = Box::pin(readiness.reset_route_probes());
            assert!(futures_util::poll!(reset.as_mut()).is_pending());
            reset
        });
        assert!(!readiness.is_ready(), "probe reset was lost");
        assert!(readiness.current_revision() > before);
        for change in queued {
            change.await;
        }
        assert!(!readiness.is_ready());
        assert!(!route_carries_proof(&readiness));

        let (readiness, _) = ready_with_one_route(true).await;
        assert!(readiness.accepts_probe("relay-a", "aa"));
        let queued = fill_owner_queue!(readiness);
        drop({
            let mut withdraw = Box::pin(readiness.replace_required_routes([]));
            assert!(futures_util::poll!(withdraw.as_mut()).is_pending());
            withdraw
        });
        assert!(
            !readiness.accepts_probe("relay-a", "aa"),
            "trust withdrawal was lost"
        );
        for change in queued {
            change.await;
        }
        assert!(!readiness.accepts_probe("relay-a", "aa"));
        assert_eq!(readiness.snapshot().required_routes, 0);
    }

    /// A success issued before a mark cannot clear it, and a mark issued
    /// before a success cannot erase it, whatever order the owner gets to
    /// them in.
    #[tokio::test]
    async fn marks_and_probes_keep_their_issue_order() {
        let (readiness, route) = ready_with_one_route(true).await;
        let revision = readiness.current_revision();
        let mut older_probe = Box::pin(readiness.record_probe_proven_at(revision, &route, "aa"));
        assert!(futures_util::poll!(older_probe.as_mut()).is_pending());
        readiness.mark_route_unreachable(&route).await;
        assert!(
            !older_probe.await.expect("older probe is handled"),
            "a success issued before the mark was published over it"
        );
        assert!(!readiness.is_ready());

        let mut older_mark = Box::pin(readiness.mark_route_unreachable(&route));
        assert!(futures_util::poll!(older_mark.as_mut()).is_pending());
        assert!(
            readiness
                .record_probe_proven_at(revision, &route, "aa")
                .await
                .expect("newer probe")
        );
        older_mark.await;
        assert!(
            readiness.is_ready(),
            "a mark issued before the success erased it"
        );
    }
}
