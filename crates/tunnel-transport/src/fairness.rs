//! Connection turnover while a public listener is full (task row M6-C193).
//!
//! A listener permit is held for a whole keep-alive connection
//! ([`crate::ListenerCapacity`]).  Without turnover, a client that holds every
//! permit with busy keep-alive connections keeps them for as long as it keeps
//! sending, and every client that connects later is refused
//! `503 CONNECTION_LIMIT` for the whole flood.  The listener cannot tell users
//! apart when it takes a permit (that happens at accept, before TLS and before
//! any bearer token is read), so fairness here is by turnover, not identity.
//!
//! **Pressure.** A listener is *under pressure* while a connection has
//! arrived with every permit held within the last [`PRESSURE_WINDOW`], that
//! is, it was refused for capacity or had to wait for a permit.  A pressure
//! episode begins with the first such arrival after at least one quiet window.
//!
//! **Turnover.** Under pressure, a served connection that has lived at least
//! its own age budget -- drawn once per connection, uniformly between 50% and
//! 100% of [`ListenerTurnover::max_age`] -- or served at least
//! [`ListenerTurnover::max_requests`] requests, *since the episode began* is
//! closed after its current response.  The per-connection draw keeps permits
//! freeing continuously: with one fixed age, every replacement started at the
//! same burst instant and the bursts repeated every `max_age` for the whole
//! flood (hosted runs 36281427390 / 36281441437, before the jitter).  It is
//! closed HTTP/1.1 by `Connection: close` on that
//! response, HTTP/2 by a graceful GOAWAY that lets in-flight streams finish.
//! A `101 Switching Protocols` response never carries the close, and nothing
//! is ever cut mid-response.  Outside pressure nothing changes.
//!
//! **Hand-off.** A freed permit must reach a client that was waiting, not the
//! recycled client's own immediate reconnect, which is usually already in the
//! listen backlog when the permit frees.  So on a listener with turnover, a
//! connection accepted over the limit first waits up to [`HANDOFF_WAIT`],
//! before any TLS work, in the permit semaphore's FIFO queue, holding the
//! refusal-margin slot it was accepted with.  If a permit frees in that time
//! it is served; otherwise it is refused `503 CONNECTION_LIMIT` exactly as
//! before (M6-C153).  Waiting clients get permits in arrival order, in
//! proportion to how many connections each has waiting.  Because each margin
//! slot now refuses at most about twice a second, a flood that does not back
//! off is slowed: arrivals beyond about `2 x refusal_margin` per second wait
//! in the kernel backlog, and beyond the backlog can see a connect timeout
//! instead of a `503`.  A separate hand-off queue with an instant `503` when
//! full was tried and rejected (coordinator decision under the owner's
//! delegation, 2026-09-27): the flood kept the queue full, refusals returned
//! to about 560 -- 1,330/s and a late client went unserved (hosted runs
//! 36283563574, 36284228822).  Measured before the hand-off existed (M6-C193 test at small
//! scale): 80 recycled permits in 20 s all went back to flood workers, and a
//! client connecting every 20 ms was refused 855 times out of 855.
//!
//! Every value here is a count, a flag or a duration: no address, identifier
//! or payload is retained.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, LazyLock, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;

use crate::server::TransportError;

/// How recently a connection must have arrived with every permit held for
/// the listener to be under pressure.
pub const PRESSURE_WINDOW: Duration = Duration::from_secs(1);

/// Default [`ListenerTurnover::max_age`].
pub const DEFAULT_TURNOVER_MAX_AGE: Duration = Duration::from_secs(10);

/// Default [`ListenerTurnover::max_requests`].
pub const DEFAULT_TURNOVER_MAX_REQUESTS: u64 = 1_000;

/// Smallest accepted [`ListenerTurnover::max_age`].
pub const MIN_TURNOVER_MAX_AGE: Duration = Duration::from_secs(1);

/// Largest accepted [`ListenerTurnover::max_age`].
pub const MAX_TURNOVER_MAX_AGE: Duration = Duration::from_secs(3_600);

/// Largest accepted [`ListenerTurnover::max_requests`].
pub const MAX_TURNOVER_MAX_REQUESTS: u64 = 1_000_000;

/// How long a connection accepted over the limit on a listener with turnover
/// waits for a freed permit, before TLS, before it is refused.  Half the
/// refusal's `retry_after_ms`.  The refusal's own deadline
/// ([`crate::ListenerCapacity::refusal_timeout`]) starts only after this
/// wait, so a hand-off connection that is refused is bounded by the sum.
pub const HANDOFF_WAIT: Duration = Duration::from_millis(500);

/// When a served keep-alive connection is recycled while its listener is
/// under pressure (task row M6-C193).  Set only on the public consumer
/// listener: device control and data sockets are never recycled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerTurnover {
    /// Connection age, counted from the later of its first byte and the start
    /// of the pressure episode, after which it is recycled.  Default
    /// [`DEFAULT_TURNOVER_MAX_AGE`]; accepts 1 s..=3600 s.
    pub max_age: Duration,
    /// Requests served since the pressure episode began after which the
    /// connection is recycled.  Default [`DEFAULT_TURNOVER_MAX_REQUESTS`];
    /// accepts 1..=1,000,000.
    pub max_requests: u64,
}

impl Default for ListenerTurnover {
    fn default() -> Self {
        Self {
            max_age: DEFAULT_TURNOVER_MAX_AGE,
            max_requests: DEFAULT_TURNOVER_MAX_REQUESTS,
        }
    }
}

impl ListenerTurnover {
    /// Validate both bounds.
    pub fn validate(&self) -> Result<(), TransportError> {
        if !(MIN_TURNOVER_MAX_AGE..=MAX_TURNOVER_MAX_AGE).contains(&self.max_age) {
            return Err(TransportError::InvalidListenerTurnover {
                field: "max_age",
                reason: "must be 1s..=3600s",
            });
        }
        if !(1..=MAX_TURNOVER_MAX_REQUESTS).contains(&self.max_requests) {
            return Err(TransportError::InvalidListenerTurnover {
                field: "max_requests",
                reason: "must be 1..=1000000",
            });
        }
        Ok(())
    }
}

/// A process-wide, payload-free view of one named listener's pressure and
/// turnover, for the relay's `/metrics` (task row M6-C193).  Listeners that
/// share a name in one process (test fixtures) are summed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListenerFairnessSnapshot {
    /// The listener's fixed name (`consumer`, `device`, `unnamed`).
    pub listener: &'static str,
    /// Whether a connection arrived with every permit held within the last
    /// [`PRESSURE_WINDOW`].
    pub under_pressure: bool,
    /// Pressure episodes begun.
    pub pressure_episodes: u64,
    /// Connections answered `503 CONNECTION_LIMIT` (M6-C153).
    pub capacity_refusals: u64,
    /// Connections accepted over the limit that were served with a permit
    /// freed within [`HANDOFF_WAIT`].
    pub handoffs: u64,
    /// Served connections closed for turnover while under pressure.
    pub recycled: u64,
}

/// The process-wide per-name counters behind [`listener_fairness`].
#[derive(Debug, Default)]
struct NamedCounters {
    last_full_ms: AtomicU64,
    pressure_episodes: AtomicU64,
    capacity_refusals: AtomicU64,
    handoffs: AtomicU64,
    recycled: AtomicU64,
}

static PROCESS_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

static NAMED: LazyLock<Mutex<BTreeMap<&'static str, Arc<NamedCounters>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn named(listener: &'static str) -> Arc<NamedCounters> {
    NAMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(listener)
        .or_default()
        .clone()
}

/// Milliseconds since the process epoch, plus one, so zero can mean "never".
fn now_mark() -> u64 {
    u64::try_from(PROCESS_EPOCH.elapsed().as_millis())
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1)
}

fn window_ms() -> u64 {
    u64::try_from(PRESSURE_WINDOW.as_millis()).unwrap_or(u64::MAX)
}

/// Every named listener's pressure and turnover counters in this process, in
/// name order.
pub fn listener_fairness() -> Vec<ListenerFairnessSnapshot> {
    let now = now_mark();
    NAMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(listener, counters)| {
            let last = counters.last_full_ms.load(Ordering::Acquire);
            ListenerFairnessSnapshot {
                listener,
                under_pressure: last != 0 && now.saturating_sub(last) <= window_ms(),
                pressure_episodes: counters.pressure_episodes.load(Ordering::Acquire),
                capacity_refusals: counters.capacity_refusals.load(Ordering::Acquire),
                handoffs: counters.handoffs.load(Ordering::Acquire),
                recycled: counters.recycled.load(Ordering::Acquire),
            }
        })
        .collect()
}

/// One listener instance's pressure state.  Only the accept loop writes it.
#[derive(Debug)]
pub(crate) struct ListenerPressure {
    last_full_ms: AtomicU64,
    episode_start_ms: AtomicU64,
    episode: AtomicU64,
    named: Arc<NamedCounters>,
    diagnostics: Option<crate::AcceptedSocketDiagnostics>,
}

impl ListenerPressure {
    pub(crate) fn new(
        listener: &'static str,
        diagnostics: Option<crate::AcceptedSocketDiagnostics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            last_full_ms: AtomicU64::new(0),
            episode_start_ms: AtomicU64::new(0),
            episode: AtomicU64::new(0),
            named: named(listener),
            diagnostics,
        })
    }

    /// Record one connection accepted while every permit was held, starting
    /// a new episode if the previous one is older than [`PRESSURE_WINDOW`].
    /// Only the accept loop calls it.
    pub(crate) fn record_full(&self) {
        let now = now_mark();
        let last = self.last_full_ms.load(Ordering::Acquire);
        if last == 0 || now.saturating_sub(last) > window_ms() {
            self.episode_start_ms.store(now, Ordering::Release);
            self.episode.fetch_add(1, Ordering::AcqRel);
            self.named.pressure_episodes.fetch_add(1, Ordering::AcqRel);
        }
        self.last_full_ms.store(now, Ordering::Release);
        self.named.last_full_ms.store(now, Ordering::Release);
    }

    /// Count one `503 CONNECTION_LIMIT` refusal.
    pub(crate) fn record_refusal(&self) {
        self.named.capacity_refusals.fetch_add(1, Ordering::AcqRel);
    }

    /// Count one over-limit connection served with a handed-off permit.
    pub(crate) fn record_handoff(&self) {
        self.named.handoffs.fetch_add(1, Ordering::AcqRel);
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.record_fairness_handoff();
        }
    }

    /// The current episode and its start, or `None` when not under pressure.
    fn current(&self, now: u64) -> Option<(u64, u64)> {
        let last = self.last_full_ms.load(Ordering::Acquire);
        if last == 0 || now.saturating_sub(last) > window_ms() {
            return None;
        }
        Some((
            self.episode.load(Ordering::Acquire),
            self.episode_start_ms.load(Ordering::Acquire),
        ))
    }

    fn record_recycle(&self) {
        self.named.recycled.fetch_add(1, Ordering::AcqRel);
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.record_fairness_recycle();
        }
    }
}

/// A per-connection age budget, uniform in `[max_age / 2, max_age]` at
/// millisecond resolution, from `random`.
pub(crate) fn jittered_age(max_age: Duration, random: u64) -> Duration {
    let max_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
    let half = max_ms / 2;
    let spread = max_ms - half;
    Duration::from_millis(half + random % spread.saturating_add(1))
}

/// A random `u64` from the standard library's per-instance random hasher
/// keys; enough to spread turnover, not for anything secret.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::hash::RandomState::new().build_hasher();
    hasher.write_u64(now_mark());
    hasher.finish()
}

#[derive(Debug, Default)]
struct TurnoverCounts {
    requests: u64,
    episode: u64,
    requests_before_episode: u64,
    recycled: bool,
}

/// One served connection's turnover state.
#[derive(Debug)]
pub(crate) struct ConnectionTurnover {
    policy: ListenerTurnover,
    /// This connection's age budget: uniform in `[max_age / 2, max_age]`.
    age_budget: Duration,
    pressure: Arc<ListenerPressure>,
    started_ms: u64,
    counts: Mutex<TurnoverCounts>,
    /// Cancelled once an HTTP/2 connection is to send GOAWAY.
    pub(crate) goaway: CancellationToken,
}

impl ConnectionTurnover {
    pub(crate) fn new(policy: ListenerTurnover, pressure: Arc<ListenerPressure>) -> Arc<Self> {
        Arc::new(Self {
            policy,
            age_budget: jittered_age(policy.max_age, random_u64()),
            pressure,
            started_ms: now_mark(),
            counts: Mutex::new(TurnoverCounts::default()),
            goaway: CancellationToken::new(),
        })
    }

    /// Count one dispatched request.
    pub(crate) fn on_request(&self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        counts.requests = counts.requests.saturating_add(1);
    }

    /// Whether this connection is to close after the response now being
    /// returned.  True at most once per connection.
    pub(crate) fn recycle_now(&self) -> bool {
        let now = now_mark();
        let Some((episode, episode_start)) = self.pressure.current(now) else {
            return false;
        };
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if counts.recycled {
            return false;
        }
        if counts.episode != episode {
            // First response this connection returns in this episode: the
            // request being answered is the first counted in it.
            counts.episode = episode;
            counts.requests_before_episode = counts.requests.saturating_sub(1);
        }
        let from = self.started_ms.max(episode_start);
        let age = Duration::from_millis(now.saturating_sub(from));
        let served = counts
            .requests
            .saturating_sub(counts.requests_before_episode);
        if age < self.age_budget && served < self.policy.max_requests {
            return false;
        }
        counts.recycled = true;
        drop(counts);
        self.pressure.record_recycle();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turnover_bounds_are_validated() {
        ListenerTurnover::default().validate().expect("default");
        for invalid in [
            ListenerTurnover {
                max_age: Duration::from_millis(999),
                ..ListenerTurnover::default()
            },
            ListenerTurnover {
                max_age: Duration::from_secs(3_601),
                ..ListenerTurnover::default()
            },
            ListenerTurnover {
                max_requests: 0,
                ..ListenerTurnover::default()
            },
            ListenerTurnover {
                max_requests: 1_000_001,
                ..ListenerTurnover::default()
            },
        ] {
            invalid.validate().expect_err("out of range");
        }
    }

    #[test]
    fn nothing_recycles_without_pressure_and_request_budget_recycles_under_it() {
        let pressure = ListenerPressure::new("fairness-unit", None);
        let turnover = ConnectionTurnover::new(
            ListenerTurnover {
                max_age: Duration::from_secs(3_600),
                max_requests: 3,
            },
            pressure.clone(),
        );
        for _ in 0..10 {
            turnover.on_request();
            assert!(!turnover.recycle_now(), "recycled without pressure");
        }
        pressure.record_full();
        // Requests before the episode do not count against its budget.
        turnover.on_request();
        assert!(!turnover.recycle_now());
        turnover.on_request();
        assert!(!turnover.recycle_now());
        turnover.on_request();
        assert!(turnover.recycle_now(), "the third request in the episode");
        turnover.on_request();
        assert!(!turnover.recycle_now(), "recycled twice");
    }

    /// M6-C193 review (B2): each connection's age budget is drawn uniformly
    /// in `[max_age / 2, max_age]`, so budgets differ between connections.
    #[test]
    fn age_budgets_are_jittered_between_half_and_full_max_age() {
        let max_age = Duration::from_secs(10);
        assert_eq!(jittered_age(max_age, 0), Duration::from_secs(5));
        assert_eq!(jittered_age(max_age, 5_000), Duration::from_secs(10));
        let budgets: Vec<Duration> = (0..200)
            .map(|_| jittered_age(max_age, random_u64()))
            .collect();
        assert!(
            budgets
                .iter()
                .all(|b| (Duration::from_secs(5)..=max_age).contains(b))
        );
        let low = budgets
            .iter()
            .filter(|b| **b < Duration::from_millis(7_500))
            .count();
        assert!(
            (40..=160).contains(&low),
            "not spread: {low} of 200 below the midpoint"
        );
    }
}
