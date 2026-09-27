//! This relay's wall-clock offset from its Redis authority (task row M7-C175).
//!
//! Every cluster-internal wall-clock comparison accepts at most
//! [`MAX_CLUSTER_CLOCK_SKEW`] of skew (M7-C173): signed membership records
//! and checkpoints, recovery approvals and the Redis authority's timestamped
//! scripts. A relay whose clock drifts past that bound starts refusing (or
//! being refused) in ways that look like authorization faults. This module
//! makes the drift visible before that and takes the relay out of rotation
//! once it passes the bound.
//!
//! One background task reads the Redis server clock (`TIME`, through
//! [`tunnel_catalog::Catalog::authority_time`]) every [`OFFSET_INTERVAL`],
//! bounded by [`OFFSET_DEADLINE`], and estimates the offset as the local
//! clock at the midpoint of the read minus the server's answer. The estimate
//! is uncertain by at most half the read's round trip, which the deadline
//! bounds.
//!
//! - The offset is published as a payload-free gauge (milliseconds, signed:
//!   positive means this relay's clock is ahead of Redis).
//! - Above [`CLOCK_OFFSET_WARN`] (2 s) the relay logs a warning once per
//!   change of state.
//! - Above [`MAX_CLUSTER_CLOCK_SKEW`] (5 s) `/readyz` answers not ready until
//!   a measurement is back within the bound.
//!
//! A failed or timed-out read changes nothing but a counter: Redis being
//! unavailable is judged by the authority and membership readiness checks,
//! and this check keeps its last verdict, so a relay found beyond the bound
//! stays not ready until a measurement says otherwise. Before the first
//! measurement the relay is within the bound (`serve` has just reached
//! Redis; the first read runs at once). A catalog without a separate clock
//! (the process-local catalog) is never measured.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    CatalogError, SharedCatalog,
    clock::{CLOCK_OFFSET_WARN, MAX_CLUSTER_CLOCK_SKEW},
};

/// How often the offset is measured.
pub(crate) const OFFSET_INTERVAL: Duration = Duration::from_secs(5);

/// The bound on one `TIME` read: the lane's verification and reply
/// deadlines (2 s each) and one second of margin, as for the authority check.
pub(crate) const OFFSET_DEADLINE: Duration = Duration::from_secs(5);

/// Where a measured offset falls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OffsetVerdict {
    /// At most [`CLOCK_OFFSET_WARN`].
    Within,
    /// Above [`CLOCK_OFFSET_WARN`], at most [`MAX_CLUSTER_CLOCK_SKEW`]:
    /// still ready, logged.
    Warn,
    /// Above [`MAX_CLUSTER_CLOCK_SKEW`]: not ready.
    Beyond,
}

impl OffsetVerdict {
    /// Classify a signed offset by its magnitude.
    pub(crate) fn of(offset: TimeDelta) -> Self {
        let magnitude = offset.abs().to_std().unwrap_or(Duration::MAX);
        if magnitude > MAX_CLUSTER_CLOCK_SKEW {
            Self::Beyond
        } else if magnitude > CLOCK_OFFSET_WARN {
            Self::Warn
        } else {
            Self::Within
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Within => 0,
            Self::Warn => 1,
            Self::Beyond => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Within,
            1 => Self::Warn,
            _ => Self::Beyond,
        }
    }
}

/// This relay's local wall clock; injected in tests.
pub(crate) trait LocalClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// The system wall clock.
pub(crate) struct SystemClock;

impl LocalClock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// The authority's wall clock; the catalog in production, injected in tests.
pub(crate) trait AuthorityClock: Send + Sync {
    fn authority_time(
        &self,
    ) -> impl Future<Output = Result<Option<DateTime<Utc>>, CatalogError>> + Send;
}

/// The catalog's authority clock (Redis `TIME`).
pub(crate) struct CatalogClock(pub(crate) SharedCatalog);

impl AuthorityClock for CatalogClock {
    fn authority_time(
        &self,
    ) -> impl Future<Output = Result<Option<DateTime<Utc>>, CatalogError>> + Send {
        let catalog = self.0.clone();
        async move { catalog.authority_time().await }
    }
}

/// The outcome of one read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Measurement {
    /// The estimated offset, local minus authority.
    Offset(TimeDelta),
    /// The authority has no separate clock; stop measuring.
    Unsupported,
    /// The read failed or exceeded [`OFFSET_DEADLINE`].
    Failed,
}

/// One bounded offset measurement.
pub(crate) async fn measure<A: AuthorityClock, L: LocalClock + ?Sized>(
    authority: &A,
    local: &L,
    deadline: Duration,
) -> Measurement {
    let before = local.now();
    let answer = tokio::time::timeout(deadline, authority.authority_time()).await;
    let after = local.now();
    match answer {
        Ok(Ok(Some(server))) => {
            let midpoint = before + (after - before) / 2;
            Measurement::Offset(midpoint - server)
        }
        Ok(Ok(None)) => Measurement::Unsupported,
        Ok(Err(_)) | Err(_) => Measurement::Failed,
    }
}

/// The published clock-offset state. Payload-free: a signed offset in
/// milliseconds, a verdict and counters.
pub(crate) struct ClockOffsetHealth {
    offset_ms: AtomicI64,
    measured: AtomicBool,
    verdict: AtomicU8,
    measurements: AtomicU64,
    failures: AtomicU64,
}

impl ClockOffsetHealth {
    pub(crate) fn new() -> Self {
        Self {
            offset_ms: AtomicI64::new(0),
            measured: AtomicBool::new(false),
            verdict: AtomicU8::new(OffsetVerdict::Within.as_u8()),
            measurements: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    /// Whether the last measurement (if any) was within the cluster
    /// clock-skew bound. Reads one atomic.
    pub(crate) fn is_ready(&self) -> bool {
        self.verdict() != OffsetVerdict::Beyond
    }

    pub(crate) fn verdict(&self) -> OffsetVerdict {
        OffsetVerdict::from_u8(self.verdict.load(Ordering::Acquire))
    }

    /// The last measured offset in milliseconds, local minus authority;
    /// `None` before the first measurement.
    pub(crate) fn offset_ms(&self) -> Option<i64> {
        self.measured
            .load(Ordering::Acquire)
            .then(|| self.offset_ms.load(Ordering::Acquire))
    }

    pub(crate) fn measurements(&self) -> u64 {
        self.measurements.load(Ordering::Relaxed)
    }

    pub(crate) fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Apply one measurement and return the verdict transition, if any, so
    /// the caller can log it once.
    pub(crate) fn record(
        &self,
        measurement: &Measurement,
    ) -> Option<(OffsetVerdict, OffsetVerdict)> {
        match measurement {
            Measurement::Offset(offset) => {
                self.measurements.fetch_add(1, Ordering::Relaxed);
                self.offset_ms
                    .store(offset.num_milliseconds(), Ordering::Release);
                self.measured.store(true, Ordering::Release);
                let next = OffsetVerdict::of(*offset);
                let previous =
                    OffsetVerdict::from_u8(self.verdict.swap(next.as_u8(), Ordering::AcqRel));
                (previous != next).then_some((previous, next))
            }
            Measurement::Failed => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                None
            }
            Measurement::Unsupported => None,
        }
    }

    /// Start the measurement loop against `catalog`; it stops when `cancel`
    /// fires or the catalog has no separate clock.
    pub(crate) fn spawn(catalog: SharedCatalog, cancel: CancellationToken) -> Arc<Self> {
        let health = Arc::new(Self::new());
        let state = health.clone();
        let authority = CatalogClock(catalog);
        tokio::spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = measure_loop(&authority, &SystemClock, &state, OFFSET_INTERVAL) => {}
            }
        });
        health
    }
}

/// Log one verdict transition in fixed words; only the offset in
/// milliseconds is attached.
fn log_transition(offset_ms: i64, previous: OffsetVerdict, next: OffsetVerdict) {
    match next {
        OffsetVerdict::Beyond => tracing::warn!(
            offset_ms,
            bound_ms = MAX_CLUSTER_CLOCK_SKEW.as_millis() as u64,
            "relay clock offset from Redis exceeds the cluster clock-skew bound; not ready"
        ),
        OffsetVerdict::Warn => tracing::warn!(
            offset_ms,
            warn_ms = CLOCK_OFFSET_WARN.as_millis() as u64,
            "relay clock offset from Redis is above the warning threshold"
        ),
        OffsetVerdict::Within => {
            tracing::info!(offset_ms, "relay clock offset from Redis is normal")
        }
    }
    if previous == OffsetVerdict::Beyond && next != OffsetVerdict::Beyond {
        tracing::info!(
            offset_ms,
            "relay clock offset back within the bound; readiness restored"
        );
    }
}

pub(crate) async fn measure_loop<A: AuthorityClock, L: LocalClock + ?Sized>(
    authority: &A,
    local: &L,
    state: &ClockOffsetHealth,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let measurement = measure(authority, local, OFFSET_DEADLINE).await;
        if measurement == Measurement::Unsupported {
            return;
        }
        if let (Some((previous, next)), Some(offset_ms)) =
            (state.record(&measurement), state.offset_ms())
        {
            log_transition(offset_ms, previous, next);
        }
    }
}

#[cfg(test)]
#[path = "clock_offset_tests.rs"]
mod tests;
