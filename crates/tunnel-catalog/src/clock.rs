//! The one cluster-internal clock-skew bound (task row M7-C173).
//!
//! Every relay-to-relay and relay-to-Redis wall-clock comparison accepts the
//! same skew: signed membership records and checkpoints
//! (`tunnel-cluster`), signed recovery approvals ([`crate::recovery`]), the
//! Redis authority's timestamped scripts, the relay's `[cluster]`
//! `max_clock_skew_seconds` ceiling, and the clock-offset readiness check.
//! They all derive from [`MAX_CLUSTER_CLOCK_SKEW_SECONDS`]; nothing else may
//! hard-code a skew.
//!
//! Why five seconds (a coordinator decision under the owner's delegation,
//! 2026-09-27): a signed membership record lives at most 60 s and is
//! refreshed every 20 s or sooner, and attachment tickets live 10-30 s. A
//! skew of 30-60 s would roughly double the bounded revocation delay
//! (record lifetime plus skew), so five seconds is the limit. It is well
//! above what NTP-disciplined hosts drift, and small against every window
//! it widens. Consumer OIDC tokens are *not* cluster-internal and use their
//! own leeway ([`crate::DEFAULT_OIDC_LEEWAY_SECONDS`]).

use std::time::Duration;

/// The cluster-internal clock-skew bound, in whole seconds.
pub const MAX_CLUSTER_CLOCK_SKEW_SECONDS: u64 = 5;

/// [`MAX_CLUSTER_CLOCK_SKEW_SECONDS`] as a monotonic-style duration.
pub const MAX_CLUSTER_CLOCK_SKEW: Duration = Duration::from_secs(MAX_CLUSTER_CLOCK_SKEW_SECONDS);

/// [`MAX_CLUSTER_CLOCK_SKEW_SECONDS`] as a signed wall-clock delta.
#[allow(clippy::cast_possible_wrap)]
pub const MAX_CLUSTER_CLOCK_SKEW_WALL: chrono::TimeDelta =
    chrono::TimeDelta::seconds(MAX_CLUSTER_CLOCK_SKEW_SECONDS as i64);

/// [`MAX_CLUSTER_CLOCK_SKEW_SECONDS`] in microseconds, the unit of the Redis
/// authority scripts.
#[allow(clippy::cast_possible_wrap)]
pub const MAX_CLUSTER_CLOCK_SKEW_US: i64 = (MAX_CLUSTER_CLOCK_SKEW_SECONDS as i64) * 1_000_000;

/// A relay whose measured offset from the Redis server clock exceeds this
/// logs a warning (it is still ready up to [`MAX_CLUSTER_CLOCK_SKEW`]).
pub const CLOCK_OFFSET_WARN: Duration = Duration::from_secs(2);

const _: () = assert!(CLOCK_OFFSET_WARN.as_secs() < MAX_CLUSTER_CLOCK_SKEW_SECONDS);
const _: () = assert!(MAX_CLUSTER_CLOCK_SKEW_SECONDS > 0 && MAX_CLUSTER_CLOCK_SKEW_SECONDS <= 5);
