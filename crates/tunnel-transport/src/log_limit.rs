//! A bounded rate limit for refusal log lines an unauthenticated peer can
//! trigger (task row M6-C52, review of `m6-client`).
//!
//! A refusal line is written before the peer has proved anything -- a TLS
//! handshake with no or a self-signed client certificate, a request with no or
//! a junk bearer token -- so without a limit anyone who can reach a public
//! listener decides how fast the relay's `info` log grows.  Admission bounds
//! concurrency, not rate.  This limiter admits at most `burst` lines per
//! `window` for each fixed key (the refusal's stage or label), counts the rest,
//! and hands that count to the next admitted line for the key, which logs it
//! as `suppressed`.  During a sustained flood that is one line per key per
//! window carrying the previous window's suppressed count; when the flood
//! stops, the count is reported by the next refusal of that key.
//!
//! The state is one small entry per key, and keys are `&'static str` labels
//! the caller chooses from a closed set, so the limiter itself is bounded.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Default: at most this many lines per key per window.
pub const DEFAULT_REFUSAL_LOG_BURST: u32 = 20;
/// Default window.
pub const DEFAULT_REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(10);

/// An append-only registry keyed by fixed `&'static str` labels.
///
/// Entries are created on first use and never removed, so a reader holds a
/// plain shared reference and no reader ever waits for a writer: each link is
/// a set-once cell.  Two callers racing to append different keys both
/// succeed, one behind the other; two racing on the same key get the same
/// entry.  It grows by one small node per distinct key, and the keys come
/// from the closed sets the callers choose, so it is bounded by them.
#[derive(Debug)]
pub(crate) struct StaticKeyRegistry<T> {
    head: OnceLock<Box<StaticKeyNode<T>>>,
}

#[derive(Debug)]
struct StaticKeyNode<T> {
    key: &'static str,
    value: T,
    next: OnceLock<Box<StaticKeyNode<T>>>,
}

impl<T> StaticKeyRegistry<T> {
    pub(crate) const fn new() -> Self {
        Self {
            head: OnceLock::new(),
        }
    }

    /// The entry for `key`, created by `init` when this is its first use.
    pub(crate) fn get_or_insert_with(&self, key: &'static str, init: impl Fn() -> T) -> &T {
        let mut link = &self.head;
        loop {
            let node = link.get_or_init(|| {
                Box::new(StaticKeyNode {
                    key,
                    value: init(),
                    next: OnceLock::new(),
                })
            });
            if node.key == key {
                return &node.value;
            }
            link = &node.next;
        }
    }

    /// Every entry, in insertion order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &T)> {
        let mut link = &self.head;
        std::iter::from_fn(move || {
            let node = link.get()?;
            link = &node.next;
            Some((node.key, &node.value))
        })
    }
}

/// Bits of a packed window word that hold the admitted-line count.
const ADMITTED_BITS: u32 = 24;
const ADMITTED_MASK: u64 = (1 << ADMITTED_BITS) - 1;

/// The largest burst the packed window word can count.  A configured burst
/// above it is clamped: sixteen million lines per window is not a limit any
/// caller relies on.
const MAX_REFUSAL_LOG_BURST: u32 = (1 << ADMITTED_BITS) - 1;

/// A per-key fixed-window line budget.  See the module documentation.
///
/// Every key's window is one atomic word, `(window start, lines admitted)`,
/// advanced by compare-and-swap, so the two always change together and
/// `admit` never waits.  The window start is kept in whole milliseconds since
/// the limiter was built (forty bits, about thirty-four years).  The
/// suppressed count is a separate counter: each suppressed line is added
/// exactly once and handed to exactly one later admitted line.
#[derive(Debug)]
pub struct RefusalLogLimiter {
    burst: u32,
    window_ms: u64,
    epoch: Instant,
    keys: StaticKeyRegistry<Window>,
}

#[derive(Debug)]
struct Window {
    /// `(started_ms << ADMITTED_BITS) | admitted`.
    state: AtomicU64,
    suppressed: AtomicU64,
}

fn pack_window(started_ms: u64, admitted: u64) -> u64 {
    (started_ms << ADMITTED_BITS) | (admitted & ADMITTED_MASK)
}

impl RefusalLogLimiter {
    /// A limiter admitting `burst` lines per `window` for each key.
    #[must_use]
    pub fn new(burst: u32, window: Duration) -> Self {
        Self {
            burst: burst.min(MAX_REFUSAL_LOG_BURST),
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            epoch: Instant::now(),
            keys: StaticKeyRegistry::new(),
        }
    }

    /// The limiter with the documented defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_REFUSAL_LOG_BURST, DEFAULT_REFUSAL_LOG_WINDOW)
    }

    /// Whether a line for `key` may be written now.  `Some(n)` admits it and
    /// carries the number of lines for this key suppressed since the last
    /// admitted one, which the caller logs; `None` suppresses it and counts
    /// it.
    pub fn admit(&self, key: &'static str) -> Option<u64> {
        self.admit_at(key, Instant::now())
    }

    /// [`RefusalLogLimiter::admit`] against an explicit clock.
    pub fn admit_at(&self, key: &'static str, now: Instant) -> Option<u64> {
        let now_ms = u64::try_from(now.saturating_duration_since(self.epoch).as_millis())
            .unwrap_or(u64::MAX)
            .min((1 << (64 - ADMITTED_BITS)) - 1);
        let entry = self.keys.get_or_insert_with(key, || Window {
            state: AtomicU64::new(pack_window(now_ms, 0)),
            suppressed: AtomicU64::new(0),
        });
        let burst = u64::from(self.burst);
        let admitted = entry
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                let mut started_ms = state >> ADMITTED_BITS;
                let mut admitted = state & ADMITTED_MASK;
                if now_ms.saturating_sub(started_ms) >= self.window_ms {
                    started_ms = now_ms;
                    admitted = 0;
                }
                // `None` leaves the word as it is: the line is suppressed.
                (admitted < burst).then(|| pack_window(started_ms, admitted + 1))
            })
            .is_ok();
        if admitted {
            Some(entry.suppressed.swap(0, Ordering::AcqRel))
        } else {
            entry.suppressed.fetch_add(1, Ordering::AcqRel);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flood admits `burst` lines per window, suppresses the rest, and the
    /// first line of the next window reports how many were suppressed.  Keys
    /// are independent, so one flooded stage does not hide another.
    #[test]
    fn a_flood_is_bounded_per_window_and_reports_what_it_suppressed() {
        let limiter = RefusalLogLimiter::new(3, Duration::from_secs(10));
        let start = Instant::now();
        let admitted: Vec<_> = (0..1000)
            .filter_map(|_| limiter.admit_at("token", start))
            .collect();
        assert_eq!(admitted, vec![0, 0, 0], "three lines in the first window");
        assert_eq!(
            limiter.admit_at("bearer", start),
            Some(0),
            "keys are separate"
        );
        let later = start + Duration::from_secs(10);
        assert_eq!(limiter.admit_at("token", later), Some(997));
        assert_eq!(limiter.admit_at("token", later), Some(0));
    }

    /// Concurrent callers share one window word per key: exactly `burst`
    /// lines are admitted, and every other line is counted once and reported
    /// by the next window's first line.
    #[test]
    fn concurrent_callers_admit_exactly_the_burst_and_lose_no_count() {
        let limiter = RefusalLogLimiter::new(7, Duration::from_secs(3_600));
        let start = Instant::now();
        let admitted: usize = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        (0..500)
                            .filter(|_| limiter.admit_at("flood", start).is_some())
                            .count()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("worker"))
                .sum()
        });
        assert_eq!(admitted, 7);
        assert_eq!(
            limiter.admit_at("flood", start + Duration::from_secs(3_600)),
            Some(8 * 500 - 7)
        );
    }

    /// The key registry keeps one entry per key under concurrent first use.
    #[test]
    fn the_key_registry_keeps_one_entry_per_key() {
        let registry: StaticKeyRegistry<AtomicU64> = StaticKeyRegistry::new();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for key in ["a", "b", "c", "d"] {
                        registry
                            .get_or_insert_with(key, || AtomicU64::new(0))
                            .fetch_add(1, Ordering::AcqRel);
                    }
                });
            }
        });
        let mut entries: Vec<_> = registry
            .iter()
            .map(|(key, count)| (key, count.load(Ordering::Acquire)))
            .collect();
        entries.sort_unstable();
        assert_eq!(entries, vec![("a", 8), ("b", 8), ("c", 8), ("d", 8)]);
    }
}
