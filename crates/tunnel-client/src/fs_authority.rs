//! M4-76: nonblocking publication of the provider's exact authorization view.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tunnel_fs_core::CapabilitySet;
use tunnel_fs_provider::{Authority, Authorization, FreshnessFailure};

use super::{pack, unpack};
use crate::DualDeadline;

const SNAPSHOT_ATTEMPTS: usize = 3;
const LIVE: u64 = 0;
const INVALIDATED: u64 = 1;
const LAPSED: u64 = 2;

#[derive(Debug, Default)]
struct AtomicDeadline {
    monotonic: AtomicU64,
    wall_started: AtomicU64,
    wall: AtomicU64,
}

#[derive(Clone, Copy)]
struct DeadlineWords {
    monotonic: u64,
    wall_started: u64,
    wall: u64,
}

impl AtomicDeadline {
    fn store(&self, words: DeadlineWords) {
        self.monotonic.store(words.monotonic, Ordering::SeqCst);
        self.wall_started.store(words.wall_started, Ordering::SeqCst);
        self.wall.store(words.wall, Ordering::SeqCst);
    }

    fn load(&self) -> DeadlineWords {
        DeadlineWords {
            monotonic: self.monotonic.load(Ordering::SeqCst),
            wall_started: self.wall_started.load(Ordering::SeqCst),
            wall: self.wall.load(Ordering::SeqCst),
        }
    }
}

fn nanos(duration: std::time::Duration) -> Option<u64> {
    u64::try_from(duration.as_nanos()).ok()
}

fn wall_nanos(time: SystemTime) -> Option<u64> {
    nanos(time.duration_since(UNIX_EPOCH).ok()?)
}

impl DeadlineWords {
    fn encode(deadline: DualDeadline, origin: Instant) -> Option<Self> {
        Some(Self {
            monotonic: nanos(deadline.monotonic.saturating_duration_since(origin))?,
            wall_started: wall_nanos(deadline.started_wall)?,
            wall: wall_nanos(deadline.wall)?,
        })
    }

    fn expired(self, now: u64, wall_now: u64) -> bool {
        now >= self.monotonic || wall_now < self.wall_started || wall_now >= self.wall
    }
}

/// The live authorization of one admitted stream, independently checked by
/// the provider before a host call. No actor or provider waits on a lock.
///
/// The actor is the normal single writer. A checked even→odd version CAS
/// enforces writer exclusion even if another caller violates that ownership.
/// Every payload word is atomic and sequentially consistent: equal even
/// versions around the reads prove that no publication overlapped them in
/// that same total order. Versions never wrap. A conflicting writer or an
/// exhausted version retires the authority as unavailable.
///
/// Readers make at most three attempts. A writer preempted mid-publication
/// can therefore conservatively close a live session with retryable 1011;
/// this is an unavailable snapshot, not observed expiry or revocation.
#[derive(Debug)]
pub struct StreamAuthority {
    version: AtomicU64,
    unavailable: AtomicBool,
    revision: AtomicU64,
    grant: AtomicU64,
    status: AtomicU64,
    bounded: AtomicBool,
    origin: Instant,
    confirmation: AtomicDeadline,
    challenge: AtomicDeadline,
    operation: AtomicDeadline,
}

impl StreamAuthority {
    /// An authority without a clock bound, for standalone provider use.
    /// The connector runtime always uses `new_until`.
    #[must_use]
    pub fn new(revision: u64, grant: CapabilitySet) -> Self {
        Self {
            version: AtomicU64::new(0),
            unavailable: AtomicBool::new(false),
            revision: AtomicU64::new(revision),
            grant: AtomicU64::new(pack(grant)),
            status: AtomicU64::new(LIVE),
            bounded: AtomicBool::new(false),
            origin: Instant::now(),
            confirmation: AtomicDeadline::default(),
            challenge: AtomicDeadline::default(),
            operation: AtomicDeadline::default(),
        }
    }

    pub(crate) fn new_until(
        revision: u64,
        grant: CapabilitySet,
        confirmation: DualDeadline,
        operation: DualDeadline,
    ) -> Self {
        let authority = Self::new(revision, grant);
        authority.confirm_until(revision, grant, confirmation, operation);
        authority
    }

    fn begin_publication(&self) -> Option<u64> {
        if self.unavailable.load(Ordering::SeqCst) {
            return None;
        }
        let version = self.version.load(Ordering::SeqCst);
        let Some(next) = version.checked_add(2) else {
            self.unavailable.store(true, Ordering::SeqCst);
            return None;
        };
        if version & 1 != 0
            || self
                .version
                .compare_exchange(version, version + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            self.unavailable.store(true, Ordering::SeqCst);
            return None;
        }
        Some(next)
    }

    fn bounds_expired_at(&self, now: Instant, wall: SystemTime) -> bool {
        let Some(now) = nanos(now.saturating_duration_since(self.origin)) else {
            return true;
        };
        let Some(wall) = wall_nanos(wall) else {
            return true;
        };
        self.bounded.load(Ordering::SeqCst)
            && (self.confirmation.load().expired(now, wall)
                || self.challenge.load().expired(now, wall)
                || self.operation.load().expired(now, wall))
    }

    /// Queue admission adds a challenge bound, never a new accepted grant.
    /// This preserves a newer challenge's independent wall-reversal anchor.
    pub(crate) fn begin_refresh(&self, challenge: DualDeadline) -> bool {
        let encoded = DeadlineWords::encode(challenge, self.origin);
        let Some(next) = self.begin_publication() else {
            return false;
        };
        let now = Instant::now();
        let wall = SystemTime::now();
        let live = self.status.load(Ordering::SeqCst) == LIVE;
        let accepted = live
            && self.bounded.load(Ordering::SeqCst)
            && !self.bounds_expired_at(now, wall)
            && !challenge.expired_at(now, wall);
        if let Some(challenge) = encoded {
            if accepted {
                self.challenge.store(challenge);
            } else if live {
                self.status.store(LAPSED, Ordering::SeqCst);
            }
        } else {
            self.unavailable.store(true, Ordering::SeqCst);
        }
        self.version.store(next, Ordering::SeqCst);
        accepted && !self.unavailable.load(Ordering::SeqCst)
    }

    /// Publish only while the current bounds remain live, including after an
    /// actor pause. A published terminal cause cannot be revived. Clock-only
    /// reader observations are not latched here: the provider that refuses a
    /// request closes its session permanently before returning that failure.
    pub(crate) fn confirm_until(
        &self,
        revision: u64,
        grant: CapabilitySet,
        confirmation: DualDeadline,
        operation: DualDeadline,
    ) -> bool {
        let encoded = DeadlineWords::encode(confirmation, self.origin)
            .zip(DeadlineWords::encode(operation, self.origin));
        let Some(next) = self.begin_publication() else {
            return false;
        };
        let now = Instant::now();
        let wall = SystemTime::now();
        let live = self.status.load(Ordering::SeqCst) == LIVE;
        let same_grant = revision == self.revision.load(Ordering::SeqCst)
            && pack(grant) == self.grant.load(Ordering::SeqCst);
        let accepted = live
            && same_grant
            && !self.bounds_expired_at(now, wall)
            && !confirmation.expired_at(now, wall)
            && !operation.expired_at(now, wall);
        if let Some((confirmation, operation)) = encoded {
            if accepted {
                self.confirmation.store(confirmation);
                // The operation belongs to admission. Renewing a grant can
                // never extend it or replace its wall-reversal anchor.
                if !self.bounded.load(Ordering::SeqCst) {
                    self.challenge.store(confirmation);
                    self.operation.store(operation);
                }
                self.bounded.store(true, Ordering::SeqCst);
            } else if live {
                self.status.store(
                    if same_grant { LAPSED } else { INVALIDATED },
                    Ordering::SeqCst,
                );
            }
        } else {
            self.unavailable.store(true, Ordering::SeqCst);
        }
        self.version.store(next, Ordering::SeqCst);
        accepted && !self.unavailable.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn current_grant(&self) -> CapabilitySet {
        unpack(self.grant.load(Ordering::SeqCst))
    }

    /// Explicit revocation is terminal, even if a late confirmation follows.
    pub fn invalidate(&self) {
        self.invalidate_for(FreshnessFailure::Invalidated);
    }

    pub(crate) fn invalidate_for(&self, reason: FreshnessFailure) {
        let Some(next) = self.begin_publication() else {
            return;
        };
        if self.status.load(Ordering::SeqCst) == LIVE {
            match reason {
                FreshnessFailure::Invalidated => self.status.store(INVALIDATED, Ordering::SeqCst),
                FreshnessFailure::DeadlineElapsed => self.status.store(LAPSED, Ordering::SeqCst),
                FreshnessFailure::SnapshotUnavailable => {
                    self.unavailable.store(true, Ordering::SeqCst);
                }
            }
        }
        self.version.store(next, Ordering::SeqCst);
    }

    fn unavailable(&self) -> Authorization {
        // Terminal status is monotonic even during an interrupted publisher.
        // Once observed, neither contention nor version exhaustion may turn
        // a known invalidation into a retryable unavailable-snapshot close.
        let freshness_failure = match self.status.load(Ordering::SeqCst) {
            INVALIDATED => FreshnessFailure::Invalidated,
            LAPSED => FreshnessFailure::DeadlineElapsed,
            _ => FreshnessFailure::SnapshotUnavailable,
        };
        Authorization {
            revision: self.revision.load(Ordering::SeqCst),
            grant: CapabilitySet::DENY,
            fresh: false,
            freshness_failure,
        }
    }

    fn current_with_clock(
        &self,
        mut clock: impl FnMut() -> (Instant, SystemTime),
    ) -> Authorization {
        for _ in 0..SNAPSHOT_ATTEMPTS {
            if self.unavailable.load(Ordering::SeqCst) {
                return self.unavailable();
            }
            let before = self.version.load(Ordering::SeqCst);
            if before & 1 != 0 {
                continue;
            }
            let revision = self.revision.load(Ordering::SeqCst);
            let grant = unpack(self.grant.load(Ordering::SeqCst));
            let status = self.status.load(Ordering::SeqCst);
            let bounded = self.bounded.load(Ordering::SeqCst);
            let confirmation = self.confirmation.load();
            let challenge = self.challenge.load();
            let operation = self.operation.load();
            // Sample after the candidate snapshot: a renewal published after
            // an earlier clock sample must not look like a wall reversal.
            let (now, wall) = clock();
            if self.version.load(Ordering::SeqCst) != before {
                continue;
            }
            if self.unavailable.load(Ordering::SeqCst) {
                return self.unavailable();
            }
            let expired = bounded
                && nanos(now.saturating_duration_since(self.origin))
                    .zip(wall_nanos(wall))
                    .is_none_or(|(now, wall)| {
                        confirmation.expired(now, wall)
                            || challenge.expired(now, wall)
                            || operation.expired(now, wall)
                    });
            let freshness_failure = if status == INVALIDATED {
                FreshnessFailure::Invalidated
            } else {
                FreshnessFailure::DeadlineElapsed
            };
            return Authorization {
                revision,
                grant,
                fresh: status == LIVE && !expired,
                freshness_failure,
            };
        }
        self.unavailable()
    }

    #[cfg(test)]
    pub(crate) fn observe_at(&self, now: Instant, wall: SystemTime) -> Authorization {
        self.current_with_clock(|| (now, wall))
    }
}

#[derive(Clone, Debug)]
pub struct SharedAuthority(pub(super) Arc<StreamAuthority>);

impl SharedAuthority {
    #[must_use]
    pub const fn new(authority: Arc<StreamAuthority>) -> Self {
        Self(authority)
    }
}

impl Authority for SharedAuthority {
    fn current(&self) -> Authorization {
        self.0.current_with_clock(|| (Instant::now(), SystemTime::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tunnel_fs_core::{Capability, SessionErrorCode};

    fn grant() -> CapabilitySet {
        CapabilitySet::from_slice(&[Capability::Read, Capability::List])
    }

    fn deadline(seconds: u64) -> DualDeadline {
        DualDeadline::new(
            Instant::now(),
            SystemTime::now(),
            Duration::from_secs(seconds),
        )
        .unwrap()
    }

    fn read(authority: &StreamAuthority) -> Authorization {
        authority.current_with_clock(|| (Instant::now(), SystemTime::now()))
    }

    #[test]
    fn m4c76_provider_checks_both_clocks_and_operation_without_actor_tick() {
        let confirmation = deadline(5);
        let operation = deadline(60);
        let authority = StreamAuthority::new_until(1, grant(), confirmation, operation);
        assert!(read(&authority).fresh);
        for (now, wall) in [
            (confirmation.monotonic, confirmation.started_wall),
            (confirmation.started, confirmation.wall),
            (
                confirmation.started,
                confirmation.started_wall - Duration::from_nanos(1),
            ),
        ] {
            let observed = authority.current_with_clock(|| (now, wall));
            assert!(!observed.fresh);
            assert_eq!(
                observed.freshness_failure,
                FreshnessFailure::DeadlineElapsed
            );
            assert_eq!(
                observed.freshness_failure.close_code(),
                SessionErrorCode::SessionLost
            );
        }
        let shorter_operation = deadline(1);
        let authority = StreamAuthority::new_until(1, grant(), confirmation, shorter_operation);
        let observed = authority
            .current_with_clock(|| (shorter_operation.monotonic, shorter_operation.wall));
        assert!(!observed.fresh, "the operation is an independent bound");
        // The later operation anchor must survive alongside the confirmation.
        let later_operation = DualDeadline::new(
            confirmation.started,
            confirmation.started_wall + Duration::from_secs(1),
            Duration::from_secs(60),
        )
        .unwrap();
        let encoded = DeadlineWords::encode(later_operation, authority.origin).unwrap();
        let next = authority.begin_publication().unwrap();
        authority.operation.store(encoded);
        authority.version.store(next, Ordering::SeqCst);
        assert!(
            !authority
                .current_with_clock(|| {
                    (
                        confirmation.started,
                        confirmation.started_wall + Duration::from_millis(500),
                    )
                })
                .fresh
        );
    }

    #[test]
    fn m4c76_timely_provider_renewal_survives_old_deadline() {
        let original = deadline(5);
        let operation = deadline(60);
        let authority = StreamAuthority::new_until(1, grant(), original, operation);
        let renewed = deadline(10);
        assert!(authority.begin_refresh(renewed));
        assert!(authority.confirm_until(1, grant(), renewed, operation));
        assert!(
            authority
                .current_with_clock(|| {
                    (
                        original.monotonic + Duration::from_millis(1),
                        original.wall + Duration::from_millis(1),
                    )
                })
                .fresh
        );
    }

    #[test]
    fn m4c76_provider_renewal_cannot_extend_admission_operation_bound() {
        let original = deadline(5);
        let operation = deadline(1);
        let authority = StreamAuthority::new_until(1, grant(), original, operation);
        assert!(authority.confirm_until(1, grant(), deadline(10), deadline(60)));
        assert!(
            !authority
                .current_with_clock(|| (operation.monotonic, operation.wall))
                .fresh
        );
    }

    #[test]
    fn m4c76_provider_checks_the_newer_in_flight_challenge_anchor() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let original = DualDeadline::new(
            now - Duration::from_secs(1),
            wall - Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .unwrap();
        let operation = DualDeadline::new(
            now - Duration::from_secs(2),
            wall - Duration::from_secs(2),
            Duration::from_secs(60),
        )
        .unwrap();
        let authority = StreamAuthority::new_until(1, grant(), original, operation);
        let challenge = deadline(5);
        assert!(authority.begin_refresh(challenge));
        let reversed =
            authority.current_with_clock(|| (now, wall - Duration::from_millis(500)));
        assert!(!reversed.fresh);
        assert_eq!(reversed.freshness_failure, FreshnessFailure::DeadlineElapsed);
        // A new challenge also cannot extend the old accepted permission.
        assert!(
            !authority
                .current_with_clock(|| (original.monotonic, original.wall))
                .fresh
        );
    }

    #[test]
    fn m4c76_snapshot_retries_never_return_a_torn_publication() {
        let bound = deadline(60);
        let authority = StreamAuthority::new_until(1, grant(), bound, bound);
        let mut clocks = 0;
        let observed = authority.current_with_clock(|| {
            clocks += 1;
            if clocks == 1 {
                authority.invalidate();
            }
            (Instant::now(), SystemTime::now())
        });
        assert_eq!(clocks, 2, "the interrupted first snapshot was discarded");
        assert!(!observed.fresh);
        assert_eq!(observed.freshness_failure, FreshnessFailure::Invalidated);
        assert_eq!(
            observed.freshness_failure.close_code(),
            SessionErrorCode::AuthExpired
        );
        assert!(!authority.confirm_until(1, grant(), bound, bound));
        assert_eq!(
            observed.freshness_failure.close_code(),
            SessionErrorCode::AuthExpired
        );
    }

    #[test]
    fn m4c76_snapshot_contention_is_bounded_and_distinct_from_expiry() {
        let bound = deadline(60);
        let authority = StreamAuthority::new_until(1, grant(), bound, bound);
        let mut reads = 0;
        let observed = authority.current_with_clock(|| {
            reads += 1;
            assert!(authority.confirm_until(1, grant(), bound, bound));
            (Instant::now(), SystemTime::now())
        });
        assert_eq!(reads, SNAPSHOT_ATTEMPTS);
        assert_eq!(
            observed.freshness_failure,
            FreshnessFailure::SnapshotUnavailable
        );
        assert_eq!(
            observed.freshness_failure.close_code(),
            SessionErrorCode::SessionLost
        );
        assert!(!observed.fresh);
        assert!(
            read(&authority).fresh,
            "reader contention did not manufacture expiry"
        );

        let next = authority.begin_publication().unwrap();
        let preempted = read(&authority);
        assert_eq!(
            preempted.freshness_failure,
            FreshnessFailure::SnapshotUnavailable
        );
        authority.version.store(next, Ordering::SeqCst);
        assert!(read(&authority).fresh);
    }

    #[test]
    fn m4c76_writer_conflict_and_version_exhaustion_retire_authority() {
        let bound = deadline(60);
        for conflict in [false, true] {
            let authority = StreamAuthority::new_until(1, grant(), bound, bound);
            let prior = if conflict {
                authority.begin_publication().unwrap() - 1
            } else {
                authority.version.store(u64::MAX - 1, Ordering::SeqCst);
                u64::MAX - 1
            };
            assert!(!authority.confirm_until(1, grant(), bound, bound));
            assert_eq!(authority.version.load(Ordering::SeqCst), prior);
            assert_eq!(
                read(&authority).freshness_failure,
                FreshnessFailure::SnapshotUnavailable
            );
            assert!(!authority.confirm_until(1, grant(), bound, bound));
        }
    }

    #[test]
    fn m4c76_terminal_cause_survives_odd_or_unavailable_publication() {
        let bound = deadline(60);
        for cause in [
            FreshnessFailure::Invalidated,
            FreshnessFailure::DeadlineElapsed,
        ] {
            for unavailable in [false, true] {
                let authority = StreamAuthority::new_until(1, grant(), bound, bound);
                authority.invalidate_for(cause);
                assert_eq!(read(&authority).freshness_failure, cause);
                if unavailable {
                    authority.version.store(u64::MAX - 1, Ordering::SeqCst);
                    assert!(!authority.confirm_until(1, grant(), bound, bound));
                } else {
                    authority.begin_publication().expect("held publisher");
                }
                let observed = read(&authority);
                assert!(!observed.fresh);
                assert_eq!(observed.freshness_failure, cause);
                assert_eq!(observed.freshness_failure.close_code(), cause.close_code());
            }
        }
    }

    #[test]
    fn m4c76_partial_deadline_publication_never_exposes_a_torn_bound() {
        let original = deadline(5);
        let operation = deadline(60);
        let authority = StreamAuthority::new_until(1, grant(), original, operation);
        let renewed = deadline(10);
        assert!(authority.begin_refresh(renewed));
        let words = DeadlineWords::encode(renewed, authority.origin).unwrap();
        let next = authority.begin_publication().expect("single publisher");
        authority
            .confirmation
            .monotonic
            .store(words.monotonic, Ordering::SeqCst);
        let while_torn = authority.current_with_clock(|| {
            (
                original.monotonic + Duration::from_millis(1),
                original.wall + Duration::from_millis(1),
            )
        });
        assert!(!while_torn.fresh);
        assert_eq!(
            while_torn.freshness_failure,
            FreshnessFailure::SnapshotUnavailable
        );
        authority
            .confirmation
            .wall_started
            .store(words.wall_started, Ordering::SeqCst);
        authority
            .confirmation
            .wall
            .store(words.wall, Ordering::SeqCst);
        authority.version.store(next, Ordering::SeqCst);
        assert!(
            authority
                .current_with_clock(|| {
                    (
                        original.monotonic + Duration::from_millis(1),
                        original.wall + Duration::from_millis(1),
                    )
                })
                .fresh
        );
        assert!(
            !authority
                .current_with_clock(|| (renewed.monotonic, renewed.wall))
                .fresh
        );
    }

    #[test]
    fn m4c76_frozen_grant_and_terminal_reason_cannot_be_replaced() {
        let bound = deadline(60);
        let authority = StreamAuthority::new_until(1, grant(), bound, bound);
        assert!(!authority.confirm_until(2, grant(), bound, bound));
        let invalidated = read(&authority);
        assert_eq!(invalidated.revision, 1);
        assert_eq!(invalidated.grant, grant());
        assert_eq!(invalidated.freshness_failure, FreshnessFailure::Invalidated);
        authority.invalidate_for(FreshnessFailure::DeadlineElapsed);
        assert_eq!(
            read(&authority).freshness_failure,
            FreshnessFailure::Invalidated
        );
    }

    #[cfg(unix)]
    #[test]
    fn m4c76_queued_provider_read_uses_the_exact_observed_failure_cause() {
        use std::cell::Cell;
        use std::rc::Rc;
        use tunnel_fs_core::FeatureSet;
        use tunnel_fs_ninep::{Frame, Message, NOFID, NONUNAME, NOTAG};
        use tunnel_fs_provider::{Outbound, Provider, default_limits};

        struct Clocked {
            authority: Arc<StreamAuthority>,
            now: Rc<Cell<(Instant, SystemTime)>>,
            invalidate_after_observation: Rc<Cell<bool>>,
        }

        impl Authority for Clocked {
            fn current(&self) -> Authorization {
                let observed = self.authority.current_with_clock(|| self.now.get());
                if self.invalidate_after_observation.replace(false) {
                    self.authority.invalidate();
                }
                observed
            }
        }

        for (cause, operation_first, invalidate_after) in [
            (None, false, false),
            (Some(FreshnessFailure::DeadlineElapsed), false, false),
            (Some(FreshnessFailure::DeadlineElapsed), false, true),
            (Some(FreshnessFailure::DeadlineElapsed), true, false),
            (Some(FreshnessFailure::Invalidated), false, false),
            (Some(FreshnessFailure::SnapshotUnavailable), false, false),
        ] {
            let root = tempfile::tempdir().expect("synthetic export");
            std::fs::write(root.path().join("probe"), b"synthetic").unwrap();
            let limits = default_limits();
            let host = tunnel_fs_host::ExportRoot::open(
                root.path(),
                grant(),
                FeatureSet::NONE,
                limits.path_bounds(),
            )
            .unwrap();
            let bound = deadline(if operation_first { 60 } else { 5 });
            let operation = deadline(if operation_first { 5 } else { 60 });
            let authority = Arc::new(StreamAuthority::new_until(1, grant(), bound, operation));
            let now = Rc::new(Cell::new((Instant::now(), SystemTime::now())));
            let invalidate_after_observation = Rc::new(Cell::new(false));
            let mut provider = Provider::new(
                host,
                limits,
                Clocked {
                    authority: Arc::clone(&authority),
                    now: Rc::clone(&now),
                    invalidate_after_observation: Rc::clone(&invalidate_after_observation),
                },
            )
            .unwrap();
            let version = provider.accept(&Frame::new(
                NOTAG,
                Message::Tversion {
                    msize: 65_536,
                    version: tunnel_fs_ninep::DIALECT.to_owned(),
                },
            ));
            assert!(matches!(
                &version[..],
                [Outbound::Frame(frame)] if matches!(&frame.message, Message::Rversion { .. })
            ));
            for (tag, message) in [
                (
                    1,
                    Message::Tattach {
                        fid: 0,
                        afid: NOFID,
                        uname: String::new(),
                        aname: String::new(),
                        n_uname: NONUNAME,
                    },
                ),
                (
                    2,
                    Message::Twalk {
                        fid: 0,
                        newfid: 1,
                        names: vec!["probe".to_owned()],
                    },
                ),
                (
                    3,
                    Message::Tlopen {
                        fid: 1,
                        flags: tunnel_fs_ninep::flags::O_RDONLY,
                    },
                ),
            ] {
                assert!(provider.accept(&Frame::new(tag, message)).is_empty());
                assert!(matches!(&provider.step()[..], [Outbound::Frame(_)]));
            }
            assert!(
                provider
                    .accept(&Frame::new(
                        4,
                        Message::Tread {
                            fid: 1,
                            offset: 0,
                            count: 9,
                        },
                    ))
                    .is_empty()
            );
            assert!(
                provider.has_work(),
                "the request is already queued under live authority"
            );
            let mut publication = None;
            match cause {
                Some(FreshnessFailure::DeadlineElapsed) => {
                    let expired = if operation_first { operation } else { bound };
                    now.set((expired.monotonic, expired.wall));
                    // This later invalidation must not reclassify the exact
                    // stale observation the provider already received.
                    invalidate_after_observation.set(invalidate_after);
                }
                Some(FreshnessFailure::Invalidated) => authority.invalidate(),
                Some(FreshnessFailure::SnapshotUnavailable) => {
                    publication = authority.begin_publication();
                }
                _ => {}
            }
            let result = provider.step();
            if let Some(next) = publication {
                authority.version.store(next, Ordering::SeqCst);
            }
            if let Some(cause) = cause {
                assert!(
                    matches!(&result[..], [Outbound::Close(code)] if *code == cause.close_code())
                );
                assert_eq!(
                    cause.close_code().close_code(),
                    Some(if cause == FreshnessFailure::Invalidated {
                        1008
                    } else {
                        1011
                    })
                );
                assert_eq!(
                    provider.stats().bytes_read,
                    0,
                    "queued host read was never performed"
                );
                assert_eq!(provider.stats().freshness_closures, 1);
                assert!(!provider.has_work());
                if cause == FreshnessFailure::DeadlineElapsed {
                    now.set((Instant::now(), SystemTime::now()));
                    let renewed = authority.confirm_until(1, grant(), deadline(10), operation);
                    if !invalidate_after {
                        assert!(
                            renewed,
                            "the actual bounds remain live after clock restoration"
                        );
                        assert!(read(&authority).fresh);
                    }
                    let refused = provider.accept(&Frame::new(
                        5,
                        Message::Tread {
                            fid: 1,
                            offset: 0,
                            count: 9,
                        },
                    ));
                    assert!(matches!(&refused[..], [Outbound::Close(_)]));
                    assert!(
                        !provider.has_work(),
                        "a closed session admits no later request"
                    );
                    assert!(provider.step().is_empty());
                    assert_eq!(provider.stats().bytes_read, 0);
                    assert_eq!(provider.stats().mutations_dispatched, 0);
                }
            } else {
                let [Outbound::Frame(frame)] = &result[..] else {
                    panic!("expected a successful host read: {result:?}");
                };
                assert!(matches!(
                    &frame.message,
                    Message::Rread { data } if data.as_slice() == b"synthetic"
                ));
                assert_eq!(provider.stats().bytes_read, 9);
            }
        }
    }
}
