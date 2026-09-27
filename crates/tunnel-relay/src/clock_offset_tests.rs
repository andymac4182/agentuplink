//! Task row M7-C175: clock-offset health with injected clocks.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::*;

/// A local clock fixed at an instant the test sets.
struct FixedLocal(Mutex<DateTime<Utc>>);

impl LocalClock for FixedLocal {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().expect("local clock")
    }
}

/// An authority clock at `local + offset_of_authority`, or failing, or
/// hanging, or absent.
struct FakeAuthority {
    local: Arc<FixedLocal>,
    /// Authority minus local.
    lead: Mutex<TimeDelta>,
    fail: AtomicBool,
    hang: AtomicBool,
    absent: AtomicBool,
    reads: AtomicUsize,
}

impl AuthorityClock for FakeAuthority {
    async fn authority_time(&self) -> Result<Option<DateTime<Utc>>, CatalogError> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        if self.hang.load(Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        if self.fail.load(Ordering::Acquire) {
            return Err(CatalogError::Database(
                std::io::Error::from(std::io::ErrorKind::ConnectionReset).into(),
            ));
        }
        if self.absent.load(Ordering::Acquire) {
            return Ok(None);
        }
        Ok(Some(self.local.now() + *self.lead.lock().expect("lead")))
    }
}

fn clocks() -> (Arc<FixedLocal>, FakeAuthority) {
    let local = Arc::new(FixedLocal(Mutex::new(
        DateTime::from_timestamp(1_800_000_000, 0).expect("instant"),
    )));
    let authority = FakeAuthority {
        local: Arc::clone(&local),
        lead: Mutex::new(TimeDelta::zero()),
        fail: AtomicBool::new(false),
        hang: AtomicBool::new(false),
        absent: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
    };
    (local, authority)
}

async fn step(state: &ClockOffsetHealth, authority: &FakeAuthority, local: &FixedLocal) {
    let measurement = measure(authority, local, Duration::from_millis(50)).await;
    state.record(&measurement);
}

fn set_lead(authority: &FakeAuthority, milliseconds: i64) {
    *authority.lead.lock().expect("lead") = TimeDelta::milliseconds(milliseconds);
}

#[test]
fn the_verdict_boundaries_are_the_warning_and_the_skew_bound() {
    let warn = i64::try_from(CLOCK_OFFSET_WARN.as_millis()).expect("ms");
    let bound = i64::try_from(MAX_CLUSTER_CLOCK_SKEW.as_millis()).expect("ms");
    assert_eq!((warn, bound), (2_000, 5_000));
    for sign in [1, -1] {
        let at = |ms: i64| OffsetVerdict::of(TimeDelta::milliseconds(sign * ms));
        assert_eq!(at(0), OffsetVerdict::Within);
        assert_eq!(at(warn), OffsetVerdict::Within);
        assert_eq!(at(warn + 1), OffsetVerdict::Warn);
        assert_eq!(at(bound), OffsetVerdict::Warn);
        assert_eq!(at(bound + 1), OffsetVerdict::Beyond);
    }
}

#[tokio::test]
async fn an_offset_beyond_the_bound_is_not_ready_until_measured_back_within_it() {
    let (local, authority) = clocks();
    let state = ClockOffsetHealth::new();
    assert!(state.is_ready(), "unmeasured is ready");
    assert_eq!(state.offset_ms(), None);

    step(&state, &authority, &local).await;
    assert_eq!(state.offset_ms(), Some(0));
    assert_eq!(state.verdict(), OffsetVerdict::Within);
    assert!(state.is_ready());

    // Relay 3 s behind Redis: offset -3 s, a warning, still ready.
    set_lead(&authority, 3_000);
    step(&state, &authority, &local).await;
    assert_eq!(state.offset_ms(), Some(-3_000));
    assert_eq!(state.verdict(), OffsetVerdict::Warn);
    assert!(state.is_ready());

    // Relay 6 s ahead of Redis: beyond the bound. One sample is not
    // enough to leave rotation; the second in a row is.
    set_lead(&authority, -6_000);
    step(&state, &authority, &local).await;
    assert_eq!(state.offset_ms(), Some(6_000));
    assert!(
        state.is_ready(),
        "one over-bound sample must not flip readiness"
    );
    step(&state, &authority, &local).await;
    assert_eq!(state.verdict(), OffsetVerdict::Beyond);
    assert!(!state.is_ready());

    // A failed read and a hung read keep the verdict: still not ready.
    authority.fail.store(true, Ordering::Release);
    step(&state, &authority, &local).await;
    authority.fail.store(false, Ordering::Release);
    authority.hang.store(true, Ordering::Release);
    step(&state, &authority, &local).await;
    authority.hang.store(false, Ordering::Release);
    assert_eq!(state.failures(), 2);
    assert!(
        !state.is_ready(),
        "a failed read must not restore readiness"
    );

    // Exactly at the bound: ready again after two in-bound samples in a row.
    set_lead(&authority, 5_000);
    step(&state, &authority, &local).await;
    assert_eq!(state.offset_ms(), Some(-5_000));
    assert!(
        !state.is_ready(),
        "one in-bound sample must not restore readiness"
    );
    step(&state, &authority, &local).await;
    assert!(state.is_ready());
    assert_eq!(state.measurements(), 6);
}

/// Opus review of #225, S2: a single outlier on either side of the line is
/// absorbed, because the streak resets when a sample falls back.
#[tokio::test]
async fn a_single_outlier_never_flips_readiness() {
    let (local, authority) = clocks();
    let state = ClockOffsetHealth::new();
    for lead in [0, -9_000, 0, -9_000, 0] {
        set_lead(&authority, lead);
        step(&state, &authority, &local).await;
        assert!(
            state.is_ready(),
            "an isolated {lead} ms outlier flipped readiness"
        );
    }
    for _ in 0..2 {
        set_lead(&authority, -9_000);
        step(&state, &authority, &local).await;
    }
    assert!(!state.is_ready());
    for lead in [0, -9_000, 0, -9_000] {
        set_lead(&authority, lead);
        step(&state, &authority, &local).await;
        assert!(
            !state.is_ready(),
            "an isolated in-bound sample at {lead} ms restored readiness"
        );
    }
}

/// Opus review of #225, S2: the round trip is measured on the monotonic
/// clock, and a sample slower than 750 ms is a failure that keeps the
/// verdict, even when its offset would flip it.
#[tokio::test(start_paused = true)]
async fn a_slow_round_trip_is_discarded() {
    struct Slow {
        delay: Duration,
        at: DateTime<Utc>,
    }
    impl AuthorityClock for Slow {
        async fn authority_time(&self) -> Result<Option<DateTime<Utc>>, CatalogError> {
            tokio::time::sleep(self.delay).await;
            Ok(Some(self.at))
        }
    }
    let local = FixedLocal(Mutex::new(
        DateTime::from_timestamp(1_800_000_000, 0).expect("instant"),
    ));
    let far = local.now() - TimeDelta::seconds(9);
    let slow = Slow {
        delay: MAX_SAMPLE_ROUND_TRIP + Duration::from_millis(1),
        at: far,
    };
    assert_eq!(
        measure(&slow, &local, OFFSET_DEADLINE).await,
        Measurement::Failed
    );
    let state = ClockOffsetHealth::new();
    for _ in 0..3 {
        state.record(&measure(&slow, &local, OFFSET_DEADLINE).await);
    }
    assert!(state.is_ready(), "slow samples moved the verdict");
    assert_eq!((state.measurements(), state.failures()), (0, 3));
    let fast = Slow {
        delay: MAX_SAMPLE_ROUND_TRIP,
        at: far,
    };
    assert_eq!(
        measure(&fast, &local, OFFSET_DEADLINE).await,
        Measurement::Offset(TimeDelta::seconds(9))
    );
}

#[tokio::test]
async fn the_estimate_uses_the_midpoint_of_the_read() {
    /// A local clock that advances 400 ms per reading.
    struct Advancing(Mutex<DateTime<Utc>>);
    impl LocalClock for Advancing {
        fn now(&self) -> DateTime<Utc> {
            let mut now = self.0.lock().expect("clock");
            let current = *now;
            *now = current + TimeDelta::milliseconds(400);
            current
        }
    }
    struct At(DateTime<Utc>);
    impl AuthorityClock for At {
        async fn authority_time(&self) -> Result<Option<DateTime<Utc>>, CatalogError> {
            Ok(Some(self.0))
        }
    }
    let start = DateTime::from_timestamp(1_800_000_000, 0).expect("instant");
    let local = Advancing(Mutex::new(start));
    // The read spans [start, start + 400 ms]; the midpoint is start + 200 ms.
    let measurement = measure(&At(start), &local, Duration::from_secs(1)).await;
    assert_eq!(
        measurement,
        Measurement::Offset(TimeDelta::milliseconds(200))
    );
}

#[tokio::test(start_paused = true)]
async fn the_loop_measures_periodically_and_stops_without_an_authority_clock() {
    let (local, authority) = clocks();
    let authority = Arc::new(authority);
    let state = Arc::new(ClockOffsetHealth::new());
    set_lead(&authority, -7_000);
    let task = {
        let authority = Arc::clone(&authority);
        let local = Arc::clone(&local);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            measure_loop(
                authority.as_ref(),
                local.as_ref(),
                &state,
                Duration::from_secs(5),
            )
            .await;
        })
    };
    tokio::time::sleep(Duration::from_secs(11)).await;
    assert_eq!(authority.reads.load(Ordering::Acquire), 3);
    assert!(!state.is_ready());
    authority.absent.store(true, Ordering::Release);
    tokio::time::sleep(Duration::from_secs(5)).await;
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("the loop stops for an authority without a clock")
        .expect("loop task");
}

async fn readyz_status(app: &axum::Router) -> (u16, String) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::get("/readyz")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("readyz");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// `/readyz` follows the clock-offset verdict: `503` beyond the bound, `200`
/// once a measurement is back within it, and never a reason in the body.
#[tokio::test]
async fn readyz_is_not_ready_beyond_the_skew_bound() {
    let (local, authority) = clocks();
    let state = Arc::new(ClockOffsetHealth::new());
    let app: axum::Router = crate::health::router(
        None,
        crate::health::ReadinessChecks {
            authority: None,
            clock: Some(Arc::clone(&state)),
        },
    );
    assert_eq!(readyz_status(&app).await.0, 200);
    set_lead(&authority, 5_001);
    step(&state, &authority, &local).await;
    step(&state, &authority, &local).await;
    assert_eq!(
        readyz_status(&app).await,
        (503, r#"{"status":"unready"}"#.to_owned())
    );
    set_lead(&authority, 4_000);
    step(&state, &authority, &local).await;
    step(&state, &authority, &local).await;
    assert_eq!(
        readyz_status(&app).await,
        (200, r#"{"status":"ready"}"#.to_owned())
    );
}
