//! C-P1-2 (issue #1745): the intake budget obeys the consumer metadata
//! worker's allowance — 5 requests per rolling 30 seconds, ≤1024 per
//! day — and does so on the injected clock, so both faces are
//! demonstrated across virtual hours without consuming real seconds
//! (the wall-clock guards at the end of each test pin that).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use uldolmok_vpatch_pipeline::budget::{
    AdmitDecision, Origin, RateBudgets, DAILY_BUDGET, SECONDS_PER_DAY, WINDOW_REQUESTS,
    WINDOW_SECONDS,
};
use uldolmok_vpatch_pipeline::clock::VirtualClock;
use uldolmok_vpatch_pipeline::intake::{fetch_with_budget, IntakeError};

const T0: i64 = 1_800_000_000;
const NVD_URL: &str = "nvd-fixture://CVE-2024-0001";

/// A fetcher that answers every URL with fixture bytes and counts its
/// hits — the transport seam tests inject in place of reqwest.
struct FixtureFetcher {
    hits: Mutex<Vec<String>>,
}

impl FixtureFetcher {
    fn new() -> Self {
        Self {
            hits: Mutex::new(Vec::new()),
        }
    }

    fn hit_count(&self) -> usize {
        self.lock_hits().len()
    }

    fn lock_hits(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl uldolmok_vpatch_pipeline::intake::Fetcher for FixtureFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        self.lock_hits().push(url.to_owned());
        Ok(br#"{"vulnerabilities":[]}"#.to_vec())
    }
}

#[test]
fn c_p1_2_sixth_request_waits_through_the_window_then_admits() {
    let started = Instant::now();
    let clock = VirtualClock::start_at(T0);
    let mut budgets = RateBudgets::new();
    let fetcher = FixtureFetcher::new();

    for _ in 0..WINDOW_REQUESTS {
        fetch_with_budget(&fetcher, &mut budgets, &clock, Origin::Nvd, NVD_URL)
            .expect("the first five requests admit immediately");
    }
    assert!(
        clock.recorded_waits().is_empty(),
        "the first five requests must not wait"
    );

    fetch_with_budget(&fetcher, &mut budgets, &clock, Origin::Nvd, NVD_URL)
        .expect("the sixth request admits after the window slide");
    // (a) the wait went through the clock, to exactly the slide instant
    assert_eq!(clock.recorded_waits(), vec![T0 + WINDOW_SECONDS]);
    assert_eq!(clock.now_value(), T0 + WINDOW_SECONDS);
    assert_eq!(fetcher.hit_count(), WINDOW_REQUESTS + 1);

    // per-origin isolation: the KEV ledger was untouched by the NVD burst
    assert_eq!(
        budgets.admit(Origin::Kev, clock.now_value()),
        AdmitDecision::Admit
    );

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the window test must not consume real time"
    );
}

#[test]
fn c_p1_2_daily_ceiling_stops_the_batch_without_real_sleeping() {
    let started = Instant::now();
    let clock = VirtualClock::start_at(T0);
    let mut budgets = RateBudgets::new();
    let fetcher = FixtureFetcher::new();

    // Drive the full day's budget through the real fetch path: every
    // window slide sleeps virtually, so this sweeps virtual hours.
    for i in 0..DAILY_BUDGET {
        fetch_with_budget(&fetcher, &mut budgets, &clock, Origin::Nvd, NVD_URL)
            .unwrap_or_else(|error| panic!("request {i} of the daily budget must admit: {error}"));
    }
    assert_eq!(fetcher.hit_count(), DAILY_BUDGET as usize);
    let waits_before_rejection = clock.recorded_waits().len();
    let advanced_to = clock.now_value();
    assert!(
        advanced_to > T0,
        "the window slides must have advanced the virtual clock"
    );

    let rejection = fetch_with_budget(&fetcher, &mut budgets, &clock, Origin::Nvd, NVD_URL)
        .expect_err("the request past the daily ceiling must be refused");
    match rejection {
        IntakeError::DailyBudgetExhausted {
            origin,
            resume_at_unix,
        } => {
            assert_eq!(origin, Origin::Nvd);
            // (b) the resume instant is the next UTC midnight of the
            // caller's clock read
            assert_eq!(
                resume_at_unix,
                (advanced_to.div_euclid(SECONDS_PER_DAY) + 1) * SECONDS_PER_DAY
            );
        }
        other => panic!("expected DailyBudgetExhausted, got {other:?}"),
    }
    // the rejection spent nothing and waited nowhere
    assert_eq!(fetcher.hit_count(), DAILY_BUDGET as usize);
    assert_eq!(clock.recorded_waits().len(), waits_before_rejection);
    assert_eq!(budgets.daily_used(Origin::Nvd, advanced_to), DAILY_BUDGET);
    // and the other origin is still open
    assert_eq!(
        budgets.admit(Origin::Kev, advanced_to),
        AdmitDecision::Admit
    );

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the daily-ceiling test must not consume real time"
    );
}
