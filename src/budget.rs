//! The intake rate budget (issue #1745 P-P1, design D2) — the producer
//! twin of the consumer metadata worker's NVD allowance
//! (`waf_cve_metadata_worker.rs`: 5 requests per rolling 30 seconds
//! unauthenticated, plus the plan's ≤1024 daily ceiling).
//!
//! One ledger per origin (`kev` / `nvd`): the KEV catalog is a single
//! file per cycle so its window rarely binds, but the law is uniform
//! per origin. The daily ceiling rolls over at the UTC midnight of the
//! caller's clock read (`div_euclid` day index — pure, no clock read
//! of its own). A decision is `Admit`, `WaitWindow` (the earliest
//! instant the oldest request slides out), or `WaitDaily` (the next
//! UTC midnight); callers wait through the injected
//! [`UvpbClock`](crate::clock::UvpbClock) and re-admit, which is what
//! keeps the whole law virtual-clock testable.

use std::collections::VecDeque;

/// The NVD unauthenticated allowance: 5 requests per rolling window.
pub const WINDOW_REQUESTS: usize = 5;
/// The rolling window length, seconds.
pub const WINDOW_SECONDS: i64 = 30;
/// The daily ceiling (the feed-rule cap convention: one fetch per rule
/// per day is the consumer's rationale; the producer adopts the same
/// number as its own ceiling, design D2).
pub const DAILY_BUDGET: u32 = 1024;
/// Seconds per UTC day — the daily rollover's divisor.
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Which upstream origin a request belongs to. Each origin keeps its
/// own ledger so a KEV catalog refresh never consumes the NVD window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The CISA KEV single-file catalog.
    Kev,
    /// The NVD CVE API 2.0 (per-CVE fetches).
    Nvd,
}

impl Origin {
    /// Stable lowercase name for logs and error lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::Kev => "kev",
            Origin::Nvd => "nvd",
        }
    }
}

/// The outcome of one budget admission over a single clock read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitDecision {
    /// Spend a request now.
    Admit,
    /// The 30-second window is full: retry at or after this unix
    /// second (when the oldest admitted request slides out).
    WaitWindow(i64),
    /// The daily ceiling is spent: retry at or after this unix second
    /// (the next UTC midnight). Batch callers treat this as a stop,
    /// not a sleep.
    WaitDaily(i64),
}

#[derive(Debug)]
struct OriginLedger {
    /// Unix seconds of admitted requests still inside the window.
    admitted: VecDeque<i64>,
    /// The UTC day index the `daily_used` count belongs to.
    day_index: Option<i64>,
    daily_used: u32,
}

impl OriginLedger {
    fn new() -> Self {
        Self {
            admitted: VecDeque::new(),
            day_index: None,
            daily_used: 0,
        }
    }

    /// Pure over the caller's clock read: evict the slid-out window
    /// entries, roll the day, then decide. A rejected request records
    /// nothing — only admitted requests consume budget.
    fn admit(&mut self, now: i64, daily_cap: u32) -> AdmitDecision {
        while self
            .admitted
            .front()
            .is_some_and(|&then| now - then >= WINDOW_SECONDS)
        {
            self.admitted.pop_front();
        }
        let today = now.div_euclid(SECONDS_PER_DAY);
        if self.day_index != Some(today) {
            self.day_index = Some(today);
            self.daily_used = 0;
        }
        if self.daily_used >= daily_cap {
            return AdmitDecision::WaitDaily((today + 1) * SECONDS_PER_DAY);
        }
        if self.admitted.len() >= WINDOW_REQUESTS {
            let oldest = self.admitted.front().copied().unwrap_or(now);
            return AdmitDecision::WaitWindow(oldest + WINDOW_SECONDS);
        }
        self.admitted.push_back(now);
        self.daily_used += 1;
        AdmitDecision::Admit
    }
}

/// The per-origin budget set the intake fetch path consults.
#[derive(Debug)]
pub struct RateBudgets {
    kev: OriginLedger,
    nvd: OriginLedger,
}

impl RateBudgets {
    /// Fresh budgets with no spent requests.
    pub fn new() -> Self {
        Self {
            kev: OriginLedger::new(),
            nvd: OriginLedger::new(),
        }
    }

    fn ledger(&mut self, origin: Origin) -> &mut OriginLedger {
        match origin {
            Origin::Kev => &mut self.kev,
            Origin::Nvd => &mut self.nvd,
        }
    }

    /// One admission decision for `origin` at the caller's clock read
    /// `now`.
    pub fn admit(&mut self, origin: Origin, now: i64) -> AdmitDecision {
        self.ledger(origin).admit(now, DAILY_BUDGET)
    }

    /// How many requests `origin` has spent in the UTC day containing
    /// `now` (0 if the ledger's day already rolled over without an
    /// admission).
    pub fn daily_used(&self, origin: Origin, now: i64) -> u32 {
        let ledger = match origin {
            Origin::Kev => &self.kev,
            Origin::Nvd => &self.nvd,
        };
        if ledger.day_index == Some(now.div_euclid(SECONDS_PER_DAY)) {
            ledger.daily_used
        } else {
            0
        }
    }
}

impl Default for RateBudgets {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;

    #[test]
    fn window_holds_five_then_names_the_slide_instant() {
        let mut ledger = OriginLedger::new();
        for offset in 0..5 {
            assert_eq!(
                ledger.admit(T0 + offset, DAILY_BUDGET),
                AdmitDecision::Admit
            );
        }
        assert_eq!(
            ledger.admit(T0 + 5, DAILY_BUDGET),
            AdmitDecision::WaitWindow(T0 + WINDOW_SECONDS)
        );
    }

    #[test]
    fn daily_cap_rolls_over_at_utc_midnight_only() {
        let mut ledger = OriginLedger::new();
        // Spend the whole day at 6-second spacing (the window never binds).
        let day_start = T0.div_euclid(SECONDS_PER_DAY) * SECONDS_PER_DAY;
        for i in 0..DAILY_BUDGET {
            let now = day_start + (i as i64) * 6;
            assert_eq!(ledger.admit(now, DAILY_BUDGET), AdmitDecision::Admit);
        }
        let last = day_start + (DAILY_BUDGET as i64 - 1) * 6;
        assert_eq!(
            ledger.admit(last + 1, DAILY_BUDGET),
            AdmitDecision::WaitDaily(day_start + SECONDS_PER_DAY)
        );
        // Same ledger, next UTC day: the counter reset on the first read.
        assert_eq!(
            ledger.admit(day_start + SECONDS_PER_DAY, DAILY_BUDGET),
            AdmitDecision::Admit
        );
    }
}
