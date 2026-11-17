//! The clock seam for the intake budget (issue #1745 P-P1, design D2).
//!
//! Every budget decision in this pipeline is a pure function of a unix
//! second the CALLER reads from a [`UvpbClock`] — the same shape the
//! consumer metadata worker uses (`RateBudget::admit` over a single
//! clock read). The budget logic never touches `SystemTime` or
//! `Instant` itself, which is what makes the virtual-clock tests
//! (`tests/budget_clock.rs`) real contracts instead of sleeps: a
//! [`VirtualClock`] answers `sleep_until` by advancing its own value,
//! so a 5-requests-per-30-seconds window or a daily-1024 ceiling is
//! exercised across hours of virtual time without consuming one real
//! second.

use std::sync::Mutex;
use std::sync::PoisonError;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The only time source the pipeline may consult: the current instant
/// and a primitive wait. Blocking on this trait is how the budget
/// spends a window slide; test clocks implement the wait as a jump.
pub trait UvpbClock: Send + Sync {
    /// The current unix second (UTC).
    fn now_unix(&self) -> i64;
    /// Blocks until `unix` (no-op if it already passed). Implementations
    /// may round up to whole seconds — the budget's granularity is
    /// seconds, not sub-second fairness.
    fn sleep_until(&self, unix: i64);
}

/// The production clock: `SystemTime` for reads, `thread::sleep` for
/// waits.
pub struct StdClock;

impl UvpbClock for StdClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs() as i64)
            .unwrap_or_default()
    }

    fn sleep_until(&self, unix: i64) {
        let now = self.now_unix();
        if unix > now {
            thread::sleep(Duration::from_secs((unix - now) as u64));
        }
    }
}

/// A deterministic in-memory clock for tests. `sleep_until` records the
/// requested instant and advances the clock to it (never backwards), so
/// budget waits consume zero real time and every wait is auditable via
/// [`VirtualClock::recorded_waits`].
pub struct VirtualClock {
    now: Mutex<i64>,
    waits: Mutex<Vec<i64>>,
}

impl VirtualClock {
    /// Starts frozen at `unix`.
    pub fn start_at(unix: i64) -> Self {
        Self {
            now: Mutex::new(unix),
            waits: Mutex::new(Vec::new()),
        }
    }

    /// The clock's current value without the trait object.
    pub fn now_value(&self) -> i64 {
        *self.lock_now()
    }

    /// Manually advances the clock (forbidden to go backwards).
    pub fn advance_to(&self, unix: i64) {
        let mut now = self.lock_now();
        if unix > *now {
            *now = unix;
        }
    }

    /// Advances by `seconds` from the current value.
    pub fn advance_by(&self, seconds: i64) {
        let target = self.now_value() + seconds;
        self.advance_to(target);
    }

    /// Every `sleep_until` instant requested of this clock, in request
    /// order — the evidence a budget test asserts on.
    pub fn recorded_waits(&self) -> Vec<i64> {
        self.lock_waits().clone()
    }

    fn lock_now(&self) -> std::sync::MutexGuard<'_, i64> {
        self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_waits(&self) -> std::sync::MutexGuard<'_, Vec<i64>> {
        self.waits.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl UvpbClock for VirtualClock {
    fn now_unix(&self) -> i64 {
        self.now_value()
    }

    fn sleep_until(&self, unix: i64) {
        self.lock_waits().push(unix);
        self.advance_to(unix);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_clock_sleep_is_a_jump_and_a_record() {
        let clock = VirtualClock::start_at(1_800_000_000);
        clock.sleep_until(1_800_000_030);
        clock.sleep_until(1_800_000_010); // backwards: no-op on the value
        assert_eq!(clock.now_value(), 1_800_000_030);
        assert_eq!(clock.recorded_waits(), vec![1_800_000_030, 1_800_000_010]);
    }

    #[test]
    fn std_clock_never_sleeps_backwards() {
        let clock = StdClock;
        let now = clock.now_unix();
        clock.sleep_until(now - 10_000);
        assert!(clock.now_unix() >= now);
    }
}
