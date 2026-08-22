//! Monotonic time abstraction for hot-path SLO tests without sleeps.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Monotonic microsecond clock used only for runtime budgets and measurements.
pub trait ChatClock: Send + Sync {
    /// Current runtime-relative monotonic microseconds.
    fn now_micros(&self) -> u64;
}

/// Production monotonic clock.
#[derive(Debug)]
pub struct SystemChatClock {
    origin: Instant,
}

impl Default for SystemChatClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl SystemChatClock {
    /// Creates a clock rooted at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChatClock for SystemChatClock {
    fn now_micros(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

/// Deterministic fake clock. Advancing never sleeps.
#[derive(Debug, Default)]
pub struct ManualChatClock {
    now: AtomicU64,
}

impl ManualChatClock {
    /// Creates a fake clock at an explicit runtime instant.
    #[must_use]
    pub const fn new(now_micros: u64) -> Self {
        Self {
            now: AtomicU64::new(now_micros),
        }
    }

    /// Advances fake time with saturating arithmetic.
    pub fn advance(&self, delta_micros: u64) {
        let _ = self
            .now
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(delta_micros))
            });
    }

    /// Sets fake time to an exact value.
    pub fn set(&self, now_micros: u64) {
        self.now.store(now_micros, Ordering::SeqCst);
    }
}

impl ChatClock for ManualChatClock {
    fn now_micros(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}
