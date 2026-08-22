use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::{
    ModelCapability, ModelRevision, ModelRuntimeError, ProviderErrorKind, ProviderId, Result,
};

/// Monotonic time and retry-delay abstraction. Tests use `ManualTimer`, so no
/// wall-clock sleeps are required.
pub trait RuntimeTimer: Send + Sync {
    /// Current monotonic milliseconds in this runtime epoch.
    fn now_ms(&self) -> u64;

    /// Waits or advances by a bounded retry delay.
    fn delay_ms(&self, delay_ms: u64);
}

/// Production monotonic timer.
#[derive(Debug)]
pub struct SystemTimer {
    origin: Instant,
}

impl Default for SystemTimer {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl SystemTimer {
    /// Creates a monotonic timer rooted at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RuntimeTimer for SystemTimer {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn delay_ms(&self, delay_ms: u64) {
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
}

/// Deterministic fake clock and delay implementation.
#[derive(Debug, Default)]
pub struct ManualTimer {
    now_ms: AtomicU64,
}

impl ManualTimer {
    /// Creates a fake timer at an explicit monotonic instant.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(now_ms),
        }
    }

    /// Advances fake time without sleeping.
    pub fn advance(&self, delta_ms: u64) {
        let _ = self
            .now_ms
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(delta_ms))
            });
    }

    /// Sets fake time, useful for boundary tests.
    pub fn set(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }
}

impl RuntimeTimer for ManualTimer {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn delay_ms(&self, delay_ms: u64) {
        self.advance(delay_ms);
    }
}

/// Bounded retry and deadline policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Maximum attempts per selected provider route.
    pub max_attempts: u8,
    /// Maximum milliseconds granted to one adapter attempt.
    pub per_attempt_timeout_ms: u64,
    /// Maximum milliseconds across every route and retry.
    pub total_timeout_ms: u64,
    /// Base deterministic exponential backoff.
    pub base_backoff_ms: u64,
    /// Maximum backoff per retry.
    pub max_backoff_ms: u64,
    /// At most one malformed-output repair, per RFC.
    pub max_schema_repairs: u8,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            per_attempt_timeout_ms: 30_000,
            total_timeout_ms: 60_000,
            base_backoff_ms: 100,
            max_backoff_ms: 2_000,
            max_schema_repairs: 1,
        }
    }
}

impl RetryPolicy {
    /// Checks retry bounds and the normative one-repair maximum.
    pub fn validate(self) -> Result<()> {
        if self.max_attempts == 0
            || self.max_attempts > 10
            || self.per_attempt_timeout_ms == 0
            || self.total_timeout_ms < self.per_attempt_timeout_ms
            || self.max_schema_repairs > 1
            || self.base_backoff_ms > self.max_backoff_ms
        {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "retry_policy",
                reason: "invalid attempt, timeout, backoff, or repair bound",
            });
        }
        Ok(())
    }

    /// Computes bounded exponential retry delay.
    #[must_use]
    pub fn delay_for(self, completed_attempts: u8, retry_after_ms: Option<u64>) -> u64 {
        let shift = u32::from(completed_attempts.saturating_sub(1)).min(31);
        let exponential = self
            .base_backoff_ms
            .saturating_mul(1_u64.checked_shl(shift).unwrap_or(u64::MAX))
            .min(self.max_backoff_ms);
        retry_after_ms
            .unwrap_or(exponential)
            .min(self.max_backoff_ms)
    }
}

/// Circuit-breaker configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitBreakerConfig {
    /// Consecutive infrastructure failures before opening.
    pub failure_threshold: u32,
    /// Cooldown before one half-open probe.
    pub open_duration_ms: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            open_duration_ms: 30_000,
        }
    }
}

impl CircuitBreakerConfig {
    /// Checks non-zero bounds.
    pub fn validate(self) -> Result<()> {
        if self.failure_threshold == 0 || self.open_duration_ms == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "circuit_breaker",
                reason: "threshold and open duration must be positive",
            });
        }
        Ok(())
    }
}

/// Circuit isolation key for one provider/model/capability route.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CircuitKey {
    /// Provider.
    pub provider: ProviderId,
    /// Exact model revision.
    pub model_revision: ModelRevision,
    /// Specialized operation.
    pub capability: ModelCapability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CircuitState {
    Closed {
        /// Consecutive infrastructure failures.
        consecutive_failures: u32,
    },
    Open {
        /// Earliest monotonic recovery probe instant.
        retry_at_ms: u64,
    },
    HalfOpen {
        /// Whether the single recovery probe was claimed.
        probe_in_flight: bool,
    },
}

impl Default for CircuitState {
    fn default() -> Self {
        Self::Closed {
            consecutive_failures: 0,
        }
    }
}

/// Observable payload-free circuit state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitSnapshot {
    /// Calls are allowed; includes consecutive infrastructure failures.
    Closed {
        /// Consecutive infrastructure failures.
        consecutive_failures: u32,
    },
    /// Calls are denied until this monotonic instant.
    Open {
        /// Earliest monotonic recovery probe instant.
        retry_at_ms: u64,
    },
    /// Exactly one recovery probe may be in flight.
    HalfOpen {
        /// Whether the single recovery probe was claimed.
        probe_in_flight: bool,
    },
}

/// Thread-safe provider circuit registry.
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    states: Mutex<BTreeMap<CircuitKey, CircuitState>>,
}

impl fmt::Debug for CircuitBreaker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircuitBreaker")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CircuitBreaker {
    /// Creates an empty circuit registry.
    pub fn new(config: CircuitBreakerConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            states: Mutex::new(BTreeMap::new()),
        })
    }

    /// Acquires permission for an attempt. After cooldown, only one half-open
    /// probe is admitted.
    pub fn allow(&self, key: &CircuitKey, now_ms: u64) -> Result<bool> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        let state = states.entry(key.clone()).or_default();
        match *state {
            CircuitState::Closed { .. } => Ok(true),
            CircuitState::Open { retry_at_ms } if now_ms < retry_at_ms => Ok(false),
            CircuitState::Open { .. } => {
                *state = CircuitState::HalfOpen {
                    probe_in_flight: true,
                };
                Ok(true)
            }
            CircuitState::HalfOpen {
                probe_in_flight: false,
            } => {
                *state = CircuitState::HalfOpen {
                    probe_in_flight: true,
                };
                Ok(true)
            }
            CircuitState::HalfOpen {
                probe_in_flight: true,
            } => Ok(false),
        }
    }

    /// Records a successful provider response, including schema-invalid output
    /// (which is a model quality issue rather than infrastructure outage).
    pub fn record_success(&self, key: &CircuitKey) -> Result<()> {
        self.states
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .insert(
                key.clone(),
                CircuitState::Closed {
                    consecutive_failures: 0,
                },
            );
        Ok(())
    }

    /// Records a provider failure. Refusal and invalid-request outcomes release
    /// a half-open probe without degrading infrastructure health.
    pub fn record_failure(
        &self,
        key: &CircuitKey,
        kind: ProviderErrorKind,
        now_ms: u64,
    ) -> Result<()> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        let state = states.entry(key.clone()).or_default();
        if !kind.affects_circuit() {
            *state = CircuitState::Closed {
                consecutive_failures: 0,
            };
            return Ok(());
        }
        let failures = match *state {
            CircuitState::Closed {
                consecutive_failures,
            } => consecutive_failures.saturating_add(1),
            CircuitState::Open { .. } | CircuitState::HalfOpen { .. } => {
                self.config.failure_threshold
            }
        };
        *state = if failures >= self.config.failure_threshold {
            CircuitState::Open {
                retry_at_ms: now_ms
                    .checked_add(self.config.open_duration_ms)
                    .ok_or(ModelRuntimeError::ArithmeticOverflow)?,
            }
        } else {
            CircuitState::Closed {
                consecutive_failures: failures,
            }
        };
        Ok(())
    }

    /// Returns a payload-free state snapshot.
    pub fn snapshot(&self, key: &CircuitKey) -> Result<CircuitSnapshot> {
        let state = self
            .states
            .lock()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .get(key)
            .copied()
            .unwrap_or_default();
        Ok(match state {
            CircuitState::Closed {
                consecutive_failures,
            } => CircuitSnapshot::Closed {
                consecutive_failures,
            },
            CircuitState::Open { retry_at_ms } => CircuitSnapshot::Open { retry_at_ms },
            CircuitState::HalfOpen { probe_in_flight } => {
                CircuitSnapshot::HalfOpen { probe_in_flight }
            }
        })
    }
}

/// Optional shared rate-limit watermark used by hosted adapters without
/// exposing credentials or provider SDK types.
#[derive(Debug, Default)]
pub struct AvailabilityRegistry {
    unavailable_until: RwLock<BTreeMap<ProviderId, u64>>,
}

impl AvailabilityRegistry {
    /// Marks a provider unavailable until an absolute monotonic instant.
    pub fn mark_unavailable(&self, provider: ProviderId, until_ms: u64) -> Result<()> {
        self.unavailable_until
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .insert(provider, until_ms);
        Ok(())
    }

    /// Checks whether the provider may be attempted now.
    pub fn available(&self, provider: &ProviderId, now_ms: u64) -> Result<bool> {
        Ok(self
            .unavailable_until
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .get(provider)
            .is_none_or(|until| now_ms >= *until))
    }
}
