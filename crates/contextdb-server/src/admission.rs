//! Shared fail-fast admission for blocking transport work.
//!
//! Tokio's blocking executor owns its own queue.  Network adapters must obtain
//! one of these permits before submitting work so overload is rejected at the
//! transport boundary instead of becoming an unbounded hidden queue.

use std::fmt;
use std::sync::Arc;

use contextdb_service::{ErrorCode, ServiceError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A workload class with an independent blocking-execution budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionClass {
    /// Latency-sensitive observation, recall, graph, runtime, and status calls.
    Interactive,
    /// Archive, backup, restore, and subject-transfer calls.
    BulkTransfer,
    /// Verification, reindexing, compaction, and other maintenance calls.
    Maintenance,
}

impl ExecutionClass {
    const fn policy_name(self) -> &'static str {
        match self {
            Self::Interactive => "transport_execution_interactive",
            Self::BulkTransfer => "transport_execution_bulk_transfer",
            Self::Maintenance => "transport_execution_maintenance",
        }
    }
}

/// Finite independent capacities for blocking transport work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionAdmissionConfig {
    interactive: usize,
    bulk_transfer: usize,
    maintenance: usize,
}

impl ExecutionAdmissionConfig {
    /// Builds a configuration. Every capacity must be nonzero.
    pub fn new(
        interactive: usize,
        bulk_transfer: usize,
        maintenance: usize,
    ) -> Result<Self, ExecutionAdmissionConfigError> {
        for (class, capacity) in [
            (ExecutionClass::Interactive, interactive),
            (ExecutionClass::BulkTransfer, bulk_transfer),
            (ExecutionClass::Maintenance, maintenance),
        ] {
            if capacity == 0 {
                return Err(ExecutionAdmissionConfigError::ZeroCapacity(class));
            }
            if capacity > Semaphore::MAX_PERMITS {
                return Err(ExecutionAdmissionConfigError::CapacityTooLarge {
                    class,
                    requested: capacity,
                    maximum: Semaphore::MAX_PERMITS,
                });
            }
        }
        Ok(Self {
            interactive,
            bulk_transfer,
            maintenance,
        })
    }

    /// Returns the configured capacity for one class.
    #[must_use]
    pub const fn capacity(self, class: ExecutionClass) -> usize {
        match class {
            ExecutionClass::Interactive => self.interactive,
            ExecutionClass::BulkTransfer => self.bulk_transfer,
            ExecutionClass::Maintenance => self.maintenance,
        }
    }
}

impl Default for ExecutionAdmissionConfig {
    fn default() -> Self {
        Self {
            interactive: 32,
            bulk_transfer: 2,
            maintenance: 1,
        }
    }
}

/// Invalid blocking-execution admission configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionAdmissionConfigError {
    /// One workload class was configured with no execution capacity.
    ZeroCapacity(ExecutionClass),
    /// One workload class exceeded Tokio's representable semaphore capacity.
    CapacityTooLarge {
        /// Workload class whose configured capacity was invalid.
        class: ExecutionClass,
        /// Requested capacity.
        requested: usize,
        /// Largest capacity accepted by the executor semaphore.
        maximum: usize,
    },
}

impl fmt::Display for ExecutionAdmissionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity(class) => {
                write!(
                    formatter,
                    "execution admission capacity is zero for {class:?}"
                )
            }
            Self::CapacityTooLarge {
                class,
                requested,
                maximum,
            } => write!(
                formatter,
                "execution admission capacity {requested} for {class:?} exceeds maximum {maximum}"
            ),
        }
    }
}

impl std::error::Error for ExecutionAdmissionConfigError {}

/// Storage-neutral shared admission authority for HTTP and gRPC adapters.
#[derive(Clone, Debug)]
pub struct ExecutionAdmission {
    interactive: Arc<Semaphore>,
    bulk_transfer: Arc<Semaphore>,
    maintenance: Arc<Semaphore>,
}

impl ExecutionAdmission {
    /// Creates independent fail-fast pools from a validated configuration.
    #[must_use]
    pub fn new(config: ExecutionAdmissionConfig) -> Self {
        Self {
            interactive: Arc::new(Semaphore::new(config.capacity(ExecutionClass::Interactive))),
            bulk_transfer: Arc::new(Semaphore::new(
                config.capacity(ExecutionClass::BulkTransfer),
            )),
            maintenance: Arc::new(Semaphore::new(config.capacity(ExecutionClass::Maintenance))),
        }
    }

    /// Acquires immediately or returns a stable content-free overload error.
    pub fn try_acquire(&self, class: ExecutionClass) -> Result<ExecutionPermit, ServiceError> {
        let semaphore = match class {
            ExecutionClass::Interactive => &self.interactive,
            ExecutionClass::BulkTransfer => &self.bulk_transfer,
            ExecutionClass::Maintenance => &self.maintenance,
        };
        Arc::clone(semaphore)
            .try_acquire_owned()
            .map(|permit| ExecutionPermit { _permit: permit })
            .map_err(|_| admission_exhausted(class))
    }

    /// Returns currently available capacity without reserving it.
    #[must_use]
    pub fn available_permits(&self, class: ExecutionClass) -> usize {
        match class {
            ExecutionClass::Interactive => self.interactive.available_permits(),
            ExecutionClass::BulkTransfer => self.bulk_transfer.available_permits(),
            ExecutionClass::Maintenance => self.maintenance.available_permits(),
        }
    }

    /// Submits one admitted blocking operation. The permit lives inside the
    /// blocking closure and is released on success, service error, or panic.
    pub async fn execute<T, F>(
        &self,
        class: ExecutionClass,
        operation: F,
    ) -> Result<T, ServiceError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, ServiceError> + Send + 'static,
    {
        let permit = self.try_acquire(class)?;
        Self::execute_admitted(permit, operation).await
    }

    /// Submits work after the caller has already reserved a permit. This is
    /// used by streaming adapters which must reject overload before emitting
    /// an operation-started event.
    pub(crate) async fn execute_admitted<T, F>(
        permit: ExecutionPermit,
        operation: F,
    ) -> Result<T, ServiceError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, ServiceError> + Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "bounded service executor failed",
                true,
            )
        })?
    }
}

impl Default for ExecutionAdmission {
    fn default() -> Self {
        Self::new(ExecutionAdmissionConfig::default())
    }
}

/// Shared admission authority type used by both network adapters.
pub type SharedExecutionAdmission = Arc<ExecutionAdmission>;

/// Permit which must remain owned by the submitted blocking closure.
#[derive(Debug)]
pub struct ExecutionPermit {
    _permit: OwnedSemaphorePermit,
}

fn admission_exhausted(class: ExecutionClass) -> ServiceError {
    ServiceError::new(
        ErrorCode::ResourceExhausted,
        "transport execution capacity is temporarily exhausted",
        true,
    )
    .with_context(
        Vec::new(),
        Some(class.policy_name().to_owned()),
        Some("retry after in-flight work completes".to_owned()),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacities_are_nonzero_and_classes_are_isolated() {
        assert!(ExecutionAdmissionConfig::new(0, 1, 1).is_err());
        assert!(ExecutionAdmissionConfig::new(1, 0, 1).is_err());
        assert!(ExecutionAdmissionConfig::new(1, 1, 0).is_err());
        assert!(matches!(
            ExecutionAdmissionConfig::new(Semaphore::MAX_PERMITS.saturating_add(1), 1, 1),
            Err(ExecutionAdmissionConfigError::CapacityTooLarge {
                class: ExecutionClass::Interactive,
                ..
            })
        ));

        let admission =
            ExecutionAdmission::new(ExecutionAdmissionConfig::new(1, 1, 1).expect("valid config"));
        let interactive = admission
            .try_acquire(ExecutionClass::Interactive)
            .expect("first interactive permit");
        let overload = admission
            .try_acquire(ExecutionClass::Interactive)
            .expect_err("second interactive request must fail fast");
        assert_eq!(overload.code, ErrorCode::ResourceExhausted);
        assert!(overload.retryable);
        assert!(admission.try_acquire(ExecutionClass::Maintenance).is_ok());
        assert!(admission.try_acquire(ExecutionClass::BulkTransfer).is_ok());
        drop(interactive);
        assert!(admission.try_acquire(ExecutionClass::Interactive).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_execution_fails_fast_and_releases_after_completion_or_panic() {
        let admission = Arc::new(ExecutionAdmission::new(
            ExecutionAdmissionConfig::new(1, 1, 1).expect("valid config"),
        ));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let first_admission = Arc::clone(&admission);
        let first = tokio::spawn(async move {
            first_admission
                .execute(ExecutionClass::Interactive, move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.blocking_recv();
                    Ok::<_, ServiceError>(7_u8)
                })
                .await
        });
        started_rx.await.expect("blocking call started");
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = Arc::clone(&second_ran);
        let overload = admission
            .execute(ExecutionClass::Interactive, move || {
                marker.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, ServiceError>(9_u8)
            })
            .await
            .expect_err("second call must fail before submission");
        assert_eq!(overload.code, ErrorCode::ResourceExhausted);
        assert!(!second_ran.load(std::sync::atomic::Ordering::SeqCst));
        release_tx.send(()).expect("release first call");
        assert_eq!(
            first.await.expect("first task joins").expect("first call"),
            7
        );

        let panic = admission
            .execute(
                ExecutionClass::Interactive,
                || -> Result<(), ServiceError> { panic!("test-only blocking panic") },
            )
            .await
            .expect_err("panic maps to unavailable");
        assert_eq!(panic.code, ErrorCode::Unavailable);
        assert_eq!(admission.available_permits(ExecutionClass::Interactive), 1);
    }
}
