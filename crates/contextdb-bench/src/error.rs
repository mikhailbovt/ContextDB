use thiserror::Error;

/// Failures produced by benchmark planning, execution, or report validation.
#[derive(Debug, Error)]
pub enum BenchError {
    /// A benchmark parameter violates the stable workload contract.
    #[error("invalid benchmark configuration `{field}`: {reason}")]
    InvalidConfiguration {
        /// Invalid field name.
        field: &'static str,
        /// Payload-free explanation.
        reason: String,
    },
    /// A deterministic integrity check did not match.
    #[error("benchmark integrity check failed: {0}")]
    Integrity(String),
    /// A telemetry cardinality or payload-safety budget was exceeded.
    #[error("telemetry budget exceeded: {0}")]
    TelemetryBudget(String),
    /// A checked arithmetic operation overflowed.
    #[error("benchmark arithmetic overflow in {0}")]
    ArithmeticOverflow(&'static str),
    /// A required worker thread terminated without a result.
    #[error("benchmark worker thread panicked")]
    WorkerPanicked,
    /// The physical storage boundary rejected an operation.
    #[error(transparent)]
    Storage(#[from] contextdb_storage::StorageError),
    /// The logical journal boundary rejected an operation.
    #[error(transparent)]
    Journal(#[from] contextdb_journal::JournalError),
    /// A machine-readable artifact could not be encoded or decoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A bounded native run could not access its local files or environment.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Result type used throughout the M17 harness.
pub type Result<T> = std::result::Result<T, BenchError>;
