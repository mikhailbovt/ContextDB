use thiserror::Error;

/// Result returned by deterministic recall.
pub type Result<T> = std::result::Result<T, RecallError>;

/// Recall planning, provider, or budget failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RecallError {
    #[error("invalid recall request: {0}")]
    InvalidRequest(String),
    #[error("recall provider failed: {0}")]
    Provider(String),
    #[error("recall continuation does not match the request snapshot or filters")]
    InvalidContinuation,
    #[error("recall deadline was exhausted")]
    DeadlineExceeded,
}
