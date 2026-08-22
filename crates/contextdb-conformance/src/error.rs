use thiserror::Error;

/// Harness/configuration failure, distinct from a canonical service error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConformanceError {
    /// Adapter framing or response decoding failed.
    #[error("adapter protocol failure: {0}")]
    Protocol(String),
    /// Required external proof artifact was not supplied.
    #[error("external artifact not supplied: {0}")]
    NotExercised(String),
    /// A conformance invariant failed.
    #[error("conformance assertion failed: {0}")]
    Assertion(String),
    /// Input/output operation failed.
    #[error("conformance I/O failed: {0}")]
    Io(String),
}

/// Harness result alias.
pub type ConformanceResult<T> = Result<T, ConformanceError>;
