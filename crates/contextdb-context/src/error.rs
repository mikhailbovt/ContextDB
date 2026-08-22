//! Error contracts for deterministic context compilation.

use thiserror::Error;

/// Result type used throughout this crate.
pub type Result<T> = std::result::Result<T, ContextError>;

/// Fail-closed errors returned by policy materialization, compilation, and rendering.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    #[error("invalid context request: {0}")]
    InvalidRequest(String),
    #[error("context provider failed: {0}")]
    Provider(String),
    #[error("authorization contract failed: {0}")]
    Authorization(String),
    #[error("hard context budget cannot be satisfied: {0}")]
    BudgetExceeded(String),
    #[error("context continuation is invalid: {0}")]
    InvalidContinuation(String),
    #[error("tokenizer failed: {0}")]
    Tokenizer(String),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}
