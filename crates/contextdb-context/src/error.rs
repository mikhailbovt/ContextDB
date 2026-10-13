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
    /// A completely rendered request exceeds its declared input or wire ceiling.
    /// This carries no inference, memory-closure or shared-work failure.
    #[error(
        "complete outgoing request exceeds declared profile: input={input_tokens}/{max_input_tokens}, wire={wire_bytes}/{max_wire_bytes}"
    )]
    OutgoingCapacityExceeded {
        /// Encoder-reported tokens for the complete outgoing request.
        input_tokens: u32,
        /// Declared complete-request input ceiling.
        max_input_tokens: u32,
        /// Actual encoded request byte length.
        wire_bytes: u64,
        /// Declared complete-request byte ceiling.
        max_wire_bytes: u64,
    },
    #[error("context continuation is invalid: {0}")]
    InvalidContinuation(String),
    #[error("tokenizer failed: {0}")]
    Tokenizer(String),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
    #[error("router scorer refused: {0}")]
    RouterScore(String),
    #[error("router proposal refused: {0}")]
    RouterProposal(String),
}
