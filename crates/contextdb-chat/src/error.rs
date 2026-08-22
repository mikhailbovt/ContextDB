//! Sanitized chat-vertical failures.

use thiserror::Error;

/// Failures at the persistent conversational middleware boundary.
#[derive(Debug, Error)]
pub enum ChatError {
    /// A bounded caller contract is invalid.
    #[error("invalid chat input: {0}")]
    InvalidInput(&'static str),
    /// The caller reused an idempotency key for different logical bytes.
    #[error("chat idempotency key is bound to another request")]
    IdempotencyConflict,
    /// A requested durable chat object does not exist.
    #[error("chat object was not found: {0}")]
    NotFound(&'static str),
    /// The principal cannot access the requested session or operation.
    #[error("chat operation is not authorized")]
    Unauthorized,
    /// A durable record failed checksum, type, or cross-reference validation.
    #[error("chat store is corrupt: {0}")]
    Corrupt(String),
    /// A recall adapter failed without exposing query or memory payloads.
    #[error("conversation recall failed: {0}")]
    Recall(String),
    /// A model-runtime adapter failed without exposing prompt or response content.
    #[error("conversation runtime failed: {0}")]
    Runtime(String),
    /// Numeric sequencing, latency, or aggregation overflowed.
    #[error("chat runtime arithmetic exhausted")]
    ArithmeticOverflow,
    /// A synchronization primitive was poisoned.
    #[error("chat runtime lock poisoned")]
    LockPoisoned,
    /// Core semantic validation rejected a typed value.
    #[error("invalid core chat contract: {0}")]
    CoreValidation(#[from] contextdb_core::ValidationError),
    /// Durable journal operation failed.
    #[error("chat journal operation failed: {0}")]
    Journal(#[from] contextdb_journal::JournalError),
    /// Physical state operation failed.
    #[error("chat storage operation failed: {0}")]
    Storage(#[from] contextdb_storage::StorageError),
    /// Checksummed record framing failed.
    #[error("chat record framing failed: {0}")]
    Format(#[from] contextdb_format::FormatError),
    /// M10 extraction or adjudication contract failed.
    #[error("chat cognition operation failed: {0}")]
    Cognition(#[from] contextdb_cognition::CognitionError),
    /// Canonical ContextPack validation failed.
    #[error("chat context operation failed: {0}")]
    Context(#[from] contextdb_context::ContextError),
    /// Internal structured serialization failed.
    #[error("chat serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Conversational runtime result.
pub type Result<T> = std::result::Result<T, ChatError>;
