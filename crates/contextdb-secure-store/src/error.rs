use thiserror::Error;

/// Fail-closed error returned by the hard-delete v2 foundation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SecureStoreError {
    /// A caller supplied a malformed or unsupported value.
    #[error("invalid secure-store input: {0}")]
    InvalidInput(String),
    /// Authenticated state, ciphertext, or evidence did not verify.
    #[error("secure-store integrity verification failed: {0}")]
    Integrity(String),
    /// A compare-and-swap token, generation, or workflow state was stale.
    #[error("secure-store state conflict: {0}")]
    StateConflict(String),
    /// The requested content-encryption key is not usable.
    #[error("content key is unavailable")]
    KeyUnavailable,
    /// The authoritative dependency closure or deletion proof is incomplete.
    #[error("deletion is incomplete: {0}")]
    DeletionIncomplete(String),
    /// An external cryptographic authority rejected the operation.
    #[error("secure-store cryptographic operation failed")]
    CryptographicFailure,
    /// Canonical serialization failed.
    #[error("secure-store canonical serialization failed")]
    Serialization,
}

/// Result alias for hard-delete v2 foundation operations.
pub type Result<T> = std::result::Result<T, SecureStoreError>;
