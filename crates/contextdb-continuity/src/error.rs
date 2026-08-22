//! Continuity error surface.

/// Result alias for continuity operations.
pub type Result<T> = std::result::Result<T, ContinuityError>;

/// Fail-closed validation, compatibility, policy, and lifecycle errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContinuityError {
    /// A caller supplied an invalid or internally inconsistent artifact.
    #[error("invalid continuity input: {0}")]
    InvalidInput(String),
    /// Stable subject, agent, checkpoint, or snapshot identity changed.
    #[error("continuity identity mismatch: {0}")]
    IdentityMismatch(String),
    /// A privacy or publication policy rejected the operation.
    #[error("continuity policy denied: {0}")]
    PolicyDenied(String),
    /// The target runtime cannot satisfy a required capability or budget.
    #[error("incompatible target runtime: {0}")]
    IncompatibleRuntime(String),
    /// A lifecycle transition is invalid or out of order.
    #[error("invalid lifecycle transition: {0}")]
    InvalidTransition(String),
    /// Canonical serialization or digesting failed.
    #[error("continuity serialization failed: {0}")]
    Serialization(String),
    /// A dependent core/context/model contract rejected the data.
    #[error("continuity dependency rejected input: {0}")]
    Dependency(String),
}
