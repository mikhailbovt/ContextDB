use thiserror::Error;

/// Coding-domain validation, history, and query errors.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CodeDomainError {
    /// A required string was empty, too long, or not canonical.
    #[error("invalid text field: {0}")]
    InvalidText(&'static str),
    /// A repository-relative path was unsafe or non-canonical.
    #[error("invalid repository path: {0}")]
    InvalidPath(String),
    /// A source range was outside the referenced file revision.
    #[error("invalid source range in {path}")]
    InvalidRange {
        /// File containing the bad range.
        path: String,
    },
    /// Caller-supplied content digest did not match the bytes.
    #[error("content digest mismatch for {0}")]
    ContentDigestMismatch(String),
    /// The snapshot parent or current-head precondition was stale.
    #[error("stale snapshot parent")]
    StaleParent,
    /// A referenced repository, snapshot, symbol, decision, or CI run is absent.
    #[error("unknown {kind}: {id}")]
    Unknown {
        /// Logical object kind.
        kind: &'static str,
        /// Safe opaque display identifier.
        id: String,
    },
    /// A key or identity appeared more than once in one atomic input.
    #[error("duplicate {kind}: {value}")]
    Duplicate {
        /// Logical object kind.
        kind: &'static str,
        /// Safe value.
        value: String,
    },
    /// A stable-identity continuity assertion was inconsistent.
    #[error("invalid symbol continuity: {0}")]
    InvalidContinuity(&'static str),
    /// A relation referenced an unknown or incompatible endpoint.
    #[error("invalid code relation")]
    InvalidRelation,
    /// A query matched several symbols and needs disambiguation.
    #[error("ambiguous symbol query")]
    AmbiguousSymbol,
    /// A query budget was zero or exceeded an implementation bound.
    #[error("invalid query budget")]
    InvalidBudget,
    /// Portable payload or one of its nested snapshot digests was invalid.
    #[error("portable code-memory payload failed verification")]
    PortableIntegrity,
    /// Sequence or size arithmetic overflowed.
    #[error("numeric limit exceeded")]
    LimitExceeded,
    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for CodeDomainError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

/// Coding-domain result alias.
pub type Result<T> = std::result::Result<T, CodeDomainError>;
