use thiserror::Error;

/// Failures produced by the deterministic reference implementation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    /// A write was prepared against an older snapshot than the current head.
    #[error("snapshot precondition failed: expected {expected}, current {current}")]
    SnapshotConflict {
        /// Snapshot sequence supplied by the caller.
        expected: u64,
        /// Current database head.
        current: u64,
    },
    /// An idempotency key was reused for a different request.
    #[error("idempotency key digest {key_digest} was reused with a different request digest")]
    IdempotencyConflict {
        /// Digest of the conflicting key; plaintext keys are not retained in errors.
        key_digest: String,
    },
    /// A requested snapshot is not known to this database.
    #[error("snapshot {requested} does not exist; current head is {head}")]
    SnapshotNotFound {
        /// Requested commit sequence.
        requested: u64,
        /// Current head at the time of lookup.
        head: u64,
    },
    /// A logical object was not found in the selected snapshot.
    #[error("{kind} {id:?} was not found")]
    NotFound {
        /// Stable object class.
        kind: &'static str,
        /// External identifier rendered without content.
        id: String,
    },
    /// A caller attempted an operation outside its authorized universe.
    #[error("operation is not authorized")]
    Unauthorized,
    /// A tenant-scoped reference operation exceeded its fixed work budget.
    #[error("tenant-scoped reference work budget was exhausted")]
    ResourceExhausted,
    /// A mutation would violate a universal logical invariant.
    #[error("invariant violation: {0}")]
    Invariant(String),
    /// Import data is malformed, non-canonical, or inconsistent.
    #[error("invalid logical import: {0}")]
    InvalidImport(String),
    /// Canonical JSON serialization unexpectedly failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// A synchronization primitive was poisoned by a panicking caller.
    #[error("reference engine lock was poisoned")]
    LockPoisoned,
    /// A deterministic failpoint interrupted a transaction.
    #[error("injected crash at {0}")]
    InjectedCrash(&'static str),
    /// A canonical `contextdb-core` value failed its local invariant checks.
    #[error("canonical core validation failed: {0}")]
    CoreValidation(String),
}

impl From<contextdb_core::ValidationError> for ReferenceError {
    fn from(value: contextdb_core::ValidationError) -> Self {
        Self::CoreValidation(value.to_string())
    }
}

/// Result type used by the reference engine.
pub type Result<T> = std::result::Result<T, ReferenceError>;
