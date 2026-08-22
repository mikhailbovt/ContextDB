use thiserror::Error;

/// Persistent graph failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GraphError {
    /// A canonical logical value failed validation.
    #[error("canonical validation failed: {0}")]
    Validation(String),
    /// The storage substrate rejected an operation.
    #[error("storage operation failed: {0}")]
    Storage(String),
    /// A graph invariant would be violated.
    #[error("graph invariant violated: {0}")]
    Invariant(String),
    /// Requested logical object is unavailable in the selected snapshot.
    #[error("{kind} {id} was not found")]
    NotFound {
        /// Logical object class.
        kind: &'static str,
        /// Stable external identifier.
        id: String,
    },
    /// Policy rejected the operation without revealing object existence or metadata.
    #[error("operation is not authorized")]
    Unauthorized,
    /// A journal maintenance operation requires a projector which this graph version does not
    /// implement. Maintenance is never silently skipped.
    #[error("unsupported graph maintenance operation: {0}")]
    UnsupportedMaintenance(&'static str),
    /// Persistent graph bytes cannot be decoded or fail integrity validation.
    #[error("corrupt graph record: {0}")]
    Corrupt(String),
    /// A bounded graph operation cannot safely materialize the requested unit of work.
    #[error("graph resource exhausted for {resource}: limit {limit}, required {required}")]
    ResourceExhausted {
        /// Stable bounded resource identifier.
        resource: &'static str,
        /// Configured hard limit.
        limit: u64,
        /// Minimum known requirement.
        required: u64,
    },
    /// Destructive adjacency maintenance is only safe with synchronized durability.
    #[error("{operation} requires synchronized durability")]
    SyncDurabilityRequired {
        /// Stable operation identifier.
        operation: &'static str,
    },
    /// Another storage-scoped adjacency maintenance operation owns the persistent fence.
    #[error("adjacency maintenance conflict: {requested} cannot run while {active} is fenced")]
    AdjacencyMaintenanceConflict {
        /// Operation which attempted to acquire or use the fence.
        requested: &'static str,
        /// Operation currently recorded by the storage-scoped fence.
        active: &'static str,
    },
    /// The graph's explicit adjacency-retention floor excludes the requested snapshot.
    #[error(
        "graph snapshot {requested} was pruned; oldest retained storage sequence is {oldest_retained}"
    )]
    SnapshotPruned {
        /// Requested physical graph sequence.
        requested: u64,
        /// Oldest sequence accepted by graph snapshot APIs.
        oldest_retained: u64,
    },
}

impl From<contextdb_core::ValidationError> for GraphError {
    fn from(value: contextdb_core::ValidationError) -> Self {
        Self::Validation(value.to_string())
    }
}

impl From<contextdb_storage::StorageError> for GraphError {
    fn from(value: contextdb_storage::StorageError) -> Self {
        Self::Storage(value.to_string())
    }
}

/// Result type for persistent graph operations.
pub type Result<T> = std::result::Result<T, GraphError>;
