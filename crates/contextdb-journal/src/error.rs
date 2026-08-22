use contextdb_core::{CommitSeq, ObservationId, ValidationError};
use contextdb_storage::{Durability, StorageError};
use thiserror::Error;

use crate::CommitStage;

/// Journal, validation, recovery, and commit failures.
#[derive(Debug, Error)]
pub enum JournalError {
    /// Physical storage rejected an operation.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A durable frame failed checksum or envelope validation.
    #[error(transparent)]
    Format(#[from] contextdb_format::FormatError),
    /// JSON payload encoding or decoding failed. Payload bytes are never included.
    #[error("journal payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Portable backup metadata, ordering, or digest is invalid.
    #[error("portable journal backup is invalid: {reason}")]
    InvalidBackup {
        /// Sanitized structural reason without record content.
        reason: String,
    },
    /// Restore is intentionally restricted to an empty target database.
    #[error("portable journal restore target is not empty")]
    RestoreTargetNotEmpty,
    /// A typed logical value failed core validation.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Idempotency key is blank or exceeds the bounded input limit.
    #[error("idempotency key must be non-blank and at most 256 bytes")]
    InvalidIdempotencyKey,
    /// One key was reused for a different operation or exact request digest.
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    /// Semantic mutation was prepared from a snapshot other than current head.
    #[error("semantic mutation base {base} does not match journal head {head}")]
    BaseSnapshotMismatch {
        /// Mutation-provided base sequence.
        base: CommitSeq,
        /// Current journal head.
        head: CommitSeq,
    },
    /// Semantic mutation references an observation that has not been accepted.
    #[error("semantic mutation references unknown observation {0}")]
    MissingObservation(ObservationId),
    /// Observation identity was previously accepted under another request.
    #[error("observation identity has already been accepted")]
    DuplicateObservation,
    /// Observation append was incorrectly embedded in a semantic publication.
    #[error("semantic mutation must reference separately accepted observations")]
    EmbeddedObservationAppend,
    /// Monotonic semantic sequence cannot advance beyond `u64::MAX`.
    #[error("semantic commit sequence exhausted")]
    CommitSequenceExhausted,
    /// Physical backend returned weaker durability than requested after commit.
    #[error(
        "physical commit {commit_seq} achieved {achieved:?}, weaker than requested {requested:?}"
    )]
    DurabilityNotAchieved {
        /// Logical commit that was not acknowledged.
        commit_seq: CommitSeq,
        /// Requested durability.
        requested: Durability,
        /// Backend-reported durability.
        achieved: Durability,
    },
    /// A deterministic fault was injected before acknowledgement.
    #[error("injected failure at {0:?}")]
    InjectedFailure(CommitStage),
    /// Commit succeeded but its response was deliberately lost.
    #[error("commit {commit_seq} succeeded but response was lost")]
    LostResponse {
        /// Durable logical sequence discoverable through idempotent retry.
        commit_seq: CommitSeq,
    },
    /// Durable journal prefix is incomplete, inconsistent, or corrupted.
    #[error("journal corruption: {reason}")]
    Corruption {
        /// Sanitized detail which never contains payload content.
        reason: String,
    },
    /// Requested logical snapshot is newer than the published head.
    #[error("journal snapshot {requested} is unavailable; head is {head}")]
    SnapshotUnavailable {
        /// Requested logical sequence.
        requested: CommitSeq,
        /// Current logical head.
        head: CommitSeq,
    },
    /// Commit mutex was poisoned by a panicking writer.
    #[error("journal commit coordinator lock poisoned")]
    CoordinatorPoisoned,
}

/// Journal result type.
pub type Result<T> = std::result::Result<T, JournalError>;
