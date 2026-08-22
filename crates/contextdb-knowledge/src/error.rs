//! Error contract for the accumulating-knowledge vertical.

use thiserror::Error;

/// Result type returned by knowledge ingestion, temporal query, and packing.
pub type Result<T> = std::result::Result<T, KnowledgeError>;

/// Fail-closed M13 error taxonomy.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum KnowledgeError {
    /// A public input violated a stable contract.
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    /// A quoted span was not present in the immutable section bytes.
    #[error("statement {statement} quotes text absent from section {section}")]
    HallucinatedCitation { statement: String, section: String },
    /// The same native revision identifier was reused with different content.
    #[error("native revision {native_revision} was reused with different logical content")]
    RevisionDigestConflict { native_revision: String },
    /// A source revision did not extend the currently published source head.
    #[error("source revision parent does not match the current immutable head")]
    SourceRevisionFork,
    /// A retraction references a source statement that has never been published.
    #[error("retraction target {source_key}/{statement_key} is unknown")]
    UnknownRetractionTarget {
        source_key: String,
        statement_key: String,
    },
    /// One stable source attempted to erase another source's independent claim.
    #[error("a source cannot retract another stable source's claim")]
    CrossFamilyRetraction,
    /// A query selected a semantic snapshot that has not been committed.
    #[error("requested snapshot is newer than the knowledge ledger")]
    FutureSnapshot,
    /// Policy metadata denied every requested operation.
    #[error("knowledge operation is not authorized")]
    Unauthorized,
    /// The commit counter cannot advance.
    #[error("knowledge commit sequence exhausted")]
    CommitSequenceExhausted,
    /// Canonical JSON or digest production failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// A canonical core invariant failed.
    #[error(transparent)]
    Core(#[from] contextdb_core::ValidationError),
    /// A provider-neutral cognition contract failed.
    #[error(transparent)]
    Cognition(#[from] contextdb_cognition::CognitionError),
    /// The model-neutral ContextPack adapter rejected malformed output.
    #[error(transparent)]
    Context(#[from] contextdb_context::ContextError),
    /// The authorization/recall boundary rejected malformed policy metadata.
    #[error(transparent)]
    Recall(#[from] contextdb_recall::RecallError),
}
