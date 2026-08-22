use contextdb_core::{ArtifactId, CommitSeq, RepresentationId, VectorSpaceId};
use thiserror::Error;

/// Rebuildable index validation, snapshot, and query failure.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum IndexError {
    #[error("index capability is unavailable: {capability}")]
    CapabilityUnavailable { capability: &'static str },
    #[error("index input is invalid: {0}")]
    Invalid(&'static str),
    #[error("projection watermark {watermark} is newer than snapshot {snapshot}")]
    FutureWatermark {
        watermark: CommitSeq,
        snapshot: CommitSeq,
    },
    #[error("unknown vector space {0}")]
    UnknownVectorSpace(VectorSpaceId),
    #[error("vector dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },
    #[error("mixed or incompatible vector space")]
    IncompatibleVectorSpace,
    #[error("unknown representation {0}")]
    UnknownRepresentation(RepresentationId),
    #[error("unknown artifact {0}")]
    UnknownArtifact(ArtifactId),
    #[error("generation {0} is not staged and verified")]
    GenerationNotReady(u64),
    #[error("generation switch must advance")]
    StaleGeneration,
    #[error("authorization universe belongs to another snapshot or index generation")]
    StaleAuthorization,
    #[error("query budget must be positive")]
    InvalidBudget,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, IndexError>;

impl From<serde_json::Error> for IndexError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}
