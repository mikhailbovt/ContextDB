use contextdb_core::ValidationError;
use thiserror::Error;

/// Fatal contract failures that prevent a proposal batch from being evaluated.
///
/// Candidate-local failures are represented as [`crate::ValidationIssue`] and
/// persisted in quarantine instead of aborting otherwise independent items.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CognitionError {
    #[error("proposal payload exceeds the configured byte limit")]
    OutputTooLarge,
    #[error("proposal payload is not valid strict JSON: {0}")]
    InvalidJson(String),
    #[error("unsupported proposal schema: expected {expected}, received {actual}")]
    SchemaMismatch { expected: String, actual: String },
    #[error("proposal processing run does not match the request")]
    ProcessingRunMismatch,
    #[error("proposal input digest does not match the authorized input")]
    InputDigestMismatch,
    #[error("proposal policy digest does not match the authenticated policy")]
    PolicyDigestMismatch,
    #[error("proposal model-call identity does not match the processing run")]
    ModelCallMismatch,
    #[error("proposal batch contains too many candidates")]
    TooManyCandidates,
    #[error("proposal batch contains duplicate local identifier {0}")]
    DuplicateLocalIdentifier(String),
    #[error("invalid proposal field {field}: {reason}")]
    InvalidProposal {
        field: &'static str,
        reason: &'static str,
    },
    #[error("semantic commit sequence is exhausted")]
    CommitSequenceExhausted,
    #[error("deterministic identifier construction failed")]
    IdentifierConstruction,
    #[error("canonical transaction failed validation: {0}")]
    CoreValidation(#[from] ValidationError),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

/// Result alias for cognition contracts.
pub type CognitionResult<T> = Result<T, CognitionError>;
