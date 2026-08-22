use thiserror::Error;

/// Result returned by ContextDB logical validation.
pub type ValidationResult<T = ()> = Result<T, ValidationError>;

/// A deterministic violation of the logical ContextDB contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("{kind} must not be the nil identifier")]
    NilIdentifier { kind: &'static str },

    #[error("{kind} is not a valid stable identifier")]
    InvalidIdentifier { kind: &'static str },

    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },

    #[error("{field} must not be blank")]
    BlankText { field: &'static str },

    #[error("invalid time range: start {start} must be before end {end}")]
    InvalidTimeRange { start: i64, end: i64 },

    #[error("invalid commit range: start {start} must be before end {end}")]
    InvalidCommitRange { start: u64, end: u64 },

    #[error("revision numbers must start at one and be contiguous")]
    InvalidRevisionSequence,

    #[error("transaction-time intervals overlap in a revision chain")]
    OverlappingTransactionIntervals,

    #[error("{field} contains a duplicate identifier")]
    DuplicateIdentifier { field: &'static str },

    #[error("semantic memory requires evidence for epistemic basis {basis}")]
    MissingEvidence { basis: &'static str },

    #[error("actor assertion basis requires an actor-assertion derivation")]
    InvalidAssertionDerivation,

    #[error("derived policy is more permissive than its source: {reason}")]
    PolicyWeakening { reason: &'static str },

    #[error("single-valued predicate has simultaneous accepted values without one conflict set")]
    CardinalityConflictWithoutConflictSet,

    #[error("predicate domain or range is incompatible with the claim")]
    PredicateTypeMismatch,

    #[error("lineage contains a cycle")]
    LineageCycle,

    #[error("an item cannot support itself through its own lineage")]
    SelfSupportingLineage,

    #[error("a hierarchy view cannot contain a cycle")]
    HierarchyCycle,

    #[error("numeric value {field} must be finite and within the documented range")]
    InvalidNumber { field: &'static str },

    #[error("invalid evidence selector: {reason}")]
    InvalidEvidenceSelector { reason: &'static str },

    #[error("observation must reference at least one content block or artifact")]
    MissingObservationContent,

    #[error("conflict set must contain at least two distinct claims")]
    InvalidConflictSet,

    #[error("candidate payload must be a structured JSON object")]
    InvalidCandidatePayload,

    #[error("invalid state transition: {reason}")]
    InvalidState { reason: &'static str },
}
