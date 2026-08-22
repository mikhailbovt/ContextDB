use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable public error code shared by every transport and SDK.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Requested semantic scope is invalid or unavailable.
    InvalidScope,
    /// Caller lacks the required capability.
    Unauthorized,
    /// A mention cannot be resolved to one canonical identity safely.
    AmbiguousIdentity,
    /// Requested snapshot is no longer retained.
    SnapshotExpired,
    /// Required derived projection is below the requested freshness floor.
    IndexTooStale,
    /// Requested operation requires evidence that was not supplied.
    EvidenceRequired,
    /// The operation cannot safely select between unresolved conflicts.
    ConflictUnresolved,
    /// A declared work, token, node, or time budget is exhausted.
    BudgetExhausted,
    /// A once-valid continuation is outside its retention or freshness window.
    ContinuationExpired,
    /// Wire, archive, storage, or semantic format is incompatible.
    FormatIncompatible,
    /// A selected external model or capability provider is unavailable.
    ProviderUnavailable,
    /// The operation completed only in an explicitly reduced profile.
    DegradedMode,
    /// Request schema or scalar invariant failed.
    InvalidArgument,
    /// Authentication or authorization denied the operation.
    PermissionDenied,
    /// Requested object or retained snapshot does not exist.
    NotFound,
    /// An idempotency key was reused with different canonical input.
    IdempotencyConflict,
    /// Continuation token was forged, stale, or bound to another request.
    InvalidContinuation,
    /// Import/export or internal invariant verification failed.
    IntegrityFailure,
    /// Service is unavailable or a lock was poisoned.
    Unavailable,
    /// An implementation limit or explicit budget was exceeded.
    ResourceExhausted,
    /// The requested capability is not implemented by this profile.
    Unsupported,
}

/// Payload-free canonical service error.
#[derive(Clone, Debug, Error, Eq, PartialEq, Serialize, Deserialize)]
#[error("{code:?}: {message}")]
#[serde(deny_unknown_fields)]
pub struct ServiceError {
    /// Stable machine code.
    pub code: ErrorCode,
    /// Safe bounded message containing no request content.
    pub message: String,
    /// Whether retrying the exact request may succeed without caller changes.
    pub retryable: bool,
    /// Safe references to partial results already committed or returned.
    #[serde(default)]
    pub partial_result_refs: Box<[String]>,
    /// Stable identifier of the policy rule that denied the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violated_policy: Option<Box<str>>,
    /// Content-free caller guidance for a safe next step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_next_action: Option<Box<str>>,
    /// Privacy-safe operation trace handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<Box<str>>,
}

impl ServiceError {
    /// Creates a payload-free error without optional remediation context.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
            partial_result_refs: Box::default(),
            violated_policy: None,
            safe_next_action: None,
            trace_id: None,
        }
    }

    /// Attaches content-free remediation metadata without changing the stable
    /// code or retry contract.
    #[must_use]
    pub fn with_context(
        mut self,
        partial_result_refs: Vec<String>,
        violated_policy: Option<String>,
        safe_next_action: Option<String>,
        trace_id: Option<String>,
    ) -> Self {
        self.partial_result_refs = partial_result_refs.into_boxed_slice();
        self.violated_policy = violated_policy.map(String::into_boxed_str);
        self.safe_next_action = safe_next_action.map(String::into_boxed_str);
        self.trace_id = trace_id.map(String::into_boxed_str);
        self
    }
}

/// Canonical service result alias.
pub type ServiceResult<T> = Result<T, ServiceError>;
