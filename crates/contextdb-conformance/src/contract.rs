use contextdb_service::{
    ErrorCode, ExplainRecallRequest, ExportRequest, ExportResponse, ImportRequest, ImportResponse,
    ObserveRequest, ObserveResponse, RecallRequest, RecallResponse, RecallTrace, ServiceError,
    VerifyRequest, VerifyResponse,
};
use serde::{Deserialize, Serialize};

/// Canonical operation shared by all general-purpose interfaces.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
pub enum CanonicalOperation {
    /// Capture one observation.
    Observe(ObserveRequest),
    /// Recall one deterministic page.
    Recall(RecallRequest),
    /// Validate and materialize a recall trace.
    ExplainRecall(ExplainRecallRequest),
    /// Export a logical archive.
    Export(ExportRequest),
    /// Import a logical archive.
    Import(ImportRequest),
    /// Verify logical state.
    Verify(VerifyRequest),
}

/// Canonical successful operation result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "response", content = "value", rename_all = "snake_case")]
pub enum CanonicalResponse {
    /// Observe receipt.
    Observe(ObserveResponse),
    /// Recall page.
    Recall(RecallResponse),
    /// Recall trace.
    ExplainRecall(RecallTrace),
    /// Archive export.
    Export(ExportResponse),
    /// Archive import receipt.
    Import(ImportResponse),
    /// Verification result.
    Verify(VerifyResponse),
}

/// Stable transport-independent service failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalError {
    /// Stable machine code.
    pub code: ErrorCode,
    /// Content-free safe message.
    pub message: String,
    /// Whether replaying unchanged input may succeed.
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

impl From<ServiceError> for CanonicalError {
    fn from(value: ServiceError) -> Self {
        Self {
            code: value.code,
            message: value.message,
            retryable: value.retryable,
            partial_result_refs: value.partial_result_refs,
            violated_policy: value.violated_policy,
            safe_next_action: value.safe_next_action,
            trace_id: value.trace_id,
        }
    }
}

/// Canonical invocation outcome after transport decoding.
pub type CanonicalOutcome = Result<CanonicalResponse, CanonicalError>;
