use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Public sensitivity ordering independent from any storage or oracle type.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Public to an explicitly permitted audience.
    #[default]
    Public,
    /// Workspace-internal.
    Internal,
    /// Private to owners/audiences.
    Private,
    /// Compartmented high-assurance data.
    Restricted,
}

/// Public consent state.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consent {
    /// Explicitly permitted.
    #[default]
    Granted,
    /// No decision; fail closed.
    Unknown,
    /// Explicitly denied.
    Denied,
}

/// Authenticated/resolved request context. Transports may authenticate however
/// they choose but must produce this exact capability input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    /// Caller-generated trace identifier.
    pub request_id: String,
    /// Administrative isolation boundary.
    pub workspace_id: String,
    /// Calling memory subject.
    pub subject_id: String,
    /// Resolved subject/group/public audience keys.
    pub audiences: BTreeSet<String>,
    /// Resolved semantic scope grants.
    pub scopes: BTreeSet<String>,
    /// Declared operation purpose.
    pub purpose: String,
    /// Maximum authorized sensitivity.
    pub clearance: Sensitivity,
}

/// Observation policy metadata evaluated without inspecting content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    /// Administrative workspace.
    pub workspace_id: String,
    /// Semantic scopes.
    pub scopes: BTreeSet<String>,
    /// Joint owners.
    pub owners: BTreeSet<String>,
    /// Audience keys; `*` is public only when policy says so.
    pub audience: BTreeSet<String>,
    /// Exact audience-to-purpose grants. Preferred over Cartesian legacy sets.
    pub audience_purpose_grants: BTreeMap<String, BTreeSet<String>>,
    /// Legacy purpose grants used only when exact grants are empty.
    pub purposes: BTreeSet<String>,
    /// Sensitivity label.
    pub sensitivity: Sensitivity,
    /// Explicit consent.
    pub consent: Consent,
    /// Whether ordinary retrieval is allowed.
    pub retrievable: bool,
}

/// Canonical observe operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveRequest {
    /// Authenticated caller context.
    pub context: RequestContext,
    /// Caller-controlled retry key.
    pub idempotency_key: String,
    /// Stable observation identity.
    pub observation_id: String,
    /// Content-free source/stream metadata.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Exact observation payload.
    pub content: serde_json::Value,
    /// Authorization label stored separately from erasable content.
    pub access: AccessPolicy,
}

/// Freshness watermarks shared by all transports.
///
/// The enclosing operation defines the sequence domain. Caller-facing recall,
/// timeline, and traversal responses use gap-free workspace-local counters;
/// privileged database receipts may expose their explicitly global storage
/// sequence instead. A workspace-local value must never be interpreted as a
/// database-global commit.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermarks {
    /// Ordered journal head in the enclosing response's sequence domain.
    pub journal: u64,
    /// Semantic publication progress in the enclosing response's sequence domain.
    pub semantic: u64,
    /// Lexical projection coverage in the enclosing response's sequence domain.
    pub lexical: u64,
    /// Vector projection coverage in the enclosing response's sequence domain.
    pub vector: u64,
    /// Graph projection coverage in the enclosing response's sequence domain.
    pub graph: u64,
}

/// Observe receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveResponse {
    /// Durable commit sequence.
    pub commit_seq: u64,
    /// True when an earlier exact request was replayed.
    pub replayed: bool,
    /// Digest of exact validated input.
    pub request_digest: String,
    /// Post-commit freshness.
    pub watermarks: Watermarks,
}

/// Canonical paginated recall request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallRequest {
    /// Authenticated caller context.
    pub context: RequestContext,
    /// Structured textual cue for the reference lexical route.
    pub query: String,
    /// Maximum hits in this page.
    pub page_size: u32,
    /// Optional gap-free workspace-local journal ordinal. Zero selects that
    /// workspace's genesis; missing selects its current visible head.
    pub at_commit: Option<u64>,
    /// Opaque authenticated pagination continuation.
    pub continuation: Option<String>,
}

/// One policy-authorized recall hit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallHit {
    /// Stable semantic record ID.
    pub id: String,
    /// Deterministic route score.
    pub score: f32,
}

/// Privacy-safe explain trace. Counts only authorized candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallTrace {
    /// Opaque digest-derived trace handle.
    pub trace_id: String,
    /// Coherent gap-free workspace-local snapshot sequence.
    pub snapshot_seq: u64,
    /// Route name.
    pub operation: String,
    /// Authorized candidates only.
    pub authorized_candidates: u64,
    /// Returned authorized IDs only.
    pub selected_ids: Vec<String>,
    /// Projection freshness.
    pub watermarks: Watermarks,
}

/// Recall page with trace and continuation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallResponse {
    /// Authorized hits in stable score/identity order.
    pub hits: Vec<RecallHit>,
    /// Explainability is part of the result, not a debug side channel.
    pub trace: RecallTrace,
    /// Authenticated next page, when more authorized hits remain.
    pub continuation: Option<String>,
}

/// Request to validate/retrieve a recall trace carried by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainRecallRequest {
    /// Authenticated caller context.
    pub context: RequestContext,
    /// Trace previously returned by recall.
    pub trace: RecallTrace,
}

/// Canonical logical archive request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    /// Authenticated caller context.
    pub context: RequestContext,
}

/// Canonical self-identifying archive bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportResponse {
    /// Archive format.
    pub format: String,
    /// Exact archive bytes.
    pub bytes: Vec<u8>,
    /// BLAKE3 digest of exact bytes.
    pub digest: String,
    /// Exported head.
    pub commit_seq: u64,
}

/// Canonical archive import request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    /// Authenticated caller context.
    pub context: RequestContext,
    /// Expected archive format.
    pub format: String,
    /// Exact bytes.
    pub bytes: Vec<u8>,
    /// Expected digest.
    pub digest: String,
}

/// Import receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportResponse {
    /// Restored head.
    pub commit_seq: u64,
    /// Restored watermarks.
    pub watermarks: Watermarks,
}

/// Verify request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// Authenticated caller context.
    pub context: RequestContext,
    /// Whether to canonical-export/import round-trip the complete state.
    pub deep: bool,
}

/// Verify result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyResponse {
    /// True only after every requested check succeeds.
    pub valid: bool,
    /// Verified head.
    pub commit_seq: u64,
    /// Canonical archive digest checked by deep verification, when requested.
    pub archive_digest: Option<String>,
}
