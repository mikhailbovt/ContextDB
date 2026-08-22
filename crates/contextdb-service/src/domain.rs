use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{AccessPolicy, AuthenticatedRequestContext, CapabilityManifestV1, Watermarks};

/// Stable logical record family exposed by the v1 memory service.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRecordKind {
    /// Stable graph identity.
    Node,
    /// Bitemporal claim.
    Claim,
    /// Traversable relation.
    Edge,
    /// Revisioned conflict set.
    Conflict,
    /// Evidence descriptor and selector.
    Evidence,
    /// Quarantined proposal.
    Candidate,
    /// Preference, boundary, goal, commitment, relationship, or self memory.
    SemanticObject,
    /// Session or situation working state.
    RuntimeState,
    /// Domain-pack extension.
    DomainExtension,
}

/// Logical lifecycle independent from epistemic acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycle {
    /// Current and eligible for ordinary reads.
    Active,
    /// Replaced by a successor.
    Superseded,
    /// Explicitly withdrawn while retained for history.
    Retracted,
    /// Retained but omitted from ordinary reads.
    Suppressed,
}

/// Inclusive/exclusive domain-time range represented in Unix nanoseconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainTimeRange {
    /// Inclusive start; missing is unbounded.
    pub from: Option<i128>,
    /// Exclusive end; missing is unbounded.
    pub to: Option<i128>,
}

/// Typed graph and evidence linkage metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLinks {
    /// Claim subject.
    pub subject: Option<String>,
    /// Edge source.
    pub source: Option<String>,
    /// Edge target.
    pub target: Option<String>,
    /// Claim/edge predicate.
    pub predicate: Option<String>,
    /// Conflict-set membership.
    pub conflict_set: Option<String>,
    /// Superseded logical records.
    pub supersedes: BTreeSet<String>,
    /// Supporting evidence records.
    pub evidence: BTreeSet<String>,
    /// Conflict members for conflict-set records.
    pub conflict_members: BTreeSet<String>,
    /// Whether the predicate is single-valued in scope.
    pub single_valued: bool,
}

/// Complete logical document accepted by correction/publication operations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDocument {
    /// Stable logical identifier.
    pub id: String,
    /// Stable record family.
    pub kind: MemoryRecordKind,
    /// Policy metadata evaluated before content.
    pub access: AccessPolicy,
    /// Domain-time validity.
    pub valid_time: DomainTimeRange,
    /// Logical lifecycle.
    pub lifecycle: MemoryLifecycle,
    /// Graph/evidence linkage.
    pub links: MemoryLinks,
    /// Canonical semantic value.
    pub value: serde_json::Value,
    /// Optional exact lexical projection input.
    pub search_text: Option<String>,
    /// Optional full-precision vector projection input.
    pub vector: Option<Vec<f32>>,
    /// Deterministic extension attributes.
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// One authorized bitemporal record revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecord {
    /// Logical document content and policy.
    pub document: MemoryDocument,
    /// Revision ordinal starting at one.
    pub revision: u32,
    /// First commit where the revision is visible.
    pub transaction_from: u64,
    /// First commit where the revision stops being current.
    pub transaction_to: Option<u64>,
}

/// Common receipt for idempotent semantic mutations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationResponse {
    /// Durable publication sequence.
    pub commit_seq: u64,
    /// True when an exact earlier request was replayed.
    pub replayed: bool,
    /// Digest of canonical mutation input, excluding transient request and
    /// authentication evidence.
    pub request_digest: String,
    /// Post-publication projection freshness.
    pub watermarks: Watermarks,
}

/// Explicit subject-owned semantic memory publication.
///
/// Unlike [`crate::ObserveRequest`], this operation publishes a recallable
/// semantic object immediately. The service derives its complete access
/// policy from the authenticated context instead of accepting a model-written
/// policy or arbitrary graph document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishMemoryRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Actor-scoped retry key.
    pub idempotency_key: String,
    /// Stable logical identity for the new semantic memory.
    pub memory_id: String,
    /// Proposed semantic value retained only in the quarantined candidate.
    pub value: serde_json::Value,
    /// Exact bounded text projected into lexical recall.
    pub search_text: String,
}

/// Bounded semantic taxonomy for agent-authored durable memory.
///
/// This taxonomy is deliberately smaller than the universal record model. It
/// describes the proposed role of one quarantined candidate. It does not imply
/// acceptance as a canonical [`MemoryRecordKind::SemanticObject`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredMemoryKind {
    /// Stable project identity or project-wide context.
    Project,
    /// A durable topic grouping related memories.
    Topic,
    /// A choice and the durable reasoning or consequence attached to it.
    Decision,
    /// A boundary, invariant, requirement, or prohibition.
    Constraint,
    /// A desired durable outcome.
    Goal,
    /// An unresolved task, question, or follow-up.
    OpenLoop,
    /// A completed checkpoint or externally meaningful result.
    Milestone,
    /// A durable subject preference that should influence future work.
    Preference,
    /// A proposed fact that still requires evidence validation and adjudication.
    Fact,
    /// A proposed bounded evidence summary; it is not independent evidence.
    EvidenceSummary,
}

/// Structured model proposal with true candidate-only hierarchy links.
///
/// The service derives the complete access policy from authenticated host
/// authority. The proposal remains quarantined and cannot enter ordinary
/// semantic recall before a separate deterministic adjudication and promotion
/// path. Implementations publish the candidate and all candidate-only links
/// atomically or publish nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeMemoryRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Actor-scoped retry key for the proposal and complete candidate-link set.
    pub idempotency_key: String,
    /// Stable logical identity for the new quarantined candidate.
    pub candidate_id: String,
    /// Bounded semantic role stored as typed attributes and recall facets.
    pub semantic_kind: StructuredMemoryKind,
    /// Canonical semantic value retained by the memory.
    pub value: serde_json::Value,
    /// Exact bounded text projected into lexical recall.
    pub search_text: String,
    /// Existing parent candidate identities. Empty creates a candidate root.
    pub parent_candidate_ids: BTreeSet<String>,
    /// Active candidate predecessors replaced by this proposal.
    pub supersedes_candidate_ids: BTreeSet<String>,
}

/// Trust state of one durable model proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateProposalState {
    /// Persisted for continuity but excluded from canonical truth and recall.
    Quarantined,
}

/// Atomic quarantined-candidate publication receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeMemoryResponse {
    /// Common durable mutation receipt.
    pub mutation: MutationResponse,
    /// Published quarantined candidate identity.
    pub candidate_id: String,
    /// Deterministic parent-to-child candidate-link identities in parent order.
    pub candidate_edge_ids: Vec<String>,
    /// Explicit non-canonical trust state.
    pub proposal_state: CandidateProposalState,
    /// Always false until a separate deterministic promotion commits truth.
    pub canonical: bool,
}

/// Policy-first bounded lexical lookup over quarantined candidates only.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallCandidatesRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Exact bounded lexical query.
    pub query: String,
    /// Optional semantic-kind allow-list.
    pub semantic_kinds: BTreeSet<StructuredMemoryKind>,
    /// Strict result cap.
    pub page_size: u32,
    /// Exact workspace commit or current when omitted.
    pub at_commit: Option<u64>,
}

/// Content-free candidate recall hit; materialization remains a separate call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRecallHit {
    /// Quarantined candidate identity.
    pub candidate_id: String,
    /// Typed semantic role proposed by the model.
    pub semantic_kind: StructuredMemoryKind,
    /// Deterministic lexical score.
    pub score: f32,
}

/// Bounded candidate-only recall response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallCandidatesResponse {
    /// Candidate IDs and typed roles ordered by score then ID.
    pub hits: Vec<CandidateRecallHit>,
    /// Snapshot used for the complete lookup.
    pub snapshot_seq: u64,
    /// Count after policy authorization and candidate-role filtering.
    pub authorized_candidates: u64,
    /// Projection freshness accompanying the read.
    pub watermarks: Watermarks,
}

/// Correction request that preserves history through a distinct successor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrectRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Actor-scoped retry key.
    pub idempotency_key: String,
    /// Existing logical record to supersede.
    pub target_id: String,
    /// Complete successor document; its `supersedes` set must contain target.
    pub replacement: MemoryDocument,
}

/// Forget semantics are explicit: reversible retraction is not hard deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgetMode {
    /// Retain content, evidence, and history with a retracted lifecycle.
    Retract,
    /// Erase content indirections and retain only a deletion tombstone.
    HardDelete,
}

/// Typed memory forgetting request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgetRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Actor-scoped retry key.
    pub idempotency_key: String,
    /// Logical record to retract or erase.
    pub target_id: String,
    /// Explicit reversible/irreversible mode.
    pub mode: ForgetMode,
    /// Content-free reason code required for hard deletion.
    pub reason: String,
}

/// Point lookup request shared by typed node/evidence/conflict methods.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetMemoryRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Stable record identifier.
    pub record_id: String,
    /// Exact snapshot commit or current when omitted.
    pub at_commit: Option<u64>,
}

/// Authorized history request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTimelineRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Stable record identifier.
    pub record_id: String,
    /// Expected record family, used to authorize evidence/conflict access
    /// before the reference engine materializes content.
    pub expected_kind: MemoryRecordKind,
    /// Exact snapshot commit or current when omitted.
    pub at_commit: Option<u64>,
    /// Strict maximum revisions returned.
    pub max_revisions: u32,
}

/// Policy-authorized bitemporal history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineResponse {
    /// Revisions in ascending transaction-time order.
    pub revisions: Vec<MemoryRecord>,
    /// Snapshot used for the whole operation.
    pub snapshot_seq: u64,
    /// Projection freshness accompanying the read.
    pub watermarks: Watermarks,
}

/// Graph traversal direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraverseDirection {
    /// Follow source to target.
    Outgoing,
    /// Follow target to source.
    Incoming,
    /// Follow both directions.
    Both,
}

/// Strictly bounded graph traversal request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraverseRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Authorized node roots.
    pub start_ids: Vec<String>,
    /// Traversal direction.
    pub direction: TraverseDirection,
    /// Optional predicate allow-list.
    pub predicate_ids: BTreeSet<String>,
    /// Maximum hops, capped by the service profile.
    pub max_hops: u8,
    /// Maximum returned nodes, capped by the service profile.
    pub max_nodes: u32,
    /// Exact snapshot commit or current when omitted.
    pub at_commit: Option<u64>,
}

/// Privacy-safe traversal result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraverseResponse {
    /// Authorized node identifiers in deterministic BFS order.
    pub node_ids: Vec<String>,
    /// Snapshot used for the complete traversal.
    pub snapshot_seq: u64,
    /// Count after authorization only.
    pub authorized_candidates: u64,
    /// Projection freshness accompanying the read.
    pub watermarks: Watermarks,
}

/// Generic canonical JSON input for a named runtime lifecycle method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Stable actor-scoped operation identifier.
    pub operation_id: String,
    /// Method-specific canonical core/continuity DTO.
    pub payload: serde_json::Value,
}

/// Generic canonical JSON output for a named runtime lifecycle method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResponse {
    /// Stable operation identifier.
    pub operation_id: String,
    /// Method-specific canonical core/continuity DTO.
    pub payload: serde_json::Value,
}

/// Generic canonical JSON input for a named maintenance method.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Stable actor-scoped operation identifier.
    pub operation_id: String,
    /// Method-specific canonical maintenance DTO.
    pub payload: serde_json::Value,
}

/// Generic canonical JSON maintenance receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceResponse {
    /// Stable operation identifier.
    pub operation_id: String,
    /// Method-specific canonical maintenance result.
    pub payload: serde_json::Value,
}

/// Authenticated administrative status request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetStatusRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
}

/// Reference administrative status without content-dependent metrics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// Stable service schema version.
    pub schema_version: u16,
    /// Implementation profile identifier.
    pub profile: String,
    /// Current coherent commit.
    pub commit_seq: u64,
    /// Projection freshness.
    pub watermarks: Watermarks,
    /// Versioned, content-free runtime capability declaration for this profile.
    pub capability_manifest: CapabilityManifestV1,
}

/// Authenticated logical backup request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBackupRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
}

/// Canonical logical backup artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupResponse {
    /// Archive format identifier.
    pub format: String,
    /// Exact canonical archive bytes.
    pub bytes: Vec<u8>,
    /// BLAKE3 digest over exact bytes.
    pub digest: String,
    /// Exported commit sequence.
    pub commit_seq: u64,
}

/// Authenticated logical restore request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBackupRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Expected archive format.
    pub format: String,
    /// Exact canonical archive bytes.
    pub bytes: Vec<u8>,
    /// Expected BLAKE3 digest.
    pub digest: String,
}

/// Restore receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBackupResponse {
    /// Restored commit sequence.
    pub commit_seq: u64,
    /// Restored projection freshness.
    pub watermarks: Watermarks,
}

/// Explicit format migration request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateFormatRequest {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Stable target logical-format identifier.
    pub target_format: String,
    /// Actor-scoped operation identifier.
    pub operation_id: String,
}
