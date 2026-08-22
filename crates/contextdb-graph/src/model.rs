use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    Audience, Claim, ClaimRevision, CommitSeq, ConflictSet, ConflictSetRevision, Directionality,
    Edge, EdgeRevision, MemorySpaceId, MemorySubjectId, MutationId, Node, NodeRevision,
    PublicationId, Purpose, ScopeId, SecurityClassification, WorkspaceId,
};
use serde::{Deserialize, Serialize};

/// Dense storage-local key. It is persisted for reopen, but never used as public identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DenseId(u64);

impl DenseId {
    /// Creates a one-based dense key.
    pub fn new(value: u64) -> crate::Result<Self> {
        if value == 0 {
            return Err(crate::GraphError::Invariant(
                "dense identifiers are one-based".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the compact integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable external ID mapped to a database-local durable dense key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdMapping {
    /// Stable UUID string.
    pub external_id: String,
    /// Dense key in this graph database.
    pub dense_id: DenseId,
    /// First graph commit that introduced the mapping.
    pub created_seq: u64,
}

/// Complete canonical node materialized at one storage snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeState {
    /// Stable node identity.
    pub node: Node,
    /// Revision visible in the selected snapshot.
    pub revision: NodeRevision,
}

/// Complete canonical claim materialized at one storage snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimState {
    /// Stable claim identity.
    pub claim: Claim,
    /// Revision visible in the selected snapshot.
    pub revision: ClaimRevision,
}

/// Complete canonical edge materialized at one storage snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EdgeState {
    /// Stable edge identity.
    pub edge: Edge,
    /// Revision visible in the selected snapshot.
    pub revision: EdgeRevision,
}

/// Complete canonical conflict set at one storage snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConflictState {
    /// Stable conflict identity.
    pub conflict: ConflictSet,
    /// Revision visible in the selected snapshot.
    pub revision: ConflictSetRevision,
}

/// Metadata-only authorization index entry evaluated before record bytes are read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyIndexEntry {
    /// Administrative workspace isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Scopes attached to the revision.
    pub scopes: BTreeSet<ScopeId>,
    /// Explicit joint owners.
    pub owners: BTreeSet<MemorySubjectId>,
    /// Perspective subjects (knower and optional experiencer).
    pub subjects: BTreeSet<MemorySubjectId>,
    /// Allowed memory spaces from scope/audience grants.
    pub memory_spaces: BTreeSet<MemorySpaceId>,
    /// Purpose to audience keys, encoded as stable strings.
    pub audience_purposes: BTreeMap<String, BTreeSet<Purpose>>,
    /// Explicit allowed purposes from ownership.
    pub allowed_purposes: BTreeSet<Purpose>,
    /// Security floor for the content.
    pub classification: SecurityClassification,
    /// Required security compartments.
    pub compartments: BTreeSet<ScopeId>,
    /// Retrieval gate from the independent use policy.
    pub retrievable: bool,
    /// Consent was resolved to granted for all required decisions.
    pub consent_granted: bool,
}

/// Selects one metadata-only policy index before protected records are materialized.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyIndexQuery {
    /// All authorized records in an administrative workspace.
    Workspace(WorkspaceId),
    /// Records about or known by one memory subject.
    Subject(MemorySubjectId),
    /// Records carrying one semantic scope.
    Scope(ScopeId),
    /// Records jointly owned by one subject.
    Owner(MemorySubjectId),
    /// Records constrained to one memory space.
    MemorySpace(MemorySpaceId),
    /// Records granted to an audience.
    Audience(Audience),
    /// Records allowing one declared purpose.
    Purpose(Purpose),
}

/// Fully resolved caller authorization context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReadPrincipal {
    /// Caller subject.
    pub subject: MemorySubjectId,
    /// Selected administrative workspace.
    pub workspace_id: WorkspaceId,
    /// Accessible semantic scopes.
    pub scopes: BTreeSet<ScopeId>,
    /// Accessible memory spaces.
    pub memory_spaces: BTreeSet<MemorySpaceId>,
    /// Group subjects and other resolved audience subject IDs.
    pub audience_subjects: BTreeSet<MemorySubjectId>,
    /// Purpose of this graph read.
    pub purpose: Purpose,
    /// Maximum authorized sensitivity.
    pub clearance: SecurityClassification,
    /// Compartments authorized to the caller.
    pub compartments: BTreeSet<ScopeId>,
}

/// Direction of bounded graph expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Follow source to target.
    Outgoing,
    /// Follow target to source.
    Incoming,
    /// Follow both directions.
    Both,
}

/// Persistent graph snapshot with one physical sequence and one complete manifest generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphSnapshot {
    /// Physical cutoff fixed for the entire read. Append-only graph history can reconstruct this
    /// cutoff even when the substrate retains only its latest physical snapshot.
    pub storage_seq: u64,
    /// Highest semantic publication reflected by this physical snapshot.
    pub semantic_seq: CommitSeq,
    /// Active immutable adjacency generation.
    pub segment_generation: u64,
}

/// Journal publication projected atomically into the persistent graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphPublication {
    /// Stable mutation identity from the semantic journal.
    pub mutation_id: MutationId,
    /// Immutable publication identity from the semantic journal.
    pub publication_id: PublicationId,
    /// Journal logical commit reflected by this projection.
    pub commit_seq: CommitSeq,
    /// Digest of the exact mutation bytes validated by the journal.
    pub mutation_digest: [u8; 32],
}

/// Replay-safe receipt for a journal-to-graph projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphProjectionReceipt {
    /// Journal publication projected by this operation.
    pub publication: GraphPublication,
    /// Physical graph snapshot containing the projection.
    pub storage_seq: u64,
    /// True when an identical already-committed projection was returned.
    pub replayed: bool,
}

/// Metadata-only administrative authorization entry.
///
/// It is deliberately stored separately from the workspace/space/subject bytes so an access
/// decision can be made without materializing the protected identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdministrativePolicyIndex {
    /// First physical graph commit that made the protected identity visible.
    pub created_seq: u64,
    /// Administrative workspace isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Subjects allowed to inspect the administrative identity.
    pub subjects: BTreeSet<MemorySubjectId>,
    /// Memory spaces whose resolved members may inspect the identity.
    pub memory_spaces: BTreeSet<MemorySpaceId>,
}

/// Immutable adjacency row containing stable public IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SegmentEdge {
    /// Stable edge ID.
    pub edge_id: String,
    /// Dense source node ID.
    pub source: DenseId,
    /// Dense target node ID.
    pub target: DenseId,
    /// Stable edge type ID.
    pub edge_type: String,
    /// Whether this relation may be followed symmetrically.
    pub directionality: Directionality,
}

/// Half-open contiguous adjacency range for one dense node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdjacencyRange {
    /// Dense node owning the row.
    pub node: DenseId,
    /// First edge offset in the corresponding adjacency array.
    pub start: u64,
    /// Exclusive edge offset in the corresponding adjacency array.
    pub end: u64,
}

/// Immutable adjacency segment. Its digest covers every preceding field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdjacencySegment {
    /// Segment format version.
    pub format_version: u16,
    /// Manifest generation that owns this segment.
    pub generation: u64,
    /// Highest commit incorporated into the base segment.
    pub built_through_seq: u64,
    /// Dense-node to half-open range table for `outgoing_edges`.
    pub outgoing_ranges: Vec<AdjacencyRange>,
    /// Contiguous edges ordered by `(source, target, edge_type, edge_id)`.
    pub outgoing_edges: Vec<SegmentEdge>,
    /// Dense-node to half-open range table for `incoming_edges`.
    pub incoming_ranges: Vec<AdjacencyRange>,
    /// Contiguous edges ordered by `(target, source, edge_type, edge_id)`.
    pub incoming_edges: Vec<SegmentEdge>,
    /// BLAKE3 digest of canonical segment content excluding this field.
    pub digest: String,
}

/// Atomically switched adjacency generation manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SegmentManifest {
    /// Adjacency storage format selected by this generation. Missing values decode as legacy v1.
    #[serde(default = "legacy_segment_format_version")]
    pub format_version: u16,
    /// Current generation.
    pub generation: u64,
    /// Highest commit covered by the base segment.
    pub built_through_seq: u64,
    /// Segment content digest.
    pub segment_digest: String,
    /// Number of authenticated row manifests in a paged v2 generation.
    #[serde(default)]
    pub row_count: u64,
    /// Number of directional edge records in a paged v2 generation.
    #[serde(default)]
    pub edge_count: u64,
    /// Aggregate key/value bytes of directional edge records in a paged v2 generation.
    #[serde(default)]
    pub edge_bytes: u64,
}

const fn legacy_segment_format_version() -> u16 {
    1
}

/// Result of one explicit adjacency retention/prune pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdjacencyPruneReport {
    /// Retention floor before this call.
    pub previous_oldest_retained_storage_seq: u64,
    /// Caller-selected retention floor published by this call.
    pub oldest_retained_storage_seq: u64,
    /// Generation which reconstructs the graph exactly at the retention floor.
    pub baseline_generation: u64,
    /// Active generation which was protected from deletion.
    pub active_generation: u64,
    /// Obsolete manifest-history entries deleted by this call.
    pub history_entries_deleted: u64,
    /// Legacy v1 generation blobs deleted by this call.
    pub v1_generations_deleted: u64,
    /// Paged v2 generations from which at least one record was deleted by this call.
    pub v2_generations_deleted: u64,
    /// Individual paged v2 records deleted by this call.
    pub v2_records_deleted: u64,
}

/// Canonical artifact metadata persisted without large payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Canonical artifact.
    pub artifact: contextdb_core::Artifact,
    /// Policy index derived from artifact ownership and its storage scope.
    pub policy: PolicyIndexEntry,
    /// Graph commit that introduced this metadata.
    pub created_seq: u64,
}

/// Privacy-safe traversal trace. Counts only the already-authorized universe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraversalTrace {
    /// Snapshot used by every step.
    pub snapshot_seq: u64,
    /// Base adjacency generation.
    pub segment_generation: u64,
    /// Authorized edges considered after policy filtering.
    pub authorized_edges: usize,
    /// Returned node IDs.
    pub selected_nodes: Vec<String>,
}

/// Bounded traversal result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraversalResult {
    /// Stable node IDs in deterministic breadth-first order.
    pub nodes: Vec<String>,
    /// Privacy-safe trace.
    pub trace: TraversalTrace,
}
