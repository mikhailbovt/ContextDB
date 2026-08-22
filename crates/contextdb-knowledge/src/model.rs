//! Public document, source revision, knowledge claim, and query contracts.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_cognition::CandidateProposal;
use contextdb_core::{
    ActorId, Artifact, ArtifactId, Claim, ClaimId, ClaimObject, ClaimRevision, CommitSeq,
    ConflictSetRecord, ContentBlock, ContentDigest, EvidenceId, EvidenceSpan, MemorySpaceId,
    NodeRecord, ObservationUnit, PolicyId, PredicateDefinition, RevisionNumber, SemanticEnvelope,
    SnapshotRef, Source, SourceId, TimeRange, TimestampMicros, TrustClass, WorkspaceId,
};
use contextdb_recall::RecallPrincipal;
use serde::{Deserialize, Serialize};

/// Input representation understood by the generic document adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentFormat {
    PlainText,
    Markdown,
    PdfExtractedText,
    HtmlExtractedText,
    Json,
    Csv,
    Other(String),
}

/// Whether a source revision publishes content or retracts the whole document.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentRevisionKind {
    Upsert,
    RetractDocument,
}

/// Exact stable reference to one source-specific statement.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStatementRef {
    pub source_key: String,
    pub statement_key: String,
}

/// Epistemic role of an extracted statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StatementEpistemic {
    /// The immutable source directly states the proposition.
    SourceAssertion,
    /// A derived proposal that never contributes to accepted consensus.
    DerivedHypothesis {
        supporting_evidence: Vec<EvidenceId>,
    },
}

/// Operation proposed by one exact document span.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DocumentStatementAction {
    Assert {
        object: ClaimObject,
        valid_time: TimeRange,
        epistemic: StatementEpistemic,
    },
    Retract {
        target: SourceStatementRef,
        reason: String,
    },
    OpenQuestion {
        question: String,
        reason: String,
    },
}

/// Structured extraction supplied by a parser, human, or proposal-only model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentStatementInput {
    pub statement_key: String,
    pub subject_key: String,
    pub subject_label: String,
    pub predicate_key: String,
    pub quote: String,
    pub action: DocumentStatementAction,
}

/// One immutable document section and its proposed semantic statements.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSectionInput {
    pub path: Vec<String>,
    pub content: String,
    pub statements: Vec<DocumentStatementInput>,
}

/// Generic, provider-neutral document revision input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRevisionInput {
    pub workspace_id: WorkspaceId,
    pub memory_space_id: MemorySpaceId,
    pub actor_id: ActorId,
    pub corpus_key: String,
    pub source_key: String,
    pub source_family: String,
    pub native_locator: String,
    pub native_revision: String,
    pub supersedes_native_revision: Option<String>,
    pub title: String,
    pub format: DocumentFormat,
    pub revision_kind: DocumentRevisionKind,
    pub created_at: Option<TimestampMicros>,
    pub effective_at: TimestampMicros,
    pub observed_at: TimestampMicros,
    pub recorded_at: TimestampMicros,
    pub trust: TrustClass,
    pub ingestion_policy: PolicyId,
    pub expected_content_hash: Option<ContentDigest>,
    pub envelope: SemanticEnvelope,
    pub sections: Vec<DocumentSectionInput>,
}

/// Materialized position of a section in the source hierarchy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSection {
    pub id: contextdb_core::NodeId,
    pub ordinal: u32,
    pub path: Vec<String>,
    /// Immutable UTF-8 bytes owned by the in-memory reference vertical.
    pub content: String,
    pub content_block_id: contextdb_core::ContentBlockId,
    pub content_hash: ContentDigest,
}

/// Hierarchy role for corpus, stable document, immutable revision, and section.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceHierarchyKind {
    Corpus,
    Document,
    Revision,
    Section,
}

/// Deterministic source hierarchy entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHierarchyEntry {
    pub id: contextdb_core::NodeId,
    pub parent: Option<contextdb_core::NodeId>,
    pub kind: SourceHierarchyKind,
    pub order_key: u64,
    pub label: String,
    pub source_id: Option<SourceId>,
    pub artifact_id: Option<ArtifactId>,
}

/// Immutable source revision assembled before semantic publication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    pub published_at: SnapshotRef,
    pub source: Source,
    pub source_key: String,
    pub corpus_key: String,
    pub source_family: String,
    pub revision: RevisionNumber,
    pub native_revision: String,
    pub supersedes: Option<ArtifactId>,
    pub content_digest: ContentDigest,
    pub logical_digest: ContentDigest,
    pub artifact: Artifact,
    pub content_blocks: Vec<ContentBlock>,
    pub observation: ObservationUnit,
    pub sections: Vec<DocumentSection>,
    pub evidence: Vec<EvidenceSpan>,
    pub hierarchy: Vec<SourceHierarchyEntry>,
    pub envelope: SemanticEnvelope,
    pub revision_kind: DocumentRevisionKind,
}

/// Adapter proposal. The cognition candidate contains no model-selected canonical IDs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KnowledgeProposalAction {
    Assert {
        subject_key: String,
        subject_label: String,
        predicate_key: String,
        object: ClaimObject,
        valid_time: TimeRange,
        epistemic: StatementEpistemic,
        cognition_candidate: Box<CandidateProposal>,
    },
    Retract {
        target: SourceStatementRef,
        reason: String,
    },
    OpenQuestion {
        subject_key: String,
        predicate_key: String,
        question: String,
        reason: String,
    },
}

/// One exact, evidence-aligned source proposal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeProposal {
    pub local_id: String,
    pub statement_key: String,
    pub section_id: contextdb_core::NodeId,
    pub evidence_id: EvidenceId,
    pub action: KnowledgeProposalAction,
}

/// Complete adapter output. Publication is a separate deterministic operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptedDocument {
    pub source_revision: SourceRevision,
    pub proposals: Vec<KnowledgeProposal>,
}

/// Source-specific canonical claim and its immutable revision chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceClaimRecord {
    pub claim: Claim,
    pub source_id: SourceId,
    pub source_key: String,
    pub source_family: String,
    pub statement_key: String,
    pub subject_key: String,
    pub predicate_key: String,
    pub revisions: contextdb_core::NonEmptyVec<ClaimRevision>,
    pub revision_reasons: Vec<SourceClaimRevisionReason>,
}

/// An explicitly retained hypothesis which is excluded from accepted source consensus.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeHypothesis {
    pub source_id: SourceId,
    pub statement_key: String,
    pub subject_key: String,
    pub predicate_key: String,
    pub object: ClaimObject,
    pub evidence: Vec<EvidenceId>,
    pub supporting_evidence: Vec<EvidenceId>,
    pub published_at: SnapshotRef,
    pub envelope: SemanticEnvelope,
}

/// An open question retained as unknown rather than fabricated knowledge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeOpenQuestion {
    pub source_id: SourceId,
    pub statement_key: String,
    pub subject_key: String,
    pub predicate_key: String,
    pub question: String,
    pub reason: String,
    pub evidence_id: EvidenceId,
    pub published_at: SnapshotRef,
    pub envelope: SemanticEnvelope,
}

/// Canonical logical export of the M13 primary state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeExport {
    pub workspace_id: Option<WorkspaceId>,
    pub snapshot: SnapshotRef,
    pub sources: BTreeMap<SourceId, Vec<SourceRevision>>,
    pub nodes: BTreeMap<String, NodeRecord>,
    pub predicates: BTreeMap<String, PredicateDefinition>,
    pub claims: BTreeMap<ClaimId, SourceClaimRecord>,
    pub conflicts: BTreeMap<String, ConflictSetRecord>,
    pub hypotheses: Vec<KnowledgeHypothesis>,
    pub open_questions: Vec<KnowledgeOpenQuestion>,
    pub slot_watermarks: BTreeMap<String, CommitSeq>,
}

/// Idempotent publication status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    Published,
    AlreadyPublished,
}

/// Atomic result returned by source publication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgePublication {
    pub status: PublicationStatus,
    pub snapshot: SnapshotRef,
    pub source_id: SourceId,
    pub artifact_id: ArtifactId,
    pub created_claims: Vec<ClaimId>,
    pub revised_claims: Vec<ClaimId>,
    pub retracted_claims: Vec<ClaimId>,
    pub hypotheses_retained: usize,
    pub open_questions_retained: usize,
    pub semantic_transaction: Option<contextdb_core::SemanticMutationSet>,
}

/// Source constraint applied to a knowledge query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConstraint {
    AnyAuthorized,
    Source { id: SourceId },
    Family { family: String },
}

/// Bitemporal and authorization-bound knowledge query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeQuery {
    pub subject_key: String,
    pub predicate_key: String,
    pub valid_at: TimestampMicros,
    pub known_at: SnapshotRef,
    pub source: SourceConstraint,
    pub include_history: bool,
    /// Whether unresolved alternatives should be disclosed rather than reduced
    /// to a blocking unknown marker.
    pub disclose_conflicts: bool,
    /// Whether source quotations may be materialized after authorization.
    pub include_excerpts: bool,
    pub principal: RecallPrincipal,
}

/// Exact source citation returned with an answer alternative.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeCitation {
    pub claim_id: ClaimId,
    pub source_id: SourceId,
    pub artifact_id: ArtifactId,
    pub native_locator: String,
    pub native_revision: String,
    pub source_family: String,
    pub evidence_id: EvidenceId,
    pub selector: contextdb_core::EvidenceSelector,
    pub quote_hash: ContentDigest,
    pub excerpt: Option<String>,
    pub trust: TrustClass,
    pub revision_lineage: Vec<ArtifactId>,
}

/// One distinct value with dependence-aware support.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeAlternative {
    pub object: ClaimObject,
    /// Intersection of the active source intervals supporting this answer.
    pub valid_time: TimeRange,
    pub claim_ids: BTreeSet<ClaimId>,
    pub independent_source_families: BTreeSet<String>,
    pub citations: Vec<KnowledgeCitation>,
    pub confidence_micros: u32,
}

/// Why a query correctly returned unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    NoAuthorizedSource,
    NoMatchingClaim,
    AllSupportRetracted,
    OnlyDerivedHypotheses,
    OpenQuestion,
}

/// Why a source-specific claim revision was appended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClaimRevisionReason {
    SourceAdded,
    SourceUpdated,
    ExplicitTemporalTransition,
    SourceRetracted,
    ConflictDetected,
    ConflictResolved,
}

/// Explicit answer state; disagreement and unknown are never flattened.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum KnowledgeAnswerState {
    Supported {
        answer: KnowledgeAlternative,
    },
    Disputed {
        conflict_set_id: contextdb_core::ConflictSetId,
        /// True when the identifier refers to a revisioned canonical conflict
        /// record; false for an authorized query-local cross-policy comparison.
        canonical_conflict: bool,
        alternatives: Vec<KnowledgeAlternative>,
    },
    Unknown {
        reason: UnknownReason,
        searched_sources: Vec<SourceId>,
        open_questions: Vec<String>,
    },
}

/// Why a historical revision entered the source-specific timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeChangeReason {
    SourceAdded,
    SourceUpdated,
    ExplicitTemporalTransition,
    SourceRetracted,
    ConflictDetected,
    ConflictResolved,
}

/// One source-backed temporal history entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeTimelineEntry {
    pub claim_id: ClaimId,
    pub revision: RevisionNumber,
    pub object: ClaimObject,
    pub valid_time: TimeRange,
    pub system_start: CommitSeq,
    pub system_end: Option<CommitSeq>,
    pub lifecycle: contextdb_core::LifecycleState,
    pub reason: KnowledgeChangeReason,
    pub citations: Vec<KnowledgeCitation>,
}

/// Complete answer used by the knowledge ContextPack seam and BENCH-C evaluator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeQueryResult {
    pub snapshot: SnapshotRef,
    pub valid_at: TimestampMicros,
    pub subject_key: String,
    pub predicate_key: String,
    pub state: KnowledgeAnswerState,
    pub history: Vec<KnowledgeTimelineEntry>,
    pub hypotheses: Vec<KnowledgeHypothesis>,
    pub source_revision_watermark: CommitSeq,
}
