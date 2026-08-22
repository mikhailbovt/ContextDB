//! Model-neutral session, recall, and context compilation contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ActorId, AgentId, ArtifactId, CheckpointId, ClaimId, CommitSeq, ConflictSetId, ContextPackId,
    EdgeId, EpisodeViewId, EvidenceId, HierarchyViewId, MemorySpaceId, MemorySubjectId,
    ModelProfileId, NodeId, NonEmptyVec, ObservationId, PolicyId, RecallRunId, ScopeRef, SessionId,
    SnapshotRef, TimeRange, TimestampMicros, Validate, ValidationError, ValidationResult,
    VectorSpaceId, WorkspaceId,
};

/// Runtime session lifecycle. Working state is never durable truth by itself.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    Suspended,
    Completed,
    Abandoned,
}

/// Conversation or agent session bound to one primary memory space.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: SessionId,
    pub agent_id: AgentId,
    pub workspace_id: WorkspaceId,
    pub participants: NonEmptyVec<MemorySubjectId>,
    pub memory_space: MemorySpaceId,
    pub started_at: TimestampMicros,
    pub ended_at: Option<TimestampMicros>,
    pub parent_session: Option<SessionId>,
    pub state: SessionState,
}

impl Validate for Session {
    fn validate(&self) -> ValidationResult {
        if self.parent_session == Some(self.id) {
            return Err(ValidationError::HierarchyCycle);
        }
        if self.ended_at.is_some_and(|ended| ended < self.started_at) {
            return Err(ValidationError::InvalidState {
                reason: "session ended before it started",
            });
        }
        let participants: BTreeSet<_> = self.participants.iter().copied().collect();
        if participants.len() != self.participants.len() {
            return Err(ValidationError::DuplicateIdentifier {
                field: "session.participants",
            });
        }
        Ok(())
    }
}

/// Current interaction mode used as a recall cue.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationMode {
    Casual,
    QuestionAnswering,
    Planning,
    Reflection,
    TaskExecution,
    Teaching,
    Forensic,
    Other(String),
}

/// Activated node in the working situation frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatedNode {
    pub node_id: NodeId,
    pub activation: f32,
}

impl Validate for ActivatedNode {
    fn validate(&self) -> ValidationResult {
        validate_unit(self.activation, "activated_node.activation")
    }
}

/// A conversational mention and its currently viable canonical identities.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveReferent {
    pub surface: String,
    pub candidates: NonEmptyVec<ActivatedNode>,
    pub resolved: Option<NodeId>,
}

impl Validate for ActiveReferent {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.surface, "active_referent.surface")?;
        for candidate in &self.candidates {
            candidate.validate()?;
        }
        if self.resolved.is_some_and(|resolved| {
            !self
                .candidates
                .iter()
                .any(|candidate| candidate.node_id == resolved)
        }) {
            return Err(ValidationError::InvalidState {
                reason: "resolved referent is absent from its candidate set",
            });
        }
        Ok(())
    }
}

/// Participant-specific working context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantContext {
    pub subject: MemorySubjectId,
    pub role: String,
    pub active_signal_nodes: Vec<NodeId>,
}

impl Validate for ParticipantContext {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.role, "participant.role")
    }
}

/// Goal held only in working memory until explicitly promoted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalFrame {
    pub goal_node: Option<NodeId>,
    pub statement: String,
    pub priority: f32,
}

impl Validate for GoalFrame {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.statement, "goal_frame.statement")?;
        validate_unit(self.priority, "goal_frame.priority")
    }
}

/// Scope with an activation weight for the current situation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeightedScope {
    pub scope: ScopeRef,
    pub weight: f32,
}

impl Validate for WeightedScope {
    fn validate(&self) -> ValidationResult {
        self.scope.validate()?;
        validate_unit(self.weight, "weighted_scope.weight")
    }
}

/// Unresolved conversational question.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenQuestion {
    pub statement: String,
    pub related_nodes: Vec<NodeId>,
}

impl Validate for OpenQuestion {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.statement, "open_question.statement")
    }
}

/// Expiring working hypothesis; never a semantic claim without promotion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkingHypothesis {
    pub statement: String,
    pub confidence: f32,
    pub supporting_observations: Vec<ObservationId>,
}

impl Validate for WorkingHypothesis {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.statement, "working_hypothesis.statement")?;
        validate_unit(self.confidence, "working_hypothesis.confidence")
    }
}

/// Expiring active conversational and agent state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationFrame {
    pub session_id: SessionId,
    pub conversation_mode: ConversationMode,
    pub active_topics: Vec<ActivatedNode>,
    pub active_referents: Vec<ActiveReferent>,
    pub participant_states: Vec<ParticipantContext>,
    pub goal_stack: Vec<GoalFrame>,
    pub active_scopes: NonEmptyVec<WeightedScope>,
    pub open_questions: Vec<OpenQuestion>,
    pub open_loops: Vec<NodeId>,
    pub working_hypotheses: Vec<WorkingHypothesis>,
    pub recent_observations: Vec<ObservationId>,
    pub environment: Option<serde_json::Value>,
    pub captured_at: TimestampMicros,
    pub expires_at: TimestampMicros,
}

impl Validate for SituationFrame {
    fn validate(&self) -> ValidationResult {
        if self.expires_at <= self.captured_at {
            return Err(ValidationError::InvalidState {
                reason: "situation frame must expire after capture",
            });
        }
        if let ConversationMode::Other(label) = &self.conversation_mode {
            crate::provenance::validate_non_blank(label, "conversation_mode")?;
        }
        for value in &self.active_topics {
            value.validate()?;
        }
        for value in &self.active_referents {
            value.validate()?;
        }
        for value in &self.participant_states {
            value.validate()?;
        }
        for value in &self.goal_stack {
            value.validate()?;
        }
        for value in &self.active_scopes {
            value.validate()?;
        }
        for value in &self.open_questions {
            value.validate()?;
        }
        for value in &self.working_hypotheses {
            value.validate()?;
        }
        Ok(())
    }
}

/// Durable resumption artifact. Its frame remains working state, not truth.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub session_id: SessionId,
    pub frame_snapshot: SituationFrame,
    pub task_state: serde_json::Value,
    pub required_memory_refs: Vec<MemoryRef>,
    pub created_seq: CommitSeq,
}

impl Validate for Checkpoint {
    fn validate(&self) -> ValidationResult {
        if self.frame_snapshot.session_id != self.session_id {
            return Err(ValidationError::InvalidState {
                reason: "checkpoint frame belongs to another session",
            });
        }
        self.frame_snapshot.validate()
    }
}

/// Model-neutral current input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum QueryContent {
    Text(String),
    Artifact(ArtifactId),
    Structured(serde_json::Value),
}

impl Validate for QueryContent {
    fn validate(&self) -> ValidationResult {
        if let Self::Text(text) = self {
            crate::provenance::validate_non_blank(text, "query.text")?;
        }
        Ok(())
    }
}

/// Time cues inferred from the current situation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalContext {
    pub now: TimestampMicros,
    pub referenced_valid_time: Option<TimeRange>,
    pub known_at: Option<CommitSeq>,
}

impl Validate for TemporalContext {
    fn validate(&self) -> ValidationResult {
        if let Some(range) = self.referenced_valid_time {
            range.validate()?;
        }
        Ok(())
    }
}

/// Full set of cues from which recall is planned.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CueBundle {
    pub current_input: QueryContent,
    pub recent_observations: Vec<ObservationId>,
    pub participants: NonEmptyVec<MemorySubjectId>,
    pub active_referents: Vec<ActiveReferent>,
    pub active_topics: Vec<NodeId>,
    pub temporal_context: TemporalContext,
    pub location_context: Option<NodeId>,
    pub conversation_mode: ConversationMode,
    pub goal: Option<String>,
    pub interaction_signals: Vec<NodeId>,
}

impl Validate for CueBundle {
    fn validate(&self) -> ValidationResult {
        self.current_input.validate()?;
        self.temporal_context.validate()?;
        if let ConversationMode::Other(label) = &self.conversation_mode {
            crate::provenance::validate_non_blank(label, "cue.conversation_mode")?;
        }
        if let Some(goal) = &self.goal {
            crate::provenance::validate_non_blank(goal, "cue.goal")?;
        }
        for referent in &self.active_referents {
            referent.validate()?;
        }
        Ok(())
    }
}

/// High-level recall intent that controls routing and stopping behavior.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallIntent {
    Continuity,
    CurrentTruth,
    HistoricalTruth,
    Associative,
    Relational,
    Procedural,
    Reflective,
    Forensic,
    Bootstrap,
    Preflight,
    Other(String),
}

/// Required facet and its minimum evidence quality.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacetRequirement {
    pub name: String,
    pub required: bool,
    pub minimum_confidence: f32,
}

impl Validate for FacetRequirement {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.name, "facet.name")?;
        validate_unit(self.minimum_confidence, "facet.minimum_confidence")
    }
}

/// Hard planner budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallBudgets {
    pub max_tokens: u32,
    pub max_latency_micros: u64,
    pub max_candidates: u32,
    pub max_graph_visits: u32,
    pub max_evidence_items: u32,
}

impl Validate for RecallBudgets {
    fn validate(&self) -> ValidationResult {
        if self.max_tokens == 0
            || self.max_latency_micros == 0
            || self.max_candidates == 0
            || self.max_graph_visits == 0
            || self.max_evidence_items == 0
        {
            return Err(ValidationError::InvalidState {
                reason: "recall budgets must be positive",
            });
        }
        Ok(())
    }
}

/// Evidence expansion requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicy {
    pub require_primary_evidence: bool,
    pub include_quotes: bool,
    pub permit_derived_only: bool,
}

/// Explicit temporal query semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TemporalConstraint {
    Current,
    ValidDuring {
        range: TimeRange,
    },
    KnownAt {
        commit_seq: CommitSeq,
    },
    Bitemporal {
        valid_during: TimeRange,
        known_at: CommitSeq,
    },
}

impl Validate for TemporalConstraint {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::ValidDuring { range } => range.validate(),
            Self::Bitemporal { valid_during, .. } => valid_during.validate(),
            Self::Current | Self::KnownAt { .. } => Ok(()),
        }
    }
}

/// Model-neutral recall request. Authorization and scope filters are mandatory inputs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallRequest {
    pub agent_id: AgentId,
    pub actor_id: ActorId,
    pub session_id: Option<SessionId>,
    pub cues: CueBundle,
    pub intent: RecallIntent,
    pub scopes: NonEmptyVec<ScopeRef>,
    pub temporal: TemporalConstraint,
    pub required_facets: Vec<FacetRequirement>,
    pub budgets: RecallBudgets,
    pub evidence_policy: EvidencePolicy,
    pub memory_use_policy: PolicyId,
    pub purpose: crate::Purpose,
    pub target_model: Option<ModelProfileId>,
}

impl Validate for RecallRequest {
    fn validate(&self) -> ValidationResult {
        self.cues.validate()?;
        if let RecallIntent::Other(label) = &self.intent {
            crate::provenance::validate_non_blank(label, "recall.intent")?;
        }
        for scope in &self.scopes {
            scope.validate()?;
        }
        self.temporal.validate()?;
        for facet in &self.required_facets {
            facet.validate()?;
        }
        self.budgets.validate()?;
        self.purpose.validate()
    }
}

/// Stable reference to any memory object that can enter a context pack.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemoryRef {
    Observation { id: ObservationId },
    EpisodeView { id: EpisodeViewId },
    Artifact { id: ArtifactId },
    Evidence { id: EvidenceId },
    Node { id: NodeId },
    Claim { id: ClaimId },
    Edge { id: EdgeId },
    ConflictSet { id: ConflictSetId },
}

/// Semantic category of model-neutral context data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextBlockKind {
    Situation,
    SelfContext,
    Participant,
    SharedHistory,
    Episode,
    Fact,
    Timeline,
    Preference,
    Boundary,
    Relationship,
    GoalOrOpenLoop,
    Procedure,
    Decision,
    Conflict,
    Unknown,
}

/// Memory data selected for a model. It is never an executable instruction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBlock {
    pub kind: ContextBlockKind,
    pub content: serde_json::Value,
    pub memory_refs: NonEmptyVec<MemoryRef>,
    pub confidence: Option<f32>,
    pub valid_time: Option<TimeRange>,
}

impl Validate for ContextBlock {
    fn validate(&self) -> ValidationResult {
        if let Some(confidence) = self.confidence {
            validate_unit(confidence, "context_block.confidence")?;
        }
        if let Some(valid_time) = self.valid_time {
            valid_time.validate()?;
        }
        Ok(())
    }
}

/// Expanded source evidence kept separate from response-control directives.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBlock {
    pub evidence_id: EvidenceId,
    pub artifact_id: Option<ArtifactId>,
    pub excerpt: Option<String>,
}

impl Validate for EvidenceBlock {
    fn validate(&self) -> ValidationResult {
        if self.excerpt.as_ref().is_some_and(String::is_empty) {
            return Err(ValidationError::BlankText {
                field: "evidence_block.excerpt",
            });
        }
        Ok(())
    }
}

/// Out-of-band response policy, never concatenated with untrusted memory content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryUseAction {
    UseSilently,
    MentionExplicitly,
    Suppress,
    DoNotSendExternally,
}

/// Policy decision for one selected memory item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUseDirective {
    pub memory: MemoryRef,
    pub action: MemoryUseAction,
    pub reason: String,
}

impl Validate for MemoryUseDirective {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.reason, "memory_use.reason")
    }
}

/// Continuation token is opaque data issued by the planner, not a storage offset contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallContinuation {
    pub run_id: RecallRunId,
    pub opaque: String,
    pub snapshot: SnapshotRef,
}

impl Validate for RecallContinuation {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.opaque, "recall_continuation.opaque")
    }
}

/// Freshness of primary and rebuildable projections.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexWatermarks {
    pub journal: CommitSeq,
    pub semantic: CommitSeq,
    pub lexical: CommitSeq,
    pub hierarchies: BTreeMap<HierarchyViewId, CommitSeq>,
    pub vectors: BTreeMap<VectorSpaceId, CommitSeq>,
    pub consolidation: CommitSeq,
}

impl IndexWatermarks {
    /// Rejects projection state from the future relative to a read snapshot.
    pub fn validate_for_snapshot(&self, snapshot: SnapshotRef) -> ValidationResult {
        if self.journal > snapshot.commit_seq
            || self.semantic > snapshot.commit_seq
            || self.lexical > snapshot.commit_seq
            || self.consolidation > snapshot.commit_seq
            || self
                .hierarchies
                .values()
                .any(|watermark| *watermark > snapshot.commit_seq)
            || self
                .vectors
                .values()
                .any(|watermark| *watermark > snapshot.commit_seq)
        {
            return Err(ValidationError::InvalidState {
                reason: "index watermark is newer than its snapshot",
            });
        }
        Ok(())
    }
}

/// Typed model-neutral context selected from one consistent snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPack {
    pub id: ContextPackId,
    pub snapshot: SnapshotRef,
    pub blocks: Vec<ContextBlock>,
    pub evidence: Vec<EvidenceBlock>,
    pub use_directives: Vec<MemoryUseDirective>,
    pub unknowns: Vec<String>,
    pub continuation: Option<RecallContinuation>,
    pub token_estimates: BTreeMap<String, u32>,
    pub safety_labels: BTreeSet<String>,
    pub watermarks: IndexWatermarks,
}

impl Validate for ContextPack {
    fn validate(&self) -> ValidationResult {
        for block in &self.blocks {
            block.validate()?;
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        for directive in &self.use_directives {
            directive.validate()?;
        }
        for unknown in &self.unknowns {
            crate::provenance::validate_non_blank(unknown, "context_pack.unknown")?;
        }
        for tokenizer in self.token_estimates.keys() {
            crate::provenance::validate_non_blank(tokenizer, "context_pack.tokenizer")?;
        }
        for label in &self.safety_labels {
            crate::provenance::validate_non_blank(label, "context_pack.safety_label")?;
        }
        if let Some(continuation) = &self.continuation {
            continuation.validate()?;
            if continuation.snapshot != self.snapshot {
                return Err(ValidationError::InvalidState {
                    reason: "recall continuation belongs to another snapshot",
                });
            }
        }
        self.watermarks.validate_for_snapshot(self.snapshot)
    }
}

/// Natural-language/user control normalized into an explicit host-side operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MemoryControlDirective {
    Remember {
        target: MemoryRef,
    },
    Correct {
        target: MemoryRef,
        replacement: serde_json::Value,
    },
    Retract {
        target: MemoryRef,
    },
    Forget {
        target: MemoryRef,
        hard_delete: bool,
    },
    Pin {
        target: MemoryRef,
    },
    MakePrivate {
        target: MemoryRef,
    },
    Share {
        target: MemoryRef,
        audience: crate::Audience,
    },
    DoNotMention {
        target: MemoryRef,
    },
    TreatAsHypothetical {
        target: MemoryRef,
    },
}

/// Planner operation recorded in an explainable recall trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallOperation {
    Authorize,
    ExactSeed,
    ActiveContextSeed,
    LexicalSeed,
    VectorSeed,
    TemporalFilter,
    RelationalTraversal,
    GraphTraversal,
    HierarchyDrillDown,
    ConflictResolution,
    EvidenceExpansion,
    SufficiencyCheck,
    ContextCompilation,
}

/// One explainable planner step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallStep {
    pub ordinal: u32,
    pub operation: RecallOperation,
    pub candidate_count: u64,
    pub selected: Vec<MemoryRef>,
    pub elapsed_micros: u64,
    pub explanation: serde_json::Value,
}

/// Completed or partial recall run tied to one snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallRun {
    pub id: RecallRunId,
    pub snapshot: SnapshotRef,
    pub steps: Vec<RecallStep>,
    pub watermarks: IndexWatermarks,
    pub result_pack: Option<ContextPackId>,
    pub warnings: Vec<String>,
}

impl Validate for RecallRun {
    fn validate(&self) -> ValidationResult {
        self.watermarks.validate_for_snapshot(self.snapshot)?;
        for (expected, step) in self.steps.iter().enumerate() {
            let expected = u32::try_from(expected).map_err(|_| ValidationError::InvalidState {
                reason: "too many recall steps",
            })?;
            if step.ordinal != expected {
                return Err(ValidationError::InvalidState {
                    reason: "recall step ordinals must be contiguous from zero",
                });
            }
        }
        for warning in &self.warnings {
            crate::provenance::validate_non_blank(warning, "recall.warning")?;
        }
        Ok(())
    }
}

fn validate_unit(value: f32, field: &'static str) -> ValidationResult {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(ValidationError::InvalidNumber { field });
    }
    Ok(())
}
