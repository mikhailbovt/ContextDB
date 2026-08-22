//! Typed higher-level memory records built on the universal semantic envelope.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AgentId, BitemporalRange, CommitRange, ConfidenceProfile, ContinuityProfileId, EpistemicState,
    EvidenceId, LineageNode, MemorySubjectId, NodeId, NonEmptyVec, RevisionNumber,
    SemanticEnvelope, TimestampMicros, TransactionRevision, Validate, ValidationError,
    ValidationResult,
};

macro_rules! impl_transaction_revision {
    ($type:ty) => {
        impl TransactionRevision for $type {
            fn revision_number(&self) -> RevisionNumber {
                self.header.revision
            }

            fn transaction_time(&self) -> CommitRange {
                self.header.temporal.transaction_time
            }
        }
    };
}

/// Common bitemporal, epistemic, evidence, and policy fields for typed memory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRevisionHeader {
    pub node_id: NodeId,
    pub revision: RevisionNumber,
    pub temporal: BitemporalRange,
    pub epistemic: EpistemicState,
    pub confidence: ConfidenceProfile,
    pub evidence: Vec<EvidenceId>,
    pub envelope: SemanticEnvelope,
}

impl MemoryRevisionHeader {
    fn validate_header(&self) -> ValidationResult {
        self.temporal.validate()?;
        self.confidence.validate()?;
        self.envelope
            .validate_for_target(&LineageNode::NodeRevision {
                id: self.node_id,
                revision: self.revision,
            })?;
        crate::semantic::validate_semantic_support(
            self.epistemic.basis,
            &self.evidence,
            &self.envelope,
        )
    }
}

/// Relative strength of a contextual preference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceStrength {
    Weak,
    Moderate,
    Strong,
    ExplicitRequirement,
}

/// Versioned preference; temporary and historical preferences remain expressible.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub header: MemoryRevisionHeader,
    pub subject: MemorySubjectId,
    pub domain: String,
    pub value: serde_json::Value,
    pub strength: PreferenceStrength,
    pub context: Vec<crate::ScopeRef>,
}

impl Validate for Preference {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        crate::provenance::validate_non_blank(&self.domain, "preference.domain")?;
        for scope in &self.context {
            scope.validate()?;
        }
        Ok(())
    }
}

impl_transaction_revision!(Preference);

/// Explicit boundary semantics, stronger than inferred preferences.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BoundaryRule {
    DoNotStore,
    DoNotRetrieve,
    DoNotInfluence,
    DoNotMention,
    LocalOnly,
    RequireConfirmation,
    Custom { statement: String },
}

/// Operational severity of a boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundarySeverity {
    Preference,
    Required,
    SafetyCritical,
}

/// Versioned user or system boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boundary {
    pub header: MemoryRevisionHeader,
    pub subject: MemorySubjectId,
    pub rule: BoundaryRule,
    pub applies_to: Vec<MemorySubjectId>,
    pub contexts: Vec<crate::ScopeRef>,
    pub severity: BoundarySeverity,
}

impl Validate for Boundary {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        if let BoundaryRule::Custom { statement } = &self.rule {
            crate::provenance::validate_non_blank(statement, "boundary.statement")?;
        }
        let applies_to: BTreeSet<_> = self.applies_to.iter().copied().collect();
        if applies_to.len() != self.applies_to.len() {
            return Err(ValidationError::DuplicateIdentifier {
                field: "boundary.applies_to",
            });
        }
        for scope in &self.contexts {
            scope.validate()?;
        }
        Ok(())
    }
}

impl_transaction_revision!(Boundary);

/// Goal lifecycle independent of its evidentiary basis.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalStatus {
    Proposed,
    Active,
    Paused,
    Completed,
    Abandoned,
    Blocked,
}

/// Expected time horizon of a goal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalHorizon {
    Immediate,
    ShortTerm,
    MediumTerm,
    LongTerm,
    Unspecified,
}

/// Versioned goal with explicit owner and related semantic nodes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Goal {
    pub header: MemoryRevisionHeader,
    pub owner: MemorySubjectId,
    pub statement: String,
    pub status: GoalStatus,
    pub horizon: GoalHorizon,
    pub related_nodes: Vec<NodeId>,
}

impl Validate for Goal {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        crate::provenance::validate_non_blank(&self.statement, "goal.statement")
    }
}

impl_transaction_revision!(Goal);

/// Trigger for a future commitment or procedure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    AtTime { at: TimestampMicros },
    AfterTime { at: TimestampMicros },
    Event { node_id: NodeId },
    ClaimBecomesCurrent { claim_id: crate::ClaimId },
    TextCue { text: String },
    Structured { value: serde_json::Value },
}

impl Validate for Condition {
    fn validate(&self) -> ValidationResult {
        if let Self::TextCue { text } = self {
            crate::provenance::validate_non_blank(text, "condition.text")?;
        }
        Ok(())
    }
}

/// Commitment lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Proposed,
    Active,
    Fulfilled,
    Cancelled,
    Missed,
    Superseded,
}

/// Versioned prospective memory, not necessarily a task-manager record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub header: MemoryRevisionHeader,
    pub owner: MemorySubjectId,
    pub beneficiary: Option<MemorySubjectId>,
    pub statement: String,
    pub due: Option<TimestampMicros>,
    pub trigger: Option<Condition>,
    pub status: CommitmentStatus,
}

impl Validate for Commitment {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        crate::provenance::validate_non_blank(&self.statement, "commitment.statement")?;
        if let Some(trigger) = &self.trigger {
            trigger.validate()?;
        }
        Ok(())
    }
}

impl_transaction_revision!(Commitment);

/// Parameter accepted by a procedure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureParameter {
    pub name: String,
    pub required: bool,
    pub description: String,
}

impl Validate for ProcedureParameter {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.name, "procedure.parameter.name")?;
        crate::provenance::validate_non_blank(&self.description, "procedure.parameter.description")
    }
}

/// Non-executable typed procedure step. Hosts decide if and how to execute it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcedureStep {
    Instruction {
        text: String,
    },
    ToolSuggestion {
        tool: String,
        arguments: serde_json::Value,
    },
    Recall {
        facets: NonEmptyVec<String>,
    },
    Verify {
        rule: String,
    },
}

impl Validate for ProcedureStep {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::Instruction { text } => {
                crate::provenance::validate_non_blank(text, "procedure.step")
            }
            Self::ToolSuggestion { tool, .. } => {
                crate::provenance::validate_non_blank(tool, "procedure.tool")
            }
            Self::Recall { facets } => {
                for facet in facets {
                    crate::provenance::validate_non_blank(facet, "procedure.facet")?;
                }
                Ok(())
            }
            Self::Verify { rule } => {
                crate::provenance::validate_non_blank(rule, "procedure.verification")
            }
        }
    }
}

/// Observed execution statistics; counts cannot imply semantic truth by themselves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureStatistics {
    pub successful_runs: u64,
    pub failed_runs: u64,
}

/// Versioned procedural memory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Procedure {
    pub header: MemoryRevisionHeader,
    pub owner: Option<MemorySubjectId>,
    pub name: String,
    pub trigger: Option<Condition>,
    pub preconditions: Vec<Condition>,
    pub parameters: Vec<ProcedureParameter>,
    pub steps: NonEmptyVec<ProcedureStep>,
    pub expected_outcomes: NonEmptyVec<String>,
    pub failure_modes: Vec<String>,
    pub rollback: Vec<ProcedureStep>,
    pub statistics: ProcedureStatistics,
}

impl Validate for Procedure {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        crate::provenance::validate_non_blank(&self.name, "procedure.name")?;
        if let Some(trigger) = &self.trigger {
            trigger.validate()?;
        }
        for condition in &self.preconditions {
            condition.validate()?;
        }
        for parameter in &self.parameters {
            parameter.validate()?;
        }
        for step in &self.steps {
            step.validate()?;
        }
        for outcome in &self.expected_outcomes {
            crate::provenance::validate_non_blank(outcome, "procedure.expected_outcome")?;
        }
        for mode in &self.failure_modes {
            crate::provenance::validate_non_blank(mode, "procedure.failure_mode")?;
        }
        for step in &self.rollback {
            step.validate()?;
        }
        Ok(())
    }
}

impl_transaction_revision!(Procedure);

/// Honest relationship category; it does not imply human emotion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    UserAgent,
    Colleague,
    Family,
    Friend,
    OrganisationMembership,
    ProjectTeam,
    Fictional,
    Other(String),
}

/// Versioned observed/configured relationship state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipState {
    pub id: crate::RelationshipStateId,
    pub header: MemoryRevisionHeader,
    pub participants: NonEmptyVec<MemorySubjectId>,
    pub relationship_kind: RelationshipKind,
    pub roles: BTreeMap<MemorySubjectId, String>,
    pub interaction_norms: Vec<String>,
    pub boundaries: Vec<NodeId>,
    pub shared_history_root: Option<NodeId>,
}

impl Validate for RelationshipState {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        let participants: BTreeSet<_> = self.participants.iter().copied().collect();
        if participants.len() < 2 || participants.len() != self.participants.len() {
            return Err(ValidationError::InvalidState {
                reason: "relationship requires at least two distinct participants",
            });
        }
        if let RelationshipKind::Other(label) = &self.relationship_kind {
            crate::provenance::validate_non_blank(label, "relationship.kind")?;
        }
        if self
            .roles
            .keys()
            .any(|subject| !participants.contains(subject))
        {
            return Err(ValidationError::InvalidState {
                reason: "relationship role belongs to a non-participant",
            });
        }
        for role in self.roles.values() {
            crate::provenance::validate_non_blank(role, "relationship.role")?;
        }
        for norm in &self.interaction_norms {
            crate::provenance::validate_non_blank(norm, "relationship.norm")?;
        }
        Ok(())
    }
}

impl_transaction_revision!(RelationshipState);

/// A shared nickname, joke, or compact relational reference.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedReference {
    pub header: MemoryRevisionHeader,
    pub participants: NonEmptyVec<MemorySubjectId>,
    pub label: String,
    pub meaning: serde_json::Value,
    pub origin_observations: NonEmptyVec<crate::ObservationId>,
    pub tone: Option<String>,
    pub mention_policy: crate::PolicyDecision,
}

impl Validate for SharedReference {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        let participants: BTreeSet<_> = self.participants.iter().copied().collect();
        if participants.len() < 2 || participants.len() != self.participants.len() {
            return Err(ValidationError::InvalidState {
                reason: "shared reference requires at least two distinct participants",
            });
        }
        crate::provenance::validate_non_blank(&self.label, "shared_reference.label")?;
        if let Some(tone) = &self.tone {
            crate::provenance::validate_non_blank(tone, "shared_reference.tone")?;
        }
        Ok(())
    }
}

impl_transaction_revision!(SharedReference);

/// Versioned operational self-model, not hidden chain-of-thought.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfModel {
    pub id: crate::SelfModelId,
    pub header: MemoryRevisionHeader,
    pub subject: MemorySubjectId,
    pub role: String,
    pub capabilities: BTreeSet<String>,
    pub limitations: BTreeSet<String>,
    pub configured_style: BTreeMap<String, serde_json::Value>,
    pub commitments: Vec<NodeId>,
    pub known_failures: Vec<NodeId>,
}

impl Validate for SelfModel {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        crate::provenance::validate_non_blank(&self.role, "self_model.role")?;
        for value in self.capabilities.iter().chain(&self.limitations) {
            crate::provenance::validate_non_blank(value, "self_model.capability_or_limitation")?;
        }
        for key in self.configured_style.keys() {
            crate::provenance::validate_non_blank(key, "self_model.style_key")?;
        }
        Ok(())
    }
}

impl_transaction_revision!(SelfModel);

/// One cognition backend in an agent's migration history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRuntimeRef {
    pub provider: String,
    pub model: String,
    pub revision: Option<String>,
    pub first_used_at: TimestampMicros,
    pub last_used_at: Option<TimestampMicros>,
}

impl Validate for ModelRuntimeRef {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.provider, "model_runtime.provider")?;
        crate::provenance::validate_non_blank(&self.model, "model_runtime.model")?;
        if let Some(revision) = &self.revision {
            crate::provenance::validate_non_blank(revision, "model_runtime.revision")?;
        }
        if self
            .last_used_at
            .is_some_and(|last_used| last_used < self.first_used_at)
        {
            return Err(ValidationError::InvalidState {
                reason: "model runtime ended before first use",
            });
        }
        Ok(())
    }
}

/// Policy controlling honest identity claims across model migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClaimPolicy {
    OperationalContinuityOnly,
    DiscloseMigrationOnRequest,
    AlwaysDiscloseMigration,
}

/// Versioned portable operational continuity profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityProfile {
    pub id: ContinuityProfileId,
    pub revision: RevisionNumber,
    pub transaction_time: CommitRange,
    pub workspace_id: crate::WorkspaceId,
    pub agent_id: AgentId,
    pub stable_subject: MemorySubjectId,
    pub model_lineage: Vec<ModelRuntimeRef>,
    pub required_bootstrap_facets: NonEmptyVec<String>,
    pub migration_policy: String,
    pub identity_claim_policy: IdentityClaimPolicy,
    pub envelope: SemanticEnvelope,
}

impl TransactionRevision for ContinuityProfile {
    fn revision_number(&self) -> RevisionNumber {
        self.revision
    }

    fn transaction_time(&self) -> CommitRange {
        self.transaction_time
    }
}

impl Validate for ContinuityProfile {
    fn validate(&self) -> ValidationResult {
        self.transaction_time.validate()?;
        self.envelope
            .validate_for_target(&LineageNode::ContinuityProfile {
                id: self.id,
                revision: self.revision,
            })?;
        if !self
            .envelope
            .ownership
            .owners
            .contains(&self.stable_subject)
        {
            return Err(ValidationError::InvalidState {
                reason: "continuity subject must be an explicit owner",
            });
        }
        for runtime in &self.model_lineage {
            runtime.validate()?;
        }
        for facet in &self.required_bootstrap_facets {
            crate::provenance::validate_non_blank(facet, "continuity.bootstrap_facet")?;
        }
        crate::provenance::validate_non_blank(&self.migration_policy, "continuity.migration_policy")
    }
}

/// Provenance status of an interaction or affective signal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalStatus {
    Reported,
    Observed,
    Inferred,
}

/// Expected lifetime of an interaction signal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalPersistence {
    Turn,
    Session,
    Historical,
    CandidateTrait,
}

/// Explicitly qualified interaction observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionSignal {
    pub header: MemoryRevisionHeader,
    pub observation_id: crate::ObservationId,
    pub subject: MemorySubjectId,
    pub kind: String,
    pub value: serde_json::Value,
    pub status: SignalStatus,
    pub persistence: SignalPersistence,
}

impl Validate for InteractionSignal {
    fn validate(&self) -> ValidationResult {
        self.header.validate_header()?;
        crate::provenance::validate_non_blank(&self.kind, "interaction_signal.kind")
    }
}

impl_transaction_revision!(InteractionSignal);
