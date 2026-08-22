use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    BitemporalRange, CandidateId, ClaimId, CommitRange, CommitSeq, ConflictSetId, EdgeId,
    EdgeTypeId, EvidenceId, LineageNode, NodeId, NonEmptyVec, PredicateId, RevisionNumber,
    ScopeRef, SemanticEnvelope, TimeRange, Validate, ValidationError, ValidationResult,
    WorkspaceId,
};

/// Core semantic node category. Domain packs extend it without changing storage identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Actor,
    Entity,
    Concept,
    Event,
    Claim,
    Relationship,
    Preference,
    Boundary,
    Goal,
    Commitment,
    Decision,
    Procedure,
    Episode,
    Artifact,
    Correction,
    Conflict,
    Reflection,
    SharedReference,
    SelfModel,
    OpenLoop,
    Unknown,
    Domain { pack: String, name: String },
}

impl Validate for NodeType {
    fn validate(&self) -> ValidationResult {
        if let Self::Domain { pack, name } = self {
            crate::provenance::validate_non_blank(pack, "node_type.pack")?;
            crate::provenance::validate_non_blank(name, "node_type.name")?;
        }
        Ok(())
    }
}

/// Canonical identity resolution state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityState {
    Canonical,
    Ambiguous,
    Redirected,
    Split,
    Retired,
}

/// Stable semantic identity. Mutable attributes live only in revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: NodeId,
    pub workspace_id: WorkspaceId,
    pub node_type: NodeType,
    pub created_seq: CommitSeq,
    pub retired_seq: Option<CommitSeq>,
    pub identity_state: IdentityState,
    pub primary_scope: ScopeRef,
}

impl Validate for Node {
    fn validate(&self) -> ValidationResult {
        self.node_type.validate()?;
        self.primary_scope.validate()?;
        if self
            .retired_seq
            .is_some_and(|retired| retired < self.created_seq)
        {
            return Err(ValidationError::InvalidState {
                reason: "node retired before it was created",
            });
        }
        Ok(())
    }
}

/// Explicit origin of a semantic assertion, independent from its acceptance state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicBasis {
    Observation,
    ActorAssertion,
    ModelInference,
    DeterministicDerivation,
    HumanAdjudication,
    Hypothesis,
}

impl EpistemicBasis {
    fn label(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::ActorAssertion => "actor_assertion",
            Self::ModelInference => "model_inference",
            Self::DeterministicDerivation => "deterministic_derivation",
            Self::HumanAdjudication => "human_adjudication",
            Self::Hypothesis => "hypothesis",
        }
    }
}

/// Publication/acceptance axis, orthogonal to epistemic origin.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceState {
    Proposed,
    Validated,
    Accepted,
    Consolidated,
    Rejected,
}

impl AcceptanceState {
    /// Returns true when the revision participates in published truth resolution.
    #[must_use]
    pub const fn is_published(self) -> bool {
        matches!(self, Self::Accepted | Self::Consolidated)
    }
}

/// Conflict axis, intentionally separate from origin and lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConflictState {
    None,
    Disputed,
    InConflict { set_id: ConflictSetId },
    Resolved { set_id: ConflictSetId },
}

impl ConflictState {
    /// Returns the referenced conflict set, if one exists.
    #[must_use]
    pub const fn set_id(self) -> Option<ConflictSetId> {
        match self {
            Self::InConflict { set_id } | Self::Resolved { set_id } => Some(set_id),
            Self::None | Self::Disputed => None,
        }
    }
}

/// Revision lifecycle axis, independent of whether the statement was accepted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Active,
    Historical,
    Superseded,
    Retracted,
    Suppressed,
    Deleted,
}

/// Orthogonal epistemic state used by claims, edges, and typed memories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpistemicState {
    pub basis: EpistemicBasis,
    pub acceptance: AcceptanceState,
    pub conflict: ConflictState,
    pub lifecycle: LifecycleState,
}

/// Calibrated confidence components. Model self-confidence is only one input upstream.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceProfile {
    pub overall: f32,
    pub source_trust: f32,
    pub extraction_quality: f32,
    pub corroboration: f32,
}

impl Validate for ConfidenceProfile {
    fn validate(&self) -> ValidationResult {
        for (field, value) in [
            ("confidence.overall", self.overall),
            ("confidence.source_trust", self.source_trust),
            ("confidence.extraction_quality", self.extraction_quality),
            ("confidence.corroboration", self.corroboration),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(ValidationError::InvalidNumber { field });
            }
        }
        Ok(())
    }
}

/// Versioned mutable attributes of a canonical node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRevision {
    pub node_id: NodeId,
    pub revision: RevisionNumber,
    pub temporal: BitemporalRange,
    pub canonical_name: String,
    pub attributes: BTreeMap<String, serde_json::Value>,
    pub epistemic: EpistemicState,
    pub confidence: ConfidenceProfile,
    pub evidence: Vec<EvidenceId>,
    pub envelope: SemanticEnvelope,
}

impl TransactionRevision for NodeRevision {
    fn revision_number(&self) -> RevisionNumber {
        self.revision
    }

    fn transaction_time(&self) -> CommitRange {
        self.temporal.transaction_time
    }
}

impl Validate for NodeRevision {
    fn validate(&self) -> ValidationResult {
        self.temporal.validate()?;
        crate::provenance::validate_non_blank(&self.canonical_name, "node.canonical_name")?;
        for key in self.attributes.keys() {
            crate::provenance::validate_non_blank(key, "node.attribute")?;
        }
        self.confidence.validate()?;
        self.envelope
            .validate_for_target(&LineageNode::NodeRevision {
                id: self.node_id,
                revision: self.revision,
            })?;
        validate_semantic_support(self.epistemic.basis, &self.evidence, &self.envelope)
    }
}

/// Stable node plus its ordered bitemporal revision chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRecord {
    pub node: Node,
    pub revisions: NonEmptyVec<NodeRevision>,
}

impl Validate for NodeRecord {
    fn validate(&self) -> ValidationResult {
        self.node.validate()?;
        if self
            .revisions
            .iter()
            .any(|revision| revision.node_id != self.node.id)
        {
            return Err(ValidationError::InvalidState {
                reason: "node revision belongs to another node",
            });
        }
        validate_revision_chain(&self.revisions)
    }
}

/// Kind and provenance of an alias.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasKind {
    Exact,
    NativeIdentifier,
    Nickname,
    Abbreviation,
    HistoricalName,
    ModelProposed,
    Other(String),
}

/// Scoped and temporal alternative name for a canonical node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alias {
    pub id: crate::AliasId,
    pub node_id: NodeId,
    pub normalized: String,
    pub original: String,
    pub kind: AliasKind,
    pub valid_time: TimeRange,
    pub transaction_time: CommitRange,
    pub confidence: ConfidenceProfile,
    pub evidence: Vec<EvidenceId>,
    pub envelope: SemanticEnvelope,
}

impl Validate for Alias {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.normalized, "alias.normalized")?;
        crate::provenance::validate_non_blank(&self.original, "alias.original")?;
        if let AliasKind::Other(label) = &self.kind {
            crate::provenance::validate_non_blank(label, "alias.kind")?;
        }
        self.valid_time.validate()?;
        self.transaction_time.validate()?;
        self.confidence.validate()?;
        self.envelope.validate()?;
        if self.evidence.is_empty() && self.kind == AliasKind::ModelProposed {
            return Err(ValidationError::MissingEvidence {
                basis: "model_proposed_alias",
            });
        }
        Ok(())
    }
}

/// Value types admitted by a predicate definition.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Node,
    String,
    Integer,
    Float,
    Boolean,
    Timestamp,
    TimeRange,
    Quantity,
    Uri,
    CodeLocation,
    Structured,
}

/// Predicate cardinality constraint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cardinality {
    RequiredSingle,
    OptionalSingle,
    Set,
    List,
}

impl Cardinality {
    fn is_single(self) -> bool {
        matches!(self, Self::RequiredSingle | Self::OptionalSingle)
    }
}

/// How a predicate changes over valid time.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalMode {
    Atemporal,
    Point,
    Interval,
    Bitemporal,
}

/// Deterministic conflict behavior for a predicate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    AllowCoexistence,
    RequireConflictSet,
    TemporalTransition,
    Reject,
}

/// Semantic transitivity declaration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transitivity {
    None,
    Transitive,
    Symmetric,
    TransitiveAndSymmetric,
}

/// Security propagation behavior when a predicate is materialized as an edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPropagation {
    InheritStrictest,
    InheritSource,
    InheritTarget,
    ExplicitOnly,
}

/// Versioned registry definition controlling claim and traversal semantics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateDefinition {
    pub id: PredicateId,
    pub name: String,
    pub domain: BTreeSet<NodeType>,
    pub range: ValueType,
    pub cardinality: Cardinality,
    pub temporal_mode: TemporalMode,
    pub inverse: Option<PredicateId>,
    pub transitivity: Transitivity,
    pub conflict_policy: ConflictPolicy,
    pub default_traversal_weight: f32,
    pub security_propagation: SecurityPropagation,
    pub version: RevisionNumber,
}

impl Validate for PredicateDefinition {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.name, "predicate.name")?;
        if self.domain.is_empty() {
            return Err(ValidationError::EmptyCollection {
                field: "predicate.domain",
            });
        }
        for node_type in &self.domain {
            node_type.validate()?;
        }
        if !self.default_traversal_weight.is_finite()
            || !(0.0..=1.0).contains(&self.default_traversal_weight)
        {
            return Err(ValidationError::InvalidNumber {
                field: "predicate.default_traversal_weight",
            });
        }
        Ok(())
    }
}

/// Typed object/value of a claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ClaimObject {
    Node(NodeId),
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Timestamp(crate::TimestampMicros),
    TimeRange(TimeRange),
    Quantity {
        value: f64,
        unit: String,
    },
    Uri(String),
    CodeLocation {
        artifact: crate::ArtifactId,
        selector: crate::EvidenceSelector,
    },
    Structured(serde_json::Value),
}

impl ClaimObject {
    /// Returns the registry value type represented by this value.
    #[must_use]
    pub const fn value_type(&self) -> ValueType {
        match self {
            Self::Node(_) => ValueType::Node,
            Self::String(_) => ValueType::String,
            Self::Integer(_) => ValueType::Integer,
            Self::Float(_) => ValueType::Float,
            Self::Boolean(_) => ValueType::Boolean,
            Self::Timestamp(_) => ValueType::Timestamp,
            Self::TimeRange(_) => ValueType::TimeRange,
            Self::Quantity { .. } => ValueType::Quantity,
            Self::Uri(_) => ValueType::Uri,
            Self::CodeLocation { .. } => ValueType::CodeLocation,
            Self::Structured(_) => ValueType::Structured,
        }
    }
}

impl Validate for ClaimObject {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::String(value) => crate::provenance::validate_non_blank(value, "claim.string"),
            Self::Float(value) => validate_f64(*value, "claim.float"),
            Self::TimeRange(value) => value.validate(),
            Self::Quantity { value, unit } => {
                validate_f64(*value, "claim.quantity")?;
                crate::provenance::validate_non_blank(unit, "claim.quantity.unit")
            }
            Self::Uri(uri) => crate::provenance::validate_non_blank(uri, "claim.uri"),
            Self::CodeLocation { selector, .. } => selector.validate(),
            Self::Structured(_)
            | Self::Node(_)
            | Self::Integer(_)
            | Self::Boolean(_)
            | Self::Timestamp(_) => Ok(()),
        }
    }
}

/// Stable identity of a claim. Its truth and value live in revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub id: ClaimId,
    pub workspace_id: WorkspaceId,
    pub subject: NodeId,
    pub predicate: PredicateId,
    pub created_seq: CommitSeq,
}

impl Validate for Claim {
    fn validate(&self) -> ValidationResult {
        Ok(())
    }
}

/// Bitemporal and epistemically explicit version of a claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRevision {
    pub claim_id: ClaimId,
    pub revision: RevisionNumber,
    pub object: ClaimObject,
    pub temporal: BitemporalRange,
    pub epistemic: EpistemicState,
    pub confidence: ConfidenceProfile,
    pub source_families: BTreeSet<String>,
    pub evidence: Vec<EvidenceId>,
    pub supersedes: Vec<ClaimId>,
    pub envelope: SemanticEnvelope,
}

impl TransactionRevision for ClaimRevision {
    fn revision_number(&self) -> RevisionNumber {
        self.revision
    }

    fn transaction_time(&self) -> CommitRange {
        self.temporal.transaction_time
    }
}

impl ClaimRevision {
    /// Returns true when this revision contributes to current accepted truth.
    #[must_use]
    pub fn is_current_published(&self) -> bool {
        self.temporal.transaction_time.end.is_none()
            && self.epistemic.acceptance.is_published()
            && self.epistemic.lifecycle == LifecycleState::Active
    }
}

impl Validate for ClaimRevision {
    fn validate(&self) -> ValidationResult {
        self.object.validate()?;
        self.temporal.validate()?;
        self.confidence.validate()?;
        for family in &self.source_families {
            crate::provenance::validate_non_blank(family, "claim.source_family")?;
        }
        self.envelope
            .validate_for_target(&LineageNode::ClaimRevision {
                id: self.claim_id,
                revision: self.revision,
            })?;
        validate_semantic_support(self.epistemic.basis, &self.evidence, &self.envelope)
    }
}

/// Stable claim with an ordered revision chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub claim: Claim,
    pub revisions: NonEmptyVec<ClaimRevision>,
}

impl Validate for ClaimRecord {
    fn validate(&self) -> ValidationResult {
        self.claim.validate()?;
        if self
            .revisions
            .iter()
            .any(|revision| revision.claim_id != self.claim.id)
        {
            return Err(ValidationError::InvalidState {
                reason: "claim revision belongs to another claim",
            });
        }
        validate_revision_chain(&self.revisions)
    }
}

/// Edge direction in the semantic multigraph.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Directionality {
    Directed,
    Undirected,
}

/// Stable traversable relation. Meaning and evidence live in revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub id: EdgeId,
    pub workspace_id: WorkspaceId,
    pub source: NodeId,
    pub target: NodeId,
    pub edge_type: EdgeTypeId,
    pub directionality: Directionality,
    pub created_seq: CommitSeq,
    pub materialized_from_claim: Option<ClaimId>,
}

impl Validate for Edge {
    fn validate(&self) -> ValidationResult {
        if self.source == self.target && self.directionality == Directionality::Undirected {
            return Err(ValidationError::InvalidState {
                reason: "undirected self-edge has no traversal meaning",
            });
        }
        Ok(())
    }
}

/// Bitemporal edge state with explicit evidence and policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeRevision {
    pub edge_id: EdgeId,
    pub revision: RevisionNumber,
    pub temporal: BitemporalRange,
    pub weight: f32,
    pub epistemic: EpistemicState,
    pub confidence: ConfidenceProfile,
    pub evidence: Vec<EvidenceId>,
    pub attributes: BTreeMap<String, serde_json::Value>,
    pub envelope: SemanticEnvelope,
}

impl TransactionRevision for EdgeRevision {
    fn revision_number(&self) -> RevisionNumber {
        self.revision
    }

    fn transaction_time(&self) -> CommitRange {
        self.temporal.transaction_time
    }
}

impl Validate for EdgeRevision {
    fn validate(&self) -> ValidationResult {
        self.temporal.validate()?;
        if !self.weight.is_finite() || !(0.0..=1.0).contains(&self.weight) {
            return Err(ValidationError::InvalidNumber {
                field: "edge.weight",
            });
        }
        self.confidence.validate()?;
        for key in self.attributes.keys() {
            crate::provenance::validate_non_blank(key, "edge.attribute")?;
        }
        self.envelope
            .validate_for_target(&LineageNode::EdgeRevision {
                id: self.edge_id,
                revision: self.revision,
            })?;
        validate_semantic_support(self.epistemic.basis, &self.evidence, &self.envelope)
    }
}

/// Stable edge with its ordered revision chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeRecord {
    pub edge: Edge,
    pub revisions: NonEmptyVec<EdgeRevision>,
}

impl Validate for EdgeRecord {
    fn validate(&self) -> ValidationResult {
        self.edge.validate()?;
        if self
            .revisions
            .iter()
            .any(|revision| revision.edge_id != self.edge.id)
        {
            return Err(ValidationError::InvalidState {
                reason: "edge revision belongs to another edge",
            });
        }
        validate_revision_chain(&self.revisions)
    }
}

/// Stable conflict identity for one subject/predicate/scope signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSet {
    pub id: ConflictSetId,
    pub workspace_id: WorkspaceId,
    pub subject: NodeId,
    pub predicate: PredicateId,
    pub scopes: NonEmptyVec<ScopeRef>,
    pub created_seq: CommitSeq,
}

impl Validate for ConflictSet {
    fn validate(&self) -> ValidationResult {
        for scope in &self.scopes {
            scope.validate()?;
        }
        Ok(())
    }
}

/// Resolution state of a conflict set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConflictResolution {
    Unresolved,
    TemporalTransition,
    ScopedCoexistence,
    WinnerWithDissent { winner: ClaimId },
    Corrected { replacement: ClaimId },
    HumanAdjudicated { winner: Option<ClaimId> },
}

/// Versioned membership and resolution of a conflict set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSetRevision {
    pub conflict_set_id: ConflictSetId,
    pub revision: RevisionNumber,
    pub transaction_time: CommitRange,
    pub members: NonEmptyVec<ClaimId>,
    pub resolution: ConflictResolution,
    pub evidence: Vec<EvidenceId>,
    pub envelope: SemanticEnvelope,
}

impl TransactionRevision for ConflictSetRevision {
    fn revision_number(&self) -> RevisionNumber {
        self.revision
    }

    fn transaction_time(&self) -> CommitRange {
        self.transaction_time
    }
}

impl Validate for ConflictSetRevision {
    fn validate(&self) -> ValidationResult {
        self.transaction_time.validate()?;
        let members: BTreeSet<_> = self.members.iter().copied().collect();
        if members.len() < 2 || members.len() != self.members.len() {
            return Err(ValidationError::InvalidConflictSet);
        }
        let declared_winner = match self.resolution {
            ConflictResolution::WinnerWithDissent { winner }
            | ConflictResolution::Corrected {
                replacement: winner,
            } => Some(winner),
            ConflictResolution::HumanAdjudicated { winner } => winner,
            ConflictResolution::Unresolved
            | ConflictResolution::TemporalTransition
            | ConflictResolution::ScopedCoexistence => None,
        };
        if declared_winner.is_some_and(|winner| !members.contains(&winner)) {
            return Err(ValidationError::InvalidConflictSet);
        }
        self.envelope
            .validate_for_target(&LineageNode::ConflictRevision {
                id: self.conflict_set_id,
                revision: self.revision,
            })?;
        if !matches!(self.resolution, ConflictResolution::Unresolved) && self.evidence.is_empty() {
            return Err(ValidationError::MissingEvidence {
                basis: "conflict_resolution",
            });
        }
        Ok(())
    }
}

/// Stable conflict set with ordered resolution history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSetRecord {
    pub conflict: ConflictSet,
    pub revisions: NonEmptyVec<ConflictSetRevision>,
}

impl Validate for ConflictSetRecord {
    fn validate(&self) -> ValidationResult {
        self.conflict.validate()?;
        if self
            .revisions
            .iter()
            .any(|revision| revision.conflict_set_id != self.conflict.id)
        {
            return Err(ValidationError::InvalidState {
                reason: "conflict revision belongs to another conflict set",
            });
        }
        validate_revision_chain(&self.revisions)
    }
}

/// Kind of quarantined model or projector proposal.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateType {
    Node,
    Alias,
    Claim,
    Edge,
    Decision,
    Commitment,
    Procedure,
    Preference,
    Correction,
    OpenQuestion,
    HierarchyLabel,
    Other(String),
}

/// Quarantine lifecycle. Accepted candidates remain auditable outside the graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CandidateValidationState {
    Quarantined,
    Validated,
    Rejected { errors: NonEmptyVec<String> },
    Promoted { commit_seq: CommitSeq },
}

/// Explicit adjudication independent from schema validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateAdjudication {
    Pending,
    Automatic,
    HumanAccepted {
        actor: crate::ActorId,
    },
    HumanRejected {
        actor: crate::ActorId,
        reason: String,
    },
}

/// Promotion components retained for explainability rather than collapsed to one opaque score.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionScore {
    pub overall: f32,
    pub explicitness: f32,
    pub future_utility: f32,
    pub source_trust: f32,
    pub corroboration: f32,
    pub sensitivity_penalty: f32,
    pub ambiguity_penalty: f32,
}

impl Validate for PromotionScore {
    fn validate(&self) -> ValidationResult {
        for (field, value) in [
            ("promotion.overall", self.overall),
            ("promotion.explicitness", self.explicitness),
            ("promotion.future_utility", self.future_utility),
            ("promotion.source_trust", self.source_trust),
            ("promotion.corroboration", self.corroboration),
            ("promotion.sensitivity_penalty", self.sensitivity_penalty),
            ("promotion.ambiguity_penalty", self.ambiguity_penalty),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(ValidationError::InvalidNumber { field });
            }
        }
        Ok(())
    }
}

/// Structured proposal held outside published semantic state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidate {
    pub id: CandidateId,
    pub source_observations: NonEmptyVec<crate::ObservationId>,
    pub candidate_type: CandidateType,
    pub payload: serde_json::Value,
    pub evidence_spans: NonEmptyVec<EvidenceId>,
    pub pipeline: crate::PipelineIdentity,
    pub model_call: Option<crate::ModelCallId>,
    pub validation_state: CandidateValidationState,
    pub promotion: PromotionScore,
    pub adjudication: CandidateAdjudication,
    pub envelope: SemanticEnvelope,
}

impl Validate for MemoryCandidate {
    fn validate(&self) -> ValidationResult {
        if let CandidateType::Other(label) = &self.candidate_type {
            crate::provenance::validate_non_blank(label, "candidate.type")?;
        }
        if !self.payload.is_object() {
            return Err(ValidationError::InvalidCandidatePayload);
        }
        self.pipeline.validate()?;
        self.promotion.validate()?;
        self.envelope
            .validate_for_target(&LineageNode::Candidate { id: self.id })?;
        if let CandidateValidationState::Rejected { errors } = &self.validation_state {
            for error in errors {
                crate::provenance::validate_non_blank(error, "candidate.error")?;
            }
        }
        if let CandidateAdjudication::HumanRejected { reason, .. } = &self.adjudication {
            crate::provenance::validate_non_blank(reason, "candidate.rejection_reason")?;
        }
        Ok(())
    }
}

/// Metadata for an auditable model call. Exact candidate payloads are persisted separately.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCall {
    pub id: crate::ModelCallId,
    pub purpose: String,
    pub provider: String,
    pub model: String,
    pub model_revision: Option<String>,
    pub prompt_version: String,
    pub schema_version: String,
    pub input_hash: crate::ContentDigest,
    pub output_hash: crate::ContentDigest,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub latency_micros: u64,
    pub external_processing_allowed: bool,
}

impl Validate for ModelCall {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.purpose, "model_call.purpose")?;
        crate::provenance::validate_non_blank(&self.provider, "model_call.provider")?;
        crate::provenance::validate_non_blank(&self.model, "model_call.model")?;
        crate::provenance::validate_non_blank(&self.prompt_version, "model_call.prompt_version")?;
        crate::provenance::validate_non_blank(&self.schema_version, "model_call.schema_version")?;
        if let Some(revision) = &self.model_revision {
            crate::provenance::validate_non_blank(revision, "model_call.model_revision")?;
        }
        Ok(())
    }
}

/// Common interface used to validate any bitemporal revision chain.
pub trait TransactionRevision: Validate {
    fn revision_number(&self) -> RevisionNumber;
    fn transaction_time(&self) -> CommitRange;
}

/// Checks one-based contiguous revision numbers and non-overlapping transaction time.
pub fn validate_revision_chain<T: TransactionRevision>(revisions: &[T]) -> ValidationResult {
    if revisions.is_empty() {
        return Err(ValidationError::EmptyCollection { field: "revisions" });
    }
    for (index, revision) in revisions.iter().enumerate() {
        revision.validate()?;
        let expected =
            u32::try_from(index + 1).map_err(|_| ValidationError::InvalidRevisionSequence)?;
        if revision.revision_number().get() != expected {
            return Err(ValidationError::InvalidRevisionSequence);
        }
    }
    for (index, left) in revisions.iter().enumerate() {
        for right in &revisions[index + 1..] {
            if left.transaction_time().overlaps(right.transaction_time()) {
                return Err(ValidationError::OverlappingTransactionIntervals);
            }
        }
    }
    Ok(())
}

/// Checks a claim value and subject type against its predicate registry definition.
pub fn validate_claim_against_predicate(
    predicate: &PredicateDefinition,
    subject_type: &NodeType,
    revision: &ClaimRevision,
) -> ValidationResult {
    predicate.validate()?;
    revision.validate()?;
    if !predicate.domain.contains(subject_type) || predicate.range != revision.object.value_type() {
        return Err(ValidationError::PredicateTypeMismatch);
    }
    Ok(())
}

/// Enforces single-valued predicate cardinality across current accepted claims.
///
/// Simultaneous distinct values are legal only when both revisions reference the
/// same explicit `ConflictSet`.
pub fn validate_predicate_cardinality(
    predicate: &PredicateDefinition,
    records: &[ClaimRecord],
) -> ValidationResult {
    predicate.validate()?;
    if !predicate.cardinality.is_single() {
        return Ok(());
    }
    let mut active = Vec::new();
    for record in records {
        record.validate()?;
        if record.claim.predicate != predicate.id {
            continue;
        }
        for revision in &record.revisions {
            if revision.is_current_published() {
                active.push((&record.claim, revision));
            }
        }
    }
    for (index, (left_claim, left)) in active.iter().enumerate() {
        for (right_claim, right) in &active[index + 1..] {
            if left_claim.subject != right_claim.subject
                || !same_scope_signature(&left.envelope.scopes, &right.envelope.scopes)
                || !left.temporal.valid_time.overlaps(right.temporal.valid_time)
                || left.object == right.object
            {
                continue;
            }
            let left_set = left.epistemic.conflict.set_id();
            let right_set = right.epistemic.conflict.set_id();
            if left_set.is_none() || left_set != right_set {
                return Err(ValidationError::CardinalityConflictWithoutConflictSet);
            }
        }
    }
    Ok(())
}

fn same_scope_signature(left: &[ScopeRef], right: &[ScopeRef]) -> bool {
    let left_set: BTreeSet<_> = left.iter().collect();
    let right_set: BTreeSet<_> = right.iter().collect();
    left_set == right_set
}

pub(crate) fn validate_semantic_support(
    basis: EpistemicBasis,
    evidence: &[EvidenceId],
    envelope: &SemanticEnvelope,
) -> ValidationResult {
    if evidence.is_empty()
        && !matches!(
            basis,
            EpistemicBasis::ActorAssertion | EpistemicBasis::Hypothesis
        )
    {
        return Err(ValidationError::MissingEvidence {
            basis: basis.label(),
        });
    }
    if basis == EpistemicBasis::ActorAssertion
        && envelope.derivation.kind != crate::DerivationKind::ActorAssertion
    {
        return Err(ValidationError::InvalidAssertionDerivation);
    }
    Ok(())
}

fn validate_f64(value: f64, field: &'static str) -> ValidationResult {
    if !value.is_finite() {
        return Err(ValidationError::InvalidNumber { field });
    }
    Ok(())
}
