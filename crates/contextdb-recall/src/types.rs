use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use contextdb_core::{
    CommitRange, EvidencePolicy, MemorySubjectId, PolicyDecision, Purpose, RecallIntent,
    RecallRequest, ScopeRef, SecurityClassification, TimeRange, TimestampMicros, Validate,
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{RecallError, Result};

/// Version of the deterministic plan and continuation contract.
pub const PLAN_VERSION: &str = "contextdb-deterministic-recall-v1";

/// Stable provider-independent document identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DocumentId(String);

impl DocumentId {
    /// Creates a non-empty document identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(RecallError::InvalidRequest(
                "document ID must not be blank".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// Returns the stable textual representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DocumentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for DocumentId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Freshness accompanying one coherent provider snapshot.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWatermarks {
    pub journal: u64,
    pub semantic: u64,
    pub lexical: u64,
    pub vector: BTreeMap<String, u64>,
    pub graph: u64,
    pub hierarchy: BTreeMap<String, u64>,
}

impl RecallWatermarks {
    /// Rejects projections from the future relative to a snapshot.
    pub fn validate_for(&self, snapshot: &ProviderSnapshot) -> Result<()> {
        if self.journal > snapshot.commit_seq
            || self.semantic > snapshot.commit_seq
            || self.lexical > snapshot.commit_seq
            || self.graph > snapshot.commit_seq
            || self
                .vector
                .values()
                .any(|value| *value > snapshot.commit_seq)
            || self
                .hierarchy
                .values()
                .any(|value| *value > snapshot.commit_seq)
        {
            return Err(RecallError::Provider(
                "provider watermark is newer than its snapshot".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Provider-independent coherent snapshot identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshot {
    pub database_id: String,
    pub commit_seq: u64,
    pub watermarks: RecallWatermarks,
}

impl ProviderSnapshot {
    /// Validates snapshot identity and watermarks.
    pub fn validate(&self) -> Result<()> {
        if self.database_id.trim().is_empty() {
            return Err(RecallError::Provider(
                "provider database ID must not be blank".to_owned(),
            ));
        }
        self.watermarks.validate_for(self)
    }
}

/// Ordered confidentiality ceiling used at the provider authorization boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl From<SecurityClassification> for RecallSensitivity {
    fn from(value: SecurityClassification) -> Self {
        match value {
            SecurityClassification::Public => Self::Public,
            SecurityClassification::Internal => Self::Internal,
            SecurityClassification::Confidential => Self::Confidential,
            SecurityClassification::Restricted => Self::Restricted,
        }
    }
}

/// Principal resolved before candidate generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallPrincipal {
    pub subject: String,
    pub audiences: BTreeSet<String>,
    pub workspace: String,
    pub scopes: BTreeSet<String>,
    pub purpose: String,
    pub clearance: RecallSensitivity,
}

impl RecallPrincipal {
    /// Creates a principal from canonical core identities and scope/purpose values.
    #[must_use]
    pub fn from_core(
        subject: MemorySubjectId,
        workspace: contextdb_core::WorkspaceId,
        scopes: &[ScopeRef],
        purpose: &Purpose,
        clearance: SecurityClassification,
    ) -> Self {
        Self {
            subject: subject.to_string(),
            audiences: BTreeSet::new(),
            workspace: workspace.to_string(),
            scopes: scopes.iter().map(|scope| scope.id.to_string()).collect(),
            purpose: purpose_key(purpose),
            clearance: clearance.into(),
        }
    }

    /// Validates non-content authorization context.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("principal.subject", self.subject.as_str()),
            ("principal.workspace", self.workspace.as_str()),
            ("principal.purpose", self.purpose.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(RecallError::InvalidRequest(format!(
                    "{name} must not be blank"
                )));
            }
        }
        if self
            .audiences
            .iter()
            .chain(&self.scopes)
            .any(|value| value.trim().is_empty())
        {
            return Err(RecallError::InvalidRequest(
                "principal audience and scope identifiers must not be blank".to_owned(),
            ));
        }
        Ok(())
    }

    /// Evaluates only policy metadata; content is not consulted.
    #[must_use]
    pub fn allows(&self, access: &AccessRule) -> bool {
        if access.workspace != self.workspace
            || access.consent != AccessConsent::Granted
            || !access.retrievable
            || access.sensitivity > self.clearance
            || !access.required_compartments.is_subset(&self.scopes)
        {
            return false;
        }
        let has_scope = access.scopes.is_empty()
            || access
                .scopes
                .iter()
                .any(|scope| self.scopes.contains(scope));
        if !has_scope {
            return false;
        }
        let owner = access.owners.contains(&self.subject);
        let mut keys = BTreeSet::from([self.subject.clone(), "*".to_owned()]);
        keys.extend(self.audiences.iter().cloned());
        if owner {
            keys.insert("@owner".to_owned());
        }
        keys.iter().any(|key| {
            access
                .audience_purpose_grants
                .get(key)
                .is_some_and(|purposes| purposes.contains(&self.purpose) || purposes.contains("*"))
        })
    }
}

/// Provider-side consent decision. Unknown fails closed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessConsent {
    Granted,
    Unknown,
    Denied,
}

/// Non-content policy metadata evaluated before a provider exposes a document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRule {
    pub workspace: String,
    pub scopes: BTreeSet<String>,
    pub owners: BTreeSet<String>,
    pub audience_purpose_grants: BTreeMap<String, BTreeSet<String>>,
    pub sensitivity: RecallSensitivity,
    pub required_compartments: BTreeSet<String>,
    pub consent: AccessConsent,
    pub retrievable: bool,
}

impl AccessRule {
    /// Validates the non-content policy envelope. An empty grant map remains a
    /// valid fail-closed policy and therefore does not become an error.
    pub fn validate(&self) -> Result<()> {
        if self.workspace.trim().is_empty() || self.owners.is_empty() {
            return Err(RecallError::Provider(
                "access rule requires a workspace and at least one owner".to_owned(),
            ));
        }
        if self
            .scopes
            .iter()
            .chain(&self.owners)
            .chain(self.audience_purpose_grants.keys())
            .chain(&self.required_compartments)
            .any(|value| value.trim().is_empty())
            || self
                .audience_purpose_grants
                .values()
                .flatten()
                .any(|value| value.trim().is_empty())
        {
            return Err(RecallError::Provider(
                "access rule identifiers and purposes must not be blank".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authorization and snapshot constraints passed to a provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub snapshot: ProviderSnapshot,
    pub principal: RecallPrincipal,
    pub filter_digest: String,
}

/// Coarse document family used by deterministic routes and facet policies.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallDocumentKind {
    Entity,
    Claim,
    Relationship,
    SharedReference,
    Episode,
    Observation,
    Preference,
    Boundary,
    Goal,
    Commitment,
    Procedure,
    Decision,
    Reflection,
    Knowledge,
    Conflict,
    Unknown,
    Domain,
}

/// Temporal visibility of a recall document.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentTemporalState {
    pub valid_time: Option<TimeRange>,
    pub transaction_time: CommitRange,
}

impl DocumentTemporalState {
    /// Validates both temporal axes.
    pub fn validate(&self) -> Result<()> {
        if let Some(valid) = self.valid_time {
            valid
                .validate()
                .map_err(|error| RecallError::InvalidRequest(error.to_string()))?;
        }
        self.transaction_time
            .validate()
            .map_err(|error| RecallError::InvalidRequest(error.to_string()))
    }
}

/// Perspective qualification used during recall resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentPerspective {
    pub knower: Option<String>,
    pub narrator: Option<String>,
    pub role: String,
}

/// Conflict state projected into recall without forcing a winner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RecallConflictState {
    None,
    Unresolved { set_id: String },
    ResolvedWinner { set_id: String },
    ResolvedLoser { set_id: String, winner: DocumentId },
    Superseded { successor: DocumentId },
}

impl RecallConflictState {
    /// Conflict ID, if present.
    #[must_use]
    pub fn set_id(&self) -> Option<&str> {
        match self {
            Self::Unresolved { set_id }
            | Self::ResolvedWinner { set_id }
            | Self::ResolvedLoser { set_id, .. } => Some(set_id),
            Self::None | Self::Superseded { .. } => None,
        }
    }
}

/// How selected memory may influence or be disclosed in a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentUseProfile {
    pub influence: PolicyDecision,
    pub mention: PolicyDecision,
    pub external_model_use: PolicyDecision,
    pub shared_with_principal: bool,
    pub personal_detail: bool,
    pub constraint_only: bool,
    pub style_only: bool,
}

/// Evidence available for one recall document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallEvidence {
    pub id: String,
    pub source_observation: Option<String>,
    pub excerpt: Option<String>,
    pub primary: bool,
    pub trust: f32,
    pub estimated_tokens: u32,
}

impl RecallEvidence {
    /// Validates source identity, trust, and token cost.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() || self.estimated_tokens == 0 {
            return Err(RecallError::InvalidRequest(
                "evidence requires a non-empty ID and positive token cost".to_owned(),
            ));
        }
        if self
            .source_observation
            .iter()
            .chain(self.excerpt.iter())
            .any(|value| value.trim().is_empty())
        {
            return Err(RecallError::InvalidRequest(
                "evidence source and excerpt must not be blank when present".to_owned(),
            ));
        }
        validate_unit(self.trust, "evidence.trust")
    }
}

/// Optional exact full-precision representation supplied by the host.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedVector {
    pub space: String,
    pub values: Vec<f32>,
}

impl SuppliedVector {
    /// Validates vector space, dimensions, and finite components.
    pub fn validate(&self) -> Result<()> {
        if self.space.trim().is_empty()
            || self.values.is_empty()
            || self.values.iter().any(|value| !value.is_finite())
        {
            return Err(RecallError::InvalidRequest(
                "supplied vector requires a space and finite non-empty values".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authorized, model-neutral memory document consumed by all recall routes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallDocument {
    pub id: DocumentId,
    pub kind: RecallDocumentKind,
    pub canonical_name: Option<String>,
    pub aliases: Vec<String>,
    pub text: String,
    pub facets: BTreeSet<String>,
    pub subjects: BTreeSet<String>,
    pub participants: BTreeSet<String>,
    pub active_keys: BTreeSet<String>,
    pub temporal: DocumentTemporalState,
    pub perspective: DocumentPerspective,
    pub conflict: RecallConflictState,
    pub evidence: Vec<RecallEvidence>,
    pub vector: Option<SuppliedVector>,
    pub source_trust: f32,
    pub importance: f32,
    pub estimated_tokens: u32,
    pub use_profile: DocumentUseProfile,
}

impl RecallDocument {
    /// Validates all content-independent invariants consumed by the planner.
    pub fn validate(&self) -> Result<()> {
        if self.estimated_tokens == 0 {
            return Err(RecallError::InvalidRequest(
                "recall document token cost must be positive".to_owned(),
            ));
        }
        if self.text.trim().is_empty() && self.canonical_name.is_none() {
            return Err(RecallError::InvalidRequest(
                "recall document needs text or a canonical name".to_owned(),
            ));
        }
        if self.perspective.role.trim().is_empty()
            || self
                .perspective
                .knower
                .iter()
                .chain(self.perspective.narrator.iter())
                .any(|value| value.trim().is_empty())
        {
            return Err(RecallError::InvalidRequest(
                "document perspective identifiers and role must not be blank".to_owned(),
            ));
        }
        if self.use_profile.constraint_only && self.use_profile.style_only {
            return Err(RecallError::InvalidRequest(
                "memory cannot be both constraint-only and style-only".to_owned(),
            ));
        }
        if self
            .conflict
            .set_id()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RecallError::InvalidRequest(
                "conflict set ID must not be blank".to_owned(),
            ));
        }
        if let Some(name) = &self.canonical_name
            && name.trim().is_empty()
        {
            return Err(RecallError::InvalidRequest(
                "canonical name must not be blank".to_owned(),
            ));
        }
        for value in self.aliases.iter().chain(&self.active_keys) {
            if value.trim().is_empty() {
                return Err(RecallError::InvalidRequest(
                    "aliases and active keys must not be blank".to_owned(),
                ));
            }
        }
        self.temporal.validate()?;
        validate_unit(self.source_trust, "document.source_trust")?;
        validate_unit(self.importance, "document.importance")?;
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        if let Some(vector) = &self.vector {
            vector.validate()?;
        }
        Ok(())
    }
}

/// Relation class with deterministic intent-dependent spreading weights.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallRelationKind {
    Contains,
    PartOf,
    About,
    RelatedTo,
    Supports,
    Refines,
    SimilarTo,
    OccurredIn,
    ParticipantIn,
    PrecededBy,
    FollowedBy,
    Triggered,
    ResultedIn,
    Supersedes,
    CorrectedBy,
    Contradicts,
    SharedWith,
    SharedHistory,
    RunningJoke,
    HasBoundary,
    CommittedTo,
    MotivatedBy,
    CausedBy,
    Requires,
    VerifiedBy,
    LearnedFrom,
    HierarchyParent,
    Domain(String),
}

/// Authorized graph relation. Endpoints must both exist in the authorized corpus.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallRelation {
    pub id: String,
    pub source: DocumentId,
    pub target: DocumentId,
    pub kind: RecallRelationKind,
    pub weight: f32,
    pub valid_time: Option<TimeRange>,
    pub trust: f32,
}

impl RecallRelation {
    /// Validates edge weights and temporal compatibility metadata.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(RecallError::InvalidRequest(
                "relation ID must not be blank".to_owned(),
            ));
        }
        if self.source == self.target {
            return Err(RecallError::InvalidRequest(
                "self-relations are not useful for bounded activation".to_owned(),
            ));
        }
        validate_unit(self.weight, "relation.weight")?;
        validate_unit(self.trust, "relation.trust")?;
        if let Some(valid) = self.valid_time {
            valid
                .validate()
                .map_err(|error| RecallError::InvalidRequest(error.to_string()))?;
        }
        if let RecallRelationKind::Domain(name) = &self.kind
            && name.trim().is_empty()
        {
            return Err(RecallError::InvalidRequest(
                "domain relation name must not be blank".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Provider record before authorization strips its access label.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDocument {
    pub access: AccessRule,
    pub document: RecallDocument,
    pub evidence: Vec<ProviderEvidence>,
}

/// Evidence with its own non-content policy label. Evidence may be more
/// restrictive than the semantic document it supports.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEvidence {
    pub access: AccessRule,
    pub evidence: RecallEvidence,
}

/// Provider relation before authorization strips its access label.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRelation {
    pub access: AccessRule,
    pub relation: RecallRelation,
}

/// Deterministic memory-gate mode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallMode {
    Never,
    Optional,
    Auto,
    Required,
    ImplicitContinuity,
    Explicit,
    Associative,
    Relational,
    Historical,
    Forensic,
}

/// Depth selected by the deterministic memory gate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallDepth {
    None,
    Hot,
    Standard,
    Deep,
}

/// Explainable reason emitted by the memory gate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateReason {
    ModeNever,
    RequiredByCaller,
    ExplicitMemoryLanguage,
    VagueReference,
    ActiveReferent,
    ActiveTopic,
    TemporalLanguage,
    HistoricalIntent,
    RelationshipIntent,
    EvidenceRequired,
    SelfContained,
    InsufficientBudget,
}

/// Result of the deterministic memory gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryGateDecision {
    pub run_recall: bool,
    pub depth: RecallDepth,
    pub reasons: Vec<GateReason>,
    pub mandatory_facets: BTreeSet<String>,
    pub preferred_routes: Vec<RecallRoute>,
}

/// Universal deterministic seed routes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallRoute {
    ActiveContext,
    ExactAlias,
    Relationship,
    Episodic,
    Temporal,
    Structural,
    Lexical,
    SuppliedVector,
}

/// Strict execution limits. The engine also applies tighter compatible limits
/// from `contextdb_core::RecallBudgets`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallLimits {
    pub max_nodes_examined: u32,
    pub max_seed_candidates: u32,
    pub max_graph_hops: u8,
    pub max_frontier_per_hop: u32,
    pub max_evidence_units: u32,
    pub max_context_tokens: u32,
    pub deadline_micros: u64,
}

impl RecallLimits {
    /// Rejects unbounded/zero execution limits.
    pub fn validate(&self) -> Result<()> {
        if self.max_nodes_examined == 0
            || self.max_seed_candidates == 0
            || self.max_graph_hops == 0
            || self.max_frontier_per_hop == 0
            || self.max_evidence_units == 0
            || self.max_context_tokens == 0
            || self.deadline_micros == 0
        {
            return Err(RecallError::InvalidRequest(
                "all recall limits must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Complete deterministic recall request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicRecallRequest {
    pub request: RecallRequest,
    pub principal: RecallPrincipal,
    pub mode: RecallMode,
    pub limits: RecallLimits,
    pub query_vector: Option<SuppliedVector>,
    pub continuation: Option<RecallContinuationToken>,
}

impl DeterministicRecallRequest {
    /// Validates core and deterministic execution contracts.
    pub fn validate(&self) -> Result<()> {
        self.request
            .validate()
            .map_err(|error| RecallError::InvalidRequest(error.to_string()))?;
        self.principal.validate()?;
        self.limits.validate()?;
        if purpose_key(&self.request.purpose) != self.principal.purpose {
            return Err(RecallError::InvalidRequest(
                "request purpose differs from authorization purpose".to_owned(),
            ));
        }
        let request_scopes: BTreeSet<_> = self
            .request
            .scopes
            .iter()
            .map(|scope| scope.id.to_string())
            .collect();
        if !request_scopes.is_subset(&self.principal.scopes) {
            return Err(RecallError::InvalidRequest(
                "request scopes exceed principal grants".to_owned(),
            ));
        }
        if let Some(vector) = &self.query_vector {
            vector.validate()?;
        }
        Ok(())
    }

    /// Effective token ceiling after applying both contracts.
    #[must_use]
    pub fn max_context_tokens(&self) -> u32 {
        self.limits
            .max_context_tokens
            .min(self.request.budgets.max_tokens)
    }

    /// Effective node ceiling after applying both contracts.
    #[must_use]
    pub fn max_nodes_examined(&self) -> u32 {
        self.limits
            .max_nodes_examined
            .min(self.request.budgets.max_candidates)
    }

    /// Effective evidence ceiling after applying both contracts.
    #[must_use]
    pub fn max_evidence_units(&self) -> u32 {
        self.limits
            .max_evidence_units
            .min(self.request.budgets.max_evidence_items)
    }

    /// Effective deadline after applying both contracts.
    #[must_use]
    pub fn deadline_micros(&self) -> u64 {
        self.limits
            .deadline_micros
            .min(self.request.budgets.max_latency_micros)
    }
}

/// Fixed-point route contribution retained for deterministic explainability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteContribution {
    pub route: RecallRoute,
    pub rank: u32,
    pub rrf_micros: u64,
}

/// Final deterministic candidate score breakdown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreBreakdown {
    pub rrf_micros: u64,
    pub activation_micros: u64,
    pub modifier_micros: u64,
    pub final_micros: u64,
    pub routes: Vec<RouteContribution>,
}

/// Memory-use decision after retrieval and before context serialization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryUseDecision {
    IncludeAndMention,
    IncludeSilently,
    IncludeOnlyAsConstraint,
    IncludeOnlyAsStyleSignal,
    WithholdDueToUncertainty,
    WithholdDueToPrivacy,
    WithholdAsIrrelevant,
}

impl MemoryUseDecision {
    /// Whether the memory may enter the returned context.
    #[must_use]
    pub const fn is_included(self) -> bool {
        matches!(
            self,
            Self::IncludeAndMention
                | Self::IncludeSilently
                | Self::IncludeOnlyAsConstraint
                | Self::IncludeOnlyAsStyleSignal
        )
    }
}

/// Selected evidence after deduplication and budget checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedEvidence {
    pub document_id: DocumentId,
    pub evidence: RecallEvidence,
}

/// Selected memory item and complete deterministic score/use explanation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallItem {
    pub document_id: DocumentId,
    pub kind: RecallDocumentKind,
    pub content: Option<String>,
    pub score: ScoreBreakdown,
    pub covered_facets: BTreeSet<String>,
    pub use_decision: MemoryUseDecision,
    pub estimated_tokens: u32,
}

/// Structured rule-based sufficiency report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SufficiencyReport {
    pub sufficient: bool,
    pub covered_facets: BTreeSet<String>,
    pub missing_facets: BTreeSet<String>,
    pub unresolved_conflicts: BTreeSet<String>,
    pub unsupported_documents: BTreeSet<DocumentId>,
    pub confidence_micros: u32,
}

/// Privacy-safe count bucket based only on the authorized universe.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CountBucket {
    Zero,
    One,
    Few,
    Several,
    Many,
}

impl CountBucket {
    /// Buckets an authorized-only count.
    #[must_use]
    pub fn from_authorized(value: usize) -> Self {
        match value {
            0 => Self::Zero,
            1 => Self::One,
            2..=4 => Self::Few,
            5..=16 => Self::Several,
            _ => Self::Many,
        }
    }
}

/// Deterministic work bucket; no wall-clock values enter explain traces.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkBucket {
    Constant,
    Small,
    Medium,
    Large,
}

impl WorkBucket {
    /// Converts authorized deterministic work units into a coarse bucket.
    #[must_use]
    pub fn from_units(value: u64) -> Self {
        match value {
            0..=1 => Self::Constant,
            2..=32 => Self::Small,
            33..=256 => Self::Medium,
            _ => Self::Large,
        }
    }
}

/// Explainable stage. Only authorized IDs and authorized-derived buckets may appear.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallTraceStep {
    pub stage: String,
    pub route: Option<RecallRoute>,
    pub authorized_input: CountBucket,
    pub output: CountBucket,
    pub work: WorkBucket,
    pub selected_ids: Vec<DocumentId>,
    pub explanation: String,
}

/// Complete privacy-safe deterministic trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallTrace {
    pub plan_version: String,
    pub filter_digest: String,
    pub snapshot: Option<ProviderSnapshot>,
    pub steps: Vec<RecallTraceStep>,
}

/// Strict budget usage accumulated by deterministic execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsage {
    pub nodes_examined: u32,
    pub graph_edges_examined: u32,
    pub max_hop_reached: u8,
    pub evidence_units: u32,
    pub context_tokens: u32,
}

/// Why recall stopped.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    GateSkipped,
    Sufficient,
    NodeBudget,
    GraphBudget,
    HopBudget,
    TokenBudget,
    Deadline,
    NoUsefulCandidates,
    UnknownOrConflicted,
    ContinuationBoundary,
}

/// Overall recall status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallStatus {
    Skipped,
    Complete,
    Partial,
    Unknown,
}

/// Snapshot/filter-bound continuation without plaintext memory content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallContinuationToken {
    pub snapshot: ProviderSnapshot,
    pub plan_version: String,
    pub filter_digest: String,
    pub next_offset: u32,
    pub visited_digest: String,
    pub covered_facet_digests: BTreeSet<String>,
    pub selected_evidence_digests: BTreeSet<String>,
    pub consumed: BudgetUsage,
    pub binding_digest: String,
}

/// Complete deterministic recall result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicRecallResult {
    pub status: RecallStatus,
    pub snapshot: Option<ProviderSnapshot>,
    pub gate: MemoryGateDecision,
    pub items: Vec<RecallItem>,
    pub evidence: Vec<SelectedEvidence>,
    pub sufficiency: SufficiencyReport,
    pub stop_reason: StopReason,
    pub usage: BudgetUsage,
    pub trace: RecallTrace,
    pub continuation: Option<RecallContinuationToken>,
    pub freshness_warnings: Vec<String>,
}

/// Purpose string shared with the reference adapter.
#[must_use]
pub fn purpose_key(value: &Purpose) -> String {
    match value {
        Purpose::Conversation => "conversation".to_owned(),
        Purpose::Personalisation => "personalisation".to_owned(),
        Purpose::TaskExecution => "task_execution".to_owned(),
        Purpose::KnowledgeRecall => "knowledge_recall".to_owned(),
        Purpose::Safety => "safety".to_owned(),
        Purpose::Audit => "audit".to_owned(),
        Purpose::Export => "export".to_owned(),
        Purpose::Migration => "migration".to_owned(),
        Purpose::UserSpecified(label) => format!("user:{label}"),
    }
}

/// Whether a factual document satisfies the request's evidence policy.
#[must_use]
pub fn evidence_satisfies(policy: EvidencePolicy, evidence: &[RecallEvidence]) -> bool {
    if !policy.require_primary_evidence {
        return policy.permit_derived_only || !evidence.is_empty();
    }
    evidence.iter().any(|item| item.primary)
}

/// True for explicit/historical intents where disclosure is expected rather than surprising.
#[must_use]
pub fn is_explicit_intent(intent: &RecallIntent, mode: RecallMode) -> bool {
    matches!(
        mode,
        RecallMode::Explicit | RecallMode::Historical | RecallMode::Forensic
    ) || matches!(
        intent,
        RecallIntent::HistoricalTruth | RecallIntent::Forensic
    )
}

fn validate_unit(value: f32, field: &str) -> Result<()> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(RecallError::InvalidRequest(format!(
            "{field} must be finite and within [0, 1]"
        )));
    }
    Ok(())
}

/// Converts optional valid-time bounds used by adapters into the canonical range.
pub(crate) fn bounded_time(from: Option<i128>, to: Option<i128>) -> Result<Option<TimeRange>> {
    let Some(start) = from else {
        if to.is_some() {
            return Err(RecallError::Provider(
                "core valid time cannot represent an end without a start".to_owned(),
            ));
        }
        return Ok(None);
    };
    let start = i64::try_from(start)
        .map_err(|_| RecallError::Provider("valid-time start exceeds core range".to_owned()))?;
    let end = to
        .map(i64::try_from)
        .transpose()
        .map_err(|_| RecallError::Provider("valid-time end exceeds core range".to_owned()))?;
    TimeRange::new(TimestampMicros(start), end.map(TimestampMicros))
        .map(Some)
        .map_err(|error| RecallError::Provider(error.to_string()))
}
