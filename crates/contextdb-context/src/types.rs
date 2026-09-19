//! Canonical model-neutral ContextPack domain types.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use contextdb_core::{
    ClaimId, ConflictSetId, ContextPackId, EpistemicBasis, EpistemicState, MemoryRef, Perspective,
    PolicyDecision, Purpose, TemporalConstraint, TimeRange, Validate,
};
use contextdb_recall::{ProviderSnapshot, RecallPrincipal};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{CONTEXT_COMPILER_VERSION, CONTEXT_PACK_SCHEMA_VERSION, ContextError, Result};

macro_rules! stable_text_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Stable ", $label, " identifier.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated ", $label, " identifier.")]
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(ContextError::InvalidRequest(
                        concat!($label, " ID must not be blank").to_owned(),
                    ));
                }
                if value.chars().any(char::is_control) {
                    return Err(ContextError::InvalidRequest(
                        concat!($label, " ID must not contain control characters").to_owned(),
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

stable_text_id!(BlockId, "context block");
stable_text_id!(EvidenceHandle, "evidence handle");
stable_text_id!(SourceHandle, "source handle");

/// Purpose-specific ContextPack shape.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPurpose {
    Conversation,
    Continuity,
    Autobiographical,
    Knowledge,
    Historical,
    Reflective,
    Action,
    Handoff,
    Bootstrap,
}

impl PackPurpose {
    /// Converts the compiler purpose to the closest canonical core purpose.
    #[must_use]
    pub const fn core_purpose(self) -> Purpose {
        match self {
            Self::Conversation | Self::Continuity | Self::Bootstrap => Purpose::Conversation,
            Self::Autobiographical | Self::Reflective => Purpose::Personalisation,
            Self::Knowledge | Self::Historical => Purpose::KnowledgeRecall,
            Self::Action => Purpose::TaskExecution,
            Self::Handoff => Purpose::Export,
        }
    }
}

/// Canonical block categories. Sections remain separate in the serialized pack.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackBlockKind {
    Situation,
    SelfContext,
    Participant,
    SharedHistory,
    Episode,
    Fact,
    Relationship,
    Preference,
    Boundary,
    Goal,
    Decision,
    Timeline,
    Procedure,
    Constraint,
    OpenLoop,
    Conflict,
    Unknown,
    /// Attributed original bytes, without an asserted world-state claim.
    RawObservation,
}

impl PackBlockKind {
    /// Whether this category asserts world or historical state.
    #[must_use]
    pub const fn is_factual(self) -> bool {
        matches!(
            self,
            Self::SharedHistory
                | Self::Episode
                | Self::Fact
                | Self::Relationship
                | Self::Preference
                | Self::Boundary
                | Self::Goal
                | Self::Decision
                | Self::Timeline
                | Self::Procedure
                | Self::Constraint
                | Self::OpenLoop
                | Self::Conflict
        )
    }

    /// Whether the category consumes the dedicated history budget.
    #[must_use]
    pub const fn is_history(self) -> bool {
        matches!(
            self,
            Self::SharedHistory | Self::Episode | Self::Timeline | Self::RawObservation
        )
    }
}

/// Structural compression level, from raw detail to compact orientation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionLevel {
    L0Orientation,
    L1Summary,
    L2Structured,
    L3Evidence,
    L4Raw,
}

/// Text that must survive every compression representation unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFragment {
    pub label: String,
    pub value: String,
}

impl ExactFragment {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_non_blank(&self.label, "exact fragment label")?;
        validate_non_blank(&self.value, "exact fragment value")
    }
}

/// One loss-declared structural representation of the same memory block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRepresentation {
    pub level: CompressionLevel,
    pub summary: String,
    pub fields: BTreeMap<String, String>,
    pub omitted_facets: BTreeSet<String>,
}

impl BlockRepresentation {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.summary.trim().is_empty() && self.fields.is_empty() {
            return Err(ContextError::InvalidRequest(
                "block representation needs a summary or structured fields".to_owned(),
            ));
        }
        for (key, value) in &self.fields {
            validate_non_blank(key, "representation field name")?;
            validate_non_blank(value, "representation field value")?;
        }
        for facet in &self.omitted_facets {
            validate_non_blank(facet, "omitted facet")?;
        }
        Ok(())
    }
}

/// Whether evidence support exists or absence is explicitly represented.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SupportState {
    Supported,
    Unsupported { reason: String },
}

/// Content trust is independent from instruction capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentTrust {
    TrustedSource,
    Mixed,
    Untrusted,
    Unknown,
}

/// Retrieved content never gains instruction privilege.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionCapability {
    None,
    HostTrusted,
}

/// Provenance family of a memory block or evidence unit.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    UserStatement,
    SharedConversation,
    Repository,
    ToolOutput,
    ExternalDocument,
    Sensor,
    DeterministicDerivation,
    ModelGenerated,
    Imported,
    Other(String),
}

/// Taint labels that renderers preserve rather than interpreting as instructions.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentTaint {
    UntrustedInstructions,
    ExternalContent,
    UserControlled,
    Generated,
    SecretLike,
    PersonallySensitive,
    Other(String),
}

/// How a renderer is allowed to interpret a data block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterpretationRule {
    FactualData,
    HistoricalData,
    ConstraintData,
    StyleSignal,
    HypothesisOnly,
    UnknownMarker,
    ConflictAlternatives,
}

/// Explicit conflict semantics; unresolved alternatives are never flattened.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictDescriptor {
    pub set_id: ConflictSetId,
    pub alternatives: BTreeSet<ClaimId>,
    pub resolution: ConflictResolution,
    pub blocking: bool,
}

/// Resolution state carried into the pack.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConflictResolution {
    Unresolved,
    Resolved { winner: ClaimId, rationale: String },
}

/// Explicitly missing knowledge, optionally blocking sufficiency.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownDescriptor {
    pub question: String,
    pub reason: String,
    pub blocking: bool,
}

/// Full authorized memory candidate before deterministic selection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackCandidate {
    pub id: BlockId,
    pub kind: PackBlockKind,
    pub representations: Vec<BlockRepresentation>,
    pub exact_fragments: Vec<ExactFragment>,
    pub memory_refs: Vec<MemoryRef>,
    pub claim_ids: BTreeSet<ClaimId>,
    pub evidence_handles: BTreeSet<EvidenceHandle>,
    pub facets: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub valid_time: Option<TimeRange>,
    pub known_at_commit: u64,
    pub perspective: Option<Perspective>,
    pub epistemic: EpistemicState,
    pub confidence_micros: u32,
    pub trust: ContentTrust,
    pub instruction_capability: InstructionCapability,
    pub source_class: SourceClass,
    pub taints: BTreeSet<ContentTaint>,
    pub interpretation: InterpretationRule,
    pub support: SupportState,
    pub conflict: Option<ConflictDescriptor>,
    pub unknown: Option<UnknownDescriptor>,
    pub utility_micros: u64,
    pub mandatory: bool,
}

impl PackCandidate {
    /// Validates semantic, evidence, temporal, and instruction/data invariants.
    pub fn validate(&self) -> Result<()> {
        if self.representations.is_empty() {
            return Err(ContextError::InvalidRequest(format!(
                "candidate {} has no representations",
                self.id
            )));
        }
        let mut levels = BTreeSet::new();
        for representation in &self.representations {
            representation.validate()?;
            if !levels.insert(representation.level) {
                return Err(ContextError::InvalidRequest(format!(
                    "candidate {} repeats a compression level",
                    self.id
                )));
            }
            if !representation.omitted_facets.is_subset(&self.facets) {
                return Err(ContextError::InvalidRequest(format!(
                    "candidate {} omits a facet it never declared",
                    self.id
                )));
            }
        }
        if !self
            .representations
            .iter()
            .any(|representation| representation.omitted_facets.is_empty())
        {
            return Err(ContextError::InvalidRequest(format!(
                "candidate {} has no facet-complete representation",
                self.id
            )));
        }
        for exact in &self.exact_fragments {
            exact.validate()?;
        }
        if self.scopes.is_empty() {
            return Err(ContextError::InvalidRequest(format!(
                "candidate {} has no explicit scope",
                self.id
            )));
        }
        for value in self.facets.iter().chain(&self.scopes) {
            validate_non_blank(value, "candidate facet or scope")?;
        }
        if let Some(valid_time) = self.valid_time {
            valid_time
                .validate()
                .map_err(|error| ContextError::InvalidRequest(error.to_string()))?;
        }
        if self.confidence_micros > 1_000_000 {
            return Err(ContextError::InvalidRequest(format!(
                "candidate {} confidence exceeds one",
                self.id
            )));
        }
        if let Some(perspective) = &self.perspective {
            perspective
                .validate()
                .map_err(|error| ContextError::InvalidRequest(error.to_string()))?;
        } else if self.kind.is_factual() {
            return Err(ContextError::InvalidRequest(format!(
                "factual candidate {} has no explicit perspective",
                self.id
            )));
        }
        if self.utility_micros == 0 {
            return Err(ContextError::InvalidRequest(format!(
                "candidate {} utility must be positive",
                self.id
            )));
        }
        if self.kind == PackBlockKind::RawObservation
            && (!self.claim_ids.is_empty()
                || self.evidence_handles.is_empty()
                || self.interpretation != InterpretationRule::HistoricalData
                || self.support != SupportState::Supported)
        {
            return Err(ContextError::InvalidRequest(
                "raw observations require original support and cannot assert current claims".into(),
            ));
        }
        if self.instruction_capability != InstructionCapability::None {
            return Err(ContextError::InvalidRequest(format!(
                "retrieved candidate {} attempted to gain instruction capability",
                self.id
            )));
        }
        if let SourceClass::Other(label) = &self.source_class {
            validate_non_blank(label, "source class")?;
        }
        for taint in &self.taints {
            if let ContentTaint::Other(label) = taint {
                validate_non_blank(label, "content taint")?;
            }
        }
        match &self.support {
            SupportState::Supported
                if self.kind.is_factual() && self.evidence_handles.is_empty() =>
            {
                return Err(ContextError::InvalidRequest(format!(
                    "supported factual candidate {} has no evidence handle",
                    self.id
                )));
            }
            SupportState::Unsupported { reason } => {
                validate_non_blank(reason, "unsupported marker reason")?;
                if !matches!(
                    self.epistemic.basis,
                    EpistemicBasis::ActorAssertion | EpistemicBasis::Hypothesis
                ) {
                    return Err(ContextError::InvalidRequest(format!(
                        "candidate {} may be unsupported only as assertion or hypothesis",
                        self.id
                    )));
                }
            }
            SupportState::Supported => {}
        }
        if self.kind.is_factual() && self.claim_ids.is_empty() {
            return Err(ContextError::InvalidRequest(format!(
                "factual candidate {} has no stable claim ID",
                self.id
            )));
        }
        match (self.kind, &self.conflict, &self.unknown) {
            (PackBlockKind::Conflict, Some(conflict), None) => {
                conflict.validate()?;
                if !conflict.alternatives.is_subset(&self.claim_ids) {
                    return Err(ContextError::InvalidRequest(format!(
                        "conflict candidate {} does not carry every alternative claim ID",
                        self.id
                    )));
                }
            }
            (PackBlockKind::Unknown, None, Some(unknown)) => unknown.validate()?,
            (PackBlockKind::Conflict, _, _) => {
                return Err(ContextError::InvalidRequest(format!(
                    "conflict candidate {} lacks exclusive conflict semantics",
                    self.id
                )));
            }
            (PackBlockKind::Unknown, _, _) => {
                return Err(ContextError::InvalidRequest(format!(
                    "unknown candidate {} lacks exclusive unknown semantics",
                    self.id
                )));
            }
            (_, Some(_), _) | (_, _, Some(_)) => {
                return Err(ContextError::InvalidRequest(format!(
                    "candidate {} carries conflict/unknown metadata in the wrong section",
                    self.id
                )));
            }
            (_, None, None) => {}
        }
        Ok(())
    }
}

impl ConflictDescriptor {
    fn validate(&self) -> Result<()> {
        if self.alternatives.len() < 2 {
            return Err(ContextError::InvalidRequest(
                "conflict must preserve at least two alternatives".to_owned(),
            ));
        }
        if let ConflictResolution::Resolved { winner, rationale } = &self.resolution {
            if !self.alternatives.contains(winner) {
                return Err(ContextError::InvalidRequest(
                    "resolved conflict winner is absent from alternatives".to_owned(),
                ));
            }
            validate_non_blank(rationale, "conflict resolution rationale")?;
        }
        Ok(())
    }
}

impl UnknownDescriptor {
    fn validate(&self) -> Result<()> {
        validate_non_blank(&self.question, "unknown question")?;
        validate_non_blank(&self.reason, "unknown reason")
    }
}

/// Disclosure policy evaluated before payload materialization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureRule {
    MayMention,
    UseSilently,
    MentionOnlyWhenExplicit,
    DoNotDisclose,
}

/// Non-content policy axes used before a provider loads candidate payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateUsePolicy {
    pub influence: PolicyDecision,
    pub mention: PolicyDecision,
    pub external_model_use: PolicyDecision,
    pub disclosure: DisclosureRule,
}

/// How one included block may influence the caller's response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseAction {
    MentionNaturally,
    UseSilently,
    ConstraintOnly,
    StyleOnly,
}

/// Compiler-issued response control, kept outside untrusted memory data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UseDirective {
    pub block_id: BlockId,
    pub action: UseAction,
    pub reason_code: DirectiveReason,
}

/// Stable non-content reason for a response-control directive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectiveReason {
    PolicyAllowsMention,
    MentionDenied,
    ExplicitRequestRequired,
    ConstraintSemantics,
    StyleSemantics,
}

/// Stable source selector for exact evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceSelector {
    TextBytes { start: u64, end: u64 },
    Lines { start: u64, end: u64 },
    TimeMicros { start: u64, end: u64 },
    JsonPointer { pointer: String },
    Whole,
}

impl EvidenceSelector {
    fn validate(&self) -> Result<()> {
        match self {
            Self::TextBytes { start, end }
            | Self::Lines { start, end }
            | Self::TimeMicros { start, end }
                if end <= start =>
            {
                Err(ContextError::InvalidRequest(
                    "evidence selector end must exceed start".to_owned(),
                ))
            }
            Self::JsonPointer { pointer } => validate_non_blank(pointer, "JSON pointer"),
            Self::TextBytes { .. } | Self::Lines { .. } | Self::TimeMicros { .. } | Self::Whole => {
                Ok(())
            }
        }
    }
}

/// Evidence materialized only after its own authorization decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackEvidence {
    pub id: EvidenceHandle,
    pub source: SourceHandle,
    pub selector: EvidenceSelector,
    pub excerpt: Option<String>,
    pub claim_ids: BTreeSet<ClaimId>,
    pub provenance_family: String,
    pub primary: bool,
    pub trust_micros: u32,
    pub source_class: SourceClass,
    pub taints: BTreeSet<ContentTaint>,
    pub lineage: Vec<SourceHandle>,
    /// Exact immutable original, independently authorized and verified by the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_span: Option<contextdb_core::OriginalSourceSpan>,
}

impl PackEvidence {
    /// Validates evidence lineage, trust, selector, and exact excerpt markers.
    pub fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        if self.excerpt.as_ref().is_some_and(|value| value.is_empty()) {
            return Err(ContextError::InvalidRequest(format!(
                "evidence {} excerpt must not be empty when present",
                self.id
            )));
        }
        if self.taints.contains(&ContentTaint::SecretLike) && self.excerpt.is_some() {
            return Err(ContextError::InvalidRequest(format!(
                "secret-like evidence {} must not carry a raw excerpt",
                self.id
            )));
        }
        if self.claim_ids.is_empty() && self.original_span.is_none() {
            return Err(ContextError::InvalidRequest(format!(
                "evidence {} supports no claim",
                self.id
            )));
        }
        if let Some(span) = &self.original_span {
            let Some(excerpt) = &self.excerpt else {
                return Err(ContextError::InvalidRequest(
                    "exact evidence requires original text".into(),
                ));
            };
            if span.end <= span.start
                || span.end - span.start != excerpt.len() as u64
                || blake3::hash(excerpt.as_bytes()).as_bytes() != span.span_digest.as_bytes()
                || self.selector
                    != (EvidenceSelector::TextBytes {
                        start: span.start,
                        end: span.end,
                    })
            {
                return Err(ContextError::InvalidRequest(
                    "original span and exact excerpt disagree".into(),
                ));
            }
        }
        validate_non_blank(&self.provenance_family, "provenance family")?;
        if self.trust_micros > 1_000_000 {
            return Err(ContextError::InvalidRequest(format!(
                "evidence {} trust exceeds one",
                self.id
            )));
        }
        if self.lineage.iter().any(|item| item == &self.source) {
            return Err(ContextError::InvalidRequest(format!(
                "evidence {} lineage directly repeats its source",
                self.id
            )));
        }
        if let SourceClass::Other(label) = &self.source_class {
            validate_non_blank(label, "evidence source class")?;
        }
        for taint in &self.taints {
            if let ContentTaint::Other(label) = taint {
                validate_non_blank(label, "evidence taint")?;
            }
        }
        Ok(())
    }
}

/// Minimum support required for one query facet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackFacetRequirement {
    pub name: String,
    pub minimum_confidence_micros: u32,
    pub require_evidence: bool,
}

impl PackFacetRequirement {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_non_blank(&self.name, "facet requirement")?;
        if self.minimum_confidence_micros > 1_000_000 {
            return Err(ContextError::InvalidRequest(format!(
                "facet {} confidence exceeds one",
                self.name
            )));
        }
        Ok(())
    }
}

/// Strict deterministic compiler budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBudgets {
    pub hard_tokens: u32,
    pub soft_tokens: u32,
    pub max_blocks: u32,
    pub max_evidence_blocks: u32,
    pub max_raw_evidence_tokens: u32,
    pub max_history_tokens: u32,
    pub max_conflict_tokens: u32,
    pub max_serialized_bytes: u32,
    pub max_selection_evaluations: u32,
}

impl ContextBudgets {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.hard_tokens == 0
            || self.soft_tokens == 0
            || self.max_blocks == 0
            || self.max_evidence_blocks == 0
            || self.max_raw_evidence_tokens == 0
            || self.max_history_tokens == 0
            || self.max_conflict_tokens == 0
            || self.max_serialized_bytes == 0
            || self.max_selection_evaluations == 0
        {
            return Err(ContextError::InvalidRequest(
                "all ContextPack budgets must be positive".to_owned(),
            ));
        }
        if self.soft_tokens > self.hard_tokens {
            return Err(ContextError::InvalidRequest(
                "soft token budget exceeds hard token budget".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Model-specific placement without changing canonical pack semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RendererKind {
    Compact,
    HostedStructured,
    Chat,
    Coding,
    CanonicalJson,
}

/// Structured representation preferred by the target runtime.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredFormat {
    CompactText,
    Json,
    Markdown,
    ToolResult,
}

/// Tested placement strategy for a model family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionProfile {
    Balanced,
    CriticalFirst,
    EvidenceAdjacent,
    SmallModelExplicit,
}

/// How a target runtime separates trusted compiler control from memory data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionHierarchy {
    SeparatedChannels,
    SinglePromptDelimited,
}

/// Target model/runtime capabilities relevant to compilation and rendering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    pub id: String,
    pub family: String,
    pub tokenizer_id: String,
    pub renderer: RendererKind,
    pub max_context_tokens: u32,
    pub reserved_output_tokens: u32,
    pub preferred_structured_format: StructuredFormat,
    pub supports_tool_results: bool,
    pub supports_native_citations: bool,
    pub supports_prompt_caching: bool,
    pub position_profile: PositionProfile,
    pub instruction_hierarchy: InstructionHierarchy,
    pub max_schema_complexity: u32,
    /// Whether authorized pack data leaves the local trust boundary.
    pub external_processing: bool,
}

impl ModelProfile {
    /// Validate the declared tokenizer, renderer and usable input/output capacity.
    pub fn validate(&self) -> Result<()> {
        validate_non_blank(&self.id, "model profile ID")?;
        validate_non_blank(&self.family, "model family")?;
        validate_non_blank(&self.tokenizer_id, "tokenizer ID")?;
        if self.max_context_tokens == 0 {
            return Err(ContextError::InvalidRequest(
                "model profile context limit must be positive".to_owned(),
            ));
        }
        if self.reserved_output_tokens >= self.max_context_tokens {
            return Err(ContextError::InvalidRequest(
                "reserved output must leave positive input context".to_owned(),
            ));
        }
        if self.max_schema_complexity == 0 {
            return Err(ContextError::InvalidRequest(
                "model profile schema complexity must be positive".to_owned(),
            ));
        }
        if self.preferred_structured_format == StructuredFormat::ToolResult
            && !self.supports_tool_results
        {
            return Err(ContextError::InvalidRequest(
                "tool-result format requires tool-result support".to_owned(),
            ));
        }
        let renderer_matches_format = matches!(
            (self.renderer, self.preferred_structured_format),
            (RendererKind::Compact, StructuredFormat::CompactText)
                | (RendererKind::HostedStructured, StructuredFormat::ToolResult)
                | (
                    RendererKind::Chat | RendererKind::Coding,
                    StructuredFormat::Markdown
                )
                | (RendererKind::CanonicalJson, StructuredFormat::Json)
        );
        if !renderer_matches_format {
            return Err(ContextError::InvalidRequest(
                "renderer differs from the model profile structured format".to_owned(),
            ));
        }
        Ok(())
    }

    /// Maximum tokens that may be allocated to all model input after reserving output.
    #[must_use]
    pub const fn available_input_tokens(&self) -> u32 {
        self.max_context_tokens - self.reserved_output_tokens
    }
}

/// Opaque progressive-pack state. The token contains only digests and counters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextContinuationToken {
    pub opaque: String,
}

/// Full deterministic compiler input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    pub pack_id: ContextPackId,
    pub snapshot: ProviderSnapshot,
    pub principal: RecallPrincipal,
    pub filter_digest: String,
    pub purpose: PackPurpose,
    pub scopes: BTreeSet<String>,
    pub temporal_view: TemporalConstraint,
    pub required_facets: Vec<PackFacetRequirement>,
    pub budgets: ContextBudgets,
    pub model_profile: ModelProfile,
    pub explicit_memory_request: bool,
    pub require_primary_evidence: bool,
    pub continuation: Option<ContextContinuationToken>,
}

impl CompileRequest {
    /// Validates snapshot, authorization, purpose, model, and budget binding.
    pub fn validate(&self) -> Result<()> {
        self.snapshot
            .validate()
            .map_err(|error| ContextError::InvalidRequest(format!("invalid snapshot: {error}")))?;
        self.principal
            .validate()
            .map_err(|error| ContextError::InvalidRequest(format!("invalid principal: {error}")))?;
        validate_non_blank(&self.filter_digest, "filter digest")?;
        if self.scopes.is_empty() || self.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(ContextError::InvalidRequest(
                "compile request requires explicit non-blank scopes".to_owned(),
            ));
        }
        if !self.scopes.is_subset(&self.principal.scopes) {
            return Err(ContextError::Authorization(
                "pack scopes exceed principal authorization".to_owned(),
            ));
        }
        self.temporal_view
            .validate()
            .map_err(|error| ContextError::InvalidRequest(error.to_string()))?;
        if purpose_key(&self.purpose.core_purpose()) != self.principal.purpose {
            return Err(ContextError::Authorization(
                "pack purpose differs from authorization purpose".to_owned(),
            ));
        }
        self.budgets.validate()?;
        self.model_profile.validate()?;
        if self.budgets.hard_tokens > self.model_profile.available_input_tokens() {
            return Err(ContextError::InvalidRequest(
                "hard token budget exceeds model input capacity after reserved output".to_owned(),
            ));
        }
        let mut facets = BTreeSet::new();
        for facet in &self.required_facets {
            facet.validate()?;
            if !facets.insert(&facet.name) {
                return Err(ContextError::InvalidRequest(format!(
                    "duplicate required facet {}",
                    facet.name
                )));
            }
        }
        Ok(())
    }
}

/// Selected immutable context block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBlock {
    pub id: BlockId,
    pub kind: PackBlockKind,
    pub representation: BlockRepresentation,
    pub exact_fragments: Vec<ExactFragment>,
    pub memory_refs: Vec<MemoryRef>,
    pub claim_ids: BTreeSet<ClaimId>,
    pub evidence_handles: BTreeSet<EvidenceHandle>,
    pub facets: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub valid_time: Option<TimeRange>,
    pub known_at_commit: u64,
    pub perspective: Option<Perspective>,
    pub epistemic: EpistemicState,
    pub confidence_micros: u32,
    pub trust: ContentTrust,
    pub instruction_capability: InstructionCapability,
    pub source_class: SourceClass,
    pub taints: BTreeSet<ContentTaint>,
    pub interpretation: InterpretationRule,
    pub support: SupportState,
    pub conflict: Option<ConflictDescriptor>,
    pub unknown: Option<UnknownDescriptor>,
}

impl ContextBlock {
    fn validate(&self) -> Result<()> {
        self.representation.validate()?;
        if self.kind == PackBlockKind::RawObservation
            && (!self.claim_ids.is_empty()
                || self.evidence_handles.is_empty()
                || self.interpretation != InterpretationRule::HistoricalData
                || self.support != SupportState::Supported)
        {
            return Err(ContextError::InvalidRequest(
                "raw observations require original support and cannot assert current claims".into(),
            ));
        }
        for exact in &self.exact_fragments {
            exact.validate()?;
        }
        if self.scopes.is_empty() || self.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(ContextError::InvalidRequest(format!(
                "block {} requires explicit non-blank scopes",
                self.id
            )));
        }
        if let Some(valid_time) = self.valid_time {
            valid_time
                .validate()
                .map_err(|error| ContextError::InvalidRequest(error.to_string()))?;
        }
        if self.confidence_micros > 1_000_000 {
            return Err(ContextError::InvalidRequest(format!(
                "block {} confidence exceeds one",
                self.id
            )));
        }
        if let Some(perspective) = &self.perspective {
            perspective
                .validate()
                .map_err(|error| ContextError::InvalidRequest(error.to_string()))?;
        } else if self.kind.is_factual() {
            return Err(ContextError::InvalidRequest(format!(
                "factual block {} has no explicit perspective",
                self.id
            )));
        }
        if self.instruction_capability != InstructionCapability::None {
            return Err(ContextError::InvalidRequest(format!(
                "block {} gained instruction capability",
                self.id
            )));
        }
        if self.kind.is_factual() && self.claim_ids.is_empty() {
            return Err(ContextError::InvalidRequest(format!(
                "factual block {} has no stable claim ID",
                self.id
            )));
        }
        match &self.support {
            SupportState::Supported
                if self.kind.is_factual() && self.evidence_handles.is_empty() =>
            {
                return Err(ContextError::InvalidRequest(format!(
                    "supported factual block {} has no evidence",
                    self.id
                )));
            }
            SupportState::Unsupported { reason } => {
                validate_non_blank(reason, "unsupported marker reason")?;
                if !matches!(
                    self.epistemic.basis,
                    EpistemicBasis::ActorAssertion | EpistemicBasis::Hypothesis
                ) {
                    return Err(ContextError::InvalidRequest(format!(
                        "block {} may be unsupported only as assertion or hypothesis",
                        self.id
                    )));
                }
            }
            SupportState::Supported => {}
        }
        if let SourceClass::Other(label) = &self.source_class {
            validate_non_blank(label, "block source class")?;
        }
        for taint in &self.taints {
            if let ContentTaint::Other(label) = taint {
                validate_non_blank(label, "block taint")?;
            }
        }
        match (self.kind, &self.conflict, &self.unknown) {
            (PackBlockKind::Conflict, Some(conflict), None) => {
                conflict.validate()?;
                if !conflict.alternatives.is_subset(&self.claim_ids) {
                    return Err(ContextError::InvalidRequest(format!(
                        "conflict block {} does not carry every alternative claim ID",
                        self.id
                    )));
                }
            }
            (PackBlockKind::Unknown, None, Some(unknown)) => unknown.validate()?,
            (PackBlockKind::Conflict, _, _) | (PackBlockKind::Unknown, _, _) => {
                return Err(ContextError::InvalidRequest(format!(
                    "block {} has malformed conflict/unknown semantics",
                    self.id
                )));
            }
            (_, Some(_), _) | (_, _, Some(_)) => {
                return Err(ContextError::InvalidRequest(format!(
                    "block {} carries conflict/unknown metadata in the wrong section",
                    self.id
                )));
            }
            (_, None, None) => {}
        }
        Ok(())
    }
}

/// Canonical sections are kept separate to prevent semantic flattening.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSections {
    pub situation: Vec<ContextBlock>,
    pub self_context: Vec<ContextBlock>,
    pub participants: Vec<ContextBlock>,
    pub shared_history: Vec<ContextBlock>,
    pub episodes: Vec<ContextBlock>,
    pub facts: Vec<ContextBlock>,
    pub relationships: Vec<ContextBlock>,
    pub preferences: Vec<ContextBlock>,
    pub boundaries: Vec<ContextBlock>,
    pub goals: Vec<ContextBlock>,
    pub decisions: Vec<ContextBlock>,
    pub timeline: Vec<ContextBlock>,
    pub procedures: Vec<ContextBlock>,
    pub constraints: Vec<ContextBlock>,
    pub open_loops: Vec<ContextBlock>,
    pub conflicts: Vec<ContextBlock>,
    pub unknowns: Vec<ContextBlock>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_observations: Vec<ContextBlock>,
}

impl PackSections {
    pub(crate) fn push(&mut self, block: ContextBlock) {
        match block.kind {
            PackBlockKind::Situation => self.situation.push(block),
            PackBlockKind::SelfContext => self.self_context.push(block),
            PackBlockKind::Participant => self.participants.push(block),
            PackBlockKind::SharedHistory => self.shared_history.push(block),
            PackBlockKind::Episode => self.episodes.push(block),
            PackBlockKind::Fact => self.facts.push(block),
            PackBlockKind::Relationship => self.relationships.push(block),
            PackBlockKind::Preference => self.preferences.push(block),
            PackBlockKind::Boundary => self.boundaries.push(block),
            PackBlockKind::Goal => self.goals.push(block),
            PackBlockKind::Decision => self.decisions.push(block),
            PackBlockKind::Timeline => self.timeline.push(block),
            PackBlockKind::Procedure => self.procedures.push(block),
            PackBlockKind::Constraint => self.constraints.push(block),
            PackBlockKind::OpenLoop => self.open_loops.push(block),
            PackBlockKind::Conflict => self.conflicts.push(block),
            PackBlockKind::Unknown => self.unknowns.push(block),
            PackBlockKind::RawObservation => self.raw_observations.push(block),
        }
    }

    /// Iterates blocks in canonical section order.
    pub fn iter(&self) -> impl Iterator<Item = &ContextBlock> {
        self.situation
            .iter()
            .chain(&self.self_context)
            .chain(&self.participants)
            .chain(&self.shared_history)
            .chain(&self.episodes)
            .chain(&self.facts)
            .chain(&self.relationships)
            .chain(&self.preferences)
            .chain(&self.boundaries)
            .chain(&self.goals)
            .chain(&self.decisions)
            .chain(&self.timeline)
            .chain(&self.procedures)
            .chain(&self.constraints)
            .chain(&self.open_loops)
            .chain(&self.conflicts)
            .chain(&self.unknowns)
            .chain(&self.raw_observations)
    }

    /// Number of complete, non-truncated blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether every canonical section is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn validate_layout(&self) -> Result<()> {
        for (kind, blocks) in [
            (PackBlockKind::Situation, self.situation.as_slice()),
            (PackBlockKind::SelfContext, self.self_context.as_slice()),
            (PackBlockKind::Participant, self.participants.as_slice()),
            (PackBlockKind::SharedHistory, self.shared_history.as_slice()),
            (PackBlockKind::Episode, self.episodes.as_slice()),
            (PackBlockKind::Fact, self.facts.as_slice()),
            (PackBlockKind::Relationship, self.relationships.as_slice()),
            (PackBlockKind::Preference, self.preferences.as_slice()),
            (PackBlockKind::Boundary, self.boundaries.as_slice()),
            (PackBlockKind::Goal, self.goals.as_slice()),
            (PackBlockKind::Decision, self.decisions.as_slice()),
            (PackBlockKind::Timeline, self.timeline.as_slice()),
            (PackBlockKind::Procedure, self.procedures.as_slice()),
            (PackBlockKind::Constraint, self.constraints.as_slice()),
            (PackBlockKind::OpenLoop, self.open_loops.as_slice()),
            (PackBlockKind::Conflict, self.conflicts.as_slice()),
            (PackBlockKind::Unknown, self.unknowns.as_slice()),
            (
                PackBlockKind::RawObservation,
                self.raw_observations.as_slice(),
            ),
        ] {
            if blocks.iter().any(|block| block.kind != kind) {
                return Err(ContextError::InvalidRequest(format!(
                    "canonical {kind:?} section contains a differently typed block"
                )));
            }
            if blocks.windows(2).any(|pair| pair[0].id >= pair[1].id) {
                return Err(ContextError::InvalidRequest(format!(
                    "canonical {kind:?} section is not strictly ID-sorted"
                )));
            }
        }
        Ok(())
    }
}

/// Scope and policy boundary fixed for one pack.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeManifest {
    pub workspace: String,
    pub subject: String,
    pub scopes: BTreeSet<String>,
    pub purpose: PackPurpose,
    pub temporal_view: TemporalConstraint,
    pub filter_digest: String,
}

/// Exact semantic graph identities represented by the selected blocks.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphManifest {
    pub memory_refs: BTreeSet<MemoryRef>,
    pub claim_ids: BTreeSet<ClaimId>,
    pub conflict_sets: BTreeSet<ConflictSetId>,
}

/// One selected block's reverse trace to source memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockProvenance {
    pub block_id: BlockId,
    pub memory_refs: Vec<MemoryRef>,
    pub evidence_handles: BTreeSet<EvidenceHandle>,
    pub source_classes: BTreeSet<SourceClass>,
}

/// Explainable provenance without duplicating source payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceManifest {
    pub compiler_version: String,
    pub policy_filter_digest: String,
    pub blocks: Vec<BlockProvenance>,
    pub evidence_sources: BTreeMap<EvidenceHandle, SourceHandle>,
}

/// Snapshot and projection watermarks used by every block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessManifest {
    pub snapshot: ProviderSnapshot,
    pub warnings: Vec<String>,
}

/// Why an otherwise authorized candidate did not enter the final pack.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    OutsideRequestedScope,
    FutureTransaction,
    EpistemicallyInactive,
    SecretRedacted,
    UnsupportedUnderEvidencePolicy,
    UnresolvedConflictWithoutManifest,
    Redundant,
    BlockBudget,
    TokenBudget,
    EvidenceBudget,
    HistoryBudget,
    ConflictBudget,
    SerializationBudget,
    SelectionEvaluationBudget,
    ContinuationBoundary,
}

/// Authorized-only omission trace. Unauthorized existence is never acknowledged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Omission {
    pub block_id: BlockId,
    pub reason: OmissionReason,
}

/// Rule-based sufficiency derived only from selected blocks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSufficiencyReport {
    pub sufficient: bool,
    pub covered_facets: BTreeSet<String>,
    pub missing_facets: BTreeSet<String>,
    pub unresolved_conflicts: BTreeSet<ConflictSetId>,
    pub blocking_unknowns: BTreeSet<BlockId>,
    pub unsupported_blocks: BTreeSet<BlockId>,
}

/// Exact deterministic budget consumption.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBudgetUsage {
    /// Legacy rendered text, or added actual provider input for continuous
    /// assemblies. Upper-bound encoders conservatively charge the whole input.
    pub rendered_tokens: u32,
    pub control_tokens: u32,
    pub data_tokens: u32,
    pub blocks: u32,
    pub evidence_blocks: u32,
    pub raw_evidence_tokens: u32,
    pub history_tokens: u32,
    pub conflict_tokens: u32,
    pub serialized_bytes: u32,
    pub selection_evaluations: u32,
}

/// Compiler pressure and deterministic selection trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilationReport {
    pub compiler_version: String,
    pub schema_version: String,
    pub model_profile: String,
    pub tokenizer: String,
    pub renderer: RendererKind,
    pub budget: ContextBudgets,
    pub usage: ContextBudgetUsage,
    pub soft_budget_exceeded: bool,
    pub selected_blocks: Vec<BlockId>,
    pub omissions: Vec<Omission>,
    pub sufficiency: PackSufficiencyReport,
}

/// Explicit empty result instead of fabricated default memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoMemoryResult {
    pub reason: NoMemoryReason,
    pub missing_facets: BTreeSet<String>,
}

/// Stable no-memory outcome reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoMemoryReason {
    NoAuthorizedCandidates,
    NoRelevantCandidates,
    BudgetCouldNotAdmitOptionalMemory,
}

/// Compilation status keeps uncertainty distinct from successful sufficiency.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackStatus {
    Sufficient,
    Partial,
    NoMemory,
}

/// Stable model-neutral ContextPack.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPack {
    pub schema_version: String,
    pub id: ContextPackId,
    pub status: PackStatus,
    pub snapshot: ProviderSnapshot,
    pub purpose: PackPurpose,
    pub scope_manifest: ScopeManifest,
    pub sections: PackSections,
    pub evidence: Vec<PackEvidence>,
    pub use_directives: Vec<UseDirective>,
    pub graph_manifest: GraphManifest,
    pub freshness: FreshnessManifest,
    pub provenance: ProvenanceManifest,
    pub continuation: Option<ContextContinuationToken>,
    pub compilation: CompilationReport,
    pub no_memory: Option<NoMemoryResult>,
}

impl ContextPack {
    /// Validates the final single-snapshot, evidence, conflict, and budget invariants.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTEXT_PACK_SCHEMA_VERSION {
            return Err(ContextError::InvalidRequest(
                "unsupported ContextPack schema version".to_owned(),
            ));
        }
        self.snapshot.validate().map_err(|error| {
            ContextError::InvalidRequest(format!("invalid pack snapshot: {error}"))
        })?;
        if self.snapshot != self.freshness.snapshot {
            return Err(ContextError::InvalidRequest(
                "freshness manifest belongs to another snapshot".to_owned(),
            ));
        }
        if self.scope_manifest.purpose != self.purpose {
            return Err(ContextError::InvalidRequest(
                "scope manifest purpose differs from pack purpose".to_owned(),
            ));
        }
        validate_non_blank(&self.scope_manifest.workspace, "scope manifest workspace")?;
        validate_non_blank(&self.scope_manifest.subject, "scope manifest subject")?;
        validate_non_blank(
            &self.scope_manifest.filter_digest,
            "scope manifest filter digest",
        )?;
        if self.scope_manifest.scopes.is_empty()
            || self
                .scope_manifest
                .scopes
                .iter()
                .any(|scope| scope.trim().is_empty())
        {
            return Err(ContextError::InvalidRequest(
                "scope manifest requires explicit non-blank scopes".to_owned(),
            ));
        }
        self.scope_manifest
            .temporal_view
            .validate()
            .map_err(|error| ContextError::InvalidRequest(error.to_string()))?;
        self.sections.validate_layout()?;
        if self.sections.self_context.len() > 1
            || (self.status != PackStatus::NoMemory && self.sections.situation.len() != 1)
        {
            return Err(ContextError::InvalidRequest(
                "non-empty ContextPack requires one situation and at most one self context"
                    .to_owned(),
            ));
        }
        if self
            .evidence
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || self
                .use_directives
                .windows(2)
                .any(|pair| pair[0].block_id >= pair[1].block_id)
            || self
                .provenance
                .blocks
                .windows(2)
                .any(|pair| pair[0].block_id >= pair[1].block_id)
            || self.compilation.omissions.windows(2).any(|pair| {
                (&pair[0].block_id, pair[0].reason) >= (&pair[1].block_id, pair[1].reason)
            })
        {
            return Err(ContextError::InvalidRequest(
                "canonical repeated records are not in strict deterministic order".to_owned(),
            ));
        }
        if self.compilation.compiler_version != CONTEXT_COMPILER_VERSION
            || self.compilation.schema_version != self.schema_version
        {
            return Err(ContextError::InvalidRequest(
                "compilation manifest version mismatch".to_owned(),
            ));
        }
        let mut block_ids = BTreeSet::new();
        let mut evidence_by_id = BTreeMap::new();
        for evidence in &self.evidence {
            evidence.validate()?;
            if evidence_by_id.insert(&evidence.id, evidence).is_some() {
                return Err(ContextError::InvalidRequest(format!(
                    "duplicate evidence {} in canonical pack",
                    evidence.id
                )));
            }
        }
        let evidence_ids: BTreeSet<_> = evidence_by_id.keys().copied().collect();
        let conflict_ids: BTreeSet<_> = self
            .sections
            .conflicts
            .iter()
            .filter_map(|block| block.conflict.as_ref().map(|value| value.set_id))
            .collect();
        for block in self.sections.iter() {
            block.validate()?;
            if !block_ids.insert(&block.id) {
                return Err(ContextError::InvalidRequest(format!(
                    "duplicate block {} in canonical pack",
                    block.id
                )));
            }
            if block.known_at_commit > self.snapshot.commit_seq {
                return Err(ContextError::InvalidRequest(format!(
                    "block {} is newer than the fixed snapshot",
                    block.id
                )));
            }
            if !block.scopes.is_subset(&self.scope_manifest.scopes) {
                return Err(ContextError::InvalidRequest(format!(
                    "block {} exceeds the pack scope manifest",
                    block.id
                )));
            }
            if !block
                .evidence_handles
                .iter()
                .all(|handle| evidence_ids.contains(handle))
                && matches!(block.support, SupportState::Supported)
            {
                return Err(ContextError::InvalidRequest(format!(
                    "block {} references missing evidence",
                    block.id
                )));
            }
            for handle in &block.evidence_handles {
                if block.kind == PackBlockKind::RawObservation
                    && evidence_by_id
                        .get(handle)
                        .is_none_or(|evidence| evidence.original_span.is_none())
                {
                    return Err(ContextError::InvalidRequest(
                        "raw observation evidence lacks original attribution".into(),
                    ));
                }
                if let Some(evidence) = evidence_by_id.get(handle)
                    && evidence.claim_ids.is_disjoint(&block.claim_ids)
                    && block.kind.is_factual()
                {
                    return Err(ContextError::InvalidRequest(format!(
                        "block {} cites evidence that supports none of its claims",
                        block.id
                    )));
                }
            }
            if let contextdb_core::ConflictState::InConflict { set_id } = block.epistemic.conflict
                && !conflict_ids.contains(&set_id)
            {
                return Err(ContextError::InvalidRequest(format!(
                    "block {} has no visible ConflictSet block",
                    block.id
                )));
            }
        }
        let expected_graph = GraphManifest {
            memory_refs: self
                .sections
                .iter()
                .flat_map(|block| block.memory_refs.iter().cloned())
                .collect(),
            claim_ids: self
                .sections
                .iter()
                .flat_map(|block| block.claim_ids.iter().copied())
                .collect(),
            conflict_sets: self
                .sections
                .conflicts
                .iter()
                .filter_map(|block| block.conflict.as_ref().map(|value| value.set_id))
                .collect(),
        };
        if self.graph_manifest != expected_graph {
            return Err(ContextError::InvalidRequest(
                "graph manifest differs from selected semantic identities".to_owned(),
            ));
        }
        let directive_ids: BTreeSet<_> = self
            .use_directives
            .iter()
            .map(|directive| &directive.block_id)
            .collect();
        if directive_ids.len() != self.use_directives.len() || directive_ids != block_ids {
            return Err(ContextError::InvalidRequest(
                "every block must have exactly one out-of-band use directive".to_owned(),
            ));
        }
        for directive in &self.use_directives {
            let block = self
                .sections
                .iter()
                .find(|block| block.id == directive.block_id)
                .ok_or_else(|| ContextError::InvalidRequest("orphan use directive".to_owned()))?;
            match (block.interpretation, directive.action) {
                (InterpretationRule::ConstraintData, UseAction::ConstraintOnly)
                | (InterpretationRule::StyleSignal, UseAction::StyleOnly) => {}
                (InterpretationRule::ConstraintData, _)
                | (_, UseAction::ConstraintOnly)
                | (InterpretationRule::StyleSignal, _)
                | (_, UseAction::StyleOnly) => {
                    return Err(ContextError::InvalidRequest(format!(
                        "use directive for {} conflicts with block interpretation",
                        directive.block_id
                    )));
                }
                (
                    InterpretationRule::FactualData
                    | InterpretationRule::HistoricalData
                    | InterpretationRule::HypothesisOnly
                    | InterpretationRule::UnknownMarker
                    | InterpretationRule::ConflictAlternatives,
                    UseAction::MentionNaturally | UseAction::UseSilently,
                ) => {}
            }
        }
        let provenance_ids: BTreeSet<_> = self
            .provenance
            .blocks
            .iter()
            .map(|entry| &entry.block_id)
            .collect();
        if provenance_ids.len() != self.provenance.blocks.len() || provenance_ids != block_ids {
            return Err(ContextError::InvalidRequest(
                "every block must have exactly one provenance manifest entry".to_owned(),
            ));
        }
        for entry in &self.provenance.blocks {
            let block = self
                .sections
                .iter()
                .find(|block| block.id == entry.block_id)
                .ok_or_else(|| {
                    ContextError::InvalidRequest("orphan provenance entry".to_owned())
                })?;
            if entry.memory_refs != block.memory_refs
                || entry.evidence_handles != block.evidence_handles
                || !entry.source_classes.contains(&block.source_class)
            {
                return Err(ContextError::InvalidRequest(format!(
                    "provenance for block {} does not reverse-trace its content",
                    block.id
                )));
            }
        }
        if self.provenance.evidence_sources.len() != self.evidence.len()
            || self.evidence.iter().any(|evidence| {
                self.provenance.evidence_sources.get(&evidence.id) != Some(&evidence.source)
            })
        {
            return Err(ContextError::InvalidRequest(
                "evidence source manifest is incomplete or inconsistent".to_owned(),
            ));
        }
        let selected_ids: BTreeSet<_> = self.compilation.selected_blocks.iter().collect();
        if selected_ids.len() != self.compilation.selected_blocks.len()
            || selected_ids != block_ids
            || self.compilation.selected_blocks
                != self
                    .sections
                    .iter()
                    .map(|block| block.id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(ContextError::InvalidRequest(
                "compilation selected-block manifest differs from canonical sections".to_owned(),
            ));
        }
        if self.compilation.usage.rendered_tokens > self.compilation.budget.hard_tokens
            || self.compilation.usage.blocks > self.compilation.budget.max_blocks
            || self.compilation.usage.evidence_blocks > self.compilation.budget.max_evidence_blocks
            || self.compilation.usage.raw_evidence_tokens
                > self.compilation.budget.max_raw_evidence_tokens
            || self.compilation.usage.history_tokens > self.compilation.budget.max_history_tokens
            || self.compilation.usage.conflict_tokens > self.compilation.budget.max_conflict_tokens
            || self.compilation.usage.serialized_bytes
                > self.compilation.budget.max_serialized_bytes
            || self.compilation.usage.selection_evaluations
                > self.compilation.budget.max_selection_evaluations
        {
            return Err(ContextError::BudgetExceeded(
                "final pack exceeds a declared hard budget".to_owned(),
            ));
        }
        if self.compilation.usage.blocks != u32::try_from(self.sections.len()).unwrap_or(u32::MAX)
            || self.compilation.usage.evidence_blocks
                != u32::try_from(self.evidence.len()).unwrap_or(u32::MAX)
            || self
                .compilation
                .usage
                .control_tokens
                .checked_add(self.compilation.usage.data_tokens)
                != Some(self.compilation.usage.rendered_tokens)
        {
            return Err(ContextError::InvalidRequest(
                "compilation budget counters disagree with canonical content".to_owned(),
            ));
        }
        if (self.status == PackStatus::NoMemory) != self.no_memory.is_some() {
            return Err(ContextError::InvalidRequest(
                "no-memory status and payload disagree".to_owned(),
            ));
        }
        if self.status == PackStatus::Sufficient && !self.compilation.sufficiency.sufficient {
            return Err(ContextError::InvalidRequest(
                "pack claims sufficiency while the rule-based report does not".to_owned(),
            ));
        }
        if let Some(no_memory) = &self.no_memory
            && no_memory.missing_facets != self.compilation.sufficiency.missing_facets
        {
            return Err(ContextError::InvalidRequest(
                "no-memory missing facets differ from the sufficiency report".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Complete compiler output including canonical bytes and separated rendering channels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledContext {
    pub pack: ContextPack,
    pub rendered: crate::RenderedContext,
    pub canonical_json: Vec<u8>,
    pub canonical_protobuf: Vec<u8>,
    pub canonical_digest: String,
}

pub(crate) fn validate_non_blank(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ContextError::InvalidRequest(format!(
            "{field} must not be blank"
        )));
    }
    Ok(())
}

pub(crate) fn purpose_key(value: &Purpose) -> String {
    contextdb_recall::purpose_key(value)
}
