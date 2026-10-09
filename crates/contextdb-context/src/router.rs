//! Versioned proposals over the existing compiler's authorized units. These
//! records are not grants or leases: execution always rebuilds the inventory and
//! validates the publication owner's read set before returning an assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use contextdb_core::{ContentDigest, ContextPackId, EpistemicState, OriginalSourceSpan};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::assembly::{charge, serialization};
use crate::{
    AssemblyBinding, BlockId, CompiledAssembly, CompressionLevel, ContextBudgetUsage, ContextError,
    ContextScorer, EvidenceHandle, InstructionCapability, InterpretationRule,
    OutgoingAssemblyManifest, PackBlockKind, RequestCountKind, Result, ScoringUnit,
};

mod strict;
mod validation;
pub(crate) use validation::normalize_spans;

pub const REQUEST_FORMAT: &str = "contextdb.router_request.v1";
pub const PLAN_FORMAT: &str = "contextdb.router_plan.v1";
pub const MANIFEST_FORMAT: &str = "contextdb.router_manifest.v1";
pub const FEATURE_SCHEMA: &str = "contextdb.routing_features.r0.v1";
pub const DESCRIPTOR_SCHEMA: &str = "contextdb.routing_descriptor.v1";
pub const MAX_UNITS: usize = 512;
pub const MAX_SCORES: usize = 4096;
pub const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;

/// The complete owner, layout, reader, scorer and bounded-inventory commitment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterBinding {
    pub owner: AssemblyBinding,
    pub compile_request: ContentDigest,
    pub control: ContentDigest,
    pub working: ContentDigest,
    pub hot: ContentDigest,
    pub current: ContentDigest,
    pub base_layout: ContentDigest,
    pub reader_profile: ContentDigest,
    pub tokenizer: String,
    pub encoder: String,
    pub scorer: String,
    pub scorer_revision: String,
    pub feature_schema: String,
    pub descriptor_schema: String,
    pub budgets: ContentDigest,
    pub candidates: ContentDigest,
    pub mandatory: ContentDigest,
    pub max_evaluations: u32,
    pub max_record_bytes: u32,
    pub max_scorer_work: u64,
    pub max_scorer_micros: u64,
    pub max_prepare_micros: u64,
    pub shared_work_at_entry: u64,
    pub shared_bytes_at_entry: u64,
    /// This feature-only profile has no cross-encoder text pairs.
    pub max_text_rerank_pairs: u32,
}

/// Compact authorized features. Unknown quantities remain absent; utility and
/// epistemic confidence are different fields. R0 has no embedding or calibration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingDescriptor {
    pub schema: String,
    pub prior_utility_micros: u64,
    pub confidence_micros: u32,
    pub block_tokens: u32,
    pub evidence_tokens: u32,
    pub embedding_reference: Option<ContentDigest>,
    pub embedding_revision: Option<String>,
    pub uncertainty: Option<f64>,
    /// Provider-specific discovery statistics are unavailable at this compiler
    /// boundary; they are not inferred from a candidate's combined R0 prior.
    pub retrieval_score: Option<u64>,
    pub index_complete: Option<bool>,
    pub missing_features: Vec<String>,
}

/// One sufficient, owner-verified support bundle and its existing representation.
/// Material is committed by digest; original bytes remain in the provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportAlternative {
    pub index: u32,
    pub level: CompressionLevel,
    pub representation_digest: ContentDigest,
    pub material_digest: ContentDigest,
    pub evidence_handles: Vec<EvidenceHandle>,
    pub originals: Vec<OriginalSourceSpan>,
    pub hard_closure: Vec<BlockId>,
    pub omitted_facets: Vec<String>,
}

/// Existing block identity and semantics, after policy-first preparation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUnit {
    pub id: BlockId,
    pub kind: PackBlockKind,
    #[serde(deserialize_with = "strict::core_value")]
    pub epistemic: EpistemicState,
    pub interpretation: InterpretationRule,
    pub render_role: RouterRenderRole,
    pub instruction_capability: InstructionCapability,
    pub scopes: Vec<String>,
    pub facets: Vec<String>,
    #[serde(deserialize_with = "strict::core_value")]
    pub memory_refs: Vec<contextdb_core::MemoryRef>,
    pub claim_ids: Vec<contextdb_core::ClaimId>,
    pub perspective: Option<contextdb_core::Perspective>,
    pub valid_time: Option<contextdb_core::TimeRange>,
    pub known_at_commit: u64,
    pub source_class: crate::SourceClass,
    #[serde(deserialize_with = "strict::core_value")]
    pub support: crate::SupportState,
    #[serde(deserialize_with = "strict::core_value")]
    pub conflict: Option<crate::ConflictDescriptor>,
    pub unknown: Option<crate::UnknownDescriptor>,
    pub candidate_digest: ContentDigest,
    pub hard_dependencies: Vec<BlockId>,
    pub complements: Vec<BlockId>,
    pub support_alternatives: Vec<SupportAlternative>,
    pub descriptor: RoutingDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterRenderRole {
    CurrentState,
    Historical,
    Proposal,
    Evidence,
    Unknown,
    Conflict,
}

/// A serializable observation of authorization, never an authorization token.
/// Only the compiler constructs it from freshly verified provider material.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedRouterRequest {
    pub format: String,
    pub pack_id: ContextPackId,
    pub binding: RouterBinding,
    #[serde(deserialize_with = "strict::core_value")]
    pub context: crate::CompileRequest,
    pub outgoing_budget: crate::OutgoingBudget,
    pub working_state: Vec<crate::OutgoingOccurrence>,
    pub hot_window: Vec<crate::OutgoingOccurrence>,
    pub current_turn: Vec<crate::OutgoingOccurrence>,
    pub units: Vec<MemoryUnit>,
    pub mandatory_ids: Vec<BlockId>,
    pub visible_originals: Vec<OriginalSourceSpan>,
    pub digest: ContentDigest,
    /// This compiler frontier is authorized, but is not an exhaustive-history
    /// or native capture/index completion report.
    pub discovery_complete: Option<bool>,
    pub capture_complete: Option<bool>,
}

/// One actual scorer evaluation. Exact integer utility preserves R0 tie breaks;
/// a STOP score is None. The selected base includes its actual ordered wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterScore {
    pub evaluation: u32,
    pub request_digest: ContentDigest,
    pub selected_base_digest: ContentDigest,
    pub seed_ids: Vec<BlockId>,
    pub closure_ids: Vec<BlockId>,
    pub utility_micros: Option<u64>,
    pub marginal_tokens: u32,
    pub prior_utility_micros: u64,
    pub new_facets: Vec<String>,
    pub adds_original_bytes: bool,
    pub raw_only: bool,
    pub trial_input_tokens: u32,
    pub trial_wire_digest: ContentDigest,
    pub outgoing_fits: bool,
    pub uncertainty: Option<f64>,
    pub calibration: Option<String>,
    pub behavior_propensity: Option<f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterDecision {
    Select,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterStopReason {
    NoPositiveMarginalGain,
    BudgetReached,
    Sufficient,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterChoice {
    pub id: BlockId,
    pub alternative_index: u32,
    pub representation_digest: ContentDigest,
    pub material_digest: ContentDigest,
}

/// An untrusted selection proposal. Reported costs never replace actual encoding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterSelectionPlan {
    pub format: String,
    pub request_digest: ContentDigest,
    pub binding: RouterBinding,
    pub decision: RouterDecision,
    pub seed_ids: Vec<BlockId>,
    pub selected_ids: Vec<BlockId>,
    pub choices: Vec<RouterChoice>,
    pub scores: Vec<RouterScore>,
    pub behavior_propensity: Option<f64>,
    pub usage: ContextBudgetUsage,
    pub input_tokens: u32,
    pub count_kind: RequestCountKind,
    pub wire_digest: ContentDigest,
    pub covered_facets: Vec<String>,
    pub visible_originals: Vec<OriginalSourceSpan>,
    pub evidence_handles: Vec<EvidenceHandle>,
    pub status: crate::PackStatus,
    #[serde(deserialize_with = "strict::core_value")]
    pub sufficiency: crate::PackSufficiencyReport,
    pub stop_reason: RouterStopReason,
}

/// Query-time lineage over the accepted compiler result. No persistence, training
/// grant or historical owner fence is implied by these hashes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterManifest {
    pub format: String,
    pub request_digest: ContentDigest,
    pub candidate_digest: ContentDigest,
    pub plan_digest: ContentDigest,
    #[serde(deserialize_with = "strict::core_value")]
    pub assembly: OutgoingAssemblyManifest,
    pub selection_evaluations: u32,
    pub scorer_micros: u64,
    pub trained_weights: Option<ContentDigest>,
    pub training_dataset: Option<ContentDigest>,
    pub fallback_from: Option<String>,
    pub fallback_revision: Option<String>,
    pub score_provenance: ScoreProvenance,
    /// Compiler stage only, before the final bounded trace envelope check. The
    /// envelope uses the same allowance but is not model/scorer/packing work.
    pub compilation_work_units: u64,
    pub compilation_bytes_processed: u64,
    pub compilation_micros: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreProvenance {
    ObservedScorer,
    UntrustedProposal,
    ObservedR0Fallback,
}

/// Exact prepared compiler material, including generated mandatory markers and
/// every authorized support alternative. These values are not custody grants.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterPreparedMaterial {
    pub candidates: Vec<crate::PackCandidate>,
    pub evidence: Vec<crate::PackEvidence>,
}

/// Independent integrity results over retained prepared material. This is not
/// source acceptance, current authorization or a successful historical replay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterMaterialVerification {
    pub support_material: RouterMaterialStatus,
    pub unit_semantics: RouterMaterialStatus,
    pub candidate_commitment: RouterMaterialStatus,
    pub historical_selection: RouterMaterialStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum RouterMaterialStatus {
    Verified,
    Unavailable(RouterMaterialUnavailableReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterMaterialUnavailableReason {
    /// V1 omits the compiler's prepared use action and directive reason, which
    /// participate in the complete candidate commitment and selection replay.
    MissingPreparedPolicy,
}

/// Check retained support material with the authoritative compiler's block
/// construction. Hash consistency grants no access and does not run a scorer.
pub fn validate_router_material(
    request: &AuthorizedRouterRequest,
    material: &RouterPreparedMaterial,
    budget: &mut QueryBudget,
) -> Result<RouterMaterialVerification> {
    crate::ContextCompiler::validate_router_material(request, material, budget)
}

impl std::fmt::Debug for RouterPreparedMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterPreparedMaterial")
            .field("candidate_count", &self.candidates.len())
            .field("evidence_count", &self.evidence.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct RoutedAssembly {
    pub assembly: CompiledAssembly,
    pub request: AuthorizedRouterRequest,
    pub plan: RouterSelectionPlan,
    pub manifest: RouterManifest,
    pub prepared_material: RouterPreparedMaterial,
}

/// A bounded floating-point scorer port; it receives the same authorized closure
/// as R0. Fixed micros quantization is explicit and never used to record R0 scores.
pub trait FiniteContextScorer: std::fmt::Debug + Send + Sync {
    fn id(&self) -> &str;
    fn revision(&self) -> &str {
        self.id()
    }
    fn latency_limit_micros(&self) -> u64 {
        1_000_000
    }
    fn score(&self, unit: &ScoringUnit, budget: &mut QueryBudget) -> Result<Option<f64>>;
}

#[derive(Debug)]
pub struct FiniteScoreAdapter<T>(pub T);

impl<T: FiniteContextScorer> ContextScorer for FiniteScoreAdapter<T> {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn revision(&self) -> &str {
        self.0.revision()
    }
    fn latency_limit_micros(&self) -> u64 {
        self.0.latency_limit_micros()
    }
    fn score(&self, unit: &ScoringUnit, budget: &mut QueryBudget) -> Result<Option<u64>> {
        Ok(self
            .0
            .score(unit, budget)?
            .map(finite_micros)
            .transpose()?
            .filter(|value| *value > 0))
    }
}

pub fn finite_micros(value: f64) -> Result<u64> {
    if !value.is_finite() || value.abs() > 1_000_000_000_000.0 {
        return Err(ContextError::RouterScore(
            "nonfinite or excessive utility".into(),
        ));
    }
    // Negative/zero marginal utility is STOP, not a negative truth probability.
    Ok(if value > 0.0 {
        (value * 1_000_000.0).round() as u64
    } else {
        0
    })
}

pub(crate) fn invalid(message: &str) -> ContextError {
    ContextError::InvalidRequest(format!("router contract: {message}"))
}

/// Streaming serialization rejects oversized records without building an
/// unbounded temporary allocation. Every byte uses the shared prepare allowance.
pub fn canonical_bytes<T: Serialize>(value: &T, budget: &mut QueryBudget) -> Result<Vec<u8>> {
    struct Bounded<'a> {
        bytes: Vec<u8>,
        budget: &'a mut QueryBudget,
    }
    impl Write for Bounded<'_> {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len().saturating_add(input.len()) > MAX_RECORD_BYTES {
                return Err(std::io::Error::other("router record exceeds byte ceiling"));
            }
            self.budget
                .charge(0, input.len() as u64)
                .map_err(|_| std::io::Error::other("shared router allowance exhausted"))?;
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    charge(budget, 1, 0)?;
    let mut writer = Bounded {
        bytes: Vec::new(),
        budget,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        if error.is_io() {
            ContextError::BudgetExceeded("bounded router serialization failed".into())
        } else {
            serialization(error)
        }
    })?;
    Ok(writer.bytes)
}

pub fn canonical_digest<T: Serialize>(
    value: &T,
    budget: &mut QueryBudget,
) -> Result<ContentDigest> {
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&canonical_bytes(value, budget)?).as_bytes(),
    ))
}

impl AuthorizedRouterRequest {
    pub fn from_json(bytes: &[u8], budget: &mut QueryBudget) -> Result<Self> {
        let result: Self = strict::decode(bytes, budget)?;
        result.validate(budget)?;
        Ok(result)
    }
    pub(crate) fn seal(mut self, budget: &mut QueryBudget) -> Result<Self> {
        self.digest = self.content_digest(budget)?;
        self.validate(budget)?;
        Ok(self)
    }
    /// Canonical integrity commitment; computing it does not authorize a record.
    pub fn content_digest(&self, budget: &mut QueryBudget) -> Result<ContentDigest> {
        canonical_digest(
            &(
                &self.format,
                self.pack_id,
                &self.binding,
                &self.context,
                self.outgoing_budget,
                &self.working_state,
                &self.hot_window,
                &self.current_turn,
                &self.units,
                &self.mandatory_ids,
                &self.visible_originals,
                self.discovery_complete,
                self.capture_complete,
            ),
            budget,
        )
    }
}

impl RouterManifest {
    pub fn from_json(
        bytes: &[u8],
        request: &AuthorizedRouterRequest,
        plan: &RouterSelectionPlan,
        assembly: &CompiledAssembly,
        budget: &mut QueryBudget,
    ) -> Result<Self> {
        let result: Self = strict::decode(bytes, budget)?;
        result.validate(request, plan, assembly, budget)?;
        Ok(result)
    }
    /// Integrity against a compiler result, not a grant or a claim that a caller's
    /// replayed score values were independently observed from a backend.
    pub fn validate(
        &self,
        request: &AuthorizedRouterRequest,
        plan: &RouterSelectionPlan,
        assembly: &CompiledAssembly,
        budget: &mut QueryBudget,
    ) -> Result<()> {
        self.validate_observation(request, plan, budget)?;
        crate::ContextCompiler::validate_router_plan_result(request, plan, assembly, budget)?;
        if self.assembly != assembly.manifest
            || self.selection_evaluations != assembly.selection_evaluations
            || self.scorer_micros != assembly.scorer_micros
        {
            return Err(invalid(
                "manifest does not describe the accepted compiler result",
            ));
        }
        Ok(())
    }

    /// Structural agreement of retained observation metadata. This cannot verify
    /// historical selection, actual wire bytes or current source authority; use
    /// `validate` when the complete compiler result is available.
    pub fn validate_observation(
        &self,
        request: &AuthorizedRouterRequest,
        plan: &RouterSelectionPlan,
        budget: &mut QueryBudget,
    ) -> Result<()> {
        charge(budget, 1, 0)?;
        canonical_bytes(&(request, plan, self), budget)?;
        plan.validate(request, budget)?;
        let assembly = &self.assembly;
        if self.format != MANIFEST_FORMAT
            || self.request_digest != request.digest
            || self.candidate_digest != request.binding.candidates
            || self.plan_digest != canonical_digest(plan, budget)?
            || assembly.layout != crate::OUTGOING_LAYOUT
            || assembly.encoder != request.binding.encoder
            || assembly.model_profile_digest != request.binding.reader_profile
            || assembly.scorer != request.binding.scorer
            || assembly.read_set.binding != request.binding.owner
            || assembly.read_set.scopes != request.context.scopes
            || assembly
                .read_set
                .selected_blocks
                .iter()
                .ne(plan.selected_ids.iter())
            || assembly.wire_digest != plan.wire_digest
            || assembly.input_tokens != plan.input_tokens
            || assembly.count_kind != plan.count_kind
            || assembly.reserved_output_tokens
                != request.context.model_profile.reserved_output_tokens
            || assembly.safety_tokens != request.outgoing_budget.safety_tokens
            || self.selection_evaluations != plan.usage.selection_evaluations
            || self.selection_evaluations > request.binding.max_evaluations
            || plan
                .scores
                .last()
                .is_some_and(|score| score.evaluation > self.selection_evaluations)
            || self.trained_weights.is_some()
            || self.training_dataset.is_some()
            || self.fallback_from.is_some() != self.fallback_revision.is_some()
            || self.fallback_from.is_some()
                != (self.score_provenance == ScoreProvenance::ObservedR0Fallback)
            || (self.score_provenance == ScoreProvenance::UntrustedProposal
                && self.scorer_micros != 0)
            || (self.score_provenance == ScoreProvenance::ObservedR0Fallback
                && assembly.scorer != crate::R0Scorer.id())
            || self
                .fallback_from
                .iter()
                .chain(&self.fallback_revision)
                .any(|value| {
                    value.trim().is_empty()
                        || value.len() > 16384
                        || value.chars().any(char::is_control)
                })
        {
            return Err(invalid("manifest observation commitments disagree"));
        }
        let mut identities = BTreeSet::new();
        let mut visible = Vec::new();
        for occurrence in &assembly.occurrences {
            charge(budget, occurrence.originals.len() as u64 + 1, 0)?;
            if !identities.insert(&occurrence.id) {
                return Err(invalid("manifest observation has duplicate occurrences"));
            }
            visible.extend(
                occurrence
                    .originals
                    .iter()
                    .map(|original| original.span.clone()),
            );
        }
        normalize_spans(&mut visible);
        if visible != plan.visible_originals {
            return Err(invalid("manifest observation visible originals disagree"));
        }
        for expected in [
            &request.working_state,
            &request.hot_window,
            &request.current_turn,
        ] {
            charge(
                budget,
                (expected.len() + assembly.occurrences.len()) as u64,
                0,
            )?;
            let ids: BTreeSet<_> = expected.iter().map(|occurrence| &occurrence.id).collect();
            let observed = assembly
                .occurrences
                .iter()
                .filter(|occurrence| ids.contains(&occurrence.id));
            if observed.ne(expected.iter()) {
                return Err(invalid("manifest observation base occurrences disagree"));
            }
        }
        let mut originals = visible;
        charge(budget, request.units.len() as u64, 0)?;
        let units: BTreeMap<_, _> = request.units.iter().map(|unit| (&unit.id, unit)).collect();
        for choice in &plan.choices {
            charge(budget, 1, 0)?;
            let unit = units
                .get(&choice.id)
                .ok_or_else(|| invalid("unknown observation choice"))?;
            let support = &unit.support_alternatives[choice.alternative_index as usize];
            charge(budget, support.originals.len() as u64, 0)?;
            originals.extend(support.originals.iter().cloned());
        }
        normalize_spans(&mut originals);
        if originals != assembly.read_set.originals {
            return Err(invalid("manifest observation read-set originals disagree"));
        }
        Ok(())
    }
}

impl RouterSelectionPlan {
    pub fn from_json(
        bytes: &[u8],
        request: &AuthorizedRouterRequest,
        budget: &mut QueryBudget,
    ) -> Result<Self> {
        let result: Self = strict::decode(bytes, budget)?;
        result.validate(request, budget)?;
        Ok(result)
    }
}
