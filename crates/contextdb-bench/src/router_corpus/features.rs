use super::*;
use crate::Result;
use contextdb_context::router::{
    RouterMaterialStatus, RouterMaterialVerification, RouterRenderRole, SupportAlternative,
    canonical_digest,
};
use contextdb_context::*;
use contextdb_core::*;
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A whitelist over verified query-time bytes. R0 utility fields are absent.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterCandidateFeatures {
    pub id: BlockId,
    pub kind: PackBlockKind,
    pub representations: Vec<BlockRepresentation>,
    pub exact_fragments: Vec<ExactFragment>,
    pub memory_refs: Vec<MemoryRef>,
    pub claim_ids: BTreeSet<ClaimId>,
    pub facets: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub valid_time: Option<TimeRange>,
    pub known_at_commit: u64,
    pub perspective: Option<Perspective>,
    pub epistemic: EpistemicState,
    pub confidence_micros: u32,
    pub trust: ContentTrust,
    pub source_class: SourceClass,
    pub taints: BTreeSet<ContentTaint>,
    pub interpretation: InterpretationRule,
    pub support: SupportState,
    pub conflict: Option<ConflictDescriptor>,
    pub unknown: Option<UnknownDescriptor>,
    pub mandatory: bool,
    pub render_role: RouterRenderRole,
    pub hard_dependencies: Vec<BlockId>,
    pub complements: Vec<BlockId>,
    pub support_alternatives: Vec<SupportAlternative>,
}
impl std::fmt::Debug for RouterCandidateFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterCandidateFeatures")
            .field("representations", &self.representations.len())
            .field("supports", &self.support_alternatives.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterFeatureMissing {
    SelectedBaseSemanticView,
    IntermediateTrialMaterial,
    PreparedPolicyCommitment,
    HistoricalSelectionReplay,
    HistoryCompleteness,
    SemanticEmbedding,
    MarginalUtilityCalibration,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterSemanticFeatures {
    pub schema: String,
    pub query: RouterQuerySpec,
    pub base: OutgoingBase,
    pub candidates: Vec<RouterCandidateFeatures>,
    pub evidence: Vec<PackEvidence>,
    pub model_profile: ModelProfile,
    pub memory_budget: ContextBudgets,
    pub outgoing_budget: OutgoingBudget,
    pub tokenizer: String,
    pub encoder: String,
    pub layout: String,
    pub missing: Vec<RouterFeatureMissing>,
}
impl std::fmt::Debug for RouterSemanticFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterSemanticFeatures")
            .field("candidates", &self.candidates.len())
            .field("evidence", &self.evidence.len())
            .field("missing", &self.missing)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterFeatureRecord {
    pub features: RouterSemanticFeatures,
    /// Commitment over the whitelist only, independent of behavior and targets.
    pub feature_digest: ContentDigest,
    /// Protected association metadata, not a numeric model feature or a grant.
    pub request_digest: ContentDigest,
    pub material_verification: RouterMaterialVerification,
}
impl std::fmt::Debug for RouterFeatureRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterFeatureRecord")
            .field("feature_digest", &self.feature_digest)
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

/// No behavior, label, evaluator reader, cache or native mutation enters this API.
pub fn build_router_features(
    input: &RouterQueryTimeRecord,
    budget: &mut QueryBudget,
) -> Result<RouterFeatureRecord> {
    let material_verification = validate_router_query_time(input, budget)?;
    let units: BTreeMap<_, _> = input
        .request
        .units
        .iter()
        .map(|unit| (&unit.id, unit))
        .collect();
    let mut candidates = Vec::new();
    // The whole input was bounded before these copies. Copy only representations
    // whose material was verified for a declared support alternative.
    for candidate in &input.material.candidates {
        charge(budget, 1, 0)?;
        let unit = units.get(&candidate.id).ok_or_else(invalid)?;
        let mut representations = Vec::new();
        for representation in &candidate.representations {
            let commitment = canonical_digest(representation, budget).map_err(|_| invalid())?;
            if unit
                .support_alternatives
                .iter()
                .any(|alternative| alternative.representation_digest == commitment)
            {
                representations.push(representation.clone());
            }
        }
        candidates.push(RouterCandidateFeatures {
            id: candidate.id.clone(),
            kind: candidate.kind,
            representations,
            exact_fragments: candidate.exact_fragments.clone(),
            memory_refs: candidate.memory_refs.clone(),
            claim_ids: candidate.claim_ids.clone(),
            facets: candidate.facets.clone(),
            scopes: candidate.scopes.clone(),
            valid_time: candidate.valid_time,
            known_at_commit: candidate.known_at_commit,
            perspective: candidate.perspective.clone(),
            epistemic: candidate.epistemic,
            confidence_micros: candidate.confidence_micros,
            trust: candidate.trust,
            source_class: candidate.source_class.clone(),
            taints: candidate.taints.clone(),
            interpretation: candidate.interpretation,
            support: candidate.support.clone(),
            conflict: candidate.conflict.clone(),
            unknown: candidate.unknown.clone(),
            mandatory: input
                .request
                .mandatory_ids
                .binary_search(&candidate.id)
                .is_ok(),
            render_role: unit.render_role,
            hard_dependencies: unit.hard_dependencies.clone(),
            complements: unit.complements.clone(),
            support_alternatives: unit.support_alternatives.clone(),
        });
    }
    let mut missing = vec![
        RouterFeatureMissing::SelectedBaseSemanticView,
        RouterFeatureMissing::IntermediateTrialMaterial,
        RouterFeatureMissing::HistoricalSelectionReplay,
        RouterFeatureMissing::HistoryCompleteness,
        RouterFeatureMissing::SemanticEmbedding,
        RouterFeatureMissing::MarginalUtilityCalibration,
    ];
    if material_verification.candidate_commitment != RouterMaterialStatus::Verified {
        missing.insert(2, RouterFeatureMissing::PreparedPolicyCommitment);
    }
    let features = RouterSemanticFeatures {
        schema: ROUTER_FEATURE_VERSION.into(),
        query: input.query.clone(),
        base: input.base.clone(),
        candidates,
        evidence: input.material.evidence.clone(),
        model_profile: input.request.context.model_profile.clone(),
        memory_budget: input.request.context.budgets,
        outgoing_budget: input.request.outgoing_budget,
        tokenizer: input.request.binding.tokenizer.clone(),
        encoder: input.request.binding.encoder.clone(),
        layout: OUTGOING_LAYOUT.into(),
        missing,
    };
    let feature_digest = digest(&features, budget)?;
    Ok(RouterFeatureRecord {
        features,
        feature_digest,
        request_digest: input.request.digest,
        material_verification,
    })
}

pub fn validate_router_query_time(
    input: &RouterQueryTimeRecord,
    budget: &mut QueryBudget,
) -> Result<RouterMaterialVerification> {
    bounded_size(input, MAX_ROUTER_EXAMPLE_BYTES, budget)?;
    input.query.validate()?;
    let observation = &input.observation;
    for value in [
        &observation.generator,
        &observation.fixture_id,
        &observation.source_domain,
        &observation.compiler_domain,
    ] {
        identity(value)?;
    }
    if input.format != ROUTER_QUERY_VERSION
        || observation.source_domain != input.query.logical_domain
        || observation.source_cutoff != input.query.known_at
        || observation.compiler_domain != input.request.context.snapshot.database_id
        || observation.compiler_cutoff != input.request.context.snapshot.commit_seq
        || observation.source_nodes.len() > MAX_ROUTER_LINEAGE_NODES
        || observation
            .source_nodes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !input.request.context.scopes.contains(&input.query.scope)
    {
        return Err(invalid());
    }
    for source in &observation.source_nodes {
        source.validate()?;
        if source.domain != observation.source_domain
            || source.kind == RouterLineageKind::Evaluation
        {
            return Err(invalid());
        }
    }
    let roots: BTreeSet<_> = observation
        .source_nodes
        .iter()
        .filter(|source| source.kind == RouterLineageKind::SourceVersion)
        .map(|source| (&source.id, source.version.as_ref()))
        .collect();
    for span in input
        .material
        .evidence
        .iter()
        .filter_map(|item| item.original_span.as_ref())
        .chain(
            input
                .base
                .control
                .iter()
                .chain(&input.base.working)
                .chain(&input.base.hot)
                .chain(&input.base.current)
                .flat_map(|message| message.originals.iter().map(|original| &original.span)),
        )
    {
        charge(budget, 1, 0)?;
        if !roots.contains(&(
            &span.event_id.to_string(),
            Some(&span.payload_digest.to_string()),
        )) {
            return Err(invalid());
        }
    }
    input.request.validate(budget).map_err(|_| invalid())?;
    validate_base(input, budget)?;
    ContextCompiler::validate_router_material(&input.request, &input.material, budget)
        .map_err(|_| invalid())
}

fn validate_base(input: &RouterQueryTimeRecord, budget: &mut QueryBudget) -> Result<()> {
    let base = &input.base;
    let binding = &input.request.binding;
    let encoder = ReferenceOutgoingEncoder(&ReferenceTokenizer);
    if binding.encoder != encoder.id()
        || binding.tokenizer != encoder.tokenizer_id()
        || canonical_digest(&base.control, budget).map_err(|_| invalid())? != binding.control
        || canonical_digest(&base.working, budget).map_err(|_| invalid())? != binding.working
        || canonical_digest(&base.hot, budget).map_err(|_| invalid())? != binding.hot
        || canonical_digest(&base.current, budget).map_err(|_| invalid())? != binding.current
        || base.control.len() + base.working.len() + base.hot.len() + base.current.len() > 256
    {
        return Err(invalid());
    }
    let mut identities = BTreeSet::new();
    let mut visible = Vec::new();
    for message in base
        .control
        .iter()
        .chain(&base.working)
        .chain(&base.hot)
        .chain(&base.current)
    {
        charge(budget, message.originals.len() as u64 + 1, 0)?;
        let control = matches!(
            message.zone,
            OutgoingZone::Control | OutgoingZone::ToolDefinitions
        );
        if !identities.insert(&message.id)
            || message.text.len() > 1024 * 1024
            || message.originals.len() > 128
            || (matches!(message.role, OutgoingRole::System | OutgoingRole::Developer) && !control)
            || (control && !message.originals.is_empty())
            || (message.role == OutgoingRole::Tool) != message.tool_result.is_some()
            || (!message.tool_calls.is_empty() && message.role != OutgoingRole::Assistant)
        {
            return Err(invalid());
        }
        let mut end = 0;
        for original in &message.originals {
            let start = usize::try_from(original.text_start).map_err(|_| invalid())?;
            let stop = usize::try_from(original.text_end).map_err(|_| invalid())?;
            let text = message.text.get(start..stop).ok_or_else(invalid)?;
            if original.text_start < end
                || original.span.end <= original.span.start
                || original.span.end - original.span.start != text.len() as u64
                || blake3::hash(text.as_bytes()).as_bytes() != original.span.span_digest.as_bytes()
            {
                return Err(invalid());
            }
            end = original.text_end;
            visible.push(original.span.clone());
        }
    }
    if base.control.iter().any(|message| {
        !matches!(
            message.zone,
            OutgoingZone::Control | OutgoingZone::ToolDefinitions
        )
    }) || base.working.iter().any(|message| {
        message.zone != OutgoingZone::WorkingState
            || message.role != OutgoingRole::User
            || !message.tool_calls.is_empty()
            || message.tool_result.is_some()
    }) || base.hot.iter().any(|message| {
        !matches!(
            message.zone,
            OutgoingZone::HotHistory | OutgoingZone::ProviderContinuation
        )
    }) || base
        .current
        .iter()
        .any(|message| message.zone != OutgoingZone::CurrentTurn)
        || !base
            .current
            .iter()
            .any(|message| message.text == input.query.query)
    {
        return Err(invalid());
    }
    for (messages, retained) in [
        (&base.working, &input.request.working_state),
        (&base.hot, &input.request.hot_window),
        (&base.current, &input.request.current_turn),
    ] {
        if messages.len() != retained.len() {
            return Err(invalid());
        }
        for (message, occurrence) in messages.iter().zip(retained) {
            if message.id != occurrence.id
                || message.zone != occurrence.zone
                || message.role != occurrence.role
                || message.originals != occurrence.originals
                || canonical_digest(message, budget).map_err(|_| invalid())? != occurrence.digest
            {
                return Err(invalid());
            }
        }
    }
    visible.sort_by_key(|span| (span.event_id, span.payload_digest, span.start, span.end));
    visible.dedup();
    if visible != input.request.visible_originals {
        return Err(invalid());
    }
    let messages: Vec<_> = base
        .control
        .iter()
        .chain(&base.working)
        .chain(&base.hot)
        .chain(&base.current)
        .cloned()
        .collect();
    let outgoing = encoder.encode(&messages, budget).map_err(|_| invalid())?;
    if canonical_digest(&(OUTGOING_LAYOUT, base, outgoing), budget).map_err(|_| invalid())?
        != binding.base_layout
    {
        return Err(invalid());
    }
    Ok(())
}
