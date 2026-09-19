//! Deterministic policy-first ContextPack compiler.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AcceptanceState, ConflictState, EpistemicBasis, EpistemicState, LifecycleState,
};

use crate::continuation::{self, ContinuationState};
use crate::{
    BlockId, BlockProvenance, BlockRepresentation, CONTEXT_COMPILER_VERSION,
    CONTEXT_PACK_SCHEMA_VERSION, CanonicalSerializer, CompilationReport, CompileRequest,
    CompiledContext, CompressionLevel, ContextBlock, ContextBudgetUsage, ContextError, ContextPack,
    ContextProvider, ContextRenderer, DirectiveReason, EvidenceHandle, FreshnessManifest,
    GraphManifest, InMemoryContextProvider, InstructionCapability, InterpretationRule,
    NoMemoryReason, NoMemoryResult, Omission, OmissionReason, PackBlockKind, PackCandidate,
    PackEvidence, PackSections, PackStatus, PackSufficiencyReport, ProvenanceManifest, Result,
    ScopeManifest, SourceClass, SupportState, TokenCounter, UseAction, UseDirective,
};

const MIN_MARGINAL_DENSITY_MICROS_PER_TOKEN: u128 = 100;

mod continuous;

#[derive(Clone, Debug)]
struct PreparedCandidate {
    candidate: PackCandidate,
    block: ContextBlock,
    evidence: Vec<PackEvidence>,
    use_action: UseAction,
    directive_reason: DirectiveReason,
    block_tokens: u32,
    evidence_tokens: u32,
    generated: bool,
}

impl PreparedCandidate {
    fn effective_facets(&self) -> BTreeSet<String> {
        self.block
            .facets
            .difference(&self.block.representation.omitted_facets)
            .cloned()
            .collect()
    }

    fn cost_tokens(&self) -> u32 {
        self.block_tokens.saturating_add(self.evidence_tokens)
    }
}

#[derive(Clone, Debug)]
struct Materialized {
    candidates: Vec<(PackCandidate, UseAction, DirectiveReason)>,
    evidence: BTreeMap<EvidenceHandle, PackEvidence>,
    omissions: Vec<Omission>,
    authorized_candidates: usize,
}

#[derive(Clone, Debug)]
struct FitOutput {
    pack: ContextPack,
    rendered: crate::RenderedContext,
    protobuf: Vec<u8>,
}

/// Stateless deterministic compiler apart from its continuation authentication key.
#[derive(Clone, Debug)]
pub struct ContextCompiler {
    continuation_key: [u8; 32],
}

impl ContextCompiler {
    /// Creates a compiler with a host-managed non-zero continuation key.
    pub fn new(continuation_key: [u8; 32]) -> Result<Self> {
        if continuation_key == [0_u8; 32] {
            return Err(ContextError::InvalidRequest(
                "continuation key must not be all zeroes".to_owned(),
            ));
        }
        Ok(Self { continuation_key })
    }

    /// Compiles an authorized, minimal, evidence-backed ContextPack.
    pub fn compile(
        &self,
        request: &CompileRequest,
        provider: &dyn ContextProvider,
        tokenizer: &dyn TokenCounter,
    ) -> Result<CompiledContext> {
        request.validate()?;
        if tokenizer.id() != request.model_profile.tokenizer_id {
            return Err(ContextError::InvalidRequest(format!(
                "tokenizer {} differs from requested profile tokenizer {}",
                tokenizer.id(),
                request.model_profile.tokenizer_id
            )));
        }
        let provider_snapshot = provider.snapshot()?;
        if provider_snapshot != request.snapshot {
            return Err(ContextError::Provider(
                "provider snapshot differs from compile request".to_owned(),
            ));
        }

        let prior_state = request
            .continuation
            .as_ref()
            .map(|token| continuation::verify(&self.continuation_key, request, token))
            .transpose()?
            .unwrap_or_default();

        let materialized = materialize_policy_first(request, provider)?;
        let mut omissions = materialized.omissions;
        let required_names: BTreeSet<_> = request
            .required_facets
            .iter()
            .map(|facet| facet.name.clone())
            .collect();
        let mut prepared = Vec::new();
        for (candidate, use_action, directive_reason) in materialized.candidates {
            let candidate_id = candidate.id.clone();
            if candidate.taints.contains(&crate::ContentTaint::SecretLike) {
                omissions.push(Omission {
                    block_id: candidate_id,
                    reason: OmissionReason::SecretRedacted,
                });
                continue;
            }
            match prepare_candidate(
                request,
                candidate,
                use_action,
                directive_reason,
                &materialized.evidence,
                &required_names,
                tokenizer,
            )? {
                Some(value) => prepared.push(value),
                None => omissions.push(Omission {
                    block_id: candidate_id,
                    reason: OmissionReason::UnsupportedUnderEvidencePolicy,
                }),
            }
        }
        prepared.sort_by(|left, right| left.block.id.cmp(&right.block.id));

        let visible_conflicts: BTreeSet<_> = prepared
            .iter()
            .filter_map(|item| item.block.conflict.as_ref().map(|value| value.set_id))
            .collect();
        prepared.retain(|item| {
            let missing = match item.block.epistemic.conflict {
                ConflictState::InConflict { set_id } => !visible_conflicts.contains(&set_id),
                ConflictState::Disputed if item.block.kind != PackBlockKind::Conflict => true,
                ConflictState::None | ConflictState::Disputed | ConflictState::Resolved { .. } => {
                    false
                }
            };
            if missing {
                omissions.push(Omission {
                    block_id: item.block.id.clone(),
                    reason: OmissionReason::UnresolvedConflictWithoutManifest,
                });
            }
            !missing
        });

        let mut selected_ids = intrinsic_mandatory_ids(&prepared);
        select_required_facets(request, &prepared, &mut selected_ids);
        close_conflicts(&prepared, &mut selected_ids)?;

        let mut generated_unknowns = Vec::new();
        for requirement in &request.required_facets {
            if !requirement_satisfied(requirement, &prepared, &selected_ids) {
                generated_unknowns.push(prepare_missing_unknown(
                    request,
                    &requirement.name,
                    tokenizer,
                )?);
            }
        }
        for generated in &generated_unknowns {
            selected_ids.insert(generated.block.id.clone());
        }
        prepared.extend(generated_unknowns);
        prepared.sort_by(|left, right| left.block.id.cmp(&right.block.id));

        let prepared_by_id: BTreeMap<_, _> = prepared
            .iter()
            .map(|candidate| (candidate.block.id.clone(), candidate))
            .collect();
        let mut selected: BTreeMap<BlockId, &PreparedCandidate> = selected_ids
            .iter()
            .filter_map(|id| prepared_by_id.get(id).map(|value| (id.clone(), *value)))
            .collect();

        let mut evaluations = 0_u32;
        let mut fit = fit_pack(
            request,
            selected.values().copied().collect(),
            &omissions,
            evaluations,
            materialized.authorized_candidates,
            None,
            tokenizer,
        )
        .map_err(|reason| {
            ContextError::BudgetExceeded(format!(
                "mandatory ContextPack content does not fit: {reason:?}"
            ))
        })?;

        let optional: Vec<_> = prepared
            .iter()
            .filter(|candidate| !selected.contains_key(&candidate.block.id))
            .collect();
        let ordered_optional = greedy_order(optional);
        let start_offset = usize::try_from(prior_state.next_offset).map_err(|_| {
            ContextError::InvalidContinuation("continuation offset does not fit usize".to_owned())
        })?;
        if start_offset > ordered_optional.len() {
            return Err(ContextError::InvalidContinuation(
                "continuation offset exceeds authorized deterministic candidate order".to_owned(),
            ));
        }
        let mut next_offset = start_offset;
        let mut stopped_for_soft_budget = false;
        for (index, candidate) in ordered_optional.iter().enumerate().skip(start_offset) {
            if evaluations >= request.budgets.max_selection_evaluations {
                stopped_for_soft_budget = true;
                next_offset = index;
                break;
            }
            if fit.pack.compilation.usage.rendered_tokens >= request.budgets.soft_tokens
                && (request.continuation.is_none() || index > start_offset)
            {
                stopped_for_soft_budget = true;
                next_offset = index;
                break;
            }
            evaluations = evaluations.saturating_add(1);
            let density =
                marginal_density(candidate, &fit.pack.compilation.sufficiency.covered_facets);
            if density < MIN_MARGINAL_DENSITY_MICROS_PER_TOKEN {
                omissions.push(Omission {
                    block_id: candidate.block.id.clone(),
                    reason: OmissionReason::Redundant,
                });
                next_offset = index + 1;
                continue;
            }
            let mut bundle = vec![*candidate];
            if let ConflictState::InConflict { set_id } = candidate.block.epistemic.conflict
                && let Some(conflict) = prepared.iter().find(|other| {
                    other
                        .block
                        .conflict
                        .as_ref()
                        .is_some_and(|descriptor| descriptor.set_id == set_id)
                })
                && !selected.contains_key(&conflict.block.id)
            {
                bundle.push(conflict);
            }
            let mut trial_selected = selected.clone();
            for value in &bundle {
                trial_selected.insert(value.block.id.clone(), value);
            }
            match fit_pack(
                request,
                trial_selected.values().copied().collect(),
                &omissions,
                evaluations,
                materialized.authorized_candidates,
                None,
                tokenizer,
            ) {
                Ok(trial) => {
                    selected = trial_selected;
                    fit = trial;
                }
                Err(reason) => omissions.push(Omission {
                    block_id: candidate.block.id.clone(),
                    reason,
                }),
            }
            next_offset = index + 1;
        }

        if !stopped_for_soft_budget {
            next_offset = ordered_optional.len();
        }
        let has_more = next_offset < ordered_optional.len();
        let continuation = if has_more {
            let current_digest = blake3::hash(&fit.protobuf);
            let chain_digest = if request.continuation.is_some() {
                let mut chain = blake3::Hasher::new();
                chain.update(&prior_state.chain_digest);
                chain.update(current_digest.as_bytes());
                *chain.finalize().as_bytes()
            } else {
                *current_digest.as_bytes()
            };
            let next_offset_u32 = u32::try_from(next_offset).map_err(|_| {
                ContextError::InvalidContinuation("candidate offset exceeds u32".to_owned())
            })?;
            let state = ContinuationState {
                next_offset: next_offset_u32,
                cumulative_tokens: prior_state
                    .cumulative_tokens
                    .checked_add(u64::from(fit.pack.compilation.usage.rendered_tokens))
                    .ok_or_else(|| {
                        ContextError::InvalidContinuation(
                            "cumulative continuation token budget overflow".to_owned(),
                        )
                    })?,
                cumulative_blocks: prior_state
                    .cumulative_blocks
                    .checked_add(u64::from(fit.pack.compilation.usage.blocks))
                    .ok_or_else(|| {
                        ContextError::InvalidContinuation(
                            "cumulative continuation block budget overflow".to_owned(),
                        )
                    })?,
                cumulative_evidence: prior_state
                    .cumulative_evidence
                    .checked_add(u64::from(fit.pack.compilation.usage.evidence_blocks))
                    .ok_or_else(|| {
                        ContextError::InvalidContinuation(
                            "cumulative continuation evidence budget overflow".to_owned(),
                        )
                    })?,
                chain_digest,
            };
            Some(continuation::issue(&self.continuation_key, request, state)?)
        } else {
            None
        };

        fit = fit_pack(
            request,
            selected.values().copied().collect(),
            &omissions,
            evaluations,
            materialized.authorized_candidates,
            continuation.clone(),
            tokenizer,
        )
        .or_else(|reason| {
            if continuation.is_some() && reason == OmissionReason::SerializationBudget {
                fit_pack(
                    request,
                    selected.values().copied().collect(),
                    &omissions,
                    evaluations,
                    materialized.authorized_candidates,
                    None,
                    tokenizer,
                )
            } else {
                Err(reason)
            }
        })
        .map_err(|reason| {
            ContextError::BudgetExceeded(format!("final ContextPack does not fit: {reason:?}"))
        })?;

        fit.pack.validate()?;
        let canonical_json = CanonicalSerializer::to_json(&fit.pack)?;
        let canonical_protobuf = CanonicalSerializer::to_protobuf(&fit.pack)?;
        let canonical_digest = blake3::hash(&canonical_protobuf).to_hex().to_string();
        Ok(CompiledContext {
            pack: fit.pack,
            rendered: fit.rendered,
            canonical_json,
            canonical_protobuf,
            canonical_digest,
        })
    }

    /// Convenience overload for the reference in-memory provider.
    pub fn compile_in_memory(
        &self,
        request: &CompileRequest,
        provider: &InMemoryContextProvider,
        tokenizer: &dyn TokenCounter,
    ) -> Result<CompiledContext> {
        self.compile(request, provider, tokenizer)
    }

    /// Compiles only the exact memory/evidence set selected by deterministic recall.
    pub fn compile_recall(
        &self,
        request: &CompileRequest,
        recall: &contextdb_recall::DeterministicRecallResult,
        binding: &crate::RecallContextBinding,
        provider: &dyn ContextProvider,
        tokenizer: &dyn TokenCounter,
    ) -> Result<CompiledContext> {
        if recall.trace.filter_digest != request.filter_digest {
            return Err(ContextError::Authorization(
                "recall and ContextPack policy filter digests differ".to_owned(),
            ));
        }
        let bound = crate::RecallBoundProvider::new(provider, recall, binding)?;
        self.compile(request, &bound, tokenizer)
    }
}

fn materialize_policy_first(
    request: &CompileRequest,
    provider: &dyn ContextProvider,
) -> Result<Materialized> {
    let mut labels = provider.candidate_labels()?;
    labels.sort_by(|left, right| left.id.cmp(&right.id));
    let mut candidates = Vec::new();
    let mut omissions = Vec::new();
    let mut authorized_candidates = 0_usize;
    let mut authorized_label_ids = BTreeSet::new();
    for label in labels {
        let Some(use_action) = label.authorize(
            &request.principal,
            request.model_profile.external_processing,
            request.explicit_memory_request,
        ) else {
            continue;
        };
        label.validate()?;
        if !authorized_label_ids.insert(label.id.clone()) {
            return Err(ContextError::Provider(format!(
                "duplicate authorized candidate policy label {}",
                label.id
            )));
        }
        authorized_candidates = authorized_candidates.saturating_add(1);
        let candidate = provider.materialize_candidate(&label.id)?;
        if candidate.id != label.id {
            return Err(ContextError::Provider(
                "materialized candidate identity differs from authorized label".to_owned(),
            ));
        }
        candidate.validate()?;
        if !candidate.scopes.is_subset(&request.scopes) {
            omissions.push(Omission {
                block_id: candidate.id,
                reason: OmissionReason::OutsideRequestedScope,
            });
            continue;
        }
        if candidate.known_at_commit > request.snapshot.commit_seq {
            omissions.push(Omission {
                block_id: candidate.id,
                reason: OmissionReason::FutureTransaction,
            });
            continue;
        }
        if candidate.epistemic.acceptance == AcceptanceState::Rejected
            || !matches!(
                candidate.epistemic.lifecycle,
                LifecycleState::Active | LifecycleState::Historical
            )
        {
            omissions.push(Omission {
                block_id: candidate.id,
                reason: OmissionReason::EpistemicallyInactive,
            });
            continue;
        }
        let directive_reason = if use_action == UseAction::MentionNaturally {
            DirectiveReason::PolicyAllowsMention
        } else if label.use_policy.disclosure == crate::DisclosureRule::MentionOnlyWhenExplicit {
            DirectiveReason::ExplicitRequestRequired
        } else {
            DirectiveReason::MentionDenied
        };
        candidates.push((candidate, use_action, directive_reason));
    }

    let requested_evidence: BTreeSet<_> = candidates
        .iter()
        .flat_map(|(candidate, _, _)| candidate.evidence_handles.iter().cloned())
        .collect();
    let requested_vec: Vec<_> = requested_evidence.iter().cloned().collect();
    let mut evidence_labels = provider.evidence_labels(&requested_vec)?;
    evidence_labels.sort_by(|left, right| left.id.cmp(&right.id));
    let mut evidence = BTreeMap::new();
    let mut authorized_evidence_ids = BTreeSet::new();
    for label in evidence_labels {
        if !requested_evidence.contains(&label.id) {
            return Err(ContextError::Provider(
                "provider returned an unrequested evidence label".to_owned(),
            ));
        }
        if !label.authorize(
            &request.principal,
            request.model_profile.external_processing,
        ) {
            continue;
        }
        label.validate()?;
        if !authorized_evidence_ids.insert(label.id.clone()) {
            return Err(ContextError::Provider(format!(
                "duplicate authorized evidence policy label {}",
                label.id
            )));
        }
        let item = provider.materialize_evidence(&label.id)?;
        if item.id != label.id {
            return Err(ContextError::Provider(
                "materialized evidence identity differs from authorized label".to_owned(),
            ));
        }
        item.validate()?;
        evidence.insert(item.id.clone(), item);
    }

    Ok(Materialized {
        candidates,
        evidence,
        omissions,
        authorized_candidates,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "candidate preparation preserves explicit policy axes"
)]
fn prepare_candidate(
    request: &CompileRequest,
    mut candidate: PackCandidate,
    mut use_action: UseAction,
    mut directive_reason: DirectiveReason,
    authorized_evidence: &BTreeMap<EvidenceHandle, PackEvidence>,
    required_names: &BTreeSet<String>,
    tokenizer: &dyn TokenCounter,
) -> Result<Option<PreparedCandidate>> {
    candidate.evidence_handles.retain(|handle| {
        authorized_evidence.get(handle).is_some_and(|evidence| {
            candidate.kind == PackBlockKind::RawObservation
                || !evidence.claim_ids.is_disjoint(&candidate.claim_ids)
        })
    });
    let evidence = match &candidate.support {
        SupportState::Supported if candidate.kind == PackBlockKind::RawObservation => {
            let selected: Vec<_> = candidate
                .evidence_handles
                .iter()
                .filter_map(|id| authorized_evidence.get(id))
                .filter(|evidence| evidence.original_span.is_some())
                .cloned()
                .collect();
            if selected.is_empty() {
                return Ok(None);
            }
            selected
        }
        SupportState::Supported if candidate.kind.is_factual() => {
            let selected = minimal_evidence(
                &candidate,
                authorized_evidence,
                request.require_primary_evidence,
                tokenizer,
            )?;
            if selected.is_empty() {
                return Ok(None);
            }
            selected
        }
        SupportState::Supported | SupportState::Unsupported { .. } => Vec::new(),
    };
    candidate.evidence_handles = evidence.iter().map(|item| item.id.clone()).collect();

    let protected_facets: BTreeSet<_> = candidate
        .facets
        .intersection(required_names)
        .cloned()
        .collect();
    let mut best: Option<(u32, CompressionLevel, BlockRepresentation, ContextBlock)> = None;
    for representation in &candidate.representations {
        if !representation.omitted_facets.is_disjoint(&protected_facets) {
            continue;
        }
        let block = to_block(&candidate, representation.clone());
        let json = serde_json::to_string(&block)
            .map_err(|error| ContextError::Serialization(error.to_string()))?;
        let tokens = tokenizer.count_tokens(&json)?;
        let key = (tokens, representation.level);
        if best
            .as_ref()
            .is_none_or(|(best_tokens, best_level, _, _)| key < (*best_tokens, *best_level))
        {
            best = Some((tokens, representation.level, representation.clone(), block));
        }
    }
    let Some((block_tokens, _, _, block)) = best else {
        return Ok(None);
    };
    let evidence_tokens = evidence.iter().try_fold(0_u32, |total, item| {
        let json = serde_json::to_string(item)
            .map_err(|error| ContextError::Serialization(error.to_string()))?;
        total
            .checked_add(tokenizer.count_tokens(&json)?)
            .ok_or_else(|| ContextError::Tokenizer("evidence token count overflow".to_owned()))
    })?;
    match candidate.interpretation {
        InterpretationRule::ConstraintData => {
            use_action = UseAction::ConstraintOnly;
            directive_reason = DirectiveReason::ConstraintSemantics;
        }
        InterpretationRule::StyleSignal => {
            use_action = UseAction::StyleOnly;
            directive_reason = DirectiveReason::StyleSemantics;
        }
        InterpretationRule::FactualData
        | InterpretationRule::HistoricalData
        | InterpretationRule::HypothesisOnly
        | InterpretationRule::UnknownMarker
        | InterpretationRule::ConflictAlternatives => {}
    }
    Ok(Some(PreparedCandidate {
        candidate,
        block,
        evidence,
        use_action,
        directive_reason,
        block_tokens,
        evidence_tokens,
        generated: false,
    }))
}

fn minimal_evidence(
    candidate: &PackCandidate,
    evidence: &BTreeMap<EvidenceHandle, PackEvidence>,
    require_primary: bool,
    tokenizer: &dyn TokenCounter,
) -> Result<Vec<PackEvidence>> {
    let available: Vec<_> = candidate
        .evidence_handles
        .iter()
        .filter_map(|handle| evidence.get(handle))
        .collect();
    let mut uncovered = candidate.claim_ids.clone();
    let mut selected = Vec::new();
    let mut used = BTreeSet::new();
    while !uncovered.is_empty() {
        let mut best: Option<(&PackEvidence, usize, u32)> = None;
        for item in &available {
            if used.contains(&item.id) {
                continue;
            }
            let coverage = item.claim_ids.intersection(&uncovered).count();
            if coverage == 0 {
                continue;
            }
            let cost = item
                .excerpt
                .as_deref()
                .map(|excerpt| tokenizer.count_tokens(excerpt))
                .transpose()?
                .unwrap_or(1)
                .max(1);
            let replace = best
                .as_ref()
                .is_none_or(|(current, current_coverage, current_cost)| {
                    evidence_better(
                        item,
                        coverage,
                        cost,
                        current,
                        *current_coverage,
                        *current_cost,
                    )
                });
            if replace {
                best = Some((item, coverage, cost));
            }
        }
        let Some((item, _, _)) = best else {
            return Ok(Vec::new());
        };
        used.insert(item.id.clone());
        for claim in &item.claim_ids {
            uncovered.remove(claim);
        }
        selected.push(item.clone());
    }
    if require_primary && !selected.iter().any(|item| item.primary) {
        let Some(primary) = available
            .iter()
            .filter(|item| item.primary && !used.contains(&item.id))
            .max_by(|left, right| {
                left.trust_micros
                    .cmp(&right.trust_micros)
                    .then_with(|| right.id.cmp(&left.id))
            })
        else {
            return Ok(Vec::new());
        };
        selected.push((*primary).clone());
    }
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(selected)
}

fn evidence_better(
    candidate: &PackEvidence,
    coverage: usize,
    cost: u32,
    current: &PackEvidence,
    current_coverage: usize,
    current_cost: u32,
) -> bool {
    candidate
        .primary
        .cmp(&current.primary)
        .then_with(|| coverage.cmp(&current_coverage))
        .then_with(|| candidate.trust_micros.cmp(&current.trust_micros))
        .then_with(|| current_cost.cmp(&cost))
        .then_with(|| current.id.cmp(&candidate.id))
        == Ordering::Greater
}

fn to_block(candidate: &PackCandidate, representation: BlockRepresentation) -> ContextBlock {
    ContextBlock {
        id: candidate.id.clone(),
        kind: candidate.kind,
        representation,
        exact_fragments: candidate.exact_fragments.clone(),
        memory_refs: candidate.memory_refs.clone(),
        claim_ids: candidate.claim_ids.clone(),
        evidence_handles: candidate.evidence_handles.clone(),
        facets: candidate.facets.clone(),
        scopes: candidate.scopes.clone(),
        valid_time: candidate.valid_time,
        known_at_commit: candidate.known_at_commit,
        perspective: candidate.perspective.clone(),
        epistemic: candidate.epistemic,
        confidence_micros: candidate.confidence_micros,
        trust: candidate.trust,
        instruction_capability: InstructionCapability::None,
        source_class: candidate.source_class.clone(),
        taints: candidate.taints.clone(),
        interpretation: candidate.interpretation,
        support: candidate.support.clone(),
        conflict: candidate.conflict.clone(),
        unknown: candidate.unknown.clone(),
    }
}

fn intrinsic_mandatory_ids(prepared: &[PreparedCandidate]) -> BTreeSet<BlockId> {
    prepared
        .iter()
        .filter(|item| {
            item.candidate.mandatory
                || matches!(
                    item.block.kind,
                    PackBlockKind::Situation | PackBlockKind::Boundary
                )
                || item
                    .block
                    .conflict
                    .as_ref()
                    .is_some_and(|value| value.blocking)
                || item
                    .block
                    .unknown
                    .as_ref()
                    .is_some_and(|value| value.blocking)
        })
        .map(|item| item.block.id.clone())
        .collect()
}

fn select_required_facets(
    request: &CompileRequest,
    prepared: &[PreparedCandidate],
    selected: &mut BTreeSet<BlockId>,
) {
    let mut covered = covered_facets(prepared, selected);
    for requirement in &request.required_facets {
        if covered.contains(&requirement.name) {
            continue;
        }
        let best = prepared
            .iter()
            .filter(|candidate| {
                candidate.effective_facets().contains(&requirement.name)
                    && block_satisfies_requirement(&candidate.block, requirement)
            })
            .max_by(|left, right| {
                left.block
                    .confidence_micros
                    .cmp(&right.block.confidence_micros)
                    .then_with(|| {
                        left.candidate
                            .utility_micros
                            .cmp(&right.candidate.utility_micros)
                    })
                    .then_with(|| right.block.id.cmp(&left.block.id))
            });
        if let Some(best) = best {
            selected.insert(best.block.id.clone());
            covered.extend(best.effective_facets());
        }
    }
}

fn close_conflicts(prepared: &[PreparedCandidate], selected: &mut BTreeSet<BlockId>) -> Result<()> {
    loop {
        let mut additions = Vec::new();
        for candidate in prepared
            .iter()
            .filter(|candidate| selected.contains(&candidate.block.id))
        {
            if let ConflictState::InConflict { set_id } = candidate.block.epistemic.conflict {
                let conflict = prepared.iter().find(|other| {
                    other
                        .block
                        .conflict
                        .as_ref()
                        .is_some_and(|descriptor| descriptor.set_id == set_id)
                });
                let Some(conflict) = conflict else {
                    return Err(ContextError::InvalidRequest(format!(
                        "selected candidate {} lacks visible conflict manifest",
                        candidate.block.id
                    )));
                };
                if !selected.contains(&conflict.block.id) {
                    additions.push(conflict.block.id.clone());
                }
            }
        }
        if additions.is_empty() {
            return Ok(());
        }
        selected.extend(additions);
    }
}

fn covered_facets(
    prepared: &[PreparedCandidate],
    selected: &BTreeSet<BlockId>,
) -> BTreeSet<String> {
    prepared
        .iter()
        .filter(|candidate| selected.contains(&candidate.block.id))
        .flat_map(PreparedCandidate::effective_facets)
        .collect()
}

fn requirement_satisfied(
    requirement: &crate::PackFacetRequirement,
    prepared: &[PreparedCandidate],
    selected: &BTreeSet<BlockId>,
) -> bool {
    prepared.iter().any(|candidate| {
        selected.contains(&candidate.block.id)
            && candidate.effective_facets().contains(&requirement.name)
            && block_satisfies_requirement(&candidate.block, requirement)
    })
}

fn block_satisfies_requirement(
    block: &ContextBlock,
    requirement: &crate::PackFacetRequirement,
) -> bool {
    block.confidence_micros >= requirement.minimum_confidence_micros
        && (!requirement.require_evidence || !block.evidence_handles.is_empty())
        && matches!(
            block.epistemic.acceptance,
            AcceptanceState::Accepted | AcceptanceState::Consolidated
        )
        && matches!(
            block.epistemic.lifecycle,
            LifecycleState::Active | LifecycleState::Historical
        )
        && matches!(
            block.epistemic.conflict,
            ConflictState::None | ConflictState::Resolved { .. }
        )
        && !matches!(
            block.interpretation,
            InterpretationRule::HypothesisOnly
                | InterpretationRule::UnknownMarker
                | InterpretationRule::ConflictAlternatives
        )
}

fn prepare_missing_unknown(
    request: &CompileRequest,
    facet: &str,
    tokenizer: &dyn TokenCounter,
) -> Result<PreparedCandidate> {
    let id = BlockId::new(format!(
        "unknown:{}",
        &blake3::hash(facet.as_bytes()).to_hex().to_string()[..16]
    ))?;
    let representation = BlockRepresentation {
        level: CompressionLevel::L0Orientation,
        summary: "Required knowledge is not established under the effective policy.".to_owned(),
        fields: BTreeMap::from([("missing_facet".to_owned(), facet.to_owned())]),
        omitted_facets: BTreeSet::new(),
    };
    let candidate = PackCandidate {
        id: id.clone(),
        kind: PackBlockKind::Unknown,
        representations: vec![representation.clone()],
        exact_fragments: Vec::new(),
        memory_refs: Vec::new(),
        claim_ids: BTreeSet::new(),
        evidence_handles: BTreeSet::new(),
        facets: BTreeSet::new(),
        scopes: request.scopes.clone(),
        valid_time: None,
        known_at_commit: request.snapshot.commit_seq,
        perspective: None,
        epistemic: EpistemicState {
            basis: EpistemicBasis::DeterministicDerivation,
            acceptance: AcceptanceState::Validated,
            conflict: ConflictState::None,
            lifecycle: LifecycleState::Active,
        },
        confidence_micros: 1_000_000,
        trust: crate::ContentTrust::TrustedSource,
        instruction_capability: InstructionCapability::None,
        source_class: SourceClass::DeterministicDerivation,
        taints: BTreeSet::new(),
        interpretation: InterpretationRule::UnknownMarker,
        support: SupportState::Supported,
        conflict: None,
        unknown: Some(crate::UnknownDescriptor {
            question: format!("What is the value of required facet `{facet}`?"),
            reason: "no authorized supported candidate met the facet threshold".to_owned(),
            blocking: true,
        }),
        utility_micros: 1_000_000,
        mandatory: true,
    };
    candidate.validate()?;
    let block = to_block(&candidate, representation);
    let json = serde_json::to_string(&block)
        .map_err(|error| ContextError::Serialization(error.to_string()))?;
    Ok(PreparedCandidate {
        candidate,
        block,
        evidence: Vec::new(),
        use_action: UseAction::MentionNaturally,
        directive_reason: DirectiveReason::PolicyAllowsMention,
        block_tokens: tokenizer.count_tokens(&json)?,
        evidence_tokens: 0,
        generated: true,
    })
}

fn greedy_order(mut candidates: Vec<&PreparedCandidate>) -> Vec<&PreparedCandidate> {
    let mut ordered = Vec::with_capacity(candidates.len());
    let mut covered = BTreeSet::new();
    while !candidates.is_empty() {
        let best_index = candidates
            .iter()
            .enumerate()
            .max_by(|(_, left), (_, right)| compare_marginal(left, right, &covered))
            .map(|(index, _)| index)
            .unwrap_or(0);
        let selected = candidates.remove(best_index);
        covered.extend(selected.effective_facets());
        ordered.push(selected);
    }
    ordered
}

fn compare_marginal(
    left: &PreparedCandidate,
    right: &PreparedCandidate,
    covered: &BTreeSet<String>,
) -> Ordering {
    let left_value = marginal_value(left, covered);
    let right_value = marginal_value(right, covered);
    let left_cost = u128::from(left.cost_tokens().max(1));
    let right_cost = u128::from(right.cost_tokens().max(1));
    (left_value * right_cost)
        .cmp(&(right_value * left_cost))
        .then_with(|| right.block.id.cmp(&left.block.id))
}

fn marginal_value(candidate: &PreparedCandidate, covered: &BTreeSet<String>) -> u128 {
    let new_facets = candidate.effective_facets().difference(covered).count() as u128;
    let multiplier = if new_facets == 0 {
        1
    } else {
        2_u128.saturating_mul(new_facets).saturating_add(1)
    };
    u128::from(candidate.candidate.utility_micros).saturating_mul(multiplier)
}

fn marginal_density(candidate: &PreparedCandidate, covered: &BTreeSet<String>) -> u128 {
    marginal_value(candidate, covered) / u128::from(candidate.cost_tokens().max(1))
}

#[allow(
    clippy::too_many_arguments,
    reason = "fit evaluation keeps every hard budget explicit"
)]
fn fit_pack(
    request: &CompileRequest,
    selected: Vec<&PreparedCandidate>,
    omissions: &[Omission],
    selection_evaluations: u32,
    authorized_candidates: usize,
    continuation: Option<crate::ContextContinuationToken>,
    tokenizer: &dyn TokenCounter,
) -> std::result::Result<FitOutput, OmissionReason> {
    let mut selected = selected;
    selected.sort_by(|left, right| {
        left.block
            .kind
            .cmp(&right.block.kind)
            .then_with(|| left.block.id.cmp(&right.block.id))
    });
    if selected.len() > request.budgets.max_blocks as usize {
        return Err(OmissionReason::BlockBudget);
    }
    if selection_evaluations > request.budgets.max_selection_evaluations {
        return Err(OmissionReason::SelectionEvaluationBudget);
    }
    let mut evidence_by_id = BTreeMap::new();
    for candidate in &selected {
        for evidence in &candidate.evidence {
            evidence_by_id
                .entry(evidence.id.clone())
                .or_insert_with(|| evidence.clone());
        }
    }
    if evidence_by_id.len() > request.budgets.max_evidence_blocks as usize {
        return Err(OmissionReason::EvidenceBudget);
    }
    let evidence: Vec<_> = evidence_by_id.into_values().collect();
    let raw_evidence_tokens = evidence
        .iter()
        .filter_map(|item| item.excerpt.as_deref())
        .try_fold(0_u32, |total, excerpt| {
            total
                .checked_add(tokenizer.count_tokens(excerpt)?)
                .ok_or_else(|| {
                    ContextError::Tokenizer("raw evidence token count overflow".to_owned())
                })
        })
        .map_err(|_| OmissionReason::EvidenceBudget)?;
    if raw_evidence_tokens > request.budgets.max_raw_evidence_tokens {
        return Err(OmissionReason::EvidenceBudget);
    }
    let history_tokens = selected
        .iter()
        .filter(|item| item.block.kind.is_history())
        .try_fold(0_u32, |total, item| {
            total
                .checked_add(item.cost_tokens())
                .ok_or(OmissionReason::HistoryBudget)
        })?;
    if history_tokens > request.budgets.max_history_tokens {
        return Err(OmissionReason::HistoryBudget);
    }
    let conflict_tokens = selected
        .iter()
        .filter(|item| item.block.kind == PackBlockKind::Conflict)
        .try_fold(0_u32, |total, item| {
            total
                .checked_add(item.cost_tokens())
                .ok_or(OmissionReason::ConflictBudget)
        })?;
    if conflict_tokens > request.budgets.max_conflict_tokens {
        return Err(OmissionReason::ConflictBudget);
    }
    let selected_source_count = selected.iter().filter(|item| !item.generated).count();
    let mut pack = assemble_pack(
        request,
        &selected,
        evidence,
        omissions,
        selection_evaluations,
        authorized_candidates,
        continuation,
        ContextBudgetUsage {
            blocks: u32::try_from(selected.len()).unwrap_or(u32::MAX),
            evidence_blocks: 0,
            raw_evidence_tokens,
            history_tokens,
            conflict_tokens,
            selection_evaluations,
            ..ContextBudgetUsage::default()
        },
        selected_source_count,
    );
    pack.compilation.usage.evidence_blocks = u32::try_from(pack.evidence.len()).unwrap_or(u32::MAX);
    let rendered = ContextRenderer::render_unchecked(&pack, &request.model_profile, tokenizer)
        .map_err(|_| OmissionReason::TokenBudget)?;
    finalize_pack(request, pack, rendered)
}

fn finalize_pack(
    request: &CompileRequest,
    mut pack: ContextPack,
    rendered: crate::RenderedContext,
) -> std::result::Result<FitOutput, OmissionReason> {
    if rendered.total_tokens > request.budgets.hard_tokens {
        return Err(OmissionReason::TokenBudget);
    }
    pack.compilation.usage.rendered_tokens = rendered.total_tokens;
    pack.compilation.usage.control_tokens = rendered.control_tokens;
    pack.compilation.usage.data_tokens = rendered.data_tokens;
    pack.compilation.soft_budget_exceeded = rendered.total_tokens > request.budgets.soft_tokens;

    let mut protobuf = CanonicalSerializer::encode_protobuf_unchecked(&pack)
        .map_err(|_| OmissionReason::SerializationBudget)?;
    let mut converged = false;
    for _ in 0..16 {
        let bytes = u32::try_from(protobuf.len()).unwrap_or(u32::MAX);
        if pack.compilation.usage.serialized_bytes == bytes {
            converged = true;
            break;
        }
        pack.compilation.usage.serialized_bytes = bytes;
        protobuf = CanonicalSerializer::encode_protobuf_unchecked(&pack)
            .map_err(|_| OmissionReason::SerializationBudget)?;
    }
    if !converged {
        return Err(OmissionReason::SerializationBudget);
    }
    protobuf = CanonicalSerializer::encode_protobuf_unchecked(&pack)
        .map_err(|_| OmissionReason::SerializationBudget)?;
    if pack.compilation.usage.serialized_bytes > request.budgets.max_serialized_bytes {
        return Err(OmissionReason::SerializationBudget);
    }
    Ok(FitOutput {
        pack,
        rendered,
        protobuf,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "canonical manifest assembly is intentionally explicit"
)]
fn assemble_pack(
    request: &CompileRequest,
    selected: &[&PreparedCandidate],
    mut evidence: Vec<PackEvidence>,
    omissions: &[Omission],
    selection_evaluations: u32,
    authorized_candidates: usize,
    continuation: Option<crate::ContextContinuationToken>,
    usage: ContextBudgetUsage,
    selected_source_count: usize,
) -> ContextPack {
    let mut sections = PackSections::default();
    let mut directives = Vec::new();
    let mut provenance_blocks = Vec::new();
    for item in selected {
        sections.push(item.block.clone());
        directives.push(UseDirective {
            block_id: item.block.id.clone(),
            action: item.use_action,
            reason_code: item.directive_reason,
        });
        provenance_blocks.push(BlockProvenance {
            block_id: item.block.id.clone(),
            memory_refs: item.block.memory_refs.clone(),
            evidence_handles: item.block.evidence_handles.clone(),
            source_classes: BTreeSet::from([item.block.source_class.clone()]),
        });
    }
    sort_sections(&mut sections);
    directives.sort_by(|left, right| left.block_id.cmp(&right.block_id));
    provenance_blocks.sort_by(|left, right| left.block_id.cmp(&right.block_id));
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    let evidence_sources = evidence
        .iter()
        .map(|item| (item.id.clone(), item.source.clone()))
        .collect();
    let graph_manifest = GraphManifest {
        memory_refs: sections
            .iter()
            .flat_map(|block| block.memory_refs.iter().cloned())
            .collect(),
        claim_ids: sections
            .iter()
            .flat_map(|block| block.claim_ids.iter().copied())
            .collect(),
        conflict_sets: sections
            .conflicts
            .iter()
            .filter_map(|block| block.conflict.as_ref().map(|value| value.set_id))
            .collect(),
    };
    let sufficiency = assess_sufficiency(request, &sections);
    let no_memory = if selected_source_count == 0 {
        Some(NoMemoryResult {
            reason: if authorized_candidates == 0 {
                NoMemoryReason::NoAuthorizedCandidates
            } else if omissions.iter().any(|omission| {
                matches!(
                    omission.reason,
                    OmissionReason::BlockBudget
                        | OmissionReason::TokenBudget
                        | OmissionReason::EvidenceBudget
                        | OmissionReason::HistoryBudget
                        | OmissionReason::ConflictBudget
                        | OmissionReason::SerializationBudget
                )
            }) {
                NoMemoryReason::BudgetCouldNotAdmitOptionalMemory
            } else {
                NoMemoryReason::NoRelevantCandidates
            },
            missing_facets: sufficiency.missing_facets.clone(),
        })
    } else {
        None
    };
    let status = if no_memory.is_some() {
        PackStatus::NoMemory
    } else if sufficiency.sufficient {
        PackStatus::Sufficient
    } else {
        PackStatus::Partial
    };
    let mut warnings = Vec::new();
    let watermarks = &request.snapshot.watermarks;
    if watermarks.semantic < request.snapshot.commit_seq {
        warnings.push("semantic_projection_lag".to_owned());
    }
    if watermarks.lexical < request.snapshot.commit_seq {
        warnings.push("lexical_projection_lag".to_owned());
    }
    if watermarks.graph < request.snapshot.commit_seq {
        warnings.push("graph_projection_lag".to_owned());
    }
    let mut canonical_omissions = omissions.to_vec();
    canonical_omissions.sort_by(|left, right| {
        left.block_id
            .cmp(&right.block_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    canonical_omissions.dedup();
    ContextPack {
        schema_version: CONTEXT_PACK_SCHEMA_VERSION.to_owned(),
        id: request.pack_id,
        status,
        snapshot: request.snapshot.clone(),
        purpose: request.purpose,
        scope_manifest: ScopeManifest {
            workspace: request.principal.workspace.clone(),
            subject: request.principal.subject.clone(),
            scopes: request.scopes.clone(),
            purpose: request.purpose,
            temporal_view: request.temporal_view,
            filter_digest: request.filter_digest.clone(),
        },
        sections,
        evidence,
        use_directives: directives,
        graph_manifest,
        freshness: FreshnessManifest {
            snapshot: request.snapshot.clone(),
            warnings,
        },
        provenance: ProvenanceManifest {
            compiler_version: CONTEXT_COMPILER_VERSION.to_owned(),
            policy_filter_digest: request.filter_digest.clone(),
            blocks: provenance_blocks,
            evidence_sources,
        },
        continuation,
        compilation: CompilationReport {
            compiler_version: CONTEXT_COMPILER_VERSION.to_owned(),
            schema_version: CONTEXT_PACK_SCHEMA_VERSION.to_owned(),
            model_profile: request.model_profile.id.clone(),
            tokenizer: request.model_profile.tokenizer_id.clone(),
            renderer: request.model_profile.renderer,
            budget: request.budgets,
            usage: ContextBudgetUsage {
                selection_evaluations,
                ..usage
            },
            soft_budget_exceeded: false,
            selected_blocks: selected.iter().map(|item| item.block.id.clone()).collect(),
            omissions: canonical_omissions,
            sufficiency,
        },
        no_memory,
    }
}

fn assess_sufficiency(request: &CompileRequest, sections: &PackSections) -> PackSufficiencyReport {
    let covered_facets: BTreeSet<_> = sections
        .iter()
        .flat_map(|block| {
            block
                .facets
                .difference(&block.representation.omitted_facets)
                .cloned()
        })
        .collect();
    let missing_facets = request
        .required_facets
        .iter()
        .filter(|requirement| {
            !sections.iter().any(|block| {
                block.facets.contains(&requirement.name)
                    && !block
                        .representation
                        .omitted_facets
                        .contains(&requirement.name)
                    && block_satisfies_requirement(block, requirement)
            })
        })
        .map(|requirement| requirement.name.clone())
        .collect::<BTreeSet<_>>();
    let unresolved_conflicts = sections
        .conflicts
        .iter()
        .filter_map(|block| {
            block.conflict.as_ref().and_then(|conflict| {
                (conflict.blocking
                    && matches!(conflict.resolution, crate::ConflictResolution::Unresolved))
                .then_some(conflict.set_id)
            })
        })
        .collect::<BTreeSet<_>>();
    let blocking_unknowns = sections
        .unknowns
        .iter()
        .filter(|block| {
            block
                .unknown
                .as_ref()
                .is_some_and(|unknown| unknown.blocking)
        })
        .map(|block| block.id.clone())
        .collect::<BTreeSet<_>>();
    let unsupported_blocks = sections
        .iter()
        .filter(|block| matches!(block.support, SupportState::Unsupported { .. }))
        .map(|block| block.id.clone())
        .collect::<BTreeSet<_>>();
    let sufficient = missing_facets.is_empty()
        && unresolved_conflicts.is_empty()
        && blocking_unknowns.is_empty()
        && unsupported_blocks.is_empty();
    PackSufficiencyReport {
        sufficient,
        covered_facets,
        missing_facets,
        unresolved_conflicts,
        blocking_unknowns,
        unsupported_blocks,
    }
}

fn sort_sections(sections: &mut PackSections) {
    sections
        .situation
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .self_context
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .participants
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .shared_history
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .episodes
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections.facts.sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .relationships
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .preferences
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .boundaries
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections.goals.sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .decisions
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .timeline
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .procedures
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .constraints
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .open_loops
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .conflicts
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .unknowns
        .sort_by(|left, right| left.id.cmp(&right.id));
    sections
        .raw_observations
        .sort_by(|left, right| left.id.cmp(&right.id));
}
