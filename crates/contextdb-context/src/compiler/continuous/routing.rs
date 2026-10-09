//! Thin observations of the authoritative continuous compiler's prepared units,
//! actual score calls and final assembly. No alternate selection or resolver.

use super::*;
use crate::router::{
    DESCRIPTOR_SCHEMA, FEATURE_SCHEMA, MANIFEST_FORMAT, MAX_RECORD_BYTES, MAX_SCORES, MemoryUnit,
    PLAN_FORMAT, REQUEST_FORMAT, RouterBinding, RouterChoice, RouterDecision, RouterManifest,
    RouterPreparedMaterial, RouterRenderRole, RouterStopReason, RoutingDescriptor,
    SupportAlternative, canonical_digest, normalize_spans,
};

#[allow(
    clippy::too_many_arguments,
    reason = "binding contains the same owner and rendering inputs"
)]
pub(super) fn make_request(
    request: &CompileAssemblyRequest,
    binding: &crate::AssemblyBinding,
    units: &BTreeMap<BlockId, Unit>,
    mandatory: &BTreeSet<BlockId>,
    base_outgoing: &EncodedOutgoing,
    scorer: &dyn ContextScorer,
    encoder: &dyn OutgoingEncoder,
    entry_allowance: (u64, u64),
    budget: &mut QueryBudget,
) -> Result<AuthorizedRouterRequest> {
    if request.context.scopes.len() > 32
        || request.context.budgets.max_selection_evaluations as usize > MAX_SCORES
    {
        return Err(router::invalid(
            "router scope or evaluation ceiling exceeded",
        ));
    }
    let mut inventory = Vec::new();
    let prepared: Vec<_> = units
        .values()
        .map(|unit| unit.variants[0].clone())
        .collect();
    for (id, unit) in units {
        let first = &unit.variants[0];
        let mut alternatives = Vec::new();
        let hard_closure: Vec<_> =
            closure_bounded(&BTreeSet::from([id.clone()]), units, &prepared, budget)?
                .into_iter()
                .collect();
        for (index, variant) in unit.variants.iter().enumerate() {
            let mut originals: Vec<_> = variant
                .evidence
                .iter()
                .filter_map(|item| item.original_span.clone())
                .collect();
            normalize_spans(&mut originals);
            alternatives.push(SupportAlternative {
                index: index as u32,
                level: variant.block.representation.level,
                representation_digest: canonical_digest(&variant.block.representation, budget)?,
                material_digest: canonical_digest(&(&variant.block, &variant.evidence), budget)?,
                evidence_handles: variant
                    .evidence
                    .iter()
                    .map(|item| item.id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                originals,
                hard_closure: hard_closure.clone(),
                omitted_facets: variant
                    .block
                    .representation
                    .omitted_facets
                    .iter()
                    .cloned()
                    .collect(),
            });
        }
        let render_role = match first.block.kind {
            PackBlockKind::RawObservation => RouterRenderRole::Evidence,
            PackBlockKind::Unknown => RouterRenderRole::Unknown,
            PackBlockKind::Conflict => RouterRenderRole::Conflict,
            _ if !first.block.epistemic.acceptance.is_published() => RouterRenderRole::Proposal,
            _ if first.block.epistemic.lifecycle != LifecycleState::Active
                || first.block.interpretation == InterpretationRule::HistoricalData =>
            {
                RouterRenderRole::Historical
            }
            _ => RouterRenderRole::CurrentState,
        };
        inventory.push(MemoryUnit {
            id: id.clone(),
            kind: first.block.kind,
            epistemic: first.block.epistemic,
            interpretation: first.block.interpretation,
            render_role,
            instruction_capability: first.block.instruction_capability,
            scopes: first.block.scopes.iter().cloned().collect(),
            facets: first.block.facets.iter().cloned().collect(),
            memory_refs: first.block.memory_refs.clone(),
            claim_ids: first.block.claim_ids.iter().copied().collect(),
            perspective: first.block.perspective.clone(),
            valid_time: first.block.valid_time,
            known_at_commit: first.block.known_at_commit,
            source_class: first.block.source_class.clone(),
            support: first.block.support.clone(),
            conflict: first.block.conflict.clone(),
            unknown: first.block.unknown.clone(),
            candidate_digest: canonical_digest(
                &unit
                    .variants
                    .iter()
                    .map(|variant| {
                        (
                            &variant.candidate,
                            variant.use_action,
                            variant.directive_reason,
                        )
                    })
                    .collect::<Vec<_>>(),
                budget,
            )?,
            hard_dependencies: unit.dependencies.hard.iter().cloned().collect(),
            complements: unit.dependencies.complements.iter().cloned().collect(),
            support_alternatives: alternatives,
            descriptor: RoutingDescriptor {
                schema: DESCRIPTOR_SCHEMA.into(),
                prior_utility_micros: first.candidate.utility_micros,
                confidence_micros: first.block.confidence_micros,
                block_tokens: first.block_tokens,
                evidence_tokens: first.evidence_tokens,
                embedding_reference: None,
                embedding_revision: None,
                uncertainty: None,
                retrieval_score: None,
                index_complete: None,
                missing_features: vec![
                    "embedding".into(),
                    "index_coverage".into(),
                    "retrieval_score".into(),
                    "uncertainty".into(),
                ],
            },
        });
    }
    let mandatory_ids: Vec<_> = mandatory.iter().cloned().collect();
    let mut visible_originals = request
        .base
        .control
        .iter()
        .chain(&request.base.working)
        .chain(&request.base.hot)
        .chain(&request.base.current)
        .flat_map(|message| message.originals.iter().map(|item| item.span.clone()))
        .collect();
    normalize_spans(&mut visible_originals);
    let binding = RouterBinding {
        owner: binding.clone(),
        compile_request: canonical_digest(&request.context, budget)?,
        control: canonical_digest(&request.base.control, budget)?,
        working: canonical_digest(&request.base.working, budget)?,
        hot: canonical_digest(&request.base.hot, budget)?,
        current: canonical_digest(&request.base.current, budget)?,
        base_layout: canonical_digest(&(OUTGOING_LAYOUT, &request.base, base_outgoing), budget)?,
        reader_profile: canonical_digest(&request.context.model_profile, budget)?,
        tokenizer: encoder.tokenizer_id().into(),
        encoder: encoder.id().into(),
        scorer: scorer.id().into(),
        scorer_revision: scorer.revision().into(),
        feature_schema: FEATURE_SCHEMA.into(),
        descriptor_schema: DESCRIPTOR_SCHEMA.into(),
        budgets: canonical_digest(
            &(
                &request.context.budgets,
                request.budget,
                request.context.model_profile.reserved_output_tokens,
            ),
            budget,
        )?,
        candidates: canonical_digest(&inventory, budget)?,
        mandatory: canonical_digest(&mandatory_ids, budget)?,
        max_evaluations: request.context.budgets.max_selection_evaluations,
        max_record_bytes: MAX_RECORD_BYTES as u32,
        max_scorer_work: u64::from(request.context.budgets.max_selection_evaluations) * 1024,
        max_scorer_micros: scorer.latency_limit_micros(),
        max_prepare_micros: 30_000_000,
        shared_work_at_entry: entry_allowance.0,
        shared_bytes_at_entry: entry_allowance.1,
        max_text_rerank_pairs: 0,
    };
    AuthorizedRouterRequest {
        format: REQUEST_FORMAT.into(),
        pack_id: request.context.pack_id,
        binding,
        context: request.context.clone(),
        outgoing_budget: request.budget,
        working_state: occurrences(&request.base.working, budget)?,
        hot_window: occurrences(&request.base.hot, budget)?,
        current_turn: occurrences(&request.base.current, budget)?,
        units: inventory,
        mandatory_ids,
        visible_originals,
        digest: ContentDigest::from_bytes([0; 32]),
        discovery_complete: None,
        capture_complete: None,
    }
    .seal(budget)
}

#[allow(
    clippy::too_many_arguments,
    reason = "score commits exact selected and trial materials"
)]
pub(super) fn score_record(
    request: &AuthorizedRouterRequest,
    selected: &BTreeSet<BlockId>,
    best: &Trial,
    unit: &ScoringUnit,
    trial: &Trial,
    evaluation: u32,
    utility: Option<u64>,
    budget: &mut QueryBudget,
) -> Result<RouterScore> {
    Ok(RouterScore {
        evaluation,
        request_digest: request.digest,
        selected_base_digest: canonical_digest(
            &(
                request.digest,
                selected,
                &best.fit.pack,
                &best.messages,
                &best.outgoing,
            ),
            budget,
        )?,
        seed_ids: unit.seeds.iter().cloned().collect(),
        closure_ids: unit.closure.iter().cloned().collect(),
        utility_micros: utility,
        marginal_tokens: unit.marginal_tokens,
        prior_utility_micros: unit.prior_utility_micros,
        new_facets: unit.new_facets.iter().cloned().collect(),
        adds_original_bytes: unit.adds_original_bytes,
        raw_only: unit.raw_only,
        trial_input_tokens: trial.outgoing.input_tokens,
        trial_wire_digest: ContentDigest::from_bytes(
            *blake3::hash(&trial.outgoing.wire).as_bytes(),
        ),
        outgoing_fits: !trial.outgoing_overflow,
        uncertainty: None,
        calibration: None,
        behavior_propensity: None,
    })
}

pub(super) fn make_plan(
    assembly: &CompiledAssembly,
    request: &AuthorizedRouterRequest,
    scores: &[RouterScore],
    budget: &mut QueryBudget,
) -> Result<RouterSelectionPlan> {
    let mut choices = Vec::new();
    let mut facets = BTreeSet::new();
    for block in assembly.context.pack.sections.iter() {
        facets.extend(
            block
                .facets
                .difference(&block.representation.omitted_facets)
                .cloned(),
        );
        let evidence: Vec<_> = assembly
            .context
            .pack
            .evidence
            .iter()
            .filter(|item| block.evidence_handles.contains(&item.id))
            .cloned()
            .collect();
        let material = canonical_digest(&(block, evidence), budget)?;
        let unit = request
            .units
            .iter()
            .find(|unit| unit.id == block.id)
            .ok_or_else(|| router::invalid("final unit absent from authorized inventory"))?;
        let alternative = unit
            .support_alternatives
            .iter()
            .find(|alternative| alternative.material_digest == material)
            .ok_or_else(|| router::invalid("final support absent from authorized inventory"))?;
        choices.push(RouterChoice {
            id: block.id.clone(),
            alternative_index: alternative.index,
            representation_digest: alternative.representation_digest,
            material_digest: material,
        });
    }
    choices.sort_by(|a, b| a.id.cmp(&b.id));
    let usage = assembly.context.pack.compilation.usage;
    let mut visible_originals: Vec<_> = assembly
        .manifest
        .occurrences
        .iter()
        .flat_map(|message| message.originals.iter().map(|item| item.span.clone()))
        .collect();
    normalize_spans(&mut visible_originals);
    let budget_reached = assembly.selection_evaluations >= request.binding.max_evaluations
        || usage.rendered_tokens >= assembly.context.pack.compilation.budget.soft_tokens;
    Ok(RouterSelectionPlan {
        format: PLAN_FORMAT.into(),
        request_digest: request.digest,
        binding: request.binding.clone(),
        decision: if assembly.optional_seeds.is_empty() {
            RouterDecision::Stop
        } else {
            RouterDecision::Select
        },
        seed_ids: assembly.optional_seeds.iter().cloned().collect(),
        selected_ids: assembly
            .manifest
            .read_set
            .selected_blocks
            .iter()
            .cloned()
            .collect(),
        choices,
        scores: scores.to_vec(),
        behavior_propensity: None,
        usage,
        input_tokens: assembly.outgoing.input_tokens,
        count_kind: assembly.outgoing.count_kind,
        wire_digest: assembly.manifest.wire_digest,
        covered_facets: facets.into_iter().collect(),
        visible_originals,
        evidence_handles: assembly
            .context
            .pack
            .evidence
            .iter()
            .map(|item| item.id.clone())
            .collect(),
        status: assembly.context.pack.status,
        sufficiency: assembly.context.pack.compilation.sufficiency.clone(),
        stop_reason: if budget_reached {
            RouterStopReason::BudgetReached
        } else {
            RouterStopReason::NoPositiveMarginalGain
        },
    })
}

pub(super) fn finish(
    assembly: CompiledAssembly,
    record: RouterRecord,
    budget: &mut QueryBudget,
) -> Result<RoutedAssembly> {
    let plan = make_plan(&assembly, &record.request, &record.scores, budget)?;
    plan.validate(&record.request, budget)?;
    let manifest = RouterManifest {
        format: MANIFEST_FORMAT.into(),
        request_digest: record.request.digest,
        candidate_digest: record.request.binding.candidates,
        plan_digest: canonical_digest(&plan, budget)?,
        assembly: assembly.manifest.clone(),
        selection_evaluations: assembly.selection_evaluations,
        scorer_micros: assembly.scorer_micros,
        trained_weights: None,
        training_dataset: None,
        fallback_from: None,
        fallback_revision: None,
        score_provenance: router::ScoreProvenance::ObservedScorer,
        compilation_work_units: 0,
        compilation_bytes_processed: 0,
        compilation_micros: 0,
    };
    let prepared_material = prepared_material(&record, &plan, &manifest, budget)?;
    Ok(RoutedAssembly {
        assembly,
        request: record.request,
        plan,
        manifest,
        prepared_material,
    })
}

fn prepared_material(
    record: &RouterRecord,
    plan: &RouterSelectionPlan,
    manifest: &RouterManifest,
    budget: &mut QueryBudget,
) -> Result<RouterPreparedMaterial> {
    #[derive(serde::Serialize)]
    struct MaterialView<'a> {
        candidates: Vec<&'a PackCandidate>,
        evidence: Vec<&'a PackEvidence>,
    }
    let candidates: Vec<_> = record
        .prepared_units
        .values()
        .map(|unit| &unit.variants[0].candidate)
        .collect();
    if candidates.iter().map(|candidate| &candidate.id).ne(record
        .request
        .units
        .iter()
        .map(|unit| &unit.id))
    {
        return Err(router::invalid(
            "prepared material differs from the authorized inventory",
        ));
    }
    let mut evidence = BTreeMap::new();
    for unit in record.prepared_units.values() {
        for variant in &unit.variants {
            charge(budget, variant.evidence.len() as u64 + 1, 0)?;
            for item in &variant.evidence {
                if evidence
                    .insert(&item.id, item)
                    .is_some_and(|existing| existing != item)
                {
                    return Err(ContextError::Provider(
                        "prepared support identity disagrees".into(),
                    ));
                }
            }
        }
    }
    let material = MaterialView {
        candidates,
        evidence: evidence.into_values().collect(),
    };
    // Borrow actual prepared values while checking the complete envelope. No
    // extra candidate/evidence payload is cloned before this bounded check.
    router::canonical_bytes(&(&record.request, plan, manifest, &material), budget)?;
    Ok(RouterPreparedMaterial {
        candidates: material.candidates.into_iter().cloned().collect(),
        evidence: material.evidence.into_iter().cloned().collect(),
    })
}

fn occurrences(
    messages: &[OutgoingMessage],
    budget: &mut QueryBudget,
) -> Result<Vec<OutgoingOccurrence>> {
    messages
        .iter()
        .map(|message| {
            Ok(OutgoingOccurrence {
                id: message.id.clone(),
                zone: message.zone,
                role: message.role,
                digest: canonical_digest(message, budget)?,
                originals: message.originals.clone(),
            })
        })
        .collect()
}
