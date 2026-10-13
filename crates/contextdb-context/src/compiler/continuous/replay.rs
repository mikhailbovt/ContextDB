//! Detached reconstruction enters the live selector after preparation. Retained
//! hashes establish consistency; they do not authenticate a supplied history.

use super::*;
use crate::router::{
    MAX_REPLAY_BYTES, MAX_REPLAY_WORK, RouterHistoricalReplay, RouterHistoricalReplayResult,
    RouterManifest, RouterMaterialStatus, RouterPreparedMaterial, RouterReplayObservation,
    RouterReplayPreparation, RouterReplayUnavailableReason,
};

pub(super) const RENDERER: &str = "contextdb.continuous-renderer.v1";

pub(super) fn validate_preparation(
    request: &AuthorizedRouterRequest,
    preparation: &RouterReplayPreparation,
    budget: &mut QueryBudget,
) -> Result<()> {
    charge(budget, 1, 0)?;
    if preparation.format != router::ROUTER_REPLAY_PREPARATION_FORMAT
        || preparation.compiler != CONTEXT_COMPILER_VERSION
        || preparation.renderer != RENDERER
        || preparation.canonical_encoding != crate::CONTEXT_PACK_CANONICAL_ENCODING
        || preparation.layout != OUTGOING_LAYOUT
        || preparation.units.len() != request.units.len()
        || preparation.units.len() > router::MAX_UNITS
        || preparation.prepared_order.len() != request.units.len()
        || preparation.omissions.len() > 1024
        || preparation.selector_work > request.binding.shared_work_at_entry
        || preparation.selector_bytes > request.binding.shared_bytes_at_entry
    {
        return Err(router::invalid(
            "unsupported or inconsistent replay preparation",
        ));
    }
    for (unit, actual) in preparation.units.iter().zip(&request.units) {
        charge(budget, unit.variants.len() as u64 + 1, 0)?;
        if unit.id != actual.id
            || unit.id.as_str().len() > 16384
            || unit.variants.len() != actual.support_alternatives.len()
            || unit.variants.is_empty()
            || unit.variants.len() > 8
        {
            return Err(router::invalid("replay unit inventory disagrees"));
        }
        for (index, variant) in unit.variants.iter().enumerate() {
            let support = &actual.support_alternatives[index];
            if variant.index as usize != index
                || variant.evidence_order.len() > 64
                || variant.block_token_handles.len() > 64
                || variant
                    .evidence_order
                    .iter()
                    .ne(support.evidence_handles.iter())
                || variant
                    .block_token_handles
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || variant
                    .block_token_handles
                    .iter()
                    .any(|handle| !support.evidence_handles.contains(handle))
                || variant.generated != unit.variants[0].generated
                || (index == 0
                    && (variant.block_tokens != actual.descriptor.block_tokens
                        || variant.evidence_tokens != actual.descriptor.evidence_tokens))
            {
                return Err(router::invalid(
                    "replay variant order or counting input disagrees",
                ));
            }
        }
    }
    if preparation
        .prepared_order
        .iter()
        .any(|id| id.as_str().len() > 16384)
        || preparation
            .omissions
            .iter()
            .any(|item| item.block_id.as_str().len() > 16384)
    {
        return Err(router::invalid("excessive replay preparation identity"));
    }
    // Bounds precede even temporary inventory allocations.
    router::canonical_bytes(preparation, budget)?;
    let order: BTreeSet<_> = preparation.prepared_order.iter().collect();
    if order.len() != preparation.prepared_order.len()
        || order
            .into_iter()
            .ne(request.units.iter().map(|unit| &unit.id))
        || preparation.digest != preparation.commitment(budget)?
    {
        return Err(router::invalid("replay preparation commitment disagrees"));
    }
    Ok(())
}

impl ContextCompiler {
    /// Validate only bounded retained observation metadata and its preparation
    /// association. This invokes no scorer/provider/tokenizer and cannot report
    /// historical selection Verified or authenticate a caller-supplied history.
    pub fn validate_router_replay_observation(
        request: &AuthorizedRouterRequest,
        manifest: &RouterManifest,
        preparation: &RouterReplayPreparation,
        observation: &RouterReplayObservation,
        budget: &mut QueryBudget,
    ) -> Result<()> {
        charge(budget, 1, 0)?;
        if request.units.len() > router::MAX_UNITS
            || preparation.units.len() > router::MAX_UNITS
            || preparation.prepared_order.len() > router::MAX_UNITS
            || preparation.omissions.len() > 1024
        {
            return Err(router::invalid("excessive replay observation inputs"));
        }
        validate_observation(request, manifest, preparation, observation, budget)?;
        router::canonical_bytes(&(request, manifest, preparation, observation), budget)?;
        Ok(())
    }

    /// Execute pinned R0 over the retained prepared state using the live selector.
    /// Current authorization, source acceptance, export and dispatch stay outside
    /// this detached computation. Timings are fresh measurements, not equality.
    #[allow(
        clippy::too_many_arguments,
        reason = "independent retained observation and trusted runtime ports"
    )]
    pub fn replay_router_r0(
        request: &AuthorizedRouterRequest,
        plan: &RouterSelectionPlan,
        manifest: &RouterManifest,
        base: &crate::OutgoingBase,
        material: &RouterPreparedMaterial,
        observation: &RouterReplayObservation,
        tokenizer: &dyn TokenCounter,
        encoder: &dyn OutgoingEncoder,
        budget: &mut QueryBudget,
    ) -> Result<RouterHistoricalReplayResult> {
        let started = std::time::Instant::now();
        charge(budget, 1, 0)?;
        let Some(policy) = &material.prepared_policy else {
            return Ok(RouterHistoricalReplayResult::Unavailable(
                RouterReplayUnavailableReason::MissingReplayPreparation,
            ));
        };
        let Some(preparation) = &policy.replay else {
            return Ok(RouterHistoricalReplayResult::Unavailable(
                RouterReplayUnavailableReason::MissingReplayPreparation,
            ));
        };
        if request.binding.scorer != crate::R0Scorer.id()
            || request.binding.scorer_revision != crate::R0Scorer.revision()
            || request.binding.feature_schema != router::FEATURE_SCHEMA
            || request.binding.max_text_rerank_pairs != 0
            || manifest.score_provenance != router::ScoreProvenance::ObservedScorer
            || manifest.fallback_from.is_some()
            || manifest.fallback_revision.is_some()
            || manifest.trained_weights.is_some()
            || manifest.training_dataset.is_some()
        {
            return Ok(RouterHistoricalReplayResult::Unavailable(
                RouterReplayUnavailableReason::UnsupportedScorerProvenance,
            ));
        }
        if tokenizer.id() != request.binding.tokenizer
            || encoder.tokenizer_id() != tokenizer.id()
            || encoder.id() != request.binding.encoder
            || preparation.format != router::ROUTER_REPLAY_PREPARATION_FORMAT
            || preparation.compiler != CONTEXT_COMPILER_VERSION
            || preparation.renderer != RENDERER
            || preparation.canonical_encoding != crate::CONTEXT_PACK_CANONICAL_ENCODING
            || preparation.layout != OUTGOING_LAYOUT
        {
            return Ok(RouterHistoricalReplayResult::Unavailable(
                RouterReplayUnavailableReason::UnsupportedRuntimeProfile,
            ));
        }
        if preparation.selector_work == 0
            || preparation.selector_bytes == 0
            || preparation.selector_work > MAX_REPLAY_WORK
            || preparation.selector_bytes > MAX_REPLAY_BYTES
        {
            return Ok(RouterHistoricalReplayResult::Unavailable(
                RouterReplayUnavailableReason::UnsupportedHistoricalAllowance,
            ));
        }
        validate_observation(request, manifest, preparation, observation, budget)?;
        // Include the original base and behavior in the joint ceiling before any
        // retained payload clone. The inherited child is reserved only afterwards.
        router::canonical_bytes(
            &(request, plan, manifest, base, material, observation),
            budget,
        )?;
        let mut inventory = Self::validate_router_material(request, material, budget)?;
        manifest.validate_observation(request, plan, budget)?;
        validate_preparation(request, preparation, budget)?;
        let (compile_request, visible, base_outgoing) =
            reconstruct_base(request, manifest, base, tokenizer, encoder, budget)?;
        let units = reconstruct_units(request, material, preparation, tokenizer, &visible, budget)?;
        charge(
            budget,
            1,
            (preparation.prepared_order.len() * size_of::<PreparedCandidate>()) as u64,
        )?;
        for id in &preparation.prepared_order {
            let variant = &units[id].variants[0];
            router::canonical_bytes(
                &(&variant.candidate, &variant.block, &variant.evidence),
                budget,
            )?;
        }
        let prepared = preparation
            .prepared_order
            .iter()
            .map(|id| units[id].variants[0].clone())
            .collect();
        let selected = request.mandatory_ids.iter().cloned().collect();
        router::canonical_bytes(
            &(request, &preparation.prepared_order, &preparation.omissions),
            budget,
        )?;
        let record = RouterRecord {
            request: request.clone(),
            scores: Vec::new(),
            prepared_units: BTreeMap::new(),
            capture_prepared_policy: true,
            replay: Some(ReplayCapture {
                selector_allowance: (preparation.selector_work, preparation.selector_bytes),
                prepared_order: preparation.prepared_order.clone(),
                omissions: preparation.omissions.clone(),
                attempts: Vec::new(),
                attempt_bytes: 0,
            }),
        };
        budget.check().map_err(|reason| {
            ContextError::BudgetExceeded(format!("shared replay allowance: {reason:?}"))
        })?;
        let mut selector_budget = budget
            .reserve(preparation.selector_work, preparation.selector_bytes)
            .map_err(|reason| {
                ContextError::BudgetExceeded(format!("historical selector reservation: {reason:?}"))
            })?;
        let (assembly, record) = select_prepared(
            SelectionExecution {
                request: &compile_request,
                provider: None,
                tokenizer,
                encoder,
                scorer: &crate::R0Scorer,
                budget: &mut selector_budget,
                capture: true,
                proposal: None,
                started,
            },
            PreparedSelection {
                units,
                prepared,
                selected,
                visible,
                omissions: preparation.omissions.clone(),
                base_outgoing,
                binding: request.binding.owner.clone(),
                router_record: Some(record),
            },
        )?;
        let record = record.ok_or_else(|| router::invalid("missing replay selection record"))?;
        // Reporting/verification consumes the enclosing allowance, never restores
        // or silently recycles any unused historical reservation.
        let actual_plan = routing::make_plan(&assembly, request, &record.scores, budget)?;
        let replay = record
            .replay
            .ok_or_else(|| router::invalid("missing replay attempts"))?;
        if actual_plan != *plan
            || replay.attempts != observation.attempts
            || assembly.manifest != manifest.assembly
            || assembly.selection_evaluations != manifest.selection_evaluations
            || assembly
                .raw_recall_pressure
                .as_ref()
                .map(router::RouterReplayPressure::from)
                != observation.raw_recall_pressure
        {
            return Err(router::invalid(
                "historical R0 selection or complete wire disagrees",
            ));
        }
        require_router_deadline(started, budget)?;
        inventory.historical_selection = RouterMaterialStatus::Verified;
        let token_count = if assembly.outgoing.count_kind == RequestCountKind::Exact {
            RouterMaterialStatus::Verified
        } else {
            RouterMaterialStatus::Unavailable(
                router::RouterMaterialUnavailableReason::NonExactRequestCount,
            )
        };
        Ok(RouterHistoricalReplayResult::Complete(Box::new(
            RouterHistoricalReplay {
                assembly,
                inventory,
                score_selection: RouterMaterialStatus::Verified,
                material_wire: RouterMaterialStatus::Verified,
                token_count,
                measured_micros: elapsed_micros(started),
            },
        )))
    }
}

fn validate_observation(
    request: &AuthorizedRouterRequest,
    manifest: &RouterManifest,
    preparation: &RouterReplayPreparation,
    observation: &RouterReplayObservation,
    budget: &mut QueryBudget,
) -> Result<()> {
    charge(budget, 1, 0)?;
    if observation.format != router::ROUTER_REPLAY_OBSERVATION_FORMAT
        || observation.preparation_digest != preparation.digest
        || observation.attempts.len() > router::MAX_SCORES
        || observation.attempts.len() != manifest.selection_evaluations as usize
    {
        return Err(router::invalid(
            "replay observation shape or preparation differs",
        ));
    }
    for (index, attempt) in observation.attempts.iter().enumerate() {
        charge(budget, attempt.seed_ids.len() as u64 + 1, 0)?;
        if attempt.evaluation as usize != index + 1
            || attempt.seed_ids.is_empty()
            || attempt.seed_ids.len() > 2
            || attempt.seed_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || attempt.seed_ids.iter().any(|id| {
                id.as_str().len() > 16384
                    || request
                        .units
                        .binary_search_by(|unit| unit.id.cmp(id))
                        .is_err()
            })
        {
            return Err(router::invalid("replay attempt identity or order differs"));
        }
    }
    Ok(())
}

fn reconstruct_base(
    request: &AuthorizedRouterRequest,
    manifest: &RouterManifest,
    base: &crate::OutgoingBase,
    tokenizer: &dyn TokenCounter,
    encoder: &dyn OutgoingEncoder,
    budget: &mut QueryBudget,
) -> Result<(CompileAssemblyRequest, OriginalInventory, EncodedOutgoing)> {
    if base.control.len() + base.working.len() + base.hot.len() + base.current.len() > 256
        || request.context.model_profile.tokenizer_id != tokenizer.id()
        || base.control.iter().any(|message| {
            !matches!(
                message.zone,
                OutgoingZone::Control | OutgoingZone::ToolDefinitions
            )
        })
        || base.working.iter().any(|message| {
            message.zone != OutgoingZone::WorkingState
                || message.role != OutgoingRole::User
                || message.originals.is_empty()
                || !message.tool_calls.is_empty()
                || message.tool_result.is_some()
        })
        || base.hot.iter().any(|message| {
            !matches!(
                message.zone,
                OutgoingZone::HotHistory | OutgoingZone::ProviderContinuation
            )
        })
        || base
            .current
            .iter()
            .any(|message| message.zone != OutgoingZone::CurrentTurn)
    {
        return Err(router::invalid("invalid retained outgoing base"));
    }
    let mut visible = OriginalInventory::new();
    let mut visible_spans = Vec::new();
    for message in base
        .control
        .iter()
        .chain(&base.working)
        .chain(&base.hot)
        .chain(&base.current)
    {
        validate_message(message)?;
        charge(budget, 1, message.text.len() as u64)?;
        for original in &message.originals {
            insert_original(
                &mut visible,
                &original.span,
                &message.text.as_bytes()[original.text_start as usize..original.text_end as usize],
            )?;
            visible_spans.push(original.span.clone());
        }
    }
    router::normalize_spans(&mut visible_spans);
    let messages: Vec<_> = base
        .control
        .iter()
        .chain(&base.working)
        .chain(&base.hot)
        .chain(&base.current)
        .cloned()
        .collect();
    validate_protocol(&messages)?;
    let base_outgoing = encoder.encode(&messages, budget)?;
    if digest(base)? != manifest.assembly.base_digest
        || router::canonical_digest(&base.control, budget)? != request.binding.control
        || router::canonical_digest(&base.working, budget)? != request.binding.working
        || router::canonical_digest(&base.hot, budget)? != request.binding.hot
        || router::canonical_digest(&base.current, budget)? != request.binding.current
        || router::canonical_digest(&(OUTGOING_LAYOUT, base, &base_outgoing), budget)?
            != request.binding.base_layout
        || visible_spans != request.visible_originals
    {
        return Err(router::invalid(
            "retained base layout or original bytes disagree",
        ));
    }
    Ok((
        CompileAssemblyRequest {
            context: request.context.clone(),
            base: base.clone(),
            budget: request.outgoing_budget,
        },
        visible,
        base_outgoing,
    ))
}

fn reconstruct_units(
    request: &AuthorizedRouterRequest,
    material: &RouterPreparedMaterial,
    preparation: &RouterReplayPreparation,
    tokenizer: &dyn TokenCounter,
    visible: &OriginalInventory,
    budget: &mut QueryBudget,
) -> Result<BTreeMap<BlockId, Unit>> {
    let policy = material
        .prepared_policy
        .as_ref()
        .ok_or_else(|| router::invalid("missing prepared policy"))?;
    charge(
        budget,
        material.evidence.len() as u64 + 1,
        (material.evidence.len() * size_of::<(&EvidenceHandle, &PackEvidence)>()) as u64,
    )?;
    let evidence: BTreeMap<_, _> = material
        .evidence
        .iter()
        .map(|item| (&item.id, item))
        .collect();
    charge(
        budget,
        visible.len() as u64 + 1,
        visible
            .values()
            .flatten()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum(),
    )?;
    let mut all_originals = visible.clone();
    for item in &material.evidence {
        if let (Some(span), Some(text)) = (&item.original_span, &item.excerpt) {
            charge(budget, 1, text.len() as u64)?;
            insert_original(&mut all_originals, span, text.as_bytes())?;
        } else {
            return Err(router::invalid("replay support lacks exact original bytes"));
        }
    }
    let mut units = BTreeMap::new();
    for (index, (unit, candidate)) in request.units.iter().zip(&material.candidates).enumerate() {
        let retained = &preparation.units[index];
        let decisions = &policy.units[index];
        if retained.variants[0].generated {
            // Check the stored marker against the same template as live generation.
            // This never derives a false flag from an Unknown kind or runs preparation.
            let facet = candidate
                .representations
                .first()
                .and_then(|representation| representation.fields.get("missing_facet"))
                .ok_or_else(|| router::invalid("generated marker has no required facet"))?;
            if !request
                .context
                .required_facets
                .iter()
                .any(|requirement| &requirement.name == facet)
                || missing_unknown_candidate(&request.context, facet)?.0 != *candidate
                || decisions.alternatives.iter().any(|decision| {
                    decision.use_action != UseAction::MentionNaturally
                        || decision.directive_reason != DirectiveReason::PolicyAllowsMention
                })
                || !request.mandatory_ids.contains(&unit.id)
                || retained.variants.len() != 1
            {
                return Err(router::invalid(
                    "retained generated marker semantics disagree",
                ));
            }
        }
        let mut variants = Vec::new();
        let representations: BTreeMap<_, _> = candidate
            .representations
            .iter()
            .map(|representation| {
                Ok((
                    router::canonical_digest(representation, budget)?,
                    representation,
                ))
            })
            .collect::<Result<_>>()?;
        for (support, retained) in unit.support_alternatives.iter().zip(&retained.variants) {
            let bytes = router::canonical_bytes(candidate, budget)?.len() as u64;
            charge(budget, 1, bytes * 3)?;
            let representation = representations
                .get(&support.representation_digest)
                .ok_or_else(|| router::invalid("missing retained representation"))?;
            let mut candidate = candidate.clone();
            candidate.evidence_handles = support.evidence_handles.iter().cloned().collect();
            let block = to_block(&candidate, (**representation).clone());
            let evidence: Vec<_> = retained
                .evidence_order
                .iter()
                .map(|handle| {
                    let item = evidence
                        .get(handle)
                        .ok_or_else(|| router::invalid("missing ordered support"))?;
                    let bytes = router::canonical_bytes(*item, budget)?.len() as u64;
                    charge(budget, 1, bytes)?;
                    Ok((*item).clone())
                })
                .collect::<Result<_>>()?;
            let mut counted_block = block.clone();
            counted_block.evidence_handles = retained.block_token_handles.iter().cloned().collect();
            let block_json = serde_json::to_string(&counted_block).map_err(serialization)?;
            charge(budget, 1, block_json.len() as u64)?;
            let evidence_tokens = evidence.iter().try_fold(0_u32, |total, item| {
                let json = serde_json::to_string(item).map_err(serialization)?;
                charge(budget, 1, json.len() as u64)?;
                total
                    .checked_add(tokenizer.count_tokens(&json)?)
                    .ok_or_else(|| router::invalid("replay evidence token overflow"))
            })?;
            if tokenizer.count_tokens(&block_json)? != retained.block_tokens
                || evidence_tokens != retained.evidence_tokens
                || router::canonical_digest(&(&block, &evidence), budget)?
                    != support.material_digest
            {
                return Err(router::invalid(
                    "retained prepared costs or material disagree",
                ));
            }
            let decision = decisions.alternatives[support.index as usize];
            variants.push(PreparedCandidate {
                candidate,
                block,
                evidence,
                use_action: decision.use_action,
                directive_reason: decision.directive_reason,
                block_tokens: retained.block_tokens,
                block_token_handles: Some(counted_block.evidence_handles),
                evidence_tokens: retained.evidence_tokens,
                generated: retained.generated,
            });
        }
        units.insert(
            unit.id.clone(),
            Unit {
                variants,
                dependencies: EvidenceDependencies {
                    hard: unit.hard_dependencies.iter().cloned().collect(),
                    supports: unit
                        .support_alternatives
                        .iter()
                        .map(|support| support.evidence_handles.iter().cloned().collect())
                        .collect(),
                    complements: unit.complements.iter().cloned().collect(),
                },
            },
        );
    }
    Ok(units)
}
