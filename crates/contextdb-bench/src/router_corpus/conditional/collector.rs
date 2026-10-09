use super::*;
#[cfg(test)]
use contextdb_context::router::RouterSelectionPlan;
use contextdb_core::OriginalSourceSpan;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Exploration {
    ConstantPositive,
    AlwaysStop,
}

struct Pending {
    input: Value,
    seeds: BTreeSet<BlockId>,
    closure: BTreeSet<BlockId>,
    selected: Witness,
    trial: Witness,
}

struct Collector {
    exploration: Exploration,
    rows: Mutex<Vec<Pending>>,
}
impl std::fmt::Debug for Collector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConditionalCollector")
            .field("exploration", &self.exploration)
            .finish_non_exhaustive()
    }
}

impl ContextScorer for Collector {
    fn id(&self) -> &str {
        "contextdb.synthetic-conditional-exploration.v1"
    }
    fn latency_limit_micros(&self) -> u64 {
        5_000_000
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn score(
        &self,
        _: &ScoringUnit,
        _: &mut QueryBudget,
    ) -> contextdb_context::Result<Option<u64>> {
        Err(ContextError::RouterScore(
            "conditional collector requires actual rendered semantics".into(),
        ))
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> contextdb_context::Result<Option<u64>> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| ContextError::Provider("conditional collector lock unavailable".into()))?;
        if rows.len() >= MAX_CONDITIONAL_CALLBACKS {
            return Err(ContextError::BudgetExceeded(
                "conditional callback ceiling".into(),
            ));
        }
        let data = unit.model_input_json(budget)?;
        budget
            .charge(1, data.len() as u64)
            .map_err(context_budget)?;
        let input = serde_json::from_slice(&data).map_err(|_| {
            ContextError::Serialization("conditional semantic JSON is invalid".into())
        })?;
        let selected = capture(unit.selected, budget)?;
        let trial = capture(unit.trial, budget)?;
        budget
            .charge(
                1,
                ((unit.identity.seed_ids.len() + unit.identity.closure_ids.len()) * 256) as u64,
            )
            .map_err(context_budget)?;
        rows.push(Pending {
            input,
            seeds: unit.identity.seed_ids.clone(),
            closure: unit.identity.closure_ids.clone(),
            selected,
            trial,
        });
        Ok(match self.exploration {
            Exploration::ConstantPositive => Some(1_000_000),
            Exploration::AlwaysStop => None,
        })
    }
}

fn context_budget(reason: contextdb_recall::QueryLimit) -> ContextError {
    ContextError::BudgetExceeded(format!("conditional observation allowance: {reason:?}"))
}

fn capture(
    view: SemanticAssemblyView<'_>,
    budget: &mut QueryBudget,
) -> contextdb_context::Result<Witness> {
    if view.wire_bytes > MAX_CONDITIONAL_INPUT_BYTES as u64 {
        return Err(ContextError::BudgetExceeded(
            "conditional observed wire ceiling".into(),
        ));
    }
    // Admit another actual reference encoding before its wire allocation. It
    // uses already-rendered messages and never calls a provider or selector.
    budget.charge(1, view.wire_bytes).map_err(context_budget)?;
    let outgoing = ReferenceOutgoingEncoder(&ReferenceTokenizer).encode(view.messages, budget)?;
    if outgoing.input_tokens != view.input_tokens
        || outgoing.count_kind != RequestCountKind::Exact
        || outgoing.wire.len() as u64 != view.wire_bytes
    {
        return Err(ContextError::Provider(
            "conditional observed reference wire changed".into(),
        ));
    }
    #[derive(Serialize)]
    struct ChoiceRef<'a> {
        block_id: &'a BlockId,
        alternative_index: u32,
        generated: bool,
    }
    budget
        .charge(
            1,
            (view.chosen_variants.len() * size_of::<ChoiceRef<'_>>()) as u64,
        )
        .map_err(context_budget)?;
    let choices: Vec<_> = view
        .chosen_variants
        .iter()
        .map(|item| ChoiceRef {
            block_id: &item.block_id,
            alternative_index: item.alternative_index,
            generated: item.generated,
        })
        .collect();
    let size = bounded(
        &(view.pack, view.messages, &outgoing, &choices),
        MAX_CONDITIONAL_INPUT_BYTES,
        budget,
    )
    .map_err(|_| ContextError::BudgetExceeded("conditional witness ceiling or allowance".into()))?;
    budget
        .charge(1, (size as u64).saturating_mul(2))
        .map_err(context_budget)?;
    Ok(Witness {
        pack: view.pack.clone(),
        messages: view.messages.to_vec(),
        outgoing,
        choices: view
            .chosen_variants
            .iter()
            .map(|item| Choice {
                block_id: item.block_id.clone(),
                alternative_index: item.alternative_index,
                generated: item.generated,
            })
            .collect(),
    })
}

pub(super) struct Collected {
    pub(super) inputs: Vec<Input>,
    pub(super) observations: Vec<Observation>,
    #[cfg(test)]
    pub(super) plan: RouterSelectionPlan,
    #[cfg(test)]
    pub(super) request: router::AuthorizedRouterRequest,
}

pub(super) fn compile_case(case: &fixture::Case, budget: &mut QueryBudget) -> Result<Collected> {
    let collector = Collector {
        exploration: case.exploration,
        rows: Mutex::new(Vec::new()),
    };
    let routed = ContextCompiler::new([7; 32])
        .map_err(|_| invalid())?
        .compile_assembly_with_router(
            &case.request,
            &case.provider,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &collector,
            budget,
        )
        .map_err(|error| {
            #[cfg(test)]
            eprintln!(
                "conditional public fixture {} compile refused: {error}",
                case.id
            );
            match error {
                ContextError::BudgetExceeded(_) => {
                    BenchError::TelemetryBudget("conditional compile allowance exhausted".into())
                }
                _ => invalid(),
            }
        })?;
    routed
        .manifest
        .validate(&routed.request, &routed.plan, &routed.assembly, budget)
        .map_err(|_| invalid())?;
    let pending = collector.rows.into_inner().map_err(|_| invalid())?;
    if pending.is_empty() || pending.len() != routed.plan.scores.len() {
        return Err(invalid());
    }
    let mut inputs = Vec::new();
    let mut observations = Vec::new();
    for (row, score) in pending.into_iter().zip(&routed.plan.scores) {
        let selected_ids = row
            .selected
            .pack
            .sections
            .iter()
            .map(|block| block.id.clone())
            .collect::<BTreeSet<_>>();
        let selected_base_digest = canonical_digest(
            &(
                routed.request.digest,
                &selected_ids,
                &row.selected.pack,
                &row.selected.messages,
                &row.selected.outgoing,
            ),
            budget,
        )
        .map_err(|_| invalid())?;
        charge(budget, row.trial.outgoing.wire.len() as u64 / 4096 + 1, 0)?;
        let trial_wire_digest =
            ContentDigest::from_bytes(*blake3::hash(&row.trial.outgoing.wire).as_bytes());
        let marginal = row
            .trial
            .outgoing
            .input_tokens
            .saturating_sub(row.selected.outgoing.input_tokens);
        if row.seeds.iter().ne(score.seed_ids.iter())
            || row.closure.iter().ne(score.closure_ids.iter())
            || selected_base_digest != score.selected_base_digest
            || trial_wire_digest != score.trial_wire_digest
            || row.trial.outgoing.input_tokens != score.trial_input_tokens
            || marginal != score.marginal_tokens
            || row.input["budget"]["outgoing_fits"].as_bool() != Some(score.outgoing_fits)
            || score.request_digest != routed.request.digest
        {
            return Err(invalid());
        }
        let feature_digest = commitment(&row.input, MAX_CONDITIONAL_INPUT_BYTES, budget)?;
        let row_id = format!("{}:callback:{}", case.id, score.evaluation);
        let selected_origins = origins(&row.selected, budget)?;
        let trial_origins = origins(&row.trial, budget)?;
        observations.push(Observation {
            row_id: row_id.clone(),
            case_id: case.id.clone(),
            logical_domain: case.domain.clone(),
            known_at: case.known_at,
            evaluation: score.evaluation,
            feature_digest,
            request_digest: routed.request.digest,
            selected_base_digest,
            trial_wire_digest,
            outgoing_fits: score.outgoing_fits,
            seed_ids: row.seeds,
            closure_ids: row.closure,
            selected_origins,
            trial_origins,
            selected: row.selected,
            trial: row.trial,
        });
        inputs.push(Input {
            row_id,
            input: row.input,
        });
    }
    Ok(Collected {
        inputs,
        observations,
        #[cfg(test)]
        plan: routed.plan,
        #[cfg(test)]
        request: routed.request,
    })
}

pub(super) fn origins(witness: &Witness, budget: &mut QueryBudget) -> Result<Vec<SourceInterval>> {
    let spans = witness
        .pack
        .evidence
        .iter()
        .filter_map(|item| item.original_span.as_ref())
        .chain(
            witness
                .messages
                .iter()
                .flat_map(|message| message.originals.iter().map(|item| &item.span)),
        );
    union(spans, budget)
}

pub(super) fn union<'a>(
    spans: impl Iterator<Item = &'a OriginalSourceSpan>,
    budget: &mut QueryBudget,
) -> Result<Vec<SourceInterval>> {
    let mut intervals = Vec::new();
    for span in spans {
        if intervals.len() >= 1024 || span.end <= span.start {
            return Err(invalid());
        }
        charge(budget, 1, size_of::<SourceInterval>() as u64)?;
        intervals.push(SourceInterval {
            event_id: span.event_id,
            payload_digest: span.payload_digest,
            start: span.start,
            end: span.end,
        });
    }
    intervals.sort();
    let mut result: Vec<SourceInterval> = Vec::new();
    for interval in intervals {
        if let Some(last) = result.last_mut()
            && last.event_id == interval.event_id
            && last.payload_digest == interval.payload_digest
            && last.end >= interval.start
        {
            last.end = last.end.max(interval.end);
        } else {
            result.push(interval);
        }
    }
    Ok(result)
}
