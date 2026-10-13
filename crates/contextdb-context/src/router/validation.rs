use super::*;
use contextdb_core::{AcceptanceState, LifecycleState};

fn ordered<T: Ord>(items: &[T], bound: usize) -> Result<()> {
    if items.len() > bound || items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("unordered, duplicate or excessive identities"));
    }
    Ok(())
}

fn text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 16384 || value.chars().any(char::is_control) {
        return Err(invalid("missing or excessive revision identity"));
    }
    Ok(())
}

fn probability(value: Option<f64>, allow_zero: bool) -> Result<()> {
    if value.is_some_and(|value| {
        !value.is_finite()
            || value > 1.0
            || if allow_zero {
                value < 0.0
            } else {
                value <= 0.0
            }
    }) {
        return Err(invalid("invalid uncertainty or propensity"));
    }
    Ok(())
}

pub(crate) fn span_key(
    span: &OriginalSourceSpan,
) -> (contextdb_core::ObservationId, ContentDigest, u64, u64) {
    (span.event_id, span.payload_digest, span.start, span.end)
}

pub(crate) fn normalize_spans(spans: &mut Vec<OriginalSourceSpan>) {
    spans.sort_by_key(span_key);
    spans.dedup();
}

fn spans(values: &[OriginalSourceSpan], bound: usize) -> Result<()> {
    if values.len() > bound
        || values.iter().any(|span| span.start >= span.end)
        || values
            .windows(2)
            .any(|pair| span_key(&pair[0]) >= span_key(&pair[1]))
    {
        return Err(invalid("invalid or duplicate original inventory"));
    }
    // Across different units, equal and overlapping original ranges are legal.
    // Byte consistency is checked against the owner when the request is rebuilt.
    Ok(())
}

impl RouterBinding {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.owner.snapshot,
            &self.owner.authorization,
            &self.owner.state,
            &self.tokenizer,
            &self.encoder,
            &self.scorer,
            &self.scorer_revision,
        ] {
            text(value)?;
        }
        let text_calls = if self.feature_schema == FEATURE_SCHEMA {
            0
        } else if self.feature_schema == crate::SEMANTIC_SCORING_FEATURE_SCHEMA {
            self.max_evaluations
        } else {
            return Err(invalid("unsupported semantic feature profile"));
        };
        if self.descriptor_schema != DESCRIPTOR_SCHEMA
            || self.max_evaluations == 0
            || self.max_evaluations as usize > MAX_SCORES
            || self.max_record_bytes as usize != MAX_RECORD_BYTES
        {
            return Err(invalid("unsupported feature schema or bounds"));
        }
        if self.max_scorer_work != u64::from(self.max_evaluations) * 1024
            || self.max_scorer_micros == 0
            || self.max_scorer_micros > 10_000_000
            || self.max_prepare_micros != 30_000_000
            || self.max_text_rerank_pairs != text_calls
        {
            return Err(invalid("unsupported scorer work or latency profile"));
        }
        Ok(())
    }
}

impl AuthorizedRouterRequest {
    /// Structural integrity only. Authority is established again by the compiler
    /// and provider, including a fresh publication-owner read-set validation.
    pub fn validate(&self, budget: &mut QueryBudget) -> Result<()> {
        charge(budget, self.units.len() as u64 + 1, 0)?;
        if self.format != REQUEST_FORMAT || self.units.len() > MAX_UNITS {
            return Err(invalid("unsupported request version or frontier"));
        }
        if self.discovery_complete.is_some() || self.capture_complete.is_some() {
            return Err(invalid(
                "this compiler profile cannot attest discovery or capture completion",
            ));
        }
        self.binding.validate()?;
        self.context.validate()?;
        if self.pack_id != self.context.pack_id
            || self.binding.compile_request != canonical_digest(&self.context, budget)?
            || self.binding.budgets
                != canonical_digest(
                    &(
                        &self.context.budgets,
                        self.outgoing_budget,
                        self.context.model_profile.reserved_output_tokens,
                    ),
                    budget,
                )?
        {
            return Err(invalid("context or budget commitment disagrees"));
        }
        let mut occurrence_ids = BTreeSet::new();
        if self.working_state.len() + self.hot_window.len() + self.current_turn.len() > 256 {
            return Err(invalid("excessive source-backed layout"));
        }
        for occurrence in self
            .working_state
            .iter()
            .chain(&self.hot_window)
            .chain(&self.current_turn)
        {
            if !occurrence_ids.insert(&occurrence.id)
                || matches!(
                    occurrence.role,
                    crate::OutgoingRole::System | crate::OutgoingRole::Developer
                )
                || occurrence.originals.is_empty()
                || occurrence.originals.len() > 128
            {
                return Err(invalid("invalid source-backed layout role or identity"));
            }
            let mut last_end = 0;
            for original in &occurrence.originals {
                if original.text_start < last_end
                    || original.text_end <= original.text_start
                    || original.span.end <= original.span.start
                    || original.text_end - original.text_start
                        != original.span.end - original.span.start
                {
                    return Err(invalid("duplicate or overlapping occurrence spans"));
                }
                last_end = original.text_end;
            }
        }
        ordered(&self.mandatory_ids, MAX_UNITS)?;
        spans(&self.visible_originals, 32768)?;
        if self.units.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid("duplicate or unordered units"));
        }
        let units: BTreeMap<_, _> = self.units.iter().map(|unit| (&unit.id, unit)).collect();
        for id in &self.mandatory_ids {
            if !units.contains_key(id) {
                return Err(invalid("unknown mandatory unit"));
            }
        }
        for unit in &self.units {
            text(unit.id.as_str())?;
            ordered(&unit.scopes, 32)?;
            ordered(&unit.facets, 512)?;
            ordered(&unit.claim_ids, 512)?;
            ordered(&unit.hard_dependencies, 64)?;
            ordered(&unit.complements, 16)?;
            if unit.scopes.is_empty()
                || unit.instruction_capability != InstructionCapability::None
                || unit.support_alternatives.is_empty()
                || unit.support_alternatives.len() > 8
            {
                return Err(invalid("invalid unit role, scope or support"));
            }
            if unit
                .scopes
                .iter()
                .any(|scope| !self.context.scopes.contains(scope))
                || unit.known_at_commit > self.context.snapshot.commit_seq
            {
                return Err(invalid("unit exceeds current scope or knowledge view"));
            }
            for value in unit.scopes.iter().chain(&unit.facets) {
                text(value)?;
            }
            if unit.render_role == RouterRenderRole::CurrentState
                && (!unit.epistemic.acceptance.is_published()
                    || unit.epistemic.lifecycle != LifecycleState::Active
                    || unit.interpretation == InterpretationRule::HistoricalData)
            {
                return Err(invalid(
                    "proposal or historical data promoted to current state",
                ));
            }
            if unit.epistemic.acceptance == AcceptanceState::Proposed
                && !matches!(
                    unit.render_role,
                    RouterRenderRole::Proposal
                        | RouterRenderRole::Evidence
                        | RouterRenderRole::Unknown
                        | RouterRenderRole::Conflict
                )
            {
                return Err(invalid("proposed data has an invalid render role"));
            }
            let descriptor = &unit.descriptor;
            if descriptor.schema != DESCRIPTOR_SCHEMA
                || descriptor.confidence_micros > 1_000_000
                || descriptor.embedding_reference.is_some()
                    != descriptor.embedding_revision.is_some()
            {
                return Err(invalid("invalid descriptor schema or masks"));
            }
            probability(descriptor.uncertainty, true)?;
            ordered(&descriptor.missing_features, 32)?;
            if descriptor.missing_features.iter().any(|value| {
                !matches!(
                    value.as_str(),
                    "embedding" | "uncertainty" | "retrieval_score" | "index_coverage"
                )
            }) || descriptor
                .missing_features
                .iter()
                .any(|value| value == "embedding")
                != descriptor.embedding_reference.is_none()
                || descriptor
                    .missing_features
                    .iter()
                    .any(|value| value == "uncertainty")
                    != descriptor.uncertainty.is_none()
                || descriptor
                    .missing_features
                    .iter()
                    .any(|value| value == "retrieval_score")
                    != descriptor.retrieval_score.is_none()
                || descriptor
                    .missing_features
                    .iter()
                    .any(|value| value == "index_coverage")
                    != descriptor.index_complete.is_none()
            {
                return Err(invalid("descriptor missing masks disagree"));
            }
            if let Some(revision) = &descriptor.embedding_revision {
                text(revision)?;
            }
            let mut support_identities = BTreeSet::new();
            for (index, alternative) in unit.support_alternatives.iter().enumerate() {
                charge(budget, 1, 0)?;
                if alternative.index as usize != index {
                    return Err(invalid("duplicate support alternative"));
                }
                if !support_identities.insert((
                    alternative.representation_digest,
                    alternative.material_digest,
                    &alternative.evidence_handles,
                )) {
                    return Err(invalid("duplicate sufficient support identity"));
                }
                ordered(&alternative.evidence_handles, 64)?;
                ordered(&alternative.hard_closure, MAX_UNITS)?;
                ordered(&alternative.omitted_facets, 512)?;
                if !alternative.hard_closure.contains(&unit.id)
                    || unit
                        .hard_dependencies
                        .iter()
                        .any(|id| !alternative.hard_closure.contains(id))
                    || alternative
                        .hard_closure
                        .iter()
                        .any(|id| !units.contains_key(id))
                    || alternative
                        .omitted_facets
                        .iter()
                        .any(|facet| !unit.facets.contains(facet))
                {
                    return Err(invalid(
                        "incomplete support hard closure or representation facets",
                    ));
                }
                for id in &alternative.evidence_handles {
                    text(id.as_str())?;
                }
                spans(&alternative.originals, 64)?;
            }
            for id in unit.hard_dependencies.iter().chain(&unit.complements) {
                if !units.contains_key(id) {
                    return Err(invalid("dependency is not authorized or available"));
                }
            }
        }
        // Bounded iterative topological elimination avoids a recursion-depth risk.
        let mut resolved = BTreeSet::new();
        loop {
            let before = resolved.len();
            for unit in &self.units {
                charge(budget, 1, 0)?;
                if unit
                    .hard_dependencies
                    .iter()
                    .all(|id| resolved.contains(id))
                {
                    resolved.insert(unit.id.clone());
                }
            }
            if resolved.len() == self.units.len() {
                break;
            }
            if before == resolved.len() {
                return Err(invalid("hard dependency cycle"));
            }
        }
        if self.binding.candidates != canonical_digest(&self.units, budget)?
            || self.binding.mandatory != canonical_digest(&self.mandatory_ids, budget)?
            || self.digest != self.content_digest(budget)?
        {
            return Err(invalid("request inventory commitment disagrees"));
        }
        Ok(())
    }
}

impl RouterScore {
    /// Adapt utility on an already priced proposal. Missing trial prices cannot
    /// be invented as zero; production execution independently checks them.
    pub fn with_finite_utility(mut self, value: Option<f64>) -> Result<Self> {
        ordered(&self.seed_ids, 2)?;
        if self.seed_ids.is_empty() || self.evaluation == 0 || self.evaluation as usize > MAX_SCORES
        {
            return Err(invalid("empty score seeds"));
        }
        self.utility_micros = value
            .map(finite_micros)
            .transpose()?
            .filter(|value| *value > 0);
        Ok(self)
    }
}

impl RouterSelectionPlan {
    pub fn validate(
        &self,
        request: &AuthorizedRouterRequest,
        budget: &mut QueryBudget,
    ) -> Result<()> {
        request.validate(budget)?;
        charge(budget, self.scores.len() as u64 + 1, 0)?;
        if self.format != PLAN_FORMAT
            || self.binding != request.binding
            || self.request_digest != request.digest
            || self.scores.len() > MAX_SCORES
        {
            return Err(invalid("stale plan binding or version"));
        }
        ordered(&self.seed_ids, MAX_UNITS)?;
        ordered(&self.selected_ids, MAX_UNITS)?;
        ordered(&self.covered_facets, 512)?;
        ordered(&self.evidence_handles, 2048)?;
        spans(&self.visible_originals, 32768)?;
        probability(self.behavior_propensity, false)?;
        let units: BTreeMap<_, _> = request.units.iter().map(|unit| (&unit.id, unit)).collect();
        let selected: BTreeSet<_> = self.selected_ids.iter().collect();
        if self.choices.len() != self.selected_ids.len()
            || self.choices.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || request
                .mandatory_ids
                .iter()
                .any(|id| !selected.contains(id))
            || self.seed_ids.iter().any(|id| !selected.contains(id))
        {
            return Err(invalid("missing mandatory closure or duplicate choice"));
        }
        let mut expected: BTreeSet<_> = request.mandatory_ids.iter().cloned().collect();
        expected.extend(self.seed_ids.iter().cloned());
        loop {
            let before = expected.len();
            for id in expected.clone() {
                let unit = units
                    .get(&id)
                    .ok_or_else(|| invalid("unknown selected unit"))?;
                expected.extend(unit.hard_dependencies.iter().cloned());
            }
            if expected.len() == before {
                break;
            }
        }
        // Conflict expansion is independently checked by production execution.
        if expected.iter().any(|id| !selected.contains(id)) {
            return Err(invalid("missing hard dependency"));
        }
        match self.decision {
            RouterDecision::Stop
                if !self.seed_ids.is_empty() || self.selected_ids != request.mandatory_ids =>
            {
                return Err(invalid("STOP changes mandatory closure"));
            }
            RouterDecision::Select
                if self.seed_ids.is_empty()
                    || self.selected_ids == request.mandatory_ids
                    || self
                        .seed_ids
                        .iter()
                        .any(|id| request.mandatory_ids.contains(id)) =>
            {
                return Err(invalid("SELECT has no discretionary addition"));
            }
            _ => {}
        }
        for (id, choice) in self.selected_ids.iter().zip(&self.choices) {
            let unit = units
                .get(id)
                .ok_or_else(|| invalid("unknown selected unit"))?;
            let alternative = unit
                .support_alternatives
                .get(choice.alternative_index as usize)
                .ok_or_else(|| invalid("unknown support alternative"))?;
            if choice.id != *id
                || choice.representation_digest != alternative.representation_digest
                || choice.material_digest != alternative.material_digest
            {
                return Err(invalid("representation or support commitment disagrees"));
            }
        }
        let mut evaluations = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for score in &self.scores {
            ordered(&score.seed_ids, 2)?;
            ordered(&score.closure_ids, MAX_UNITS)?;
            ordered(&score.new_facets, 512)?;
            if score.evaluation == 0
                || score.evaluation > request.binding.max_evaluations
                || !evaluations.insert(score.evaluation)
                || score.seed_ids.is_empty()
                || !identities.insert((score.selected_base_digest, &score.seed_ids))
                || score.request_digest != request.digest
                || score
                    .seed_ids
                    .iter()
                    .chain(&score.closure_ids)
                    .any(|id| !units.contains_key(id))
            {
                return Err(invalid("unknown, duplicate or stale score"));
            }
            probability(score.uncertainty, true)?;
            probability(score.behavior_propensity, false)?;
            if let Some(calibration) = &score.calibration {
                text(calibration)?;
            }
        }
        if self
            .scores
            .windows(2)
            .any(|pair| pair[0].evaluation >= pair[1].evaluation)
            || self.usage.selection_evaluations > request.binding.max_evaluations
        {
            return Err(invalid("invalid evaluation order or work ceiling"));
        }
        canonical_bytes(self, budget)?;
        Ok(())
    }
}
