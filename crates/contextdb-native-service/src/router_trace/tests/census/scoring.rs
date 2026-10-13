//! Bounded observation of actual installed semantic callbacks.

use super::*;

struct CountingWriter {
    bytes: usize,
    limit: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(input.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "census byte overflow"))?;
        if next > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "census serialized byte ceiling",
            ));
        }
        self.bytes = next;
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn bound<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<usize> {
    charge(budget, 1, 0)?;
    let mut writer = CountingWriter { bytes: 0, limit };
    serde_json::to_writer(&mut writer, value).map_err(|_| invalid())?;
    charge(budget, writer.bytes as u64 / 4096 + 1, 0)?;
    Ok(writer.bytes)
}

pub(super) fn bytes<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<Vec<u8>> {
    let size = bound(value, limit, budget)?;
    charge(budget, 1, (size as u64).saturating_mul(2))?;
    let data = serde_json::to_vec(value).map_err(|_| invalid())?;
    if data.len() != size {
        return Err(invalid());
    }
    Ok(data)
}

fn capture(view: SemanticAssemblyView<'_>, budget: &mut QueryBudget) -> Result<Witness> {
    if view.wire_bytes > MAX_INPUT as u64 || view.chosen_variants.len() > 512 {
        return Err(invalid());
    }
    // Only already-rendered messages are encoded; there is no provider read or
    // second selection. Admit the real wire allocation before the encoder.
    charge(budget, 1, view.wire_bytes)?;
    let outgoing = ReferenceOutgoingEncoder(&ReferenceTokenizer).encode(view.messages, budget)?;
    if outgoing.input_tokens != view.input_tokens
        || outgoing.count_kind != RequestCountKind::Exact
        || outgoing.wire.len() as u64 != view.wire_bytes
    {
        return Err(invalid());
    }
    #[derive(Serialize)]
    struct ChoiceRef<'a> {
        block_id: &'a BlockId,
        alternative_index: u32,
        generated: bool,
    }
    charge(
        budget,
        1,
        (view.chosen_variants.len() * size_of::<ChoiceRef<'_>>()) as u64,
    )?;
    let choices: Vec<_> = view
        .chosen_variants
        .iter()
        .map(|choice| ChoiceRef {
            block_id: &choice.block_id,
            alternative_index: choice.alternative_index,
            generated: choice.generated,
        })
        .collect();
    let size = bound(
        &(view.pack, view.messages, &outgoing, &choices),
        MAX_INPUT,
        budget,
    )?;
    charge(budget, 1, (size as u64).saturating_mul(2))?;
    Ok(Witness {
        pack: view.pack.clone(),
        messages: view.messages.to_vec(),
        outgoing,
        choices: view
            .chosen_variants
            .iter()
            .map(|choice| Choice {
                block_id: choice.block_id.clone(),
                alternative_index: choice.alternative_index,
                generated: choice.generated,
            })
            .collect(),
    })
}

impl ContextScorer for Collector {
    fn id(&self) -> &str {
        GENERATOR
    }
    fn revision(&self) -> &str {
        "public-native-sizing-v1"
    }
    fn latency_limit_micros(&self) -> u64 {
        9_000_000
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn failure_policy(&self) -> ScorerFailurePolicy {
        ScorerFailurePolicy::Refuse
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<u64>> {
        Err(ContextError::RouterScore(
            "sizing requires the native semantic route".into(),
        ))
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        let mut rows = self.rows.lock().map_err(|_| invalid())?;
        if rows.len() >= MAX_CASE_ROWS {
            return Err(invalid());
        }
        // This callback is entered only after the installed CurrentScorer has
        // admitted ModelProcessing, whole current source controls and natural
        // text. No caller flag can route an arbitrary archive into this fixture.
        let data = unit.model_input_json(budget)?;
        if data.len() > MAX_INPUT {
            return Err(invalid());
        }
        charge(budget, 1, (data.len() as u64).saturating_mul(2))?;
        let input = serde_json::from_slice(&data).map_err(|_| invalid())?;
        let selected = capture(unit.selected, budget)?;
        let trial = capture(unit.trial, budget)?;
        let size = bound(
            &(unit.identity.seed_ids, unit.identity.closure_ids),
            MAX_INPUT,
            budget,
        )?;
        charge(budget, 1, (size as u64).saturating_mul(2))?;
        rows.push(Pending {
            input,
            seeds: unit.identity.seed_ids.clone(),
            closure: unit.identity.closure_ids.clone(),
            selected,
            trial,
        });
        Ok(match self.exploration {
            Exploration::AlwaysStop => None,
            Exploration::ConstantPositive => Some(1_000_000),
        })
    }
}
