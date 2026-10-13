//! Freeze content-free cost strata before reading annotations or utility masks.

use super::*;

pub(super) const POLICY: &str = "actual-reference-source-and-protocol-cost-controls.v4";
pub(super) type Strata = BTreeMap<(String, usize, Vec<u8>), Vec<usize>>;

fn text_cost(text: &str, budget: &mut QueryBudget) -> Result<Value> {
    charge(budget, 1 + text.len() as u64 / 4096, text.len() as u64)?;
    Ok(serde_json::json!({"bytes": text.len(),
        "reference_tokens": ReferenceTokenizer.count_tokens(text).map_err(|_| invalid())?,
        "escaped_bytes": bytes(&text, MAX_CONDITIONAL_INPUT_BYTES, budget)?.len()}))
}

fn base_shape(base: &Value, budget: &mut QueryBudget) -> Result<Value> {
    let mut zones = BTreeMap::new();
    for zone in ["control", "working", "hot", "current"] {
        let messages = base[zone].as_array().ok_or_else(invalid)?;
        let mut shapes = Vec::new();
        for message in messages {
            shapes.push(
                serde_json::json!({"role": message["role"], "zone": message["zone"],
                "text": text_cost(message["text"].as_str().ok_or_else(invalid)?, budget)?,
                "tool_calls": message["tool_calls"].as_array().ok_or_else(invalid)?.len(),
                "tool_result": !message["tool_result"].is_null()}),
            );
        }
        zones.insert(zone, shapes);
    }
    Ok(serde_json::json!(zones))
}

fn sorted(values: Vec<Value>, budget: &mut QueryBudget) -> Result<Vec<Vec<u8>>> {
    let mut bag = values
        .iter()
        .map(|value| bytes(value, MAX_CONDITIONAL_INPUT_BYTES, budget))
        .collect::<Result<Vec<_>>>()?;
    bag.sort();
    Ok(bag)
}

fn assembly_shape(
    input: &Value,
    witness: &Witness,
    origins: &[SourceInterval],
    budget: &mut QueryBudget,
) -> Result<Value> {
    let mut blocks = Vec::new();
    for block in witness.pack.sections.iter() {
        let choice = witness
            .choices
            .iter()
            .find(|choice| choice.block_id == block.id)
            .ok_or_else(invalid)?;
        blocks.push(serde_json::json!({"kind": block.kind, "level": block.representation.level,
            "alternative": choice.alternative_index, "generated": choice.generated,
            "support_count": block.evidence_handles.len(), "fragment_count": block.exact_fragments.len(),
            "source_class": block.source_class, "trust": block.trust, "taints": block.taints,
            "interpretation": block.interpretation, "epistemic": input["blocks"].as_array()
                .ok_or_else(invalid)?.iter().find(|value| value["kind"] == serde_json::json!(block.kind))
                .ok_or_else(invalid)?["epistemic"]}));
    }
    let mut supports = Vec::new();
    for evidence in &witness.pack.evidence {
        supports.push(serde_json::json!({"primary": evidence.primary, "source_class": evidence.source_class,
            "taints": evidence.taints,
            "original_bytes": evidence.original_span.as_ref().map(|span| span.end - span.start),
            "excerpt_cost": evidence.excerpt.as_deref().map(|text| text_cost(text, budget)).transpose()?}));
    }
    let messages: Vec<_> = witness.messages.iter().map(|message| {
        let lengths: Vec<_> = message.originals.iter().map(|source| source.span.end - source.span.start).collect();
        serde_json::json!({"zone": message.zone, "role": message.role, "original_bytes": lengths,
            "calls": message.tool_calls.len(), "result": message.tool_result.is_some()})
    }).collect();
    let mut original_lengths: Vec<_> = origins
        .iter()
        .map(|source| source.end - source.start)
        .collect();
    original_lengths.sort();
    Ok(
        serde_json::json!({"input_tokens": witness.outgoing.input_tokens,
        "wire_bytes": witness.outgoing.wire.len(), "count_kind": witness.outgoing.count_kind,
        "added_original_bytes": input["added_original_bytes"].as_u64().ok_or_else(invalid)?,
        "usage": input["usage"], "blocks": sorted(blocks, budget)?,
        "supports": sorted(supports, budget)?, "messages": messages, "source_union_bytes": original_lengths}),
    )
}

pub(super) fn freeze(artifacts: &Artifacts, budget: &mut QueryBudget) -> Result<Strata> {
    if artifacts.inputs.len() != MAX_CONTROLLED_ROWS
        || artifacts.observations.len() != MAX_CONTROLLED_ROWS
    {
        return Err(invalid());
    }
    let mut strata = Strata::new();
    let mut bases = BTreeMap::new();
    let mut per_case = BTreeMap::<_, BTreeSet<_>>::new();
    for (index, (input, row)) in artifacts
        .inputs
        .iter()
        .zip(&artifacts.observations)
        .enumerate()
    {
        if input.row_id != row.row_id
            || !row.outgoing_fits
            || !matches!(row.seed_ids.len(), 1 | 2)
            || row.closure_ids != row.seed_ids
        {
            return Err(invalid());
        }
        let base = base_shape(&input.input["base"], budget)?;
        let selected = assembly_shape(
            &input.input["selected"],
            &row.selected,
            &row.selected_origins,
            budget,
        )?;
        let base_key = bytes(&(&base, &selected), MAX_CONDITIONAL_INPUT_BYTES, budget)?;
        if bases
            .get(&row.logical_domain)
            .is_some_and(|old| old != &base_key)
        {
            return Err(BenchError::Integrity(format!(
                "resident base footprints differ in {} at {}",
                row.logical_domain, row.case_id
            )));
        }
        bases.insert(row.logical_domain.clone(), base_key);
        let case = per_case
            .entry((&row.case_id, row.selected_base_digest))
            .or_default();
        if !case.insert(row.seed_ids.clone()) {
            return Err(invalid());
        }
        let key = serde_json::json!({"base": base, "selected": selected,
            "trial": assembly_shape(&input.input["trial"], &row.trial, &row.trial_origins, budget)?,
            "seed_count": row.seed_ids.len(), "closure_count": row.closure_ids.len(),
            "memory_limits": input.input["budget"]["memory"], "outgoing_limits": input.input["budget"]["outgoing"]});
        strata
            .entry((
                row.logical_domain.clone(),
                row.seed_ids.len(),
                bytes(&key, MAX_CONDITIONAL_INPUT_BYTES, budget)?,
            ))
            .or_default()
            .push(index);
    }
    if bases.len() != HISTORY_COUNT || per_case.len() != CASE_COUNT {
        return Err(invalid());
    }
    for proposals in per_case.values() {
        let inventory: BTreeSet<_> = proposals
            .iter()
            .flat_map(|set| set.iter().cloned())
            .collect();
        if inventory.len() != 4
            || proposals.len() != 10
            || proposals.iter().filter(|set| set.len() == 1).count() != 4
            || proposals.iter().filter(|set| set.len() == 2).count() != 6
        {
            return Err(invalid());
        }
    }
    Ok(strata)
}

pub(super) fn join_labels(
    artifacts: &Artifacts,
    strata: &Strata,
    budget: &mut QueryBudget,
) -> Result<()> {
    if artifacts.targets.len() != artifacts.observations.len() {
        return Err(invalid());
    }
    let mut mixed = BTreeSet::new();
    let mut known_bases = BTreeSet::new();
    for ((domain, cardinality, _), members) in strata {
        let mut labels = BTreeSet::new();
        for index in members {
            charge(budget, 1, 0)?;
            let row = &artifacts.observations[*index];
            let target = &artifacts.targets[*index];
            if target.row_id != row.row_id || target.useful.is_some() != target.provenance.is_some()
            {
                return Err(invalid());
            }
            if let Some(useful) = target.useful {
                known_bases.insert((&row.case_id, row.selected_base_digest));
                // Already-resident zero-cost negatives cannot establish a
                // content-versus-cost contrast for an added original.
                if artifacts.inputs[*index].input["trial"]["added_original_bytes"]
                    .as_u64()
                    .ok_or_else(invalid)?
                    > 0
                {
                    labels.insert(useful);
                }
            }
        }
        if labels == BTreeSet::from([false, true]) {
            mixed.insert((domain.as_str(), *cardinality));
        }
    }
    if known_bases.len() != CASE_COUNT || mixed.len() != HISTORY_COUNT * 2 {
        let missing: Vec<_> = artifacts
            .observations
            .iter()
            .map(|row| (row.logical_domain.as_str(), row.seed_ids.len()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|key| !mixed.contains(key))
            .map(|(domain, cardinality)| {
                let case = artifacts
                    .observations
                    .iter()
                    .find(|row| row.logical_domain == domain)
                    .map(|row| row.case_id.as_str())
                    .unwrap_or("unknown");
                (case, cardinality)
            })
            .collect();
        return Err(BenchError::Integrity(format!(
            "known bases {}/{CASE_COUNT}, nonzero mixed cost strata {}/{}, missing {missing:?}",
            known_bases.len(),
            mixed.len(),
            HISTORY_COUNT * 2
        )));
    }
    Ok(())
}
