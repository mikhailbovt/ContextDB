use super::*;
use std::{collections::BTreeSet, fs};

pub(super) use super::super::builtin::files::validate_root;
use super::super::builtin::files::{read_bounded, regular, write_new};

fn decode<T: Serialize + DeserializeOwned>(
    data: &[u8],
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<T> {
    if data.len() > limit {
        return Err(invalid());
    }
    charge(budget, 1, data.len() as u64)?;
    let value: T = serde_json::from_slice(data).map_err(|_| invalid())?;
    if bytes(&value, limit, budget)? != data {
        return Err(invalid());
    }
    Ok(value)
}

fn artifact(data: &[u8], budget: &mut QueryBudget) -> Result<Artifact> {
    charge(budget, data.len() as u64 / 4096 + 1, 0)?;
    Ok(Artifact {
        bytes: data.len() as u64,
        digest: ContentDigest::from_bytes(*blake3::hash(data).as_bytes()),
    })
}

pub(super) fn write(root: &Path, corpus: &Artifacts, budget: &mut QueryBudget) -> Result<()> {
    validate_root(root, false)?;
    validate_counts(corpus, budget)?;
    let mut output = BTreeMap::new();
    output.insert(
        FILES[0],
        bytes(&corpus.inputs, MAX_CONDITIONAL_CORPUS_BYTES, budget)?,
    );
    output.insert(
        FILES[1],
        bytes(&corpus.observations, MAX_CONDITIONAL_CORPUS_BYTES, budget)?,
    );
    output.insert(
        FILES[2],
        bytes(&corpus.targets, MAX_CONDITIONAL_CORPUS_BYTES, budget)?,
    );
    output.insert(
        FILES[3],
        bytes(&corpus.lineage, MAX_CONDITIONAL_CORPUS_BYTES, budget)?,
    );
    let total: usize = output.values().map(Vec::len).sum();
    if total > MAX_CONDITIONAL_CORPUS_BYTES {
        return Err(invalid());
    }
    let mut artifacts = BTreeMap::new();
    for (name, data) in &output {
        artifacts.insert((*name).into(), artifact(data, budget)?);
    }
    let manifest = Manifest {
        format: CONDITIONAL_CORPUS_FORMAT.into(),
        profile: CONDITIONAL_MODEL_PROFILE.into(),
        builder: CONDITIONAL_BUILDER.into(),
        generator: CONDITIONAL_GENERATOR.into(),
        cases: corpus.lineage.cases.len(),
        rows: corpus.inputs.len(),
        artifacts,
    };
    let manifest = bytes(&manifest, 64 * 1024, budget)?;
    if total + manifest.len() > MAX_CONDITIONAL_CORPUS_BYTES {
        return Err(invalid());
    }
    fs::create_dir(root).map_err(|_| invalid())?;
    for (name, data) in output {
        write_new(root, name, &data, budget)?;
    }
    // The manifest is the completion witness. A partial root is never resumed,
    // accepted or overwritten by this entry point.
    write_new(root, "manifest.json", &manifest, budget)
}

pub(super) fn verify(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    validate_root(root, true)?;
    let manifest_bytes = read_bounded(&root.join("manifest.json"), 64 * 1024, budget)?;
    let manifest: Manifest = decode(&manifest_bytes, 64 * 1024, budget)?;
    if manifest.format != CONDITIONAL_CORPUS_FORMAT
        || manifest.profile != CONDITIONAL_MODEL_PROFILE
        || manifest.builder != CONDITIONAL_BUILDER
        || manifest.generator != CONDITIONAL_GENERATOR
        || manifest.cases != fixture::SCENARIOS.len() * 4
        || manifest.cases > MAX_CONDITIONAL_CASES
        || manifest.rows == 0
        || manifest.rows > MAX_CONDITIONAL_ROWS
        || manifest
            .artifacts
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != FILES.into_iter().collect()
    {
        return Err(invalid());
    }
    let permitted: BTreeSet<_> = FILES.into_iter().chain(["manifest.json"]).collect();
    let mut entries = 0;
    for entry in fs::read_dir(root).map_err(|_| invalid())? {
        charge(budget, 1, 0)?;
        entries += 1;
        let path = entry.map_err(|_| invalid())?.path();
        if entries > permitted.len()
            || !permitted.contains(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(invalid)?,
            )
            || !regular(&path)?
        {
            return Err(invalid());
        }
    }
    if entries != permitted.len() {
        return Err(invalid());
    }
    // Admit the complete declared batch before allocating any artifact payload.
    let mut total = manifest_bytes.len() as u64;
    for item in manifest.artifacts.values() {
        total = total.checked_add(item.bytes).ok_or_else(invalid)?;
        if item.bytes == 0
            || item.bytes > MAX_CONDITIONAL_CORPUS_BYTES as u64
            || total > MAX_CONDITIONAL_CORPUS_BYTES as u64
        {
            return Err(invalid());
        }
    }
    let mut loaded = BTreeMap::new();
    for name in FILES {
        let item = &manifest.artifacts[name];
        let data = read_bounded(&root.join(name), item.bytes as usize, budget)?;
        if data.len() as u64 != item.bytes || artifact(&data, budget)? != *item {
            return Err(invalid());
        }
        loaded.insert(name, data);
    }
    let inputs: Vec<Input> = decode(&loaded[FILES[0]], MAX_CONDITIONAL_CORPUS_BYTES, budget)?;
    let observations: Vec<Observation> =
        decode(&loaded[FILES[1]], MAX_CONDITIONAL_CORPUS_BYTES, budget)?;
    let targets: Vec<targets::Target> =
        decode(&loaded[FILES[2]], MAX_CONDITIONAL_CORPUS_BYTES, budget)?;
    let lineage: Lineage = decode(&loaded[FILES[3]], MAX_CONDITIONAL_CORPUS_BYTES, budget)?;
    let corpus = Artifacts {
        inputs,
        observations,
        targets,
        lineage,
    };
    if corpus.inputs.len() != manifest.rows || corpus.lineage.cases.len() != manifest.cases {
        return Err(invalid());
    }
    validate_counts(&corpus, budget)?;
    validate_rows(&corpus, budget)?;
    let expected = build_artifacts(budget)?;
    if expected.lineage != corpus.lineage
        || expected.observations.len() != corpus.observations.len()
    {
        return Err(invalid());
    }
    for (((input, observed), fresh_input), fresh_observed) in corpus
        .inputs
        .iter()
        .zip(&corpus.observations)
        .zip(&expected.inputs)
        .zip(&expected.observations)
    {
        if input.row_id != fresh_input.row_id
            || normalized_input(&input.input, budget)?
                != normalized_input(&fresh_input.input, budget)?
        {
            return Err(invalid());
        }
        bounded(observed, MAX_CONDITIONAL_INPUT_BYTES, budget)?;
        let size = bounded(fresh_observed, MAX_CONDITIONAL_INPUT_BYTES, budget)?;
        charge(budget, 1, (size as u64).saturating_mul(2))?;
        let mut fresh = fresh_observed.clone();
        // This digest commits the originally observed, bounded input, including
        // its volatile allowances; those clocks cannot be recreated cold.
        fresh.feature_digest = observed.feature_digest;
        if &fresh != observed {
            return Err(invalid());
        }
    }
    // Re-evaluate only after input-only callback regeneration. Required proof
    // sets come from the fixed public generator, never the loaded target file.
    let oracle_by_case = fixture::SCENARIOS
        .into_iter()
        .flat_map(|scenario| (0..4_u32).map(move |group| (group, scenario)));
    for (group, scenario) in oracle_by_case {
        let case = fixture::build_case(group, scenario, budget)?;
        let roots = corpus
            .lineage
            .cases
            .iter()
            .find(|item| item.example_id == case.id)
            .ok_or_else(invalid)?
            .roots
            .clone();
        let provenance = RouterLabelProvenance {
            kind: RouterLabelKind::SyntheticSourceSet,
            evaluator_version: targets::EVALUATOR.into(),
            available_at: case.known_at + 1,
            logical_domain: case.domain.clone(),
            source_nodes: roots,
        };
        for (row, target) in corpus
            .observations
            .iter()
            .zip(&corpus.targets)
            .filter(|(row, _)| row.case_id == case.id)
        {
            if targets::label_row(row, &case.oracle, &provenance, budget)? != *target {
                return Err(invalid());
            }
        }
    }
    report(&manifest, &manifest_bytes, &corpus, budget)
}

pub(super) fn validate_rows(corpus: &Artifacts, budget: &mut QueryBudget) -> Result<()> {
    let mut ids = BTreeSet::new();
    let cases: BTreeMap<_, _> = corpus
        .lineage
        .cases
        .iter()
        .map(|case| (&case.example_id, case))
        .collect();
    for ((input, observed), target) in corpus
        .inputs
        .iter()
        .zip(&corpus.observations)
        .zip(&corpus.targets)
    {
        bounded(&input.input, MAX_CONDITIONAL_INPUT_BYTES, budget)?;
        if !ids.insert(&input.row_id)
            || input.row_id != observed.row_id
            || target.row_id != observed.row_id
            || observed.row_id != format!("{}:callback:{}", observed.case_id, observed.evaluation)
            || observed.evaluation == 0
            || observed.evaluation > MAX_CONDITIONAL_CALLBACKS as u32
            || input.input["format"] != SEMANTIC_SCORING_FEATURE_SCHEMA
            || commitment(&input.input, MAX_CONDITIONAL_INPUT_BYTES, budget)?
                != observed.feature_digest
            || target.feature_digest != observed.feature_digest
            || target.evaluation != observed.evaluation
            || target.selected_base_digest != observed.selected_base_digest
            || target.trial_wire_digest != observed.trial_wire_digest
            || input.input["budget"]["outgoing_fits"].as_bool() != Some(observed.outgoing_fits)
        {
            return Err(invalid());
        }
        let case = cases.get(&observed.case_id).ok_or_else(invalid)?;
        if case.logical_domain != observed.logical_domain || case.cutoff != observed.known_at {
            return Err(invalid());
        }
        for key in VOLATILE_KEYS {
            let value = input.input["budget"][key].as_u64().ok_or_else(invalid)?;
            let cap = match key {
                "remaining_work" => 100_000,
                "remaining_bytes" => 16 * 1024 * 1024,
                "remaining_timeout_micros" => 30_000_000,
                "remaining_scorer_work" => 64 * 1024,
                "remaining_scorer_micros" => 5_000_000,
                "remaining_evaluations" => 64,
                _ => return Err(invalid()),
            };
            if value > cap {
                return Err(invalid());
            }
        }
        for witness in [&observed.selected, &observed.trial] {
            bounded(witness, MAX_CONDITIONAL_INPUT_BYTES, budget)?;
            witness.pack.validate().map_err(|_| invalid())?;
            charge(budget, 1, witness.outgoing.wire.len() as u64)?;
            if ReferenceOutgoingEncoder(&ReferenceTokenizer)
                .encode(&witness.messages, budget)
                .map_err(|_| invalid())?
                != witness.outgoing
                || witness.outgoing.count_kind != RequestCountKind::Exact
            {
                return Err(invalid());
            }
            for span in witness
                .pack
                .evidence
                .iter()
                .filter_map(|item| item.original_span.as_ref())
                .chain(
                    witness
                        .messages
                        .iter()
                        .flat_map(|message| message.originals.iter().map(|item| &item.span)),
                )
            {
                let reference = RouterLineageRef {
                    kind: RouterLineageKind::SourceVersion,
                    domain: observed.logical_domain.clone(),
                    id: span.event_id.to_string(),
                    version: Some(span.payload_digest.to_string()),
                };
                if !case.roots.contains(&reference) {
                    return Err(invalid());
                }
            }
        }
        let selected = observed
            .selected
            .pack
            .sections
            .iter()
            .map(|block| block.id.clone())
            .collect::<BTreeSet<_>>();
        if canonical_digest(
            &(
                observed.request_digest,
                &selected,
                &observed.selected.pack,
                &observed.selected.messages,
                &observed.selected.outgoing,
            ),
            budget,
        )
        .map_err(|_| invalid())?
            != observed.selected_base_digest
            || artifact(&observed.trial.outgoing.wire, budget)?.digest != observed.trial_wire_digest
            || collector::origins(&observed.selected, budget)? != observed.selected_origins
            || collector::origins(&observed.trial, budget)? != observed.trial_origins
        {
            return Err(invalid());
        }
        if target.useful.is_some() != target.provenance.is_some() {
            return Err(invalid());
        }
        if let Some(provenance) = &target.provenance {
            let node = corpus
                .lineage
                .nodes
                .iter()
                .find(|node| {
                    node.reference
                        == (RouterLineageRef {
                            kind: RouterLineageKind::Evaluation,
                            domain: observed.logical_domain.clone(),
                            id: format!("source-label:{}", observed.case_id),
                            version: Some("v1".into()),
                        })
                })
                .ok_or_else(invalid)?;
            if provenance.kind != RouterLabelKind::SyntheticSourceSet
                || provenance.evaluator_version != targets::EVALUATOR
                || provenance.available_at != observed.known_at + 1
                || provenance.available_at != node.available_at
                || provenance.logical_domain != observed.logical_domain
                || provenance.source_nodes != case.roots
                || node.parents != case.roots
            {
                return Err(invalid());
            }
        }
    }
    if assign_router_group_time_split(
        &corpus.lineage.nodes,
        &corpus.lineage.cases,
        &corpus.lineage.split,
        budget,
    )? != corpus.lineage.assignments
    {
        return Err(invalid());
    }
    Ok(())
}

fn report(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    corpus: &Artifacts,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    let mut supervised = BTreeSet::new();
    let mut supervised_per_fold = BTreeMap::new();
    let assigned: BTreeMap<_, _> = corpus
        .lineage
        .assignments
        .iter()
        .map(|row| (&row.example_id, row.partition))
        .collect();
    for (row, target) in corpus.observations.iter().zip(&corpus.targets) {
        if target.useful.is_some() {
            supervised.insert((&row.case_id, row.selected_base_digest));
        }
    }
    for (case, _) in &supervised {
        let partition = assigned.get(case).ok_or_else(invalid)?;
        let key = match partition {
            RouterPartition::Train => "train",
            RouterPartition::Validation => "validation",
            RouterPartition::Test => "test",
            RouterPartition::Quarantined => "quarantined",
        };
        *supervised_per_fold.entry(key).or_insert(0usize) += 1;
    }
    if supervised_per_fold.values().any(|count| *count > 64) {
        return Err(invalid());
    }
    let count = |partition| {
        corpus
            .lineage
            .assignments
            .iter()
            .filter(|row| row.partition == partition)
            .count()
    };
    Ok(ConditionalRouterCorpusReport {
        format: manifest.format.clone(),
        model_profile: manifest.profile.clone(),
        manifest_digest: artifact(manifest_bytes, budget)?.digest,
        cases: manifest.cases,
        rows: manifest.rows,
        supervised_groups: supervised.len(),
        positive: corpus
            .targets
            .iter()
            .filter(|item| item.useful == Some(true))
            .count(),
        negative: corpus
            .targets
            .iter()
            .filter(|item| item.useful == Some(false))
            .count(),
        unknown: corpus
            .targets
            .iter()
            .filter(|item| item.useful.is_none())
            .count(),
        train: count(RouterPartition::Train),
        validation: count(RouterPartition::Validation),
        test: count(RouterPartition::Test),
        quarantined: count(RouterPartition::Quarantined),
        reference_source_wire: "verified:public-synthetic-reference-observations",
        volatile_allowance_replayed: false,
        reader_benefit_measured: false,
        private_intake_available: false,
    })
}
