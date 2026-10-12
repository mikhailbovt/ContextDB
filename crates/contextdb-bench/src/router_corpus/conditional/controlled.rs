//! Fixed source-backed resident controls, with post-callback interval labels.
//! Authored programs are correlated synthetic cases, not real conversations.

mod controls;
mod fixture;

use super::*;

pub const CONTROLLED_CORPUS_FORMAT: &str = "contextdb.router-corpus.controlled-resident.v4";
pub const CONTROLLED_DATA_PROFILE: &str = "contextdb.kev-public-controlled-resident-data.v4";
pub const CONTROLLED_BUILDER: &str = "contextdb.router-controlled-resident-builtin.v4";
pub const CONTROLLED_GENERATOR: &str = "contextdb.router-controlled-resident-synthetic.v4";
pub const MAX_CONTROLLED_ROWS: usize = 480;
const EVALUATOR: &str = "synthetic-controlled-resident-source-coverage.v4";
const HISTORY_COUNT: usize = 16;
const CASE_COUNT: usize = 48;
const QUERIES: &str = include_str!("controlled/queries.json");
const ANNOTATIONS: &str = include_str!("controlled/annotations.json");
const ANCESTRY: &str = include_str!("controlled/ancestry.json");

const PROFILE: files::Profile = files::Profile {
    format: CONTROLLED_CORPUS_FORMAT,
    model: CONTROLLED_DATA_PROFILE,
    builder: CONTROLLED_BUILDER,
    generator: CONTROLLED_GENERATOR,
    evaluator: EVALUATOR,
    revision: "v4",
    cases: CASE_COUNT,
    max_rows: MAX_CONTROLLED_ROWS,
    build,
    validate,
    metadata,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Queries {
    format: String,
    histories: Vec<History>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Annotations {
    format: String,
    recipes: Vec<Annotation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ancestry {
    format: String,
    shared_research_schema: String,
    claims_independent_real_conversations: bool,
    claims_statistical_independence: bool,
    histories: Vec<HistoryAncestry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryAncestry {
    history_id: String,
    partition: RouterPartition,
    authored_program_family: String,
    content_template_ancestors: Vec<String>,
    seed_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    id: String,
    partition: RouterPartition,
    family: String,
    program: String,
    working: String,
    query: String,
    cutoff: u64,
    originals: Vec<OriginalSeed>,
    candidate_source_ids: Vec<String>,
    probes: Vec<Probe>,
    tool_bindings: Vec<ToolBinding>,
    content_template_ancestors: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalSeed {
    id: String,
    role: String,
    text: String,
    known_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    id: String,
    resident_source_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolBinding {
    call_source_id: String,
    result_source_id: String,
    tool_call_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Annotation {
    history_id: String,
    rule: String,
    sufficient_source_sets: Vec<Vec<String>>,
}

impl History {
    fn domain(&self) -> String {
        format!(
            "synthetic:controlled:{}",
            super::fixture::stable_uuid(&format!("v4:{}", self.id))
        )
    }
    fn case_id(&self, probe: &Probe) -> String {
        format!("{}-{}", self.id, probe.id)
    }
    fn original(&self, id: &str) -> Result<&OriginalSeed> {
        self.originals
            .iter()
            .find(|source| source.id == id)
            .ok_or_else(invalid)
    }
}

fn asset<T: DeserializeOwned>(text: &str, budget: &mut QueryBudget) -> Result<T> {
    if text.len() > MAX_CONDITIONAL_INPUT_BYTES {
        return Err(invalid());
    }
    charge(budget, 1, (text.len() as u64).saturating_mul(2))?;
    serde_json::from_str(text).map_err(|_| invalid())
}

fn histories(budget: &mut QueryBudget) -> Result<Vec<History>> {
    let queries: Queries = asset(QUERIES, budget)?;
    if queries.format != "contextdb.router-controlled-resident-queries.v4" {
        return Err(invalid());
    }
    let histories = queries.histories;
    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut folds = BTreeMap::new();
    let mut tool_folds = BTreeMap::new();
    if histories.len() != HISTORY_COUNT {
        return Err(invalid());
    }
    for history in &histories {
        let originals: BTreeSet<_> = history.originals.iter().map(|source| &source.id).collect();
        let roster: BTreeSet<_> = history.candidate_source_ids.iter().collect();
        let fold = match history.partition {
            RouterPartition::Train => "train",
            RouterPartition::Validation => "validation",
            _ => return Err(invalid()),
        };
        if !ids.insert(&history.id)
            || !families.insert(&history.family)
            || !matches!(history.program.as_str(), "regular" | "supersession")
            || history.cutoff != 8
            || history.query.is_empty()
            || history.query.len() > 2048
            || history.working.is_empty()
            || history.working.len() > 2048
            || !history.content_template_ancestors.is_empty()
            || originals.len() != history.originals.len()
            || roster.len() != 4
            || history.candidate_source_ids.len() != 4
            || !roster.is_subset(&originals)
            || history.originals.iter().any(|source| {
                source.text.is_empty()
                    || source.text.len() > 2048
                    || source.known_at == 0
                    || source.known_at >= history.cutoff
                    || !matches!(source.role.as_str(), "user" | "assistant" | "tool")
            })
            || history
                .originals
                .windows(2)
                .any(|pair| pair[0].known_at >= pair[1].known_at)
            || history.candidate_source_ids.windows(2).any(|pair| {
                history.original(&pair[0]).map(|a| a.known_at).ok()
                    >= history.original(&pair[1]).map(|a| a.known_at).ok()
            })
            || history.probes.len() != 3
            || history
                .probes
                .iter()
                .map(|probe| probe.id.as_str())
                .collect::<BTreeSet<_>>()
                != BTreeSet::from([
                    "sufficient",
                    if history.program == "regular" {
                        "irrelevant"
                    } else {
                        "stale"
                    },
                    "partial",
                ])
        {
            return Err(invalid());
        }
        let mut residents = BTreeSet::new();
        for probe in &history.probes {
            let set: BTreeSet<_> = probe.resident_source_ids.iter().collect();
            if set.len() != 2
                || probe.resident_source_ids.len() != 2
                || !set.is_subset(&roster)
                || !residents.insert(set)
            {
                return Err(invalid());
            }
        }
        let mut calls = BTreeSet::new();
        let mut results = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        for binding in &history.tool_bindings {
            let call = history.original(&binding.call_source_id)?;
            let result = history.original(&binding.result_source_id)?;
            if call.role != "assistant"
                || result.role != "tool"
                || call.known_at >= result.known_at
                || roster.contains(&call.id)
                || !roster.contains(&result.id)
                || binding.tool_call_id.is_empty()
                || binding.tool_call_id.len() > 128
                || !calls.insert(&call.id)
                || !results.insert(&result.id)
                || !bindings.insert(&binding.tool_call_id)
            {
                return Err(invalid());
            }
        }
        let expected_originals = if bindings.is_empty() { 4 } else { 6 };
        if history.originals.len() != expected_originals
            || (!bindings.is_empty() && bindings.len() != 2)
            || history
                .originals
                .iter()
                .any(|source| match source.role.as_str() {
                    "user" => !roster.contains(&source.id),
                    "assistant" => !calls.contains(&source.id),
                    "tool" => !results.contains(&source.id),
                    _ => true,
                })
        {
            return Err(invalid());
        }
        *folds
            .entry((fold, history.program.as_str()))
            .or_insert(0usize) += 1;
        if !bindings.is_empty() {
            *tool_folds
                .entry((fold, history.program.as_str()))
                .or_insert(0usize) += 1;
        }
    }
    if folds
        != BTreeMap::from([
            (("train", "regular"), 4),
            (("train", "supersession"), 4),
            (("validation", "regular"), 4),
            (("validation", "supersession"), 4),
        ])
        || tool_folds.len() != 4
        || tool_folds.values().any(|count| *count == 0)
    {
        return Err(invalid());
    }
    Ok(histories)
}

fn ancestry(histories: &[History], budget: &mut QueryBudget) -> Result<Ancestry> {
    let ancestry: Ancestry = asset(ANCESTRY, budget)?;
    if ancestry.format != "contextdb.router-controlled-resident-ancestry.v4"
        || ancestry.shared_research_schema != "three-resident-four-candidate-cost-controls.v4"
        || ancestry.claims_independent_real_conversations
        || ancestry.claims_statistical_independence
        || ancestry.histories.len() != histories.len()
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for row in &ancestry.histories {
        let history = histories
            .iter()
            .find(|history| history.id == row.history_id)
            .ok_or_else(invalid)?;
        if !seen.insert(&row.history_id)
            || row.partition != history.partition
            || row.authored_program_family != history.family
            || row.content_template_ancestors != history.content_template_ancestors
            || row.seed_sha256.len() != 64
            || !row
                .seed_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
    }
    Ok(ancestry)
}

fn metadata(budget: &mut QueryBudget) -> Result<Option<Value>> {
    let histories = histories(budget)?;
    ancestry(&histories, budget)?;
    let ancestry: Value = asset(ANCESTRY, budget)?;
    // Ancestry is host metadata. The same complete original program binds all
    // resident variants; unsupported template ancestry is refused, never erased.
    let cases: Vec<_> = histories
        .iter()
        .flat_map(|history| {
            history.probes.iter().map(|probe| {
                serde_json::json!({"case_id": history.case_id(probe), "history_id": history.id,
            "probe": probe.id, "resident_source_ids": probe.resident_source_ids})
            })
        })
        .collect();
    Ok(Some(serde_json::json!({
        "format": "contextdb.router-controlled-resident-population.v4",
        "shared_research_schema": "three-resident-four-candidate-cost-controls.v4",
        "claims_independent_real_conversations": false,
        "claims_statistical_independence": false,
        "reference_controls": controls::POLICY,
        "ancestry": ancestry,
        "cases": cases,
    })))
}

/// Writes this fixed public population, with no general or private import API.
pub fn write_builtin_router_controlled_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    files::validate_root(root, false)?;
    charge(budget, 1, 0)?;
    if root.try_exists().map_err(|_| invalid())? {
        return verify_builtin_router_controlled_corpus(root, budget);
    }
    let artifacts = build(budget)?;
    files::write_profile(root, &artifacts, &PROFILE, budget)?;
    files::verify_profile(root, &PROFILE, budget)
}

/// Reconstructs actual compiler callbacks and independently rederives labels.
pub fn verify_builtin_router_controlled_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    files::verify_profile(root, &PROFILE, budget)
}

fn build(budget: &mut QueryBudget) -> Result<Artifacts> {
    let histories = histories(budget)?;
    let ancestry = ancestry(&histories, budget)?;
    let mut artifacts = Artifacts {
        inputs: Vec::new(),
        observations: Vec::new(),
        targets: Vec::new(),
        lineage: Lineage {
            nodes: Vec::new(),
            cases: Vec::new(),
            split: RouterSplitSpec {
                domains: BTreeMap::new(),
            },
            assignments: Vec::new(),
        },
    };
    let mut nodes = BTreeMap::new();
    let mut source_maps = BTreeMap::new();
    // Every candidate and every callback is built before annotation parsing.
    for history in &histories {
        let history_ancestry = ancestry
            .histories
            .iter()
            .find(|row| row.history_id == history.id)
            .ok_or_else(invalid)?;
        artifacts.lineage.split.domains.insert(
            history.domain(),
            match history.partition {
                RouterPartition::Train => RouterTimeCutoffs {
                    train_until: 9,
                    validation_until: 10,
                },
                RouterPartition::Validation => RouterTimeCutoffs {
                    train_until: 0,
                    validation_until: 9,
                },
                _ => return Err(invalid()),
            },
        );
        for probe in &history.probes {
            let mut child = budget.reserve(100_000, 16 * 1024 * 1024).map_err(|_| {
                BenchError::TelemetryBudget("controlled compile reserve exhausted".into())
            })?;
            let case = fixture::build(history, probe, &mut child)?;
            let collected = collector::compile(&case.compiler_input(), &mut child)?;
            fixture::validate_exploration(&case, &collected.observations, &mut child)?;
            if artifacts.inputs.len() + collected.inputs.len() > MAX_CONTROLLED_ROWS {
                return Err(invalid());
            }
            let (roots, case_nodes) =
                fixture::lineage(history, &case, &history_ancestry.seed_sha256)?;
            for node in case_nodes {
                if nodes.get(&node.reference).is_some_and(|old| old != &node) {
                    return Err(invalid());
                }
                nodes.insert(node.reference.clone(), node);
            }
            source_maps.insert(case.id.clone(), case.intervals()?);
            artifacts.lineage.cases.push(RouterExampleLineage {
                example_id: case.id,
                logical_domain: case.domain,
                cutoff: history.cutoff,
                roots,
            });
            artifacts.inputs.extend(collected.inputs);
            artifacts.observations.extend(collected.observations);
        }
    }
    let strata = controls::freeze(&artifacts, budget).map_err(|error| match error {
        BenchError::Integrity(reason) => {
            BenchError::Integrity(format!("controlled input footprints: {reason}"))
        }
        other => other,
    })?;
    let annotations: Annotations = asset(ANNOTATIONS, budget)?;
    if annotations.format != "contextdb.router-controlled-resident-annotations.v4"
        || annotations.recipes.len() != HISTORY_COUNT
    {
        return Err(invalid());
    }
    let annotations: BTreeMap<_, _> = annotations
        .recipes
        .into_iter()
        .map(|row| (row.history_id.clone(), row))
        .collect();
    if annotations.len() != HISTORY_COUNT {
        return Err(invalid());
    }
    let mut rules = BTreeMap::<_, BTreeSet<_>>::new();
    for history in &histories {
        let annotation = annotations.get(&history.id).ok_or_else(invalid)?;
        rules
            .entry(match history.partition {
                RouterPartition::Train => "train",
                _ => "validation",
            })
            .or_default()
            .insert(annotation.rule.as_str());
        let rule = match annotation.rule.as_str() {
            "additive" => targets::Rule::Additive,
            "sufficient_union_only" => targets::Rule::SufficientUnionOnly,
            _ => return Err(invalid()),
        };
        if annotation.sufficient_source_sets.len() != 1
            || annotation.sufficient_source_sets[0].len() != 2
            || annotation.sufficient_source_sets[0]
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != 2
            || annotation.sufficient_source_sets[0]
                .iter()
                .any(|id| !history.candidate_source_ids.contains(id))
            || annotation.sufficient_source_sets[0]
                .iter()
                .collect::<BTreeSet<_>>()
                != history
                    .probes
                    .iter()
                    .find(|probe| probe.id == "sufficient")
                    .ok_or_else(invalid)?
                    .resident_source_ids
                    .iter()
                    .collect::<BTreeSet<_>>()
        {
            return Err(invalid());
        }
        for probe in &history.probes {
            let id = history.case_id(probe);
            let case = artifacts
                .lineage
                .cases
                .iter()
                .find(|case| case.example_id == id)
                .ok_or_else(invalid)?;
            let sources = source_maps.get(&id).ok_or_else(invalid)?;
            let oracle = targets::Oracle {
                rule,
                sufficient_sets: annotation
                    .sufficient_source_sets
                    .iter()
                    .map(|set| {
                        set.iter()
                            .map(|id| sources.get(id).cloned().ok_or_else(invalid))
                            .collect::<Result<_>>()
                    })
                    .collect::<Result<_>>()?,
            };
            let provenance = RouterLabelProvenance {
                kind: RouterLabelKind::SyntheticSourceSet,
                evaluator_version: EVALUATOR.into(),
                available_at: history.cutoff + 1,
                logical_domain: case.logical_domain.clone(),
                source_nodes: case.roots.clone(),
            };
            let reference = RouterLineageRef {
                kind: RouterLineageKind::Evaluation,
                domain: case.logical_domain.clone(),
                id: format!("source-label:{id}"),
                version: Some("v4".into()),
            };
            nodes.insert(
                reference.clone(),
                RouterLineageNode {
                    reference,
                    available_at: history.cutoff + 1,
                    parents: case.roots.clone(),
                },
            );
            for row in artifacts
                .observations
                .iter()
                .filter(|row| row.case_id == id)
            {
                artifacts.targets.push(targets::label_with_evaluator(
                    row,
                    &oracle,
                    &provenance,
                    EVALUATOR,
                    budget,
                )?);
            }
        }
    }
    if rules
        .values()
        .any(|rules| rules != &BTreeSet::from(["additive", "sufficient_union_only"]))
    {
        return Err(invalid());
    }
    controls::join_labels(&artifacts, &strata, budget).map_err(|error| match error {
        BenchError::Integrity(reason) => {
            BenchError::Integrity(format!("controlled cost-label contrast: {reason}"))
        }
        other => other,
    })?;
    artifacts.lineage.nodes = nodes.into_values().collect();
    artifacts.lineage.assignments = assign_router_group_time_split(
        &artifacts.lineage.nodes,
        &artifacts.lineage.cases,
        &artifacts.lineage.split,
        budget,
    )?;
    validate(&artifacts, budget)?;
    Ok(artifacts)
}

fn validate(artifacts: &Artifacts, budget: &mut QueryBudget) -> Result<()> {
    validate_counts_with_limit(artifacts, MAX_CONTROLLED_ROWS, budget)?;
    let strata = controls::freeze(artifacts, budget)?;
    controls::join_labels(artifacts, &strata, budget)?;
    let groups: BTreeSet<_> = artifacts
        .observations
        .iter()
        .map(|row| (&row.case_id, row.selected_base_digest))
        .collect();
    let mut folds = BTreeMap::new();
    for case in &artifacts.lineage.assignments {
        let fold = match case.partition {
            RouterPartition::Train => "train",
            RouterPartition::Validation => "validation",
            _ => return Err(invalid()),
        };
        *folds.entry(fold).or_insert(0usize) += 1;
    }
    if artifacts.lineage.cases.len() != CASE_COUNT
        || artifacts.inputs.len() != MAX_CONTROLLED_ROWS
        || groups.len() != CASE_COUNT
        || artifacts.lineage.split.domains.len() != HISTORY_COUNT
        || artifacts
            .lineage
            .assignments
            .iter()
            .map(|row| row.group_digest)
            .collect::<BTreeSet<_>>()
            .len()
            != HISTORY_COUNT
        || folds != BTreeMap::from([("train", 24), ("validation", 24)])
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
