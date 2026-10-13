//! Fixed authored counterfactuals of actual selected-state compiler callbacks.
//! Labels measure source coverage; they do not establish downstream benefit.

mod fixture;

use super::*;

pub const MATCHED_CORPUS_FORMAT: &str = "contextdb.router-corpus.matched-closure.v2";
pub const MATCHED_MODEL_PROFILE: &str = "contextdb.kev-public-matched-lossless-bce.v2";
pub const MATCHED_BUILDER: &str = "contextdb.router-matched-builtin.v2";
pub const MATCHED_GENERATOR: &str = "contextdb.router-matched-synthetic.v2";
pub const MAX_MATCHED_ROWS: usize = 532;
const EVALUATOR: &str = "synthetic-matched-source-coverage.v2";
const HISTORY_COUNT: usize = 16;
const CASE_COUNT: usize = 34;
const ASSET: &str = include_str!("matched/seeds.json");

const PROFILE: files::Profile = files::Profile {
    format: MATCHED_CORPUS_FORMAT,
    model: MATCHED_MODEL_PROFILE,
    builder: MATCHED_BUILDER,
    generator: MATCHED_GENERATOR,
    evaluator: EVALUATOR,
    revision: "v2",
    cases: CASE_COUNT,
    max_rows: MAX_MATCHED_ROWS,
    build,
    validate,
    metadata,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seeds {
    authoring_source_sha256: String,
    histories: Vec<History>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    id: String,
    partition: RouterPartition,
    family: String,
    rule: String,
    working: String,
    query: String,
    events: Vec<(String, String, String)>,
    resident: Vec<String>,
    proofs: Vec<Vec<String>>,
    seed_sha256: String,
    #[serde(default)]
    base_tool_exchange: Option<ToolExchange>,
    #[serde(default)]
    unresolved_query: Option<String>,
    #[serde(default)]
    conflict_sources: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolExchange {
    result_source_id: String,
    call_text: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Probe {
    Missing,
    Resident,
    Unresolved,
}
impl Probe {
    fn name(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Resident => "resident",
            Self::Unresolved => "unresolved",
        }
    }
    fn id(self, history: &History) -> String {
        format!("{}-{}", history.id, self.name())
    }
}
impl History {
    fn probes(&self) -> impl Iterator<Item = Probe> {
        [
            Some(Probe::Missing),
            Some(Probe::Resident),
            self.unresolved_query.as_ref().map(|_| Probe::Unresolved),
        ]
        .into_iter()
        .flatten()
    }
    fn domain(&self) -> String {
        // Fixture names and folds remain host metadata, not semantic content.
        format!(
            "synthetic:matched:{}",
            super::fixture::stable_uuid(&self.id)
        )
    }
}

fn seeds(budget: &mut QueryBudget) -> Result<Seeds> {
    if ASSET.len() > MAX_CONDITIONAL_INPUT_BYTES {
        return Err(invalid());
    }
    charge(budget, 1, (ASSET.len() as u64).saturating_mul(2))?;
    let seeds: Seeds = serde_json::from_str(ASSET).map_err(|_| invalid())?;
    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut folds = BTreeMap::new();
    let mut cases = 0;
    if seeds.histories.len() != HISTORY_COUNT || seeds.authoring_source_sha256.len() != 64 {
        return Err(invalid());
    }
    for history in &seeds.histories {
        let sources: BTreeSet<_> = history.events.iter().map(|event| &event.0).collect();
        if !ids.insert(&history.id)
            || !families.insert(&history.family)
            || history.seed_sha256.len() != 64
            || sources.len() != 4
            || history.events.len() != 4
            || history.resident.len() != 2
            || history.resident[0] == history.resident[1]
            || history.events.iter().any(|event| {
                !matches!(event.1.as_str(), "user" | "assistant" | "tool")
                    || event.2.is_empty()
                    || event.2.len() > 2048
            })
            || history.resident.iter().any(|id| !sources.contains(id))
            || history.proofs.len() != 1
            || history.proofs[0] != history.resident
            || !matches!(history.rule.as_str(), "additive" | "sufficient_union_only")
            || !matches!(
                history.partition,
                RouterPartition::Train | RouterPartition::Validation
            )
            || if history.unresolved_query.is_some() {
                history.conflict_sources.len() != 2
                    || history.conflict_sources[0] == history.conflict_sources[1]
            } else {
                !history.conflict_sources.is_empty()
            }
        {
            return Err(invalid());
        }
        for id in &history.conflict_sources {
            if !history
                .events
                .iter()
                .any(|event| &event.0 == id && event.1 == "assistant")
            {
                return Err(invalid());
            }
        }
        *folds
            .entry(match history.partition {
                RouterPartition::Train => "train",
                _ => "validation",
            })
            .or_insert(0usize) += 1;
        cases += history.probes().count();
    }
    if cases != CASE_COUNT || folds != BTreeMap::from([("train", 8), ("validation", 8)]) {
        return Err(invalid());
    }
    Ok(seeds)
}

fn metadata(budget: &mut QueryBudget) -> Result<Option<Value>> {
    let seeds = seeds(budget)?;
    let histories: Vec<_> = seeds
        .histories
        .iter()
        .map(|history| {
            serde_json::json!({
                "history_id": history.id,
                "partition": history.partition,
                "authored_program_family": history.family,
                "content_template_ancestors": [],
                "seed_sha256": history.seed_sha256,
                "claims_independent_real_conversations": false,
            })
        })
        .collect();
    let cases: Vec<_> = seeds.histories.iter().flat_map(|history| history.probes().map(|probe|
        serde_json::json!({"case_id": probe.id(history), "history_id": history.id, "probe": probe.name()})
    )).collect();
    Ok(Some(serde_json::json!({
        "format": "contextdb.router-matched-population.v2",
        "authored_seed_sha256": seeds.authoring_source_sha256,
        "shared_research_schema": "two-fact-four-candidate-matched-probes.v2",
        "histories": histories,
        "cases": cases,
    })))
}

/// Writes only this fixed public population; no arbitrary/native intake exists.
pub fn write_builtin_router_matched_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    files::validate_root(root, false)?;
    charge(budget, 1, 0)?;
    if root.try_exists().map_err(|_| invalid())? {
        return verify_builtin_router_matched_corpus(root, budget);
    }
    let artifacts = build(budget)?;
    files::write_profile(root, &artifacts, &PROFILE, budget)?;
    files::verify_profile(root, &PROFILE, budget)
}

/// Cold reconstructs every callback and independent interval annotation.
pub fn verify_builtin_router_matched_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    files::verify_profile(root, &PROFILE, budget)
}

fn build(budget: &mut QueryBudget) -> Result<Artifacts> {
    let seeds = seeds(budget)?;
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
    for history in &seeds.histories {
        artifacts.lineage.split.domains.insert(
            history.domain(),
            match history.partition {
                RouterPartition::Train => RouterTimeCutoffs {
                    train_until: 7,
                    validation_until: 8,
                },
                RouterPartition::Validation => RouterTimeCutoffs {
                    train_until: 0,
                    validation_until: 7,
                },
                _ => return Err(invalid()),
            },
        );
        for probe in history.probes() {
            let mut child = budget.reserve(100_000, 16 * 1024 * 1024).map_err(|_| {
                BenchError::TelemetryBudget("matched compile reserve exhausted".into())
            })?;
            let case = fixture::build(history, probe, &mut child)?;
            let collected = collector::compile(&case.compiler_input(), &mut child)?;
            fixture::validate_exploration(&case, probe, &collected.observations, &mut child)?;
            if artifacts.inputs.len() + collected.inputs.len() > MAX_MATCHED_ROWS {
                return Err(invalid());
            }
            let (roots, case_nodes) = fixture::lineage(history, &case)?;
            for node in case_nodes {
                if nodes.get(&node.reference).is_some_and(|old| old != &node) {
                    return Err(invalid());
                }
                nodes.insert(node.reference.clone(), node);
            }
            // Annotation creation follows the actual input-only compiler pass.
            let oracle = fixture::oracle(history, probe, &case)?;
            let provenance = RouterLabelProvenance {
                kind: RouterLabelKind::SyntheticSourceSet,
                evaluator_version: EVALUATOR.into(),
                available_at: 7,
                logical_domain: case.domain.clone(),
                source_nodes: roots.clone(),
            };
            let reference = RouterLineageRef {
                kind: RouterLineageKind::Evaluation,
                domain: case.domain.clone(),
                id: format!("source-label:{}", case.id),
                version: Some("v2".into()),
            };
            nodes.insert(
                reference.clone(),
                RouterLineageNode {
                    reference,
                    available_at: 7,
                    parents: roots.clone(),
                },
            );
            for row in &collected.observations {
                artifacts.targets.push(targets::label_with_evaluator(
                    row,
                    &oracle,
                    &provenance,
                    EVALUATOR,
                    &mut child,
                )?);
            }
            artifacts.lineage.cases.push(RouterExampleLineage {
                example_id: case.id,
                logical_domain: case.domain,
                cutoff: 6,
                roots,
            });
            artifacts.inputs.extend(collected.inputs);
            artifacts.observations.extend(collected.observations);
        }
    }
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
    validate_counts_with_limit(artifacts, MAX_MATCHED_ROWS, budget)?;
    let mut groups = BTreeMap::<_, Vec<Option<bool>>>::new();
    let assigned: BTreeMap<_, _> = artifacts
        .lineage
        .assignments
        .iter()
        .map(|row| (&row.example_id, row.partition))
        .collect();
    for (row, label) in artifacts.observations.iter().zip(&artifacts.targets) {
        groups
            .entry((&row.case_id, row.selected_base_digest))
            .or_default()
            .push(label.useful);
    }
    let mut supervised = BTreeMap::from([("train", 0usize), ("validation", 0usize)]);
    let mut unsupervised = 0;
    for ((case, _), labels) in &groups {
        if labels.iter().all(Option::is_none) {
            unsupervised += 1;
            continue;
        }
        let key = match assigned.get(case) {
            Some(RouterPartition::Train) => "train",
            Some(RouterPartition::Validation) => "validation",
            _ => return Err(invalid()),
        };
        *supervised.get_mut(key).ok_or_else(invalid)? += 1;
    }
    if artifacts.lineage.cases.len() != CASE_COUNT
        || artifacts.inputs.len() != MAX_MATCHED_ROWS
        || artifacts.lineage.split.domains.len() != HISTORY_COUNT
        || artifacts
            .lineage
            .assignments
            .iter()
            .map(|row| row.group_digest)
            .collect::<BTreeSet<_>>()
            .len()
            != HISTORY_COUNT
        || supervised != BTreeMap::from([("train", 32), ("validation", 32)])
        || unsupervised != 2
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
