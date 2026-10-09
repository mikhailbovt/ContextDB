//! Public synthetic observations of the compiler's actual conditional trials.
//! Source-coverage labels are a declared surrogate, not reader benefit or rights.

mod collector;
mod files;
mod fixture;
mod targets;

use super::*;
use crate::Result;
use contextdb_context::router::canonical_digest;
use contextdb_context::*;
use contextdb_core::{ContentDigest, ObservationId};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const CONDITIONAL_CORPUS_FORMAT: &str = "contextdb.router-corpus.rendered-closure.v1";
pub const CONDITIONAL_MODEL_PROFILE: &str =
    "contextdb.kev-public-synthetic-rendered-closure-bce.v1";
pub const CONDITIONAL_BUILDER: &str = "contextdb.router-conditional-builtin.v1";
pub const CONDITIONAL_GENERATOR: &str = "contextdb.router-conditional-synthetic.v1";
pub const MAX_CONDITIONAL_CASES: usize = 64;
pub const MAX_CONDITIONAL_CALLBACKS: usize = 128;
pub const MAX_CONDITIONAL_ROWS: usize = 512;
pub const MAX_CONDITIONAL_GROUP_TRIALS: usize = 16;
pub const MAX_CONDITIONAL_CORPUS_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CONDITIONAL_INPUT_BYTES: usize = 2 * 1024 * 1024;

const FILES: [&str; 4] = [
    "inputs.json",
    "observations.json",
    "targets.json",
    "lineage.json",
];
const VOLATILE_KEYS: [&str; 6] = [
    "remaining_work",
    "remaining_bytes",
    "remaining_timeout_micros",
    "remaining_scorer_work",
    "remaining_scorer_micros",
    "remaining_evaluations",
];

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) row_id: String,
    pub(super) input: Value,
}

/// Host metadata; it is never passed to the model formatter.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceInterval {
    pub(super) event_id: ObservationId,
    pub(super) payload_digest: ContentDigest,
    pub(super) start: u64,
    pub(super) end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Choice {
    pub(super) block_id: BlockId,
    pub(super) alternative_index: u32,
    pub(super) generated: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Witness {
    pub(super) pack: ContextPack,
    pub(super) messages: Vec<OutgoingMessage>,
    pub(super) outgoing: EncodedOutgoing,
    pub(super) choices: Vec<Choice>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub(super) row_id: String,
    pub(super) case_id: String,
    pub(super) logical_domain: String,
    pub(super) known_at: u64,
    pub(super) evaluation: u32,
    pub(super) feature_digest: ContentDigest,
    pub(super) request_digest: ContentDigest,
    pub(super) selected_base_digest: ContentDigest,
    pub(super) trial_wire_digest: ContentDigest,
    pub(super) outgoing_fits: bool,
    pub(super) seed_ids: BTreeSet<BlockId>,
    pub(super) closure_ids: BTreeSet<BlockId>,
    pub(super) selected_origins: Vec<SourceInterval>,
    pub(super) trial_origins: Vec<SourceInterval>,
    pub(super) selected: Witness,
    pub(super) trial: Witness,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lineage {
    pub(super) nodes: Vec<RouterLineageNode>,
    pub(super) cases: Vec<RouterExampleLineage>,
    pub(super) split: RouterSplitSpec,
    pub(super) assignments: Vec<RouterSplitAssignment>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    bytes: u64,
    digest: ContentDigest,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    profile: String,
    builder: String,
    generator: String,
    cases: usize,
    rows: usize,
    artifacts: BTreeMap<String, Artifact>,
}

pub(super) struct Artifacts {
    pub(super) inputs: Vec<Input>,
    pub(super) observations: Vec<Observation>,
    targets: Vec<targets::Target>,
    pub(super) lineage: Lineage,
}

/// Counts observed synthetic trials. No source permission or model quality claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConditionalRouterCorpusReport {
    pub format: String,
    pub model_profile: String,
    pub manifest_digest: ContentDigest,
    pub cases: usize,
    pub rows: usize,
    pub supervised_groups: usize,
    pub positive: usize,
    pub negative: usize,
    pub unknown: usize,
    pub train: usize,
    pub validation: usize,
    pub test: usize,
    pub quarantined: usize,
    pub reference_source_wire: &'static str,
    pub volatile_allowance_replayed: bool,
    pub reader_benefit_measured: bool,
    pub private_intake_available: bool,
}

/// Writes only fixed public synthetic fixtures; existing completed jobs are
/// checked, incomplete roots refused, and imported/native inputs unsupported.
pub fn write_builtin_router_conditional_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    files::validate_root(root, false)?;
    charge(budget, 1, 0)?;
    if root.try_exists().map_err(|_| invalid())? {
        return verify_builtin_router_conditional_corpus(root, budget);
    }
    let artifacts = build_artifacts(budget)?;
    files::write(root, &artifacts, budget)?;
    files::verify(root, budget)
}

/// Reconstructs these public fixtures through the live callback. Exact semantic
/// and wire material is checked; historical volatile allowances are observations.
pub fn verify_builtin_router_conditional_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<ConditionalRouterCorpusReport> {
    files::verify(root, budget)
}

pub(super) fn bytes<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<Vec<u8>> {
    if limit > MAX_CONDITIONAL_CORPUS_BYTES {
        return Err(invalid());
    }
    Ok(serialize(value, limit, true, budget)?.bytes)
}

pub(super) fn bounded<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<usize> {
    Ok(serialize(value, limit, false, budget)?.size)
}

pub(super) fn commitment<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<ContentDigest> {
    let data = bytes(value, limit, budget)?;
    charge(budget, data.len() as u64 / 4096 + 1, 0)?;
    Ok(ContentDigest::from_bytes(*blake3::hash(&data).as_bytes()))
}

pub(super) fn normalized_input(input: &Value, budget: &mut QueryBudget) -> Result<Value> {
    let size = bounded(input, MAX_CONDITIONAL_INPUT_BYTES, budget)?;
    charge(budget, 1, (size as u64).saturating_mul(2))?;
    let mut input = input.clone();
    let budget = input
        .get_mut("budget")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?;
    for key in VOLATILE_KEYS {
        if budget.remove(key).is_none() {
            return Err(invalid());
        }
    }
    Ok(input)
}

pub(super) fn build_artifacts(budget: &mut QueryBudget) -> Result<Artifacts> {
    let mut inputs = Vec::new();
    let mut observations = Vec::new();
    let mut targets = Vec::new();
    let mut nodes = BTreeMap::new();
    let mut cases = Vec::new();
    let mut domains = BTreeMap::new();
    for group in 0..4_u32 {
        let domain = fixture::domain(group);
        domains.insert(
            domain,
            if group == 3 {
                RouterTimeCutoffs {
                    train_until: 303,
                    validation_until: 399,
                }
            } else {
                RouterTimeCutoffs {
                    train_until: 99,
                    validation_until: 199,
                }
            },
        );
        for scenario in fixture::SCENARIOS {
            if cases.len() >= MAX_CONDITIONAL_CASES {
                return Err(invalid());
            }
            let mut child = budget.reserve(100_000, 16 * 1024 * 1024).map_err(|_| {
                BenchError::TelemetryBudget("conditional compile reserve exhausted".into())
            })?;
            let case = fixture::build_case(group, scenario, &mut child)?;
            let collected = collector::compile_case(&case, &mut child)?;
            if inputs.len() + collected.inputs.len() > MAX_CONDITIONAL_ROWS {
                return Err(invalid());
            }
            let (roots, case_nodes) = fixture::lineage(&case)?;
            for node in case_nodes {
                if nodes
                    .get(&node.reference)
                    .is_some_and(|previous| previous != &node)
                {
                    return Err(invalid());
                }
                nodes.insert(node.reference.clone(), node);
            }
            let provenance = RouterLabelProvenance {
                kind: RouterLabelKind::SyntheticSourceSet,
                evaluator_version: targets::EVALUATOR.into(),
                available_at: case.known_at + 1,
                logical_domain: case.domain.clone(),
                source_nodes: roots.clone(),
            };
            let evaluation_ref = RouterLineageRef {
                kind: RouterLineageKind::Evaluation,
                domain: case.domain.clone(),
                id: format!("source-label:{}", case.id),
                version: Some("v1".into()),
            };
            nodes.insert(
                evaluation_ref.clone(),
                RouterLineageNode {
                    reference: evaluation_ref,
                    available_at: provenance.available_at,
                    parents: roots.clone(),
                },
            );
            for row in &collected.observations {
                targets.push(targets::label_row(
                    row,
                    &case.oracle,
                    &provenance,
                    &mut child,
                )?);
            }
            cases.push(RouterExampleLineage {
                example_id: case.id.clone(),
                logical_domain: case.domain.clone(),
                cutoff: case.known_at,
                roots,
            });
            inputs.extend(collected.inputs);
            observations.extend(collected.observations);
        }
    }
    let nodes: Vec<_> = nodes.into_values().collect();
    let split = RouterSplitSpec { domains };
    let assignments = assign_router_group_time_split(&nodes, &cases, &split, budget)?;
    let artifacts = Artifacts {
        inputs,
        observations,
        targets,
        lineage: Lineage {
            nodes,
            cases,
            split,
            assignments,
        },
    };
    validate_counts(&artifacts, budget)?;
    Ok(artifacts)
}

pub(super) fn validate_counts(artifacts: &Artifacts, budget: &mut QueryBudget) -> Result<()> {
    if artifacts.lineage.cases.len() > MAX_CONDITIONAL_CASES
        || artifacts.inputs.len() > MAX_CONDITIONAL_ROWS
        || artifacts.inputs.len() != artifacts.observations.len()
        || artifacts.inputs.len() != artifacts.targets.len()
    {
        return Err(invalid());
    }
    let mut groups = BTreeMap::new();
    let mut per_case = BTreeMap::new();
    for row in &artifacts.observations {
        charge(budget, 1, 0)?;
        let count = groups
            .entry((&row.case_id, row.selected_base_digest))
            .or_insert(0usize);
        *count += 1;
        if *count > MAX_CONDITIONAL_GROUP_TRIALS {
            return Err(invalid());
        }
        let count = per_case.entry(&row.case_id).or_insert(0usize);
        *count += 1;
        if *count > MAX_CONDITIONAL_CALLBACKS {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
