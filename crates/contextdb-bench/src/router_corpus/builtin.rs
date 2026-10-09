//! Local, deterministic synthetic artifacts. No native/private intake is offered.

use super::*;
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

const FILES: [&str; 5] = [
    "query-time.json",
    "features.json",
    "behavior.json",
    "targets.json",
    "lineage.json",
];
const MANIFEST: &str = "manifest.json";
const BUILDER: &str = "contextdb.router-builtin.v1";
const REPLAY_FORMAT: &str = "contextdb.router-corpus.synthetic-replay.v1";
const REPLAY_BUILDER: &str = "contextdb.router-builtin-replay.v1";

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
    builder: String,
    generator: String,
    examples: usize,
    artifacts: BTreeMap<String, Artifact>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lineage {
    nodes: Vec<RouterLineageNode>,
    examples: Vec<RouterExampleLineage>,
    split: RouterSplitSpec,
    assignments: Vec<RouterSplitAssignment>,
}
struct BuiltinArtifacts {
    manifest: Manifest,
    files: BTreeMap<String, Vec<u8>>,
}

/// Aggregate synthetic conformance only, not memory quality or a trained router.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct BuiltinRouterCorpusReport {
    pub format: String,
    pub manifest_digest: ContentDigest,
    pub examples: usize,
    pub known_labels: usize,
    pub train: usize,
    pub validation: usize,
    pub test: usize,
    pub quarantined: usize,
    pub historical_selection: &'static str,
    pub current_source_wire: &'static str,
    pub trained_router: bool,
}

/// Writes only these built-in public synthetic originals, into a new owned root.
/// A completed exact retry is verified; an incomplete directory is preserved and
/// refused. No user-selected source, native trace or imported corpus is writable.
pub fn write_builtin_router_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<BuiltinRouterCorpusReport> {
    write_builtin(root, false, budget)
}

/// Writes the explicitly versioned built-in replay profile, retaining actual
/// compiler preparation and behavior. This accepts no private or native inputs.
pub fn write_builtin_router_replay_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<BuiltinRouterCorpusReport> {
    write_builtin(root, true, budget)
}

fn write_builtin(
    root: &Path,
    replay: bool,
    budget: &mut QueryBudget,
) -> Result<BuiltinRouterCorpusReport> {
    validate_root(root, false)?;
    charge(budget, 1, 0)?;
    if root.try_exists().map_err(|_| invalid())? {
        return verify_builtin(root, replay, budget);
    }
    let expected = build_artifacts(replay, budget)?;
    fs::create_dir(root).map_err(|_| invalid())?;
    for (name, bytes) in &expected.files {
        write_new(root, name, bytes, budget)?;
    }
    let manifest = router_corpus_bytes(&expected.manifest, MAX_ROUTER_TARGET_BYTES, budget)?;
    write_new(root, MANIFEST, &manifest, budget)?;
    verify_builtin(root, replay, budget)
}

/// Cold validates commitments, separated features/targets and complete connected
/// group/time lineage. Hashes are integrity metadata, never materialization rights.
pub fn verify_builtin_router_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<BuiltinRouterCorpusReport> {
    verify_builtin(root, false, budget)
}

/// Cold executes pinned R0 over the frozen preparation through the live
/// compiler's selector. Targets remain separate and supply no scorer inputs.
pub fn verify_builtin_router_replay_corpus(
    root: &Path,
    budget: &mut QueryBudget,
) -> Result<BuiltinRouterCorpusReport> {
    verify_builtin(root, true, budget)
}

fn verify_builtin(
    root: &Path,
    replay: bool,
    budget: &mut QueryBudget,
) -> Result<BuiltinRouterCorpusReport> {
    validate_root(root, true)?;
    let manifest_bytes = read_bounded(&root.join(MANIFEST), MAX_ROUTER_TARGET_BYTES, budget)?;
    let manifest: Manifest = decode(&manifest_bytes, MAX_ROUTER_TARGET_BYTES, budget)?;
    let format = if replay {
        REPLAY_FORMAT
    } else {
        ROUTER_CORPUS_VERSION
    };
    let builder = if replay { REPLAY_BUILDER } else { BUILDER };
    if manifest.format != format
        || manifest.builder != builder
        || manifest.generator != fixture::GENERATOR
        || manifest.examples != fixture::SCENARIOS.len() * 4
        || manifest
            .artifacts
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != FILES.into_iter().collect()
    {
        return Err(invalid());
    }
    let permitted: BTreeSet<_> = FILES.into_iter().chain([MANIFEST]).collect();
    for entry in fs::read_dir(root).map_err(|_| invalid())? {
        charge(budget, 1, 0)?;
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name();
        if !permitted.contains(name.to_str().ok_or_else(invalid)?) || !regular(&entry.path())? {
            return Err(invalid());
        }
    }
    let mut total = 0_u64;
    let mut files = BTreeMap::<&str, Vec<u8>>::new();
    for name in FILES {
        let artifact = manifest.artifacts.get(name).ok_or_else(invalid)?;
        total = total.checked_add(artifact.bytes).ok_or_else(invalid)?;
        if artifact.bytes > MAX_ROUTER_EXAMPLE_BYTES as u64
            || total > MAX_ROUTER_CORPUS_BYTES as u64
        {
            return Err(invalid());
        }
        let bytes = read_bounded(&root.join(name), MAX_ROUTER_EXAMPLE_BYTES, budget)?;
        if bytes.len() as u64 != artifact.bytes
            || ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()) != artifact.digest
        {
            return Err(invalid());
        }
        files.insert(name, bytes);
    }
    let inputs: Vec<RouterQueryTimeRecord> = decode(
        files.get("query-time.json").ok_or_else(invalid)?,
        MAX_ROUTER_EXAMPLE_BYTES,
        budget,
    )?;
    let features: Vec<RouterFeatureRecord> = decode(
        files.get("features.json").ok_or_else(invalid)?,
        MAX_ROUTER_EXAMPLE_BYTES,
        budget,
    )?;
    if inputs.len() != manifest.examples || features.len() != inputs.len() {
        return Err(invalid());
    }
    // Feature construction reads only input records; evaluation is decoded later.
    for (input, feature) in inputs.iter().zip(&features) {
        if build_router_features(input, budget)? != *feature {
            return Err(invalid());
        }
    }
    let behavior: Vec<RouterBehaviorRecord> = decode(
        files.get("behavior.json").ok_or_else(invalid)?,
        MAX_ROUTER_EXAMPLE_BYTES,
        budget,
    )?;
    let targets: Vec<RouterUtilityTargets> = decode(
        files.get("targets.json").ok_or_else(invalid)?,
        MAX_ROUTER_EXAMPLE_BYTES,
        budget,
    )?;
    let lineage: Lineage = decode(
        files.get("lineage.json").ok_or_else(invalid)?,
        MAX_ROUTER_EXAMPLE_BYTES,
        budget,
    )?;
    if behavior.len() != inputs.len()
        || targets.len() != inputs.len()
        || lineage.examples.len() != inputs.len()
    {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    for (((input, observed), target), roots) in inputs
        .iter()
        .zip(&behavior)
        .zip(&targets)
        .zip(&lineage.examples)
    {
        if !ids.insert(&input.query.id)
            || input.observation.generator != fixture::GENERATOR
            || observed.attempt != RouterAttemptStatus::Prepared
            || observed.accepted_receipt.is_some()
        {
            return Err(invalid());
        }
        validate_router_example(input, observed, target, roots, budget)?;
        if replay {
            let result = replay_router_behavior(
                input,
                observed,
                &contextdb_context::ReferenceTokenizer,
                &contextdb_context::ReferenceOutgoingEncoder(
                    &contextdb_context::ReferenceTokenizer,
                ),
                budget,
            )?;
            if !matches!(
                result,
                contextdb_context::router::RouterHistoricalReplayResult::Complete(_)
            ) {
                return Err(invalid());
            }
        } else if observed.replay_observation.is_some() || input.material.prepared_policy.is_some()
        {
            // The fixed legacy profile cannot silently accept a new profile.
            return Err(invalid());
        }
    }
    validate_builtin_profile(&inputs, &targets, &lineage, budget)?;
    if assign_router_group_time_split(&lineage.nodes, &lineage.examples, &lineage.split, budget)?
        != lineage.assignments
    {
        return Err(invalid());
    }
    let count = |partition| {
        lineage
            .assignments
            .iter()
            .filter(|item| item.partition == partition)
            .count()
    };
    Ok(BuiltinRouterCorpusReport {
        format: format.into(),
        manifest_digest: digest(&manifest, budget)?,
        examples: inputs.len(),
        known_labels: targets.iter().map(RouterUtilityTargets::known_labels).sum(),
        train: count(RouterPartition::Train),
        validation: count(RouterPartition::Validation),
        test: count(RouterPartition::Test),
        quarantined: count(RouterPartition::Quarantined),
        historical_selection: if replay {
            "verified: complete frozen prepared-state R0 replay"
        } else {
            "unavailable: missing prepared policy and intermediate trials"
        },
        current_source_wire: "unavailable: synthetic corpus has no native acceptance",
        trained_router: false,
    })
}

mod files;
mod records;
use files::{read_bounded, regular, validate_root, write_new};
use records::{build_artifacts, validate_builtin_profile};
#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod tests;
