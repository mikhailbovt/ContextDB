use super::*;
use std::{fs, time::Duration};

fn allowance() -> QueryBudget {
    QueryBudget::new(
        30_000_000,
        3 * 1024 * 1024 * 1024,
        Duration::from_secs(120),
        Default::default(),
    )
}

#[test]
fn complete_inventory_has_source_content_controls_for_both_cardinalities() {
    let mut budget = allowance();
    let artifacts =
        build(&mut budget).expect("all input-only callbacks before interval annotations");
    let strata =
        controls::freeze(&artifacts, &mut budget).expect("independent actual reference footprint");
    controls::join_labels(&artifacts, &strata, &mut budget)
        .expect("positive and negative nonzero-source costs in every history");
    assert_eq!(
        (artifacts.lineage.cases.len(), artifacts.inputs.len()),
        (48, 480)
    );
    for case in &artifacts.lineage.cases {
        let rows: Vec<_> = artifacts
            .observations
            .iter()
            .filter(|row| row.case_id == case.example_id)
            .collect();
        assert!(rows[..4].iter().all(|row| row.seed_ids.len() == 1));
        assert!(rows[4..].iter().all(|row| row.seed_ids.len() == 2));
    }
    assert_eq!(
        artifacts
            .observations
            .iter()
            .filter(|row| row.seed_ids.len() == 1)
            .count(),
        192
    );
    assert_eq!(
        artifacts
            .observations
            .iter()
            .filter(|row| row.seed_ids.len() == 2)
            .count(),
        288
    );
    assert!(artifacts.targets.iter().any(|target| target.reason
        == targets::Reason::PartialRequiredCoverage
        && target.useful.is_none()
        && target.provenance.is_none()));
    assert_eq!(
        artifacts
            .lineage
            .assignments
            .iter()
            .map(|row| row.group_digest)
            .collect::<BTreeSet<_>>()
            .len(),
        16
    );
}

#[test]
fn hot_tool_bindings_preserve_original_versions_and_stale_sources_do_not_complete() {
    let mut budget = allowance();
    let histories = histories(&mut budget).expect("fixed fresh inputs");
    let history = histories
        .iter()
        .find(|history| history.program == "supersession" && !history.tool_bindings.is_empty())
        .expect("explicit correction with original tool calls");
    let probe = history
        .probes
        .iter()
        .find(|probe| probe.id == "stale")
        .expect("equal-size stale context");
    let case = fixture::build(history, probe, &mut budget).expect("full source chronology");
    let input = case.compiler_input();
    assert_eq!(
        input
            .request
            .base
            .hot
            .iter()
            .map(|message| message.role)
            .collect::<Vec<_>>(),
        [
            OutgoingRole::User,
            OutgoingRole::Assistant,
            OutgoingRole::Tool
        ]
    );
    assert_eq!(input.request.base.current.len(), 1);
    assert_eq!(input.request.base.current[0].role, OutgoingRole::User);
    let call = &input.request.base.hot[1];
    let result = &input.request.base.hot[2];
    assert_eq!(call.tool_calls.first(), result.tool_result.as_ref());
    let intervals = case.intervals().expect("actual version intervals");
    let binding = history
        .tool_bindings
        .iter()
        .find(|binding| {
            probe
                .resident_source_ids
                .contains(&binding.result_source_id)
        })
        .expect("resident result links to its actual call");
    assert_eq!(
        result.originals[0].span.event_id,
        intervals[&binding.result_source_id].event_id
    );
    assert_eq!(
        call.originals[0].span.payload_digest,
        intervals[&binding.call_source_id].payload_digest
    );
    let ancestry = ancestry(&histories, &mut budget).expect("complete history ancestor");
    let seed = ancestry
        .histories
        .iter()
        .find(|seed| seed.history_id == history.id)
        .expect("authored seed witness");
    let (roots, _) = fixture::lineage(history, &case, &seed.seed_sha256)
        .expect("all archived calls, results and current sources");
    assert_eq!(roots.len(), history.originals.len() + 2);
    let other =
        fixture::build(history, &history.probes[0], &mut budget).expect("other resident variant");
    assert_eq!(
        fixture::lineage(history, &other, &seed.seed_sha256)
            .expect("same full ancestry")
            .0,
        roots
    );
    let collected = collector::compile(&input, &mut budget).expect("actual STOP callbacks");
    fixture::validate_exploration(&case, &collected.observations, &mut budget)
        .expect("all four singles and six pairs");
    // Evaluator admission happens after callbacks; an alternate gold recipe
    // changes labels without changing any source, feature or compiler witness.
    let recipes: Annotations = asset(ANNOTATIONS, &mut budget).expect("separate annotation asset");
    let recipe = recipes
        .recipes
        .iter()
        .find(|recipe| recipe.history_id == history.id)
        .expect("declared current source proof");
    let oracle = targets::Oracle {
        rule: targets::Rule::SufficientUnionOnly,
        sufficient_sets: recipe
            .sufficient_source_sets
            .iter()
            .map(|set| set.iter().map(|id| intervals[id].clone()).collect())
            .collect(),
    };
    let provenance = RouterLabelProvenance {
        kind: RouterLabelKind::SyntheticSourceSet,
        evaluator_version: EVALUATOR.into(),
        available_at: history.cutoff + 1,
        logical_domain: case.domain.clone(),
        source_nodes: roots,
    };
    let labels: Vec<_> = collected
        .observations
        .iter()
        .map(|row| {
            targets::label_with_evaluator(row, &oracle, &provenance, EVALUATOR, &mut budget)
                .expect("source-only independent correction labels")
        })
        .collect();
    assert!(labels.iter().any(|label| label.useful == Some(true)));
    assert!(labels.iter().any(|label| label.useful == Some(false)));
    assert!(
        labels
            .iter()
            .all(|label| label.reason != targets::Reason::AlreadySufficient),
        "old attributed decision cannot satisfy its replacement"
    );
    let empty = targets::Oracle {
        rule: targets::Rule::Additive,
        sufficient_sets: Vec::new(),
    };
    for (row, label) in collected.observations.iter().zip(labels) {
        let alternate =
            targets::label_with_evaluator(row, &empty, &provenance, EVALUATOR, &mut budget)
                .expect("independent alternate evaluator");
        assert_eq!(alternate.feature_digest, label.feature_digest);
        assert_eq!(alternate.trial_wire_digest, label.trial_wire_digest);
        assert_eq!(alternate.useful, Some(false));
    }
}

#[test]
fn cold_verifier_rejects_rehashed_resident_label_and_legacy_profile() {
    let artifacts = build(&mut allowance()).expect("full real controlled population");
    let temp = tempfile::tempdir().expect("owned output parent");
    let root = fs::canonicalize(temp.path())
        .expect("canonical parent")
        .join("controlled");
    files::write_profile(&root, &artifacts, &PROFILE, &mut allowance())
        .expect("bounded five artifacts");
    let report = verify_builtin_router_controlled_corpus(&root, &mut allowance())
        .expect("cold callback and oracle reproduction");
    assert_eq!(
        (report.cases, report.rows, report.supervised_groups),
        (48, 480, 48)
    );
    assert_eq!(
        (
            report.train,
            report.validation,
            report.test,
            report.quarantined
        ),
        (24, 24, 0, 0)
    );
    assert!(
        !report.reader_benefit_measured
            && !report.private_intake_available
            && !report.volatile_allowance_replayed
    );
    assert!(verify_builtin_router_matched_corpus(&root, &mut allowance()).is_err());
    assert!(verify_builtin_router_conditional_corpus(&root, &mut allowance()).is_err());
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("manifest"))
            .expect("typed manifest");
    let mut labels = artifacts.targets;
    let resident = labels
        .iter_mut()
        .find(|target| target.reason == targets::Reason::AlreadySufficient)
        .expect("fully resident known negative");
    resident.useful = Some(true);
    let changed = bytes(&labels, MAX_CONDITIONAL_CORPUS_BYTES, &mut allowance())
        .expect("bounded tampered target");
    manifest.artifacts.insert(
        "targets.json".into(),
        Artifact {
            bytes: changed.len() as u64,
            digest: ContentDigest::from_bytes(*blake3::hash(&changed).as_bytes()),
        },
    );
    fs::write(root.join("targets.json"), changed).expect("owned rehash");
    fs::write(
        root.join("manifest.json"),
        bytes(&manifest, 64 * 1024, &mut allowance()).expect("rehashed completion"),
    )
    .expect("owned manifest");
    assert!(
        verify_builtin_router_controlled_corpus(&root, &mut allowance()).is_err(),
        "matching file hashes cannot authorize altered source utility"
    );
}
