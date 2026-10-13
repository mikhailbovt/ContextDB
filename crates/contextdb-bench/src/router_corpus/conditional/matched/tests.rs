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

fn labeled(history: &History, probe: Probe) -> Vec<(Observation, targets::Target)> {
    let mut budget = allowance();
    let case = fixture::build(history, probe, &mut budget).expect("fixed query-time inventory");
    let collected =
        collector::compile(&case.compiler_input(), &mut budget).expect("actual compiler callbacks");
    fixture::validate_exploration(&case, probe, &collected.observations, &mut budget)
        .expect("full input-only exploration");
    let (roots, _) = fixture::lineage(history, &case).expect("original lineage");
    let oracle = fixture::oracle(history, probe, &case).expect("post-callback original intervals");
    let provenance = RouterLabelProvenance {
        kind: RouterLabelKind::SyntheticSourceSet,
        evaluator_version: EVALUATOR.into(),
        available_at: 7,
        logical_domain: case.domain,
        source_nodes: roots,
    };
    collected
        .observations
        .into_iter()
        .map(|row| {
            let target =
                targets::label_with_evaluator(&row, &oracle, &provenance, EVALUATOR, &mut budget)
                    .expect("independent interval coverage");
            (row, target)
        })
        .collect()
}

#[test]
fn explores_irrelevant_first_source_and_retains_current_complete_negatives() {
    let seeds = seeds(&mut allowance()).expect("sixteen authored histories");
    let history = seeds
        .histories
        .iter()
        .find(|row| row.id == "offline-shot-transfer")
        .expect("revocation history");
    let missing = labeled(history, Probe::Missing);
    let resident = labeled(history, Probe::Resident);
    assert_eq!((missing.len(), resident.len()), (16, 16));
    assert!(
        missing.iter().any(|(row, target)| row
            .selected
            .pack
            .evidence
            .iter()
            .any(|source| source.excerpt.as_deref() == Some(history.events[0].2.as_str()))
            && target.useful == Some(true)),
        "negative first source still explores a later useful state"
    );
    assert!(
        resident
            .iter()
            .all(|(_, target)| target.useful == Some(false)),
        "complete current originals make every optional recall known unnecessary"
    );
    let pair = missing
        .iter()
        .find(|(row, target)| row.seed_ids.len() == 2 && target.useful == Some(true))
        .expect("coverage-positive pair");
    assert!(
        pair.0
            .trial
            .pack
            .evidence
            .iter()
            .any(|source| source.excerpt.as_deref() == Some(history.events[1].2.as_str()))
    );
    assert!(
        missing
            .iter()
            .flat_map(|(row, _)| &row.trial.pack.evidence)
            .any(
                |source| source.excerpt.as_deref() == Some(history.events[3].2.as_str())
                    && source.source_class == SourceClass::ModelGenerated
            )
    );
}

#[test]
fn reuses_actual_tool_original_and_masks_mandatory_unresolved_proposals() {
    let seeds = seeds(&mut allowance()).expect("fixed authored population");
    let history = seeds
        .histories
        .iter()
        .find(|row| row.id == "render-clock")
        .expect("tool history");
    let mut budget = allowance();
    let case =
        fixture::build(history, Probe::Missing, &mut budget).expect("linked actual tool exchange");
    let base = &case.compiler_input().request.base;
    let call = base
        .hot
        .iter()
        .find(|message| !message.tool_calls.is_empty())
        .expect("attributed assistant call");
    let result = base
        .current
        .iter()
        .find(|message| message.role == OutgoingRole::Tool)
        .expect("actual current result");
    assert_eq!(result.tool_result.as_ref(), call.tool_calls.first());
    assert_eq!(result.text, history.events[2].2);
    let rows = labeled(history, Probe::Missing);
    assert!(rows.iter().all(|(row, _)| {
        row.selected_origins.iter().any(|span| {
            span.event_id == result.originals[0].span.event_id
                && span.payload_digest == result.originals[0].span.payload_digest
        })
    }));
    assert!(
        rows.iter()
            .flat_map(|(row, _)| &row.trial.pack.evidence)
            .any(
                |source| source.excerpt.as_deref() == Some(result.text.as_str())
                    && source.source_class == SourceClass::ToolOutput
            )
    );
    let unresolved = seeds
        .histories
        .iter()
        .find(|row| row.id == "package-handoff")
        .expect("proposal history");
    let rows = labeled(unresolved, Probe::Unresolved);
    assert_eq!(rows.len(), 10);
    assert!(rows.iter().all(|(row, target)| {
        target.useful.is_none()
            && target.provenance.is_none()
            && target.reason == targets::Reason::UnresolvedTask
            && [PackBlockKind::Conflict, PackBlockKind::Unknown]
                .iter()
                .all(|kind| {
                    row.selected
                        .pack
                        .sections
                        .iter()
                        .any(|block| &block.kind == kind)
                })
    }));
}

#[test]
fn cold_verifier_refuses_rehashed_wrong_labels_and_foreign_population() {
    let artifacts = build(&mut allowance()).expect("full actual matched population");
    let temp = tempfile::tempdir().expect("owned output parent");
    let parent = fs::canonicalize(temp.path()).expect("canonical parent");
    let root = parent.join("matched");
    files::write_profile(&root, &artifacts, &PROFILE, &mut allowance())
        .expect("bounded complete artifacts");
    let report = verify_builtin_router_matched_corpus(&root, &mut allowance())
        .expect("cold callback regeneration");
    assert_eq!(
        (report.cases, report.rows, report.supervised_groups),
        (34, 532, 64)
    );
    assert_eq!((report.test, report.quarantined), (0, 0));
    assert!(
        !report.reader_benefit_measured
            && !report.private_intake_available
            && !report.volatile_allowance_replayed
    );
    assert!(verify_builtin_router_conditional_corpus(&root, &mut allowance()).is_err());
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("manifest"))
            .expect("typed metadata");
    let mut labels = artifacts.targets;
    let known = labels
        .iter_mut()
        .find(|target| target.useful.is_some())
        .expect("known label");
    known.useful = known.useful.map(|value| !value);
    let changed = bytes(&labels, MAX_CONDITIONAL_CORPUS_BYTES, &mut allowance())
        .expect("bounded rehashed tamper");
    manifest.artifacts.insert(
        "targets.json".into(),
        Artifact {
            bytes: changed.len() as u64,
            digest: ContentDigest::from_bytes(*blake3::hash(&changed).as_bytes()),
        },
    );
    fs::write(root.join("targets.json"), changed).expect("owned tamper fixture");
    fs::write(
        root.join("manifest.json"),
        bytes(&manifest, 64 * 1024, &mut allowance()).expect("rehashed manifest"),
    )
    .expect("owned completion witness");
    assert!(
        verify_builtin_router_matched_corpus(&root, &mut allowance()).is_err(),
        "internally consistent hashes cannot authorize false utility gold"
    );
}
