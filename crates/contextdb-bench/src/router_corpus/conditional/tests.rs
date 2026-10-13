//! Real callback and cold-artifact gates for the public source-coverage surrogate.

use super::*;
use contextdb_recall::QueryCancellation;
use router::RouterSelectionPlan;
use std::{fs, time::Duration};

fn allowance() -> QueryBudget {
    QueryBudget::new(
        30_000_000,
        3 * 1024 * 1024 * 1024,
        Duration::from_secs(120),
        Default::default(),
    )
}

fn provenance(case: &fixture::Case) -> RouterLabelProvenance {
    let (roots, _) = fixture::lineage(case).expect("actual source lineage");
    RouterLabelProvenance {
        kind: RouterLabelKind::SyntheticSourceSet,
        evaluator_version: targets::EVALUATOR.into(),
        available_at: case.known_at + 1,
        logical_domain: case.domain.clone(),
        source_nodes: roots,
    }
}

fn normalized_rows(rows: &[Input]) -> Vec<Value> {
    let mut budget = allowance();
    rows.iter()
        .map(|row| normalized_input(&row.input, &mut budget).expect("named volatile fields"))
        .collect()
}

fn stable_action_plan(plan: &RouterSelectionPlan) -> Value {
    let mut value = serde_json::to_value(plan).expect("actual typed action plan");
    let binding = value["binding"].as_object_mut().expect("routing binding");
    // Both compilations consume the same enclosing allowance. Its entry
    // counters remain recorded, but do not change the selected actions.
    for field in ["shared_work_at_entry", "shared_bytes_at_entry"] {
        assert!(
            binding
                .remove(field)
                .expect("observed entry allowance")
                .is_u64()
        );
    }
    value
        .as_object_mut()
        .expect("plan")
        .remove("request_digest")
        .expect("quota-bound request commitment");
    for score in value["scores"].as_array_mut().expect("actual evaluations") {
        let fields = score.as_object_mut().expect("typed score");
        for field in ["request_digest", "selected_base_digest"] {
            fields
                .remove(field)
                .expect("quota-derived score commitment");
        }
    }
    value
}

fn validate_original_commitments(collected: &collector::Collected, budget: &mut QueryBudget) {
    collected
        .request
        .validate(budget)
        .expect("original request validates with its observed entry quota");
    assert_eq!(collected.request.binding, collected.plan.binding);
    assert_eq!(collected.request.digest, collected.plan.request_digest);
    assert_eq!(collected.observations.len(), collected.plan.scores.len());
    for (row, score) in collected.observations.iter().zip(&collected.plan.scores) {
        assert_eq!(row.request_digest, collected.request.digest);
        assert_eq!(score.request_digest, collected.request.digest);
        let selected: BTreeSet<_> = row
            .selected
            .pack
            .sections
            .iter()
            .map(|block| block.id.clone())
            .collect();
        let digest = canonical_digest(
            &(
                row.request_digest,
                &selected,
                &row.selected.pack,
                &row.selected.messages,
                &row.selected.outgoing,
            ),
            budget,
        )
        .expect("exact quota-bound selected tuple");
        assert_eq!(digest, row.selected_base_digest);
        assert_eq!(digest, score.selected_base_digest);
        charge(budget, 1, row.trial.outgoing.wire.len() as u64).expect("bounded trial proof");
        let wire = ContentDigest::from_bytes(*blake3::hash(&row.trial.outgoing.wire).as_bytes());
        assert_eq!(wire, row.trial_wire_digest);
        assert_eq!(wire, score.trial_wire_digest);
    }
}

fn text_in(witness: &Witness) -> String {
    witness
        .messages
        .iter()
        .map(|message| message.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn source_covered(origins: &[SourceInterval], required: &SourceInterval) -> bool {
    origins.iter().any(|span| {
        span.event_id == required.event_id
            && span.payload_digest == required.payload_digest
            && span.start <= required.start
            && span.end >= required.end
    })
}

fn assert_semantic_keys(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                assert!(
                    ![
                        "id",
                        "row_id",
                        "case_id",
                        "request_digest",
                        "selected_base_digest",
                        "trial_wire_digest",
                        "payload_digest",
                        "evaluator_version",
                        "useful",
                        "utility_micros",
                        "prior_utility_micros",
                        "known_at",
                        "source_nodes",
                    ]
                    .contains(&key.as_str()),
                    "host/evaluator field entered compiler model input: {key}",
                );
                assert_semantic_keys(child);
            }
        }
        Value::Array(items) => items.iter().for_each(assert_semantic_keys),
        _ => {}
    }
}

#[test]
fn real_fixed_policy_trajectory_is_gold_independent_and_masks_partial_complements() {
    let mut budget = allowance();
    let mut case = fixture::build_case(0, fixture::Scenario::EarlyCode, &mut budget)
        .expect("independent built-in query and candidate input");
    let first = collector::compile_case(&case, &mut budget).expect("actual semantic callbacks");
    assert!(!first.inputs.is_empty());
    assert_eq!(first.inputs.len(), first.plan.scores.len());
    for input in &first.inputs {
        assert_semantic_keys(&input.input);
    }
    let original_targets = first
        .observations
        .iter()
        .map(|row| {
            targets::label_row(row, &case.oracle, &provenance(&case), &mut budget)
                .expect("post-collection source-coverage label")
        })
        .collect::<Vec<_>>();
    assert!(original_targets.iter().any(|row| row.useful == Some(true)));

    // Changing only the evaluator cannot propose a trial or force a winner.
    case.oracle.sufficient_sets.clear();
    let second = collector::compile_case(&case, &mut budget).expect("same fixed exploration");
    assert_eq!(
        normalized_rows(&first.inputs),
        normalized_rows(&second.inputs)
    );
    assert!(first.plan.binding.shared_work_at_entry > second.plan.binding.shared_work_at_entry);
    assert!(first.plan.binding.shared_bytes_at_entry > second.plan.binding.shared_bytes_at_entry);
    assert_ne!(first.request.digest, second.request.digest);
    validate_original_commitments(&first, &mut budget);
    validate_original_commitments(&second, &mut budget);
    assert_eq!(
        stable_action_plan(&first.plan),
        stable_action_plan(&second.plan),
    );
    for (before, after) in first.observations.iter().zip(&second.observations) {
        assert!(
            before.selected == after.selected,
            "complete selected pack/messages/choices/encoding changed with gold"
        );
        assert!(
            before.trial == after.trial,
            "complete trial pack/messages/choices/encoding changed with gold"
        );
        assert_eq!(before.selected.outgoing.wire, after.selected.outgoing.wire);
        assert_eq!(before.trial.outgoing.wire, after.trial.outgoing.wire);
        assert_ne!(
            before.selected_base_digest, after.selected_base_digest,
            "original commitments must retain different entry quotas"
        );
        assert_eq!(before.trial_wire_digest, after.trial_wire_digest);
        assert_eq!(
            targets::label_row(after, &case.oracle, &provenance(&case), &mut budget)
                .expect("different post-collection label")
                .useful,
            Some(false),
        );
    }

    let bases: BTreeSet<_> = first
        .observations
        .iter()
        .map(|row| row.selected_base_digest)
        .collect();
    assert!(
        bases.len() > 1,
        "a real winner must advance the selected base"
    );
    assert!(
        first
            .observations
            .iter()
            .any(|row| row.selected.pack.sections.iter().count() > 1)
    );
    // Volatile observations stay in the raw callback, and no other semantic
    // field is erased by the cold comparator.
    let raw = &first.inputs[0].input;
    for key in VOLATILE_KEYS {
        assert!(raw["budget"][key].is_u64());
    }
    let mut volatile = raw.clone();
    for key in VOLATILE_KEYS {
        volatile["budget"][key] = Value::from(raw["budget"][key].as_u64().expect("counter") + 1);
    }
    assert_eq!(
        normalized_input(raw, &mut budget).expect("stable view"),
        normalized_input(&volatile, &mut budget).expect("stable view")
    );
    volatile["budget"]["outgoing_fits"] =
        Value::Bool(!raw["budget"]["outgoing_fits"].as_bool().expect("fit"));
    assert_ne!(
        normalized_input(raw, &mut budget).expect("stable view"),
        normalized_input(&volatile, &mut budget).expect("stable view")
    );

    let complement = fixture::build_case(0, fixture::Scenario::Complement, &mut budget)
        .expect("complement input");
    let rows =
        collector::compile_case(&complement, &mut budget).expect("real input-only pair proposals");
    let labeled = rows
        .observations
        .iter()
        .map(|row| {
            let target = targets::label_row(
                row,
                &complement.oracle,
                &provenance(&complement),
                &mut budget,
            )
            .expect("conditional label");
            (row, target)
        })
        .collect::<Vec<_>>();
    assert!(labeled.iter().any(|(row, target)| row.seed_ids.len() == 1
        && target.reason == targets::Reason::PartialRequiredCoverage
        && target.useful.is_none()
        && target.provenance.is_none()));
    assert!(
        labeled
            .iter()
            .any(|(row, target)| row.seed_ids.len() == 2 && target.useful == Some(true))
    );
    assert!(labeled.iter().any(|(row, target)| {
        row.seed_ids.len() == 1
            && target.useful == Some(true)
            && complement.oracle.sufficient_sets[0]
                .iter()
                .any(|source| source_covered(&row.selected_origins, source))
    }));

    let mandatory =
        fixture::build_case(0, fixture::Scenario::MandatoryConflictUnknown, &mut budget)
            .expect("mandatory state");
    let stopped = collector::compile_case(&mandatory, &mut budget).expect("actual STOP policy");
    assert_eq!(stopped.plan.decision, router::RouterDecision::Stop);
    assert!(
        stopped
            .plan
            .scores
            .iter()
            .all(|score| score.utility_micros.is_none())
    );
    for row in &stopped.observations {
        for kind in [PackBlockKind::Unknown, PackBlockKind::Conflict] {
            assert!(
                row.selected
                    .pack
                    .sections
                    .iter()
                    .any(|block| block.kind == kind)
            );
        }
        assert_eq!(
            targets::label_row(row, &mandatory.oracle, &provenance(&mandatory), &mut budget)
                .expect("unresolved task stays masked")
                .useful,
            None
        );
    }

    let alternative = fixture::build_case(0, fixture::Scenario::HardAlternative, &mut budget)
        .expect("alternative support input");
    let alternatives =
        collector::compile_case(&alternative, &mut budget).expect("actual chosen support");
    let code_id = &alternative.source_ids["atlas-code"];
    let local_id = &alternative.source_ids["atlas-local"];
    let actual = alternatives
        .observations
        .iter()
        .find(|row| row.seed_ids == BTreeSet::from([code_id.clone()]))
        .expect("single seed with hard closure");
    assert!(actual.closure_ids.contains(local_id));
    assert!(
        actual
            .trial
            .choices
            .iter()
            .any(|choice| &choice.block_id == code_id && choice.alternative_index == 1)
    );
    assert!(
        alternative.oracle.sufficient_sets[0]
            .iter()
            .all(|source| source_covered(&actual.trial_origins, source))
    );
    let long_alternative = &alternative.oracle.sufficient_sets[1][0];
    assert!(!source_covered(&actual.trial_origins, long_alternative));
    assert!(!text_in(&actual.trial).contains("Its retained attribution confirms"));
    assert_eq!(
        targets::label_row(
            actual,
            &alternative.oracle,
            &provenance(&alternative),
            &mut budget
        )
        .expect("actual sufficient support set")
        .useful,
        Some(true)
    );

    let resident = fixture::build_case(0, fixture::Scenario::ResidentCode, &mut budget)
        .expect("resident source");
    let resident_rows =
        collector::compile_case(&resident, &mut budget).expect("resident callbacks");
    for row in &resident_rows.observations {
        assert!(source_covered(
            &row.selected_origins,
            &resident.oracle.sufficient_sets[0][0]
        ));
        assert_eq!(
            targets::label_row(row, &resident.oracle, &provenance(&resident), &mut budget)
                .expect("resident coverage adds no source gain")
                .useful,
            Some(false)
        );
    }
    let partial = fixture::build_case(0, fixture::Scenario::PartialResident, &mut budget)
        .expect("partial resident source");
    let partial_rows = collector::compile_case(&partial, &mut budget).expect("exact overlap union");
    let required = &partial.oracle.sufficient_sets[0][0];
    let code_id = &partial.source_ids["atlas-code"];
    let row = partial_rows
        .observations
        .iter()
        .find(|row| {
            row.seed_ids == BTreeSet::from([code_id.clone()])
                && !source_covered(&row.selected_origins, required)
        })
        .expect("suffix added beyond resident prefix");
    let prefix = row
        .selected_origins
        .iter()
        .find(|span| span.event_id == required.event_id)
        .expect("actual prefix");
    assert_eq!(prefix.start, required.start);
    assert_eq!(prefix.end, "Код сейфа ".len() as u64);
    assert!(source_covered(&row.trial_origins, required));
    assert_eq!(
        row.trial_origins
            .iter()
            .filter(|span| span.event_id == required.event_id)
            .count(),
        1
    );
    let observed = partial_rows
        .inputs
        .iter()
        .find(|input| input.row_id == row.row_id)
        .expect("exact callback input");
    assert_eq!(
        observed.input["trial"]["added_original_bytes"].as_u64(),
        Some(required.end - prefix.end)
    );
    let original = &partial.originals[&required.event_id];
    let suffix = original
        .text
        .get(prefix.end as usize..required.end as usize)
        .expect("UTF8 exact suffix");
    assert!(text_in(&row.trial).contains(suffix));
    let mut left = original.span.clone();
    left.end = prefix.end;
    left.span_digest = ContentDigest::from_bytes(
        *blake3::hash(&original.text.as_bytes()[..left.end as usize]).as_bytes(),
    );
    let mut right = original.span.clone();
    right.start = prefix.end - 1; // The shared ASCII space is a genuine overlap.
    right.span_digest = ContentDigest::from_bytes(
        *blake3::hash(&original.text.as_bytes()[right.start as usize..]).as_bytes(),
    );
    let union = collector::union([&left, &right].into_iter(), &mut budget)
        .expect("same-event partial range union");
    assert!(union.len() == 1 && union[0] == *required);

    let tool = fixture::build_case(0, fixture::Scenario::ToolIndirect, &mut budget)
        .expect("current tool observation");
    let tool_rows = collector::compile_case(&tool, &mut budget).expect("actual current protocol");
    let input = &tool_rows.inputs[0].input;
    assert!(
        input["base"]["working"]
            .as_array()
            .expect("working")
            .iter()
            .any(|message| message["text"]
                .as_str()
                .is_some_and(|text| text.contains("unresolved steps remain open")))
    );
    assert!(
        input["base"]["current"]
            .as_array()
            .expect("current")
            .iter()
            .any(|message| message["role"] == "tool"
                && message["tool_result"] == 0
                && message["text"]
                    .as_str()
                    .is_some_and(|text| text.contains("permitted offline path")))
    );
    assert_semantic_keys(input);
}

#[test]
fn temporal_queries_exclude_future_originals_and_labels_bind_the_legal_correction_cutoff() {
    let mut budget = allowance();
    let mut early =
        fixture::build_case(0, fixture::Scenario::EarlyCode, &mut budget).expect("early snapshot");
    let early_rows = collector::compile_case(&early, &mut budget).expect("early callbacks");
    assert_eq!(early.known_at, 3);
    assert!(!early.source_ids.contains_key("atlas-correction"));
    assert!(
        early
            .originals
            .values()
            .all(|source| source.known_at <= early.known_at)
    );
    for row in &early_rows.inputs {
        let input = bytes(row, MAX_CONDITIONAL_INPUT_BYTES, &mut budget).expect("early input");
        let text = std::str::from_utf8(&input).expect("UTF8");
        assert!(!text.contains("8426") && !text.contains("Исправляю"));
    }
    for row in &early_rows.observations {
        for span in row.selected_origins.iter().chain(&row.trial_origins) {
            assert!(early.originals[&span.event_id].known_at <= row.known_at);
        }
    }

    let corrected = fixture::build_case(0, fixture::Scenario::CorrectedCode, &mut budget)
        .expect("legal current correction");
    let corrected_rows =
        collector::compile_case(&corrected, &mut budget).expect("corrected callbacks");
    assert_eq!(corrected.known_at, 4);
    let correction_id = &corrected.source_ids["atlas-correction"];
    let current = corrected_rows
        .observations
        .iter()
        .find(|row| row.seed_ids == BTreeSet::from([correction_id.clone()]))
        .expect("actual correction trial");
    assert!(text_in(&current.trial).contains("теперь 8426, прежний 7319 отменён"));
    let target = targets::label_row(
        current,
        &corrected.oracle,
        &provenance(&corrected),
        &mut budget,
    )
    .expect("correction coverage label");
    assert_eq!(target.useful, Some(true));
    assert_eq!(target.evaluation, current.evaluation);
    assert_eq!(target.selected_base_digest, current.selected_base_digest);
    assert_eq!(
        target
            .provenance
            .as_ref()
            .expect("known label provenance")
            .available_at,
        corrected.known_at + 1
    );

    let old_id = &corrected.source_ids["atlas-code"];
    let stale = corrected_rows
        .observations
        .iter()
        .find(|row| {
            row.seed_ids == BTreeSet::from([old_id.clone()])
                && !source_covered(&row.trial_origins, &corrected.oracle.sufficient_sets[0][0])
        })
        .expect("old observation without current correction");
    assert_eq!(
        targets::label_row(
            stale,
            &corrected.oracle,
            &provenance(&corrected),
            &mut budget
        )
        .expect("explicit source-coverage negative")
        .useful,
        Some(false)
    );
    // This is a correction source-coverage oracle, not a reader counterfactual
    // claim about every closure that also contains a stale observation.

    let (roots, nodes) = fixture::lineage(&corrected).expect("all query-time sources");
    assert!(
        nodes
            .iter()
            .all(|node| node.available_at <= corrected.known_at)
    );
    assert!(
        roots
            .iter()
            .all(|root| root.kind == RouterLineageKind::SourceVersion)
    );
    assert!(
        roots
            .iter()
            .any(|root| root.id == corrected.oracle.sufficient_sets[0][0].event_id.to_string())
    );
    early
        .originals
        .values_mut()
        .next()
        .expect("source")
        .known_at = early.known_at + 1;
    assert!(
        fixture::lineage(&early).is_err(),
        "future source must not become a query-time root"
    );
    let mut invalid_provenance = provenance(&corrected);
    invalid_provenance.available_at = corrected.known_at;
    assert!(
        targets::label_row(current, &corrected.oracle, &invalid_provenance, &mut budget).is_err()
    );
}

fn replace_artifact(root: &Path, name: &str, data: &[u8]) {
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("completed manifest"))
            .expect("manifest shape");
    manifest.artifacts.insert(
        name.into(),
        Artifact {
            bytes: data.len() as u64,
            digest: ContentDigest::from_bytes(*blake3::hash(data).as_bytes()),
        },
    );
    fs::write(root.join(name), data).expect("self-rehashed untrusted artifact");
    fs::write(
        root.join("manifest.json"),
        bytes(&manifest, 64 * 1024, &mut allowance()).expect("canonical manifest"),
    )
    .expect("hashes are not proof of semantic agreement");
}

#[test]
fn cold_exact_joins_lineage_and_bounds_preserve_the_legacy_profile() {
    let old_before = super::super::fixture::build_case(
        0,
        super::super::fixture::Scenario::EarlyCode,
        &mut allowance(),
    )
    .expect("legacy API before conditional generation");
    let mut corpus =
        build_artifacts(&mut allowance()).expect("whole bounded public conditional corpus");
    validate_counts(&corpus, &mut allowance()).expect("declared inventory");
    files::validate_rows(&corpus, &mut allowance()).expect("exact source and callback joins");
    assert_eq!(corpus.lineage.cases.len(), fixture::SCENARIOS.len() * 4);
    assert!(!corpus.inputs.is_empty() && corpus.inputs.len() <= MAX_CONDITIONAL_ROWS);
    let assignments = &corpus.lineage.assignments;
    for group in 0..4 {
        let rows: Vec<_> = assignments
            .iter()
            .filter(|row| row.example_id.starts_with(&format!("group-{group}-")))
            .collect();
        assert_eq!(rows.len(), fixture::SCENARIOS.len());
        assert!(
            rows.iter()
                .all(|row| row.group_digest == rows[0].group_digest)
        );
        assert!(rows.iter().all(|row| row.partition
            == [
                RouterPartition::Train,
                RouterPartition::Validation,
                RouterPartition::Test,
                RouterPartition::Quarantined
            ][group]));
    }
    for ((input, observed), target) in corpus
        .inputs
        .iter()
        .zip(&corpus.observations)
        .zip(&corpus.targets)
    {
        assert_eq!(input.row_id, observed.row_id);
        assert_eq!(target.evaluation, observed.evaluation);
        assert_eq!(target.feature_digest, observed.feature_digest);
        assert_eq!(target.selected_base_digest, observed.selected_base_digest);
        assert_eq!(target.trial_wire_digest, observed.trial_wire_digest);
        assert_semantic_keys(&input.input);
    }
    // A target cannot borrow any other evaluation, base, feature or trial.
    let original = corpus.targets[0].clone();
    corpus.targets[0].evaluation += 1;
    assert!(files::validate_rows(&corpus, &mut allowance()).is_err());
    corpus.targets[0] = original.clone();
    let unrelated = ContentDigest::from_bytes([93; 32]);
    corpus.targets[0].selected_base_digest = unrelated;
    assert!(files::validate_rows(&corpus, &mut allowance()).is_err());
    corpus.targets[0] = original.clone();
    corpus.targets[0].trial_wire_digest = unrelated;
    assert!(files::validate_rows(&corpus, &mut allowance()).is_err());
    corpus.targets[0] = original.clone();
    corpus.targets[0].feature_digest = unrelated;
    assert!(files::validate_rows(&corpus, &mut allowance()).is_err());
    corpus.targets[0] = original;

    let old_after = super::super::fixture::build_case(
        0,
        super::super::fixture::Scenario::EarlyCode,
        &mut allowance(),
    )
    .expect("legacy API after conditional generation");
    assert_eq!(
        old_before.routed.plan.binding.feature_schema,
        router::FEATURE_SCHEMA
    );
    assert_eq!(
        old_before.routed.assembly.outgoing.wire,
        old_after.routed.assembly.outgoing.wire
    );
    assert_eq!(
        bytes(
            &old_before.routed.plan,
            MAX_CONDITIONAL_INPUT_BYTES,
            &mut allowance()
        )
        .expect("legacy plan"),
        bytes(
            &old_after.routed.plan,
            MAX_CONDITIONAL_INPUT_BYTES,
            &mut allowance()
        )
        .expect("same legacy plan"),
    );
    assert!(old_after.routed.prepared_material.prepared_policy.is_none());
    assert!(old_after.routed.replay_observation.is_none());
    assert_eq!(
        ROUTER_CORPUS_VERSION,
        "contextdb.router-corpus.synthetic.v1"
    );
    assert_ne!(
        CONDITIONAL_MODEL_PROFILE,
        "contextdb.kev-public-synthetic-initial-context-bce.v1"
    );

    let temp = tempfile::tempdir().expect("owned synthetic output parent");
    let parent = fs::canonicalize(temp.path()).expect("canonical parent on every platform");
    files::validate_root(&parent, true).expect("intentional strict path admission");
    let root = parent.join("conditional");
    files::write(&root, &corpus, &mut allowance()).expect("bounded artifacts");
    let report = verify_builtin_router_conditional_corpus(&root, &mut allowance())
        .expect("cold exact validation");
    assert!(
        !report.reader_benefit_measured
            && !report.private_intake_available
            && !report.volatile_allowance_replayed
    );
    assert!(report.positive > 0 && report.negative > 0 && report.unknown > 0);
    assert_eq!(
        (
            report.train,
            report.validation,
            report.test,
            report.quarantined
        ),
        (12, 12, 12, 12)
    );
    let manifest = fs::read(root.join("manifest.json")).expect("completion witness");
    assert_eq!(
        report,
        write_builtin_router_conditional_corpus(&root, &mut allowance())
            .expect("lost ACK exact retry")
    );
    assert_eq!(
        manifest,
        fs::read(root.join("manifest.json")).expect("completed bytes unchanged")
    );

    let original_inputs = fs::read(root.join("inputs.json")).expect("inputs");
    let original_observations = fs::read(root.join("observations.json")).expect("observations");
    let original_targets = fs::read(root.join("targets.json")).expect("targets");
    // Rehash all four association commitments while changing a nonvolatile
    // capacity field. The cold actual compiler input must still disagree.
    corpus.inputs[0].input["budget"]["memory"]["hard_tokens"] = Value::from(11999);
    let altered = commitment(
        &corpus.inputs[0].input,
        MAX_CONDITIONAL_INPUT_BYTES,
        &mut allowance(),
    )
    .expect("new untrusted feature commitment");
    corpus.observations[0].feature_digest = altered;
    corpus.targets[0].feature_digest = altered;
    replace_artifact(
        &root,
        "inputs.json",
        &bytes(
            &corpus.inputs,
            MAX_CONDITIONAL_CORPUS_BYTES,
            &mut allowance(),
        )
        .expect("forged bounded inputs"),
    );
    replace_artifact(
        &root,
        "observations.json",
        &bytes(
            &corpus.observations,
            MAX_CONDITIONAL_CORPUS_BYTES,
            &mut allowance(),
        )
        .expect("forged joins"),
    );
    replace_artifact(
        &root,
        "targets.json",
        &bytes(
            &corpus.targets,
            MAX_CONDITIONAL_CORPUS_BYTES,
            &mut allowance(),
        )
        .expect("forged labels"),
    );
    assert!(verify_builtin_router_conditional_corpus(&root, &mut allowance()).is_err());
    replace_artifact(&root, "inputs.json", &original_inputs);
    replace_artifact(&root, "observations.json", &original_observations);
    replace_artifact(&root, "targets.json", &original_targets);

    let original_lineage = fs::read(root.join("lineage.json")).expect("lineage");
    let mut broken = corpus.lineage.clone();
    broken
        .nodes
        .iter_mut()
        .find(|node| node.reference.kind == RouterLineageKind::Evaluation)
        .expect("separate later evaluator")
        .parents
        .pop();
    replace_artifact(
        &root,
        "lineage.json",
        &bytes(&broken, MAX_CONDITIONAL_CORPUS_BYTES, &mut allowance()).expect("broken derivation"),
    );
    assert!(verify_builtin_router_conditional_corpus(&root, &mut allowance()).is_err());
    replace_artifact(&root, "lineage.json", &original_lineage);
    assert_eq!(
        report,
        verify_builtin_router_conditional_corpus(&root, &mut allowance())
            .expect("exact restored artifacts")
    );

    let mut empty = QueryBudget::new(0, 0, Duration::from_secs(10), Default::default());
    let fresh = parent.join("never-written");
    assert!(write_builtin_router_conditional_corpus(&fresh, &mut empty).is_err());
    assert!(!fresh.exists());
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled =
        QueryBudget::new(10_000_000, 1 << 30, Duration::from_secs(10), cancellation);
    assert!(write_builtin_router_conditional_corpus(&fresh, &mut cancelled).is_err());
    assert!(!fresh.exists());
    let mut no_copy = QueryBudget::new(1, 0, Duration::from_secs(10), Default::default());
    assert!(normalized_input(&corpus.inputs[0].input, &mut no_copy).is_err());
    let oversized = Value::String("x".repeat(MAX_CONDITIONAL_INPUT_BYTES + 1));
    assert!(normalized_input(&oversized, &mut allowance()).is_err());
    let incomplete = parent.join("incomplete");
    fs::create_dir(&incomplete).expect("interrupted output");
    fs::write(incomplete.join("inputs.json.part"), b"PENDING_SYNTHETIC").expect("partial bytes");
    assert!(write_builtin_router_conditional_corpus(&incomplete, &mut allowance()).is_err());
    assert_eq!(
        fs::read(incomplete.join("inputs.json.part")).expect("preserved interrupted bytes"),
        b"PENDING_SYNTHETIC"
    );
}
