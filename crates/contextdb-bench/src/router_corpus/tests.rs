use super::*;
use contextdb_context::router::{RouterMaterialStatus, canonical_digest};
use contextdb_recall::{QueryBudget, QueryCancellation};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

fn allowance() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        256 * 1024 * 1024,
        Duration::from_secs(20),
        Default::default(),
    )
}
fn built(scenario: fixture::Scenario) -> (RouterQueryTimeRecord, RouterBehaviorRecord) {
    let case = fixture::build_case(0, scenario, &mut allowance())
        .expect("actual built-in compiler fixture");
    let mut roots = BTreeSet::new();
    for span in case
        .routed
        .prepared_material
        .evidence
        .iter()
        .filter_map(|item| item.original_span.as_ref())
        .chain(
            case.base
                .control
                .iter()
                .chain(&case.base.working)
                .chain(&case.base.hot)
                .chain(&case.base.current)
                .flat_map(|message| message.originals.iter().map(|original| &original.span)),
        )
    {
        roots.insert(RouterLineageRef {
            kind: RouterLineageKind::SourceVersion,
            domain: case.query.logical_domain.clone(),
            id: span.event_id.to_string(),
            version: Some(span.payload_digest.to_string()),
        });
    }
    let behavior = RouterBehaviorRecord {
        format: ROUTER_BEHAVIOR_VERSION.into(),
        example_id: case.query.id.clone(),
        request_digest: case.routed.request.digest,
        plan: case.routed.plan,
        manifest: case.routed.manifest,
        attempt: RouterAttemptStatus::Prepared,
        accepted_receipt: None,
        replay_observation: case.routed.replay_observation,
    };
    let observation = SyntheticObservationBinding {
        generator: fixture::GENERATOR.into(),
        fixture_id: case.fixture_id,
        source_domain: case.query.logical_domain.clone(),
        source_cutoff: case.query.known_at,
        compiler_domain: case.routed.request.context.snapshot.database_id.clone(),
        compiler_cutoff: case.routed.request.context.snapshot.commit_seq,
        source_nodes: roots.into_iter().collect(),
    };
    (
        RouterQueryTimeRecord {
            format: ROUTER_QUERY_VERSION.into(),
            query: case.query,
            request: case.routed.request,
            base: case.base,
            material: case.routed.prepared_material,
            observation,
        },
        behavior,
    )
}
fn provenance(input: &RouterQueryTimeRecord) -> RouterLabelProvenance {
    RouterLabelProvenance {
        kind: RouterLabelKind::SyntheticSourceSet,
        evaluator_version: "synthetic-source-set.v1".into(),
        available_at: input.query.known_at,
        logical_domain: input.query.logical_domain.clone(),
        source_nodes: input.observation.source_nodes.clone(),
    }
}
fn targets(input: &RouterQueryTimeRecord, behavior: &RouterBehaviorRecord) -> RouterUtilityTargets {
    RouterUtilityTargets {
        format: ROUTER_TARGET_VERSION.into(),
        example_id: input.query.id.clone(),
        conditional_base_digest: behavior
            .plan
            .scores
            .first()
            .expect("observed scoring base")
            .selected_base_digest,
        candidates: input
            .request
            .units
            .iter()
            .map(|unit| CandidateUtilityTarget {
                candidate_id: unit.id.clone(),
                useful: None,
                provenance: None,
            })
            .collect(),
        bundles: Vec::new(),
    }
}

#[test]
fn query_projection_and_actual_features_exclude_evaluation_and_r0_utilities() {
    let mut target = crate::continuous_history(0).evaluation.remove(0);
    let projected = RouterQuerySpec::from_target(&target, "fixture-domain", &mut allowance())
        .expect("query-only projection");
    target.answer = "FUTURE_EVALUATOR_SECRET".into();
    target.evidence_ids = vec!["forged-future-source".into()];
    assert_eq!(
        projected,
        RouterQuerySpec::from_target(&target, "fixture-domain", &mut allowance())
            .expect("same observable query")
    );
    let (mut input, behavior) = built(fixture::Scenario::EarlyCode);
    let original =
        build_router_features(&input, &mut allowance()).expect("verified actual compiler material");
    assert_eq!(
        original.material_verification.support_material,
        RouterMaterialStatus::Verified
    );
    assert!(matches!(
        original.material_verification.historical_selection,
        RouterMaterialStatus::Unavailable(_)
    ));
    let feature_bytes = router_corpus_bytes(
        &original.features,
        MAX_ROUTER_EXAMPLE_BYTES,
        &mut allowance(),
    )
    .expect("bounded features");
    let text = std::str::from_utf8(&feature_bytes).expect("feature JSON");
    for excluded in [
        "utility_micros",
        "prior_utility_micros",
        "selected_ids",
        "scores",
        "teacher",
        "FUTURE_EVALUATOR_SECRET",
    ] {
        assert!(!text.contains(excluded));
    }
    for candidate in &mut input.material.candidates {
        candidate.utility_micros = 23;
    }
    for unit in &mut input.request.units {
        unit.descriptor.prior_utility_micros = 23;
    }
    input.request.binding.candidates = canonical_digest(&input.request.units, &mut allowance())
        .expect("changed R0 observation binding");
    input.request.digest = input
        .request
        .content_digest(&mut allowance())
        .expect("new input commitment");
    let changed = build_router_features(&input, &mut allowance())
        .expect("policy commitment remains explicitly unavailable");
    assert_eq!(changed.feature_digest, original.feature_digest);
    assert_ne!(changed.request_digest, original.request_digest);
    assert!(!format!("{input:?} {changed:?} {behavior:?}").contains("Код сейфа Atlas"));
    let mut missing_root = input.clone();
    missing_root.observation.source_nodes.pop();
    assert!(build_router_features(&missing_root, &mut allowance()).is_err());
    let mut injected = serde_json::to_value(&input).expect("input");
    injected.as_object_mut().expect("object").insert(
        "teacher_verdict".into(),
        serde_json::json!("FUTURE_EVALUATOR_SECRET"),
    );
    assert!(
        RouterQueryTimeRecord::from_json(
            &serde_json::to_vec(&injected).expect("forged transport"),
            &mut allowance()
        )
        .is_err()
    );
}

#[test]
fn unknown_multi_positive_all_zero_and_complement_labels_keep_independent_masks() {
    let (input, behavior) = built(fixture::Scenario::Complement);
    let mut labels = targets(&input, &behavior);
    let optional: Vec<_> = input
        .request
        .units
        .iter()
        .filter(|unit| !input.request.mandatory_ids.contains(&unit.id))
        .map(|unit| unit.id.clone())
        .collect();
    assert!(optional.len() >= 2);
    assert_eq!(labels.known_labels(), 0);
    labels.bundles.push(BundleUtilityTarget {
        bundle_id: "explicit-complement".into(),
        members: optional[..2].to_vec(),
        useful: Some(true),
        provenance: Some(provenance(&input)),
    });
    validate_router_targets(&input, &behavior, &labels, &mut allowance())
        .expect("bundle-only knowledge does not label members");
    assert!(labels.candidates.iter().all(|item| item.useful.is_none()));
    for target in labels
        .candidates
        .iter_mut()
        .filter(|item| optional[..2].contains(&item.candidate_id))
    {
        target.useful = Some(true);
        target.provenance = Some(provenance(&input));
    }
    assert_eq!(labels.known_labels(), 3);
    validate_router_targets(&input, &behavior, &labels, &mut allowance())
        .expect("several independent positives");
    let bytes = router_corpus_bytes(&labels, MAX_ROUTER_TARGET_BYTES, &mut allowance())
        .expect("bounded target partition");
    assert_eq!(
        RouterUtilityTargets::from_json(&bytes, &mut allowance()).expect("cold masked labels"),
        labels
    );
    labels.candidates[0].useful = Some(false);
    labels.candidates[0].provenance = None;
    assert!(validate_router_targets(&input, &behavior, &labels, &mut allowance()).is_err());
    let (input, mut behavior) = built(fixture::Scenario::NoMemory);
    let mut zero = targets(&input, &behavior);
    for target in zero
        .candidates
        .iter_mut()
        .filter(|item| !input.request.mandatory_ids.contains(&item.candidate_id))
    {
        target.useful = Some(false);
        target.provenance = Some(provenance(&input));
    }
    validate_router_targets(&input, &behavior, &zero, &mut allowance())
        .expect("all-zero optional labels remain valid");
    assert!(!input.request.mandatory_ids.is_empty());
    behavior.plan.behavior_propensity = Some(1.0);
    assert!(validate_router_behavior(&input, &behavior, &mut allowance()).is_err());
}

fn source(domain: &str, id: &str, version: &str) -> RouterLineageRef {
    RouterLineageRef {
        kind: RouterLineageKind::SourceVersion,
        domain: domain.into(),
        id: id.into(),
        version: Some(version.into()),
    }
}
fn split() -> RouterSplitSpec {
    RouterSplitSpec {
        domains: BTreeMap::from([(
            "domain".into(),
            RouterTimeCutoffs {
                train_until: 10,
                validation_until: 20,
            },
        )]),
    }
}
fn example(id: &str, cutoff: u64, roots: Vec<RouterLineageRef>) -> RouterExampleLineage {
    RouterExampleLineage {
        example_id: id.into(),
        logical_domain: "domain".into(),
        cutoff,
        roots,
    }
}

#[test]
fn typed_connected_groups_are_permutation_stable_and_boundary_windows_quarantine() {
    let a = source("domain", "original", "v1");
    let b = source("domain", "original", "v2");
    let c = source("domain", "other-original", "v1");
    let nodes = vec![
        RouterLineageNode {
            reference: a.clone(),
            available_at: 2,
            parents: Vec::new(),
        },
        RouterLineageNode {
            reference: b.clone(),
            available_at: 12,
            parents: vec![a.clone()],
        },
        RouterLineageNode {
            reference: c.clone(),
            available_at: 23,
            parents: Vec::new(),
        },
    ];
    let examples = vec![
        example("early", 4, vec![a.clone()]),
        example("corrected", 13, vec![b]),
        example("independent", 24, vec![c]),
    ];
    let assigned = assign_router_group_time_split(&nodes, &examples, &split(), &mut allowance())
        .expect("connected historical window");
    assert_eq!(
        assigned
            .iter()
            .find(|item| item.example_id == "early")
            .expect("early")
            .partition,
        RouterPartition::Quarantined
    );
    assert_eq!(
        assigned
            .iter()
            .find(|item| item.example_id == "corrected")
            .expect("corrected")
            .partition,
        RouterPartition::Quarantined
    );
    assert_eq!(
        assigned
            .iter()
            .find(|item| item.example_id == "independent")
            .expect("independent")
            .partition,
        RouterPartition::Test
    );
    let mut reversed_nodes = nodes.clone();
    reversed_nodes.reverse();
    let mut reversed_examples = examples.clone();
    reversed_examples.reverse();
    assert_eq!(
        assigned,
        assign_router_group_time_split(
            &reversed_nodes,
            &reversed_examples,
            &split(),
            &mut allowance()
        )
        .expect("order-independent grouping")
    );
    assert!(
        assign_router_group_time_split(
            &nodes,
            &[example("future-leak", 1, vec![a])],
            &split(),
            &mut allowance()
        )
        .is_err()
    );
    let mut broken = nodes.clone();
    broken[1].parents = vec![source("domain", "missing", "v1")];
    assert!(
        assign_router_group_time_split(&broken, &examples, &split(), &mut allowance()).is_err()
    );
    let mut cyclic = nodes.clone();
    cyclic[0].available_at = 12;
    cyclic[0].parents = vec![cyclic[1].reference.clone()];
    assert!(
        assign_router_group_time_split(&cyclic, &examples, &split(), &mut allowance()).is_err()
    );
    let mut foreign = nodes.clone();
    let other = source("other-domain", "foreign", "v1");
    foreign.push(RouterLineageNode {
        reference: other.clone(),
        available_at: 1,
        parents: Vec::new(),
    });
    foreign[1].parents = vec![other];
    let mut domains = split();
    domains.domains.insert(
        "other-domain".into(),
        RouterTimeCutoffs {
            train_until: 10,
            validation_until: 20,
        },
    );
    assert!(
        assign_router_group_time_split(&foreign, &examples, &domains, &mut allowance()).is_err()
    );
    let mut leaked = nodes;
    let evaluator = RouterLineageRef {
        kind: RouterLineageKind::Evaluation,
        domain: "domain".into(),
        id: "teacher-verdict".into(),
        version: Some("v1".into()),
    };
    leaked.push(RouterLineageNode {
        reference: evaluator.clone(),
        available_at: 1,
        parents: Vec::new(),
    });
    leaked[0].parents = vec![evaluator];
    assert!(
        assign_router_group_time_split(&leaked, &examples, &split(), &mut allowance()).is_err(),
        "even an early evaluator verdict cannot be a query-time derivation ancestor"
    );
}

#[test]
fn bounds_and_cancellation_reject_before_feature_copies_and_never_echo_payload() {
    let (mut input, _) = built(fixture::Scenario::EarlyCode);
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        100_000,
        16 * 1024 * 1024,
        Duration::from_secs(20),
        cancellation,
    );
    assert!(build_router_features(&input, &mut cancelled).is_err());
    let mut exhausted = QueryBudget::new(100_000, 1, Duration::from_secs(20), Default::default());
    assert!(build_router_features(&input, &mut exhausted).is_err());
    input.query.query = "PRIVATE_PAYLOAD".repeat(4096);
    let error = build_router_features(&input, &mut allowance()).expect_err("bounded query");
    assert!(!error.to_string().contains("PRIVATE_PAYLOAD"));
    assert!(
        RouterUtilityTargets::from_json(&vec![b' '; MAX_ROUTER_TARGET_BYTES + 1], &mut allowance())
            .is_err()
    );
}
