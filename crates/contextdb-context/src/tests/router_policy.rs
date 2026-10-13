//! Actual compiler policy capture, complete commitments and legacy compatibility.

use super::*;
use crate::router::{
    ROUTER_PREPARED_POLICY_FORMAT, RouterMaterialStatus, RouterMaterialUnavailableReason,
    RouterPreparedMaterial, RouterPreparedPolicy,
};

fn with_policy(
    request: &CompileAssemblyRequest,
    provider: &dyn AssemblyProvider,
    scorer: &dyn ContextScorer,
    budget: &mut QueryBudget,
) -> Result<RoutedAssembly> {
    ContextCompiler::new([7; 32])?.compile_assembly_with_router_policy(
        request,
        provider,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        scorer,
        budget,
    )
}

fn captured() -> RoutedAssembly {
    must(with_policy(
        &input(),
        &shared_fixture(false),
        &Stop,
        &mut allowance(),
    ))
}

fn policy_a(material: &mut RouterPreparedMaterial) -> &mut crate::router::RouterPreparedUnitPolicy {
    material
        .prepared_policy
        .as_mut()
        .expect("explicit compiler policy")
        .units
        .iter_mut()
        .find(|unit| unit.id.as_str() == "a")
        .expect("discarded multi-support unit")
}

#[test]
fn explicit_policy_cold_roundtrip_verifies_every_variant_and_actual_directive() {
    for scorer in [&Stop as &dyn ContextScorer, &R0Scorer] {
        let mut query = input();
        query.context.required_facets.push(PackFacetRequirement {
            name: "not-established".into(),
            minimum_confidence_micros: 1,
            require_evidence: true,
        });
        let provider = shared_fixture(false);
        let legacy = must(routed(&query, &provider, scorer));
        let record = must(with_policy(&query, &provider, scorer, &mut allowance()));
        assert_eq!(record.request, legacy.request);
        assert_eq!(record.plan, legacy.plan);
        assert_eq!(record.assembly.outgoing, legacy.assembly.outgoing);
        assert_eq!(
            record.assembly.context.canonical_protobuf,
            legacy.assembly.context.canonical_protobuf
        );
        assert!(
            record
                .request
                .units
                .iter()
                .any(|unit| unit.kind == PackBlockKind::Unknown)
        );
        let material: RouterPreparedMaterial = must(serde_json::from_slice(&must(
            serde_json::to_vec(&record.prepared_material),
        )));
        let policy = material.prepared_policy.as_ref().expect("compiler policy");
        assert_eq!(policy.format, ROUTER_PREPARED_POLICY_FORMAT);
        assert_eq!(policy.units.len(), record.request.units.len());
        assert_eq!(
            policy
                .units
                .iter()
                .find(|unit| unit.id.as_str() == "a")
                .expect("a")
                .alternatives
                .len(),
            2,
            "both sufficient supports are retained, including discarded support"
        );
        for directive in &record.assembly.context.pack.use_directives {
            let choice = record
                .plan
                .choices
                .iter()
                .find(|choice| choice.id == directive.block_id)
                .expect("selected support");
            let actual = &policy
                .units
                .iter()
                .find(|unit| unit.id == directive.block_id)
                .expect("policy unit")
                .alternatives[choice.alternative_index as usize];
            assert_eq!(actual.use_action, directive.action);
            assert_eq!(actual.directive_reason, directive.reason_code);
        }
        let verification = must(ContextCompiler::validate_router_material(
            &record.request,
            &material,
            &mut allowance(),
        ));
        assert_eq!(
            verification.candidate_commitment,
            RouterMaterialStatus::Verified
        );
        assert_eq!(
            verification.historical_selection,
            RouterMaterialStatus::Unavailable(
                RouterMaterialUnavailableReason::MissingReplayPreparation
            )
        );
    }

    let replay = must(
        must(ContextCompiler::new([7; 32])).compile_assembly_with_router_replay(
            &input(),
            &shared_fixture(false),
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &R0Scorer,
            &mut allowance(),
        ),
    );
    let verification = must(ContextCompiler::validate_router_material(
        &replay.request,
        &replay.prepared_material,
        &mut allowance(),
    ));
    assert_eq!(
        verification.candidate_commitment,
        RouterMaterialStatus::Verified
    );
    assert_eq!(
        verification.historical_selection,
        RouterMaterialStatus::Unavailable(
            RouterMaterialUnavailableReason::HistoricalReplayNotExecuted
        )
    );
    let preparation = replay
        .prepared_material
        .prepared_policy
        .as_ref()
        .and_then(|policy| policy.replay.as_ref())
        .expect("actual replay preparation");
    let observation = replay.replay_observation.as_ref().expect("actual behavior");
    must(ContextCompiler::validate_router_replay_observation(
        &replay.request,
        &replay.manifest,
        preparation,
        observation,
        &mut allowance(),
    ));
    let mut mismatched = observation.clone();
    mismatched.preparation_digest = ContentDigest::from_bytes([81; 32]);
    assert!(
        ContextCompiler::validate_router_replay_observation(
            &replay.request,
            &replay.manifest,
            preparation,
            &mismatched,
            &mut allowance()
        )
        .is_err()
    );

    // These policies are independently chosen by the real provider/prepare path,
    // rather than inferred from roles by the retained-material validator.
    for (interpretation, disclosure, action, reason) in [
        (
            InterpretationRule::FactualData,
            DisclosureRule::UseSilently,
            UseAction::UseSilently,
            DirectiveReason::MentionDenied,
        ),
        (
            InterpretationRule::FactualData,
            DisclosureRule::MentionOnlyWhenExplicit,
            UseAction::UseSilently,
            DirectiveReason::ExplicitRequestRequired,
        ),
        (
            InterpretationRule::ConstraintData,
            DisclosureRule::UseSilently,
            UseAction::ConstraintOnly,
            DirectiveReason::ConstraintSemantics,
        ),
        (
            InterpretationRule::StyleSignal,
            DisclosureRule::UseSilently,
            UseAction::StyleOnly,
            DirectiveReason::StyleSemantics,
        ),
    ] {
        let mut candidate = fact("controlled", "shared", true);
        candidate.candidate.interpretation = interpretation;
        candidate.use_policy.disclosure = disclosure;
        let provider = fixture(
            vec![situation_candidate(), candidate],
            vec![source(
                "shared",
                claim(1),
                "An exact independently attributed decision.",
            )],
        );
        let record = must(with_policy(&input(), &provider, &Stop, &mut allowance()));
        let actual = &record
            .prepared_material
            .prepared_policy
            .as_ref()
            .expect("actual policy")
            .units
            .iter()
            .find(|unit| unit.id.as_str() == "controlled")
            .expect("controlled unit")
            .alternatives[0];
        assert_eq!(
            (actual.use_action, actual.directive_reason),
            (action, reason)
        );
        assert_eq!(
            must(ContextCompiler::validate_router_material(
                &record.request,
                &record.prepared_material,
                &mut allowance()
            ))
            .candidate_commitment,
            RouterMaterialStatus::Verified
        );
    }
}

#[test]
fn discarded_policy_unused_representations_and_candidate_flags_are_committed() {
    let record = captured();
    assert!(record.plan.seed_ids.is_empty());
    let mut action = record.prepared_material.clone();
    policy_a(&mut action).alternatives[1].use_action = UseAction::UseSilently;
    let mut reason = record.prepared_material.clone();
    policy_a(&mut reason).alternatives[1].directive_reason = DirectiveReason::MentionDenied;
    let mut unused = record.prepared_material.clone();
    let unit = record
        .request
        .units
        .iter()
        .find(|unit| unit.id.as_str() == "a")
        .expect("unit");
    unused
        .candidates
        .iter_mut()
        .find(|candidate| candidate.id == unit.id)
        .expect("candidate")
        .representations
        .iter_mut()
        .find(|representation| {
            unit.support_alternatives
                .iter()
                .all(|alternative| alternative.level != representation.level)
        })
        .expect("unused representation")
        .summary
        .push_str(" valid unused bytes are also committed");
    let mut flag = record.prepared_material.clone();
    flag.candidates
        .iter_mut()
        .find(|candidate| candidate.id.as_str() == "a")
        .expect("candidate")
        .mandatory = true;
    for (name, material) in [
        ("discarded action", action),
        ("discarded reason", reason),
        ("unused representation", unused),
        ("candidate-only flag", flag),
    ] {
        assert!(
            matches!(ContextCompiler::validate_router_material(&record.request, &material, &mut allowance()), Err(ContextError::InvalidRequest(ref reason)) if reason.contains("candidate commitment")),
            "{name}"
        );
    }
    let mut request = record.request.clone();
    request
        .units
        .iter_mut()
        .find(|unit| unit.id.as_str() == "a")
        .expect("unit")
        .candidate_digest = ContentDigest::from_bytes([51; 32]);
    request.binding.candidates = must(canonical_digest(&request.units, &mut allowance()));
    let request = must(request.seal(&mut allowance()));
    assert!(
        matches!(ContextCompiler::validate_router_material(&request, &record.prepared_material, &mut allowance()), Err(ContextError::InvalidRequest(ref reason)) if reason.contains("candidate commitment"))
    );
}

#[test]
fn legacy_bytes_stay_unchanged_and_new_policy_shape_is_strict_and_redacted() {
    #[derive(serde::Serialize)]
    struct LegacyMaterial<'a> {
        candidates: &'a [PackCandidate],
        evidence: &'a [PackEvidence],
    }
    let provider = shared_fixture(false);
    let legacy = must(routed(&input(), &provider, &Stop));
    assert!(legacy.prepared_material.prepared_policy.is_none());
    let old_shape = LegacyMaterial {
        candidates: &legacy.prepared_material.candidates,
        evidence: &legacy.prepared_material.evidence,
    };
    assert_eq!(
        must(serde_json::to_vec(&legacy.prepared_material)),
        must(serde_json::to_vec(&old_shape))
    );
    let mut current_budget = allowance();
    let mut legacy_budget = allowance();
    assert_eq!(
        must(crate::router::canonical_bytes(
            &legacy.prepared_material,
            &mut current_budget
        )),
        must(crate::router::canonical_bytes(
            &old_shape,
            &mut legacy_budget
        ))
    );
    assert_eq!(
        (
            current_budget.remaining_work(),
            current_budget.remaining_bytes()
        ),
        (
            legacy_budget.remaining_work(),
            legacy_budget.remaining_bytes()
        )
    );
    let record = captured();
    type Change = fn(&mut RouterPreparedMaterial);
    let mutations: [(&str, Change); 8] = [
        ("unsupported format", |material| {
            material
                .prepared_policy
                .as_mut()
                .expect("policy")
                .format
                .push_str(".future")
        }),
        ("missing unit", |material| {
            material
                .prepared_policy
                .as_mut()
                .expect("policy")
                .units
                .pop();
        }),
        ("reordered units", |material| {
            material
                .prepared_policy
                .as_mut()
                .expect("policy")
                .units
                .swap(0, 1)
        }),
        ("duplicate unit", |material| {
            let policy = material.prepared_policy.as_mut().expect("policy");
            policy.units[1] = policy.units[0].clone();
        }),
        ("missing support", |material| {
            policy_a(material).alternatives.pop();
        }),
        ("duplicate index", |material| {
            policy_a(material).alternatives[1].index = 0
        }),
        ("reordered supports", |material| {
            policy_a(material).alternatives.swap(0, 1)
        }),
        ("extra support", |material| {
            let policy = policy_a(material);
            policy.alternatives.push(policy.alternatives[0]);
        }),
    ];
    for (name, change) in mutations {
        let mut material = record.prepared_material.clone();
        change(&mut material);
        assert!(
            ContextCompiler::validate_router_material(&record.request, &material, &mut allowance())
                .is_err(),
            "{name}"
        );
    }
    let policy = record
        .prepared_material
        .prepared_policy
        .as_ref()
        .expect("policy");
    let mut unknown = must(serde_json::to_value(policy));
    unknown["units"][0]["alternatives"][0]["future_gold"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RouterPreparedPolicy>(unknown).is_err());
    let bytes = must(serde_json::to_string(policy));
    let duplicate = bytes.replacen("\"index\":0", "\"index\":0,\"index\":0", 1);
    assert_ne!(duplicate, bytes);
    assert!(serde_json::from_str::<RouterPreparedPolicy>(&duplicate).is_err());
    let mut redacted = policy.clone();
    redacted.units[0].id = must(BlockId::new("private-candidate-secret"));
    assert!(!format!("{redacted:?}").contains("private-candidate-secret"));
    assert!(!format!("{:?}", redacted.units[0]).contains("private-candidate-secret"));
}

#[test]
fn policy_capture_and_validation_share_the_enclosing_budget_and_reject_oversize() {
    let record = captured();
    for (work, bytes, cancelled) in [(0, 4096, false), (4096, 1, false), (4096, 4096, true)] {
        let cancellation = contextdb_recall::QueryCancellation::default();
        if cancelled {
            cancellation.cancel();
        }
        let mut budget =
            QueryBudget::new(work, bytes, std::time::Duration::from_secs(5), cancellation);
        assert!(matches!(
            ContextCompiler::validate_router_material(
                &record.request,
                &record.prepared_material,
                &mut budget
            ),
            Err(ContextError::BudgetExceeded(_))
        ));
    }
    let mut oversized = record.prepared_material.clone();
    oversized.candidates[0].representations[0].summary =
        "x".repeat(crate::router::MAX_RECORD_BYTES + 1);
    assert!(matches!(
        ContextCompiler::validate_router_material(&record.request, &oversized, &mut allowance()),
        Err(ContextError::BudgetExceeded(_))
    ));
    let compiler = must(ContextCompiler::new([7; 32]));
    let provider = shared_fixture(false);
    let request = input();
    let scorer = CountingR0::default();
    let mut legacy_budget = allowance();
    let legacy = must(compiler.compile_assembly_with_router(
        &request,
        &provider,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        &scorer,
        &mut legacy_budget,
    ));
    let scored = scorer.0.load(Ordering::SeqCst);
    let mut policy_budget = allowance();
    let explicit = must(compiler.compile_assembly_with_router_policy(
        &request,
        &provider,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        &scorer,
        &mut policy_budget,
    ));
    assert_eq!(
        scorer.0.load(Ordering::SeqCst),
        2 * scored,
        "policy capture adds no scorer evaluations"
    );
    assert_eq!(legacy.plan, explicit.plan);
    assert!(policy_budget.remaining_bytes() < legacy_budget.remaining_bytes());
    assert!(policy_budget.remaining_work() < legacy_budget.remaining_work());
    let cancellation = contextdb_recall::QueryCancellation::default();
    cancellation.cancel();
    let mut budget = QueryBudget::new(
        500_000,
        512 * 1024 * 1024,
        std::time::Duration::from_secs(5),
        cancellation,
    );
    assert!(matches!(
        with_policy(&request, &provider, &scorer, &mut budget),
        Err(ContextError::BudgetExceeded(_))
    ));
    assert_eq!(scorer.0.load(Ordering::SeqCst), 2 * scored);
}
