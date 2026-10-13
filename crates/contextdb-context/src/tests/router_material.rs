//! Checks actual prepared compiler material, including supports absent from the
//! selected slate. These integrity results do not grant source or replay rights.

use super::*;
use crate::router::{
    RouterMaterialStatus, RouterMaterialUnavailableReason, RouterPreparedMaterial,
    validate_router_material,
};

fn recorded() -> RoutedAssembly {
    must(routed(&input(), &shared_fixture(false), &Stop))
}

fn reseal(mut request: AuthorizedRouterRequest) -> AuthorizedRouterRequest {
    request.binding.candidates = must(canonical_digest(&request.units, &mut allowance()));
    must(request.seal(&mut allowance()))
}

fn candidate_a(material: &mut RouterPreparedMaterial) -> &mut PackCandidate {
    material
        .candidates
        .iter_mut()
        .find(|candidate| candidate.id.as_str() == "a")
        .expect("retained optional candidate")
}

#[test]
fn cold_compiler_material_verifies_discarded_supports_and_generated_unknown() {
    let mut query = input();
    query.context.required_facets.push(PackFacetRequirement {
        name: "not-established".into(),
        minimum_confidence_micros: 1,
        require_evidence: true,
    });
    let record = must(routed(&query, &shared_fixture(false), &Stop));
    assert!(record.plan.seed_ids.is_empty());
    assert!(
        record
            .request
            .units
            .iter()
            .any(|unit| unit.kind == PackBlockKind::Unknown)
    );
    assert!(record.assembly.context.pack.evidence.is_empty());
    assert_eq!(record.prepared_material.evidence.len(), 2);
    let request = must(AuthorizedRouterRequest::from_json(
        &must(serde_json::to_vec(&record.request)),
        &mut allowance(),
    ));
    let material: RouterPreparedMaterial = must(serde_json::from_slice(&must(serde_json::to_vec(
        &record.prepared_material,
    ))));
    let result = must(validate_router_material(
        &request,
        &material,
        &mut allowance(),
    ));
    assert_eq!(result.support_material, RouterMaterialStatus::Verified);
    assert_eq!(result.unit_semantics, RouterMaterialStatus::Verified);
    for status in [result.candidate_commitment, result.historical_selection] {
        assert_eq!(
            status,
            RouterMaterialStatus::Unavailable(
                RouterMaterialUnavailableReason::MissingPreparedPolicy
            )
        );
    }
}

#[test]
fn discarded_support_bytes_and_reshashed_source_metadata_are_not_ignored() {
    let record = recorded();
    assert!(record.plan.seed_ids.is_empty());
    let mut material = record.prepared_material.clone();
    let item = material
        .evidence
        .iter_mut()
        .find(|item| item.id.as_str() == "alternative")
        .expect("discarded sufficient support");
    let old = item.excerpt.as_ref().expect("exact source");
    let changed = old.replace("An independent", "An counterfeit");
    assert_eq!(old.len(), changed.len());
    assert_ne!(*old, changed);
    item.original_span.as_mut().expect("original").span_digest =
        ContentDigest::from_bytes(*blake3::hash(changed.as_bytes()).as_bytes());
    item.excerpt = Some(changed);
    must(item.validate());
    assert!(matches!(
        validate_router_material(&record.request, &material, &mut allowance()),
        Err(ContextError::InvalidRequest(ref reason)) if reason.contains("support material")
    ));

    let mut request = record.request.clone();
    request
        .units
        .iter_mut()
        .find(|unit| unit.id.as_str() == "a")
        .expect("unit")
        .support_alternatives[0]
        .originals[0]
        .payload_digest = ContentDigest::from_bytes([39; 32]);
    let request = reseal(request);
    assert!(matches!(
        validate_router_material(&request, &record.prepared_material, &mut allowance()),
        Err(ContextError::InvalidRequest(ref reason)) if reason.contains("original spans")
    ));

    let mut material = record.prepared_material.clone();
    let unit = record
        .request
        .units
        .iter()
        .find(|unit| unit.id.as_str() == "a")
        .expect("unit");
    candidate_a(&mut material)
        .representations
        .iter_mut()
        .find(|representation| representation.level == unit.support_alternatives[0].level)
        .expect("actual prepared representation")
        .summary
        .push_str(" changed");
    assert!(matches!(
        validate_router_material(&record.request, &material, &mut allowance()),
        Err(ContextError::InvalidRequest(ref reason)) if reason.contains("representation is absent")
    ));
}

#[test]
fn rehashed_unit_roles_identity_and_temporal_semantics_must_match_the_same_block() {
    let record = recorded();
    type Mutation = fn(&mut crate::router::MemoryUnit);
    let changes: [(&str, Mutation); 4] = [
        ("role", |unit| {
            unit.render_role = RouterRenderRole::Historical
        }),
        ("identity", |unit| unit.claim_ids = vec![claim(99)]),
        ("knowledge", |unit| unit.known_at_commit -= 1),
        ("attribution", |unit| {
            unit.source_class = SourceClass::ModelGenerated
        }),
    ];
    for (name, change) in changes {
        let mut request = record.request.clone();
        change(
            request
                .units
                .iter_mut()
                .find(|unit| unit.id.as_str() == "a")
                .expect("unit"),
        );
        let request = reseal(request);
        assert!(
            matches!(
                validate_router_material(&request, &record.prepared_material, &mut allowance()),
                Err(ContextError::InvalidRequest(ref reason)) if reason.contains("unit semantics")
            ),
            "{name} cannot be repaired by rehashing the request"
        );
    }
}

#[test]
fn exact_inventory_and_shared_allowance_fail_before_material_cloning() {
    let record = recorded();
    let mut duplicate = record.prepared_material.clone();
    duplicate.candidates[1] = duplicate.candidates[0].clone();
    assert!(matches!(
        validate_router_material(&record.request, &duplicate, &mut allowance()),
        Err(ContextError::InvalidRequest(ref reason)) if reason.contains("duplicate")
    ));
    let mut missing = record.prepared_material.clone();
    missing
        .evidence
        .retain(|item| item.id.as_str() != "alternative");
    assert!(matches!(
        validate_router_material(&record.request, &missing, &mut allowance()),
        Err(ContextError::InvalidRequest(ref reason)) if reason.contains("complete support inventory")
    ));
    let mut extra = record.prepared_material.clone();
    let mut item = extra.evidence[0].clone();
    item.id = must(EvidenceHandle::new("zzz-extra"));
    extra.evidence.push(item);
    assert!(matches!(
        validate_router_material(&record.request, &extra, &mut allowance()),
        Err(ContextError::InvalidRequest(ref reason)) if reason.contains("complete support inventory")
    ));
    let mut oversized = record.prepared_material.clone();
    candidate_a(&mut oversized).representations[0].summary =
        "x".repeat(crate::router::MAX_RECORD_BYTES + 1);
    assert!(matches!(
        validate_router_material(&record.request, &oversized, &mut allowance()),
        Err(ContextError::BudgetExceeded(_))
    ));
    for (work, bytes, cancelled) in [(0, 4096, false), (4096, 1, false), (4096, 4096, true)] {
        let cancellation = contextdb_recall::QueryCancellation::default();
        if cancelled {
            cancellation.cancel();
        }
        let mut budget =
            QueryBudget::new(work, bytes, std::time::Duration::from_secs(5), cancellation);
        assert!(matches!(
            validate_router_material(&record.request, &record.prepared_material, &mut budget),
            Err(ContextError::BudgetExceeded(_))
        ));
    }
}

#[test]
fn v1_missing_candidate_policy_cannot_turn_support_checks_into_full_replay() {
    let record = recorded();
    let mut material = record.prepared_material.clone();
    let unit = record
        .request
        .units
        .iter()
        .find(|unit| unit.id.as_str() == "a")
        .expect("unit");
    candidate_a(&mut material)
        .representations
        .iter_mut()
        .find(|representation| {
            unit.support_alternatives
                .iter()
                .all(|alternative| alternative.level != representation.level)
        })
        .expect("retained representation not used by any prepared support")
        .summary
        .push_str(" structurally valid but outside every support commitment");
    let mut request = record.request.clone();
    request
        .units
        .iter_mut()
        .find(|unit| unit.id.as_str() == "a")
        .expect("unit")
        .candidate_digest = ContentDigest::from_bytes([51; 32]);
    let request = reseal(request);
    let result = must(ContextCompiler::validate_router_material(
        &request,
        &material,
        &mut allowance(),
    ));
    assert_eq!(result.support_material, RouterMaterialStatus::Verified);
    assert_eq!(
        result.candidate_commitment,
        RouterMaterialStatus::Unavailable(RouterMaterialUnavailableReason::MissingPreparedPolicy)
    );
    assert_eq!(
        result.historical_selection,
        RouterMaterialStatus::Unavailable(RouterMaterialUnavailableReason::MissingPreparedPolicy)
    );
}

#[test]
fn manifest_observation_checks_real_stop_and_selected_metadata_without_fabricating_an_assembly() {
    for record in [
        recorded(),
        must(routed(&input(), &shared_fixture(false), &R0Scorer)),
    ] {
        must(
            record
                .manifest
                .validate_observation(&record.request, &record.plan, &mut allowance()),
        );
        must(record.manifest.validate(
            &record.request,
            &record.plan,
            &record.assembly,
            &mut allowance(),
        ));
    }
    let original = source("current", claim(1), "The current user request.");
    let mut query = input();
    let mut current = message("current-user", &original.evidence, OutgoingRole::User);
    current.zone = OutgoingZone::CurrentTurn;
    query.base.current.push(current);
    let mut provider = shared_fixture(false);
    provider.originals.insert(
        original
            .evidence
            .original_span
            .as_ref()
            .expect("original")
            .event_id,
        original
            .evidence
            .excerpt
            .as_ref()
            .expect("text")
            .as_bytes()
            .to_vec(),
    );
    let record = must(routed(&query, &provider, &Stop));
    must(
        record
            .manifest
            .validate_observation(&record.request, &record.plan, &mut allowance()),
    );
    type Mutation = fn(&mut RouterManifest);
    let changes: [(&str, Mutation); 16] = [
        ("request", |manifest| {
            manifest.request_digest = ContentDigest::from_bytes([70; 32])
        }),
        ("candidate inventory", |manifest| {
            manifest.candidate_digest = ContentDigest::from_bytes([70; 32])
        }),
        ("plan", |manifest| {
            manifest.plan_digest = ContentDigest::from_bytes([70; 32])
        }),
        ("reader", |manifest| {
            manifest.assembly.model_profile_digest = ContentDigest::from_bytes([70; 32])
        }),
        ("owner", |manifest| {
            manifest
                .assembly
                .read_set
                .binding
                .authorization
                .push_str(" changed")
        }),
        ("scope", |manifest| {
            manifest.assembly.read_set.scopes.clear()
        }),
        ("selection", |manifest| {
            manifest.assembly.read_set.selected_blocks.clear()
        }),
        ("wire metadata", |manifest| {
            manifest.assembly.wire_digest = ContentDigest::from_bytes([70; 32])
        }),
        ("count metadata", |manifest| {
            manifest.assembly.input_tokens += 1
        }),
        ("count kind", |manifest| {
            manifest.assembly.count_kind = match manifest.assembly.count_kind {
                RequestCountKind::Exact => RequestCountKind::ConservativeUpperBound,
                RequestCountKind::ConservativeUpperBound => RequestCountKind::Exact,
            }
        }),
        ("reserved output", |manifest| {
            manifest.assembly.reserved_output_tokens += 1
        }),
        ("safety", |manifest| manifest.assembly.safety_tokens += 1),
        ("evaluations", |manifest| {
            manifest.selection_evaluations += 1
        }),
        ("training", |manifest| {
            manifest.training_dataset = Some(ContentDigest::from_bytes([70; 32]))
        }),
        ("fallback", |manifest| {
            manifest.fallback_from = Some("unsupported".into())
        }),
        ("unobserved timing", |manifest| {
            manifest.score_provenance = ScoreProvenance::UntrustedProposal;
            manifest.scorer_micros = 1;
        }),
    ];
    for (name, change) in changes {
        let mut manifest = record.manifest.clone();
        change(&mut manifest);
        assert!(
            manifest
                .validate_observation(&record.request, &record.plan, &mut allowance())
                .is_err(),
            "{name}"
        );
    }
    let mut manifest = record.manifest.clone();
    manifest
        .assembly
        .occurrences
        .push(manifest.assembly.occurrences[0].clone());
    assert!(
        manifest
            .validate_observation(&record.request, &record.plan, &mut allowance())
            .is_err()
    );
    let mut manifest = record.manifest.clone();
    manifest.assembly.read_set.originals.clear();
    assert!(
        manifest
            .validate_observation(&record.request, &record.plan, &mut allowance())
            .is_err()
    );
    let mut manifest = record.manifest.clone();
    let original = manifest
        .assembly
        .occurrences
        .iter_mut()
        .find(|item| item.id == record.request.current_turn[0].id)
        .expect("current source-backed occurrence");
    original.digest = ContentDigest::from_bytes([70; 32]);
    assert!(
        manifest
            .validate_observation(&record.request, &record.plan, &mut allowance())
            .is_err()
    );
}

#[test]
fn observation_metadata_agreement_does_not_verify_actual_wire_and_still_shares_allowance() {
    let record = recorded();
    let mut plan = record.plan.clone();
    plan.wire_digest = ContentDigest::from_bytes([71; 32]);
    let mut manifest = record.manifest.clone();
    manifest.assembly.wire_digest = plan.wire_digest;
    manifest.plan_digest = must(canonical_digest(&plan, &mut allowance()));
    must(manifest.validate_observation(&record.request, &plan, &mut allowance()));
    assert!(
        manifest
            .validate(&record.request, &plan, &record.assembly, &mut allowance())
            .is_err()
    );

    for (work, bytes, cancelled) in [(0, 4096, false), (4096, 1, false), (4096, 4096, true)] {
        let cancellation = contextdb_recall::QueryCancellation::default();
        if cancelled {
            cancellation.cancel();
        }
        let mut budget =
            QueryBudget::new(work, bytes, std::time::Duration::from_secs(5), cancellation);
        assert!(matches!(
            record
                .manifest
                .validate_observation(&record.request, &record.plan, &mut budget),
            Err(ContextError::BudgetExceeded(_))
        ));
    }
    let mut oversized = record.manifest.clone();
    oversized.assembly.pack_digest = "x".repeat(crate::router::MAX_RECORD_BYTES + 1);
    assert!(matches!(
        oversized.validate_observation(&record.request, &record.plan, &mut allowance()),
        Err(ContextError::BudgetExceeded(_))
    ));
}
