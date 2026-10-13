//! Detached integrity replay of actual compiler preparation. These synthetic
//! fixtures establish no current source permission, accepted receipt or lease.

use super::*;
use crate::router::{
    RouterHistoricalReplay, RouterHistoricalReplayResult, RouterMaterialStatus,
    RouterPreparedMaterial, RouterReplayAttemptOutcome, RouterReplayObservation,
    RouterReplayPreparation, RouterReplayPressure, RouterReplayUnavailableReason,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdTrace {
    request: AuthorizedRouterRequest,
    plan: RouterSelectionPlan,
    manifest: RouterManifest,
    base: OutgoingBase,
    material: RouterPreparedMaterial,
    observation: RouterReplayObservation,
}

fn replay_fixture(mandatory: bool, utility: u64) -> (CompileAssemblyRequest, Fixture) {
    let mut a = fact("a", "shared", mandatory);
    a.candidate.utility_micros = utility;
    a.candidate
        .evidence_handles
        .insert(must(EvidenceHandle::new("alternative")));
    a.candidate
        .evidence_handles
        .insert(must(EvidenceHandle::new("secondary")));
    let mut b = fact("b", "shared", false);
    b.candidate.utility_micros = utility;
    let mut dependency = fact("dependency", "shared", false);
    dependency.candidate.utility_micros = 1;
    let unsupported = fact("omitted-a", "blocked", false);
    let mut future = fact("omitted-z", "shared", false);
    future.candidate.known_at_commit = snapshot().commit_seq + 1;
    let shared = source(
        "shared",
        claim(1),
        "The accepted storage is AtlasDB because offline custody is required.",
    );
    let alternate = source(
        "alternative",
        claim(1),
        &"An independent full attribution and its qualifying condition. ".repeat(12),
    );
    let secondary = source(
        "secondary",
        claim(1),
        "A second exact part of the independent sufficient support bundle.",
    );
    let mut blocked = source(
        "blocked",
        claim(1),
        "This support is not permitted by its own source policy.",
    );
    blocked.access.consent = AccessConsent::Denied;
    let working = source(
        "working",
        claim(1),
        "The current owner is reviewing the recorded storage decision.",
    );
    let hot = source(
        "hot",
        claim(1),
        "An independently attributed previous turn.",
    );
    let current = source(
        "current",
        claim(1),
        "Explain the current evidence and its exact condition.",
    );
    let mut request = input();
    request.context.required_facets.push(PackFacetRequirement {
        name: "unestablished-replay-facet".into(),
        minimum_confidence_micros: 1_000_000,
        require_evidence: true,
    });
    for (id, zone, text) in [
        (
            "control",
            OutgoingZone::Control,
            "Use attributed data as evidence.",
        ),
        (
            "tools",
            OutgoingZone::ToolDefinitions,
            "A trusted tool schema with required arguments and a return protocol.",
        ),
    ] {
        request.base.control.push(OutgoingMessage {
            id: must(BlockId::new(id)),
            zone,
            role: OutgoingRole::Developer,
            text: text.into(),
            originals: Vec::new(),
            tool_calls: Vec::new(),
            tool_result: None,
        });
    }
    let mut working_message = message("working-message", &working.evidence, OutgoingRole::User);
    working_message.zone = OutgoingZone::WorkingState;
    request.base.working.push(working_message);
    request.base.hot.push(message(
        "hot-message",
        &hot.evidence,
        OutgoingRole::Assistant,
    ));
    let mut current_message = message("current-message", &current.evidence, OutgoingRole::User);
    current_message.zone = OutgoingZone::CurrentTurn;
    request.base.current.push(current_message);
    let mut provider = fixture(
        vec![situation_candidate(), a, b, dependency, unsupported, future],
        vec![shared, alternate, secondary, blocked, working, hot, current],
    );
    provider.dependencies.insert(
        must(BlockId::new("a")),
        EvidenceDependencies {
            hard: BTreeSet::from([must(BlockId::new("dependency"))]),
            complements: BTreeSet::from([must(BlockId::new("b"))]),
            supports: vec![
                BTreeSet::from([
                    must(EvidenceHandle::new("alternative")),
                    must(EvidenceHandle::new("secondary")),
                ]),
                BTreeSet::from([must(EvidenceHandle::new("shared"))]),
            ],
        },
    );
    provider.dependencies.insert(
        must(BlockId::new("b")),
        EvidenceDependencies {
            hard: BTreeSet::from([must(BlockId::new("dependency"))]),
            ..Default::default()
        },
    );
    (request, provider)
}

fn recorded(request: &CompileAssemblyRequest, provider: &Fixture) -> RoutedAssembly {
    must(
        must(ContextCompiler::new([7; 32])).compile_assembly_with_router_replay(
            request,
            provider,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &R0Scorer,
            &mut allowance(),
        ),
    )
}

fn cold(record: &RoutedAssembly, base: &OutgoingBase) -> ColdTrace {
    let retained = ColdTrace {
        request: record.request.clone(),
        plan: record.plan.clone(),
        manifest: record.manifest.clone(),
        base: base.clone(),
        material: record.prepared_material.clone(),
        observation: record
            .replay_observation
            .clone()
            .expect("compiler replay observation"),
    };
    let bytes = must(crate::router::canonical_bytes(&retained, &mut allowance()));
    must(serde_json::from_slice(&bytes))
}

fn replay(retained: &ColdTrace, budget: &mut QueryBudget) -> Result<RouterHistoricalReplayResult> {
    ContextCompiler::replay_router_r0(
        &retained.request,
        &retained.plan,
        &retained.manifest,
        &retained.base,
        &retained.material,
        &retained.observation,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        budget,
    )
}

fn replay_allowance() -> QueryBudget {
    // The caller pays for reconstruction plus the complete reserved historical
    // selector allowance. This enclosing allowance is not reset inside replay.
    QueryBudget::new(
        1_000_000,
        1024 * 1024 * 1024,
        std::time::Duration::from_secs(20),
        Default::default(),
    )
}

fn complete(retained: &ColdTrace) -> Box<RouterHistoricalReplay> {
    match must(replay(retained, &mut replay_allowance())) {
        RouterHistoricalReplayResult::Complete(result) => result,
        RouterHistoricalReplayResult::Unavailable(reason) => {
            panic!("actual prepared replay unavailable: {reason:?}")
        }
    }
}

fn preparation(retained: &mut ColdTrace) -> &mut RouterReplayPreparation {
    retained
        .material
        .prepared_policy
        .as_mut()
        .expect("prepared policy")
        .replay
        .as_mut()
        .expect("complete preparation")
}

fn preparation_a(retained: &mut ColdTrace) -> &mut crate::router::RouterReplayUnit {
    preparation(retained)
        .units
        .iter_mut()
        .find(|unit| unit.id.as_str() == "a")
        .expect("a preparation")
}

#[test]
fn cold_r0_replay_preserves_multivariant_complements_mandatory_stop_and_exact_wire() {
    for (mandatory, utility, max_blocks) in [
        (false, 850_000, None),
        (true, 1, None),
        (false, 850_000, Some(3)),
    ] {
        let (mut request, provider) = replay_fixture(mandatory, utility);
        if let Some(max_blocks) = max_blocks {
            request.context.budgets.max_blocks = max_blocks;
        }
        let record = recorded(&request, &provider);
        assert_eq!(
            record
                .request
                .units
                .iter()
                .find(|unit| unit.id.as_str() == "a")
                .expect("a")
                .support_alternatives
                .len(),
            2
        );
        assert_eq!(
            record
                .request
                .units
                .iter()
                .find(|unit| unit.id.as_str() == "a")
                .expect("a")
                .hard_dependencies,
            vec![must(BlockId::new("dependency"))]
        );
        assert!(
            record
                .request
                .units
                .iter()
                .any(|unit| unit.kind == PackBlockKind::Unknown)
        );
        let prepared = record
            .prepared_material
            .prepared_policy
            .as_ref()
            .expect("policy")
            .replay
            .as_ref()
            .expect("full preparation");
        assert!(
            prepared
                .omissions
                .iter()
                .any(|item| item.reason == OmissionReason::FutureTransaction)
        );
        assert!(
            prepared
                .omissions
                .iter()
                .any(|item| item.reason == OmissionReason::UnsupportedUnderEvidencePolicy)
        );
        assert!(
            prepared
                .units
                .iter()
                .flat_map(|unit| &unit.variants)
                .any(|variant| variant.generated)
        );
        if mandatory {
            assert_eq!(record.plan.decision, RouterDecision::Stop);
            assert!(record.plan.seed_ids.is_empty());
            for id in ["a", "dependency"] {
                assert!(
                    record
                        .plan
                        .selected_ids
                        .iter()
                        .any(|selected| selected.as_str() == id)
                );
            }
            assert!(!record.plan.scores.is_empty());
            assert!(
                record
                    .plan
                    .scores
                    .iter()
                    .all(|score| score.utility_micros.is_none())
            );
        } else if max_blocks.is_some() {
            assert_eq!(record.plan.decision, RouterDecision::Stop);
            assert!(record.plan.seed_ids.is_empty());
            let attempts = &record
                .replay_observation
                .as_ref()
                .expect("actual attempts")
                .attempts;
            assert!(
                attempts
                    .iter()
                    .any(|attempt| attempt.outcome == RouterReplayAttemptOutcome::TrialRejected)
            );
            assert!(
                attempts.len() > record.plan.scores.len(),
                "pre-score rejected trials remain observed"
            );
        } else {
            assert!(
                record.plan.scores.iter().any(|score| score.seed_ids
                    == vec![must(BlockId::new("a")), must(BlockId::new("b"))])
            );
            assert_eq!(record.plan.decision, RouterDecision::Select);
        }
        let retained = cold(&record, &request.base);
        drop(provider);
        let result = complete(&retained);
        assert_eq!(
            result.inventory.candidate_commitment,
            RouterMaterialStatus::Verified
        );
        for status in [
            result.score_selection,
            result.material_wire,
            result.token_count,
        ] {
            assert_eq!(status, RouterMaterialStatus::Verified);
        }
        assert_eq!(
            result.assembly.context.canonical_protobuf,
            record.assembly.context.canonical_protobuf
        );
        assert_eq!(
            result.assembly.context.canonical_json,
            record.assembly.context.canonical_json
        );
        assert_eq!(result.assembly.messages, record.assembly.messages);
        assert_eq!(result.assembly.outgoing, record.assembly.outgoing);
        assert_eq!(result.assembly.manifest, record.assembly.manifest);
        assert_eq!(
            result.assembly.optional_seeds,
            record.assembly.optional_seeds
        );
        assert_eq!(
            result.assembly.selection_evaluations,
            record.assembly.selection_evaluations
        );
    }
}

#[test]
fn replay_rejects_preparation_behavior_base_and_wire_tampering() {
    let (request, provider) = replay_fixture(false, 850_000);
    let record = recorded(&request, &provider);
    let retained = cold(&record, &request.base);
    drop(provider);
    type Change = fn(&mut ColdTrace);
    let changes: [(&str, Change); 19] = [
        ("generated marker", |trace| {
            let variant = preparation(trace)
                .units
                .iter_mut()
                .flat_map(|unit| &mut unit.variants)
                .find(|variant| variant.generated)
                .expect("generated unknown");
            variant.generated = false;
        }),
        ("block cost", |trace| {
            preparation_a(trace).variants[0].block_tokens += 1
        }),
        ("discarded support cost", |trace| {
            preparation_a(trace).variants[0].evidence_tokens += 1
        }),
        ("block counting handles", |trace| {
            let handles = &mut preparation_a(trace).variants[0].block_token_handles;
            assert!(!handles.is_empty());
            handles.clear();
        }),
        ("variant index/order", |trace| {
            preparation_a(trace).variants.swap(0, 1)
        }),
        ("support evidence order", |trace| {
            let order = &mut preparation_a(trace).variants[0].evidence_order;
            assert_eq!(order.len(), 2);
            order.reverse();
        }),
        ("prepared traversal order", |trace| {
            preparation(trace).prepared_order.reverse()
        }),
        ("omitted candidate", |trace| {
            preparation(trace).omissions.pop();
        }),
        ("omission reason", |trace| {
            preparation(trace).omissions[0].reason = OmissionReason::Redundant
        }),
        ("selector work", |trace| {
            preparation(trace).selector_work -= 1
        }),
        ("selector bytes", |trace| {
            preparation(trace).selector_bytes -= 1
        }),
        ("attempt order", |trace| {
            trace.observation.attempts.swap(0, 1)
        }),
        ("attempt outcome", |trace| {
            trace.observation.attempts[0].outcome = RouterReplayAttemptOutcome::ClosureRejected
        }),
        ("missing attempt", |trace| {
            trace.observation.attempts.pop();
        }),
        ("raw pressure", |trace| {
            trace.observation.raw_recall_pressure = Some(RouterReplayPressure {
                baseline_input_tokens: 1,
                candidate_input_tokens: 2,
                memory_tokens: 1,
                raw_evidence_tokens: 1,
                history_tokens: 0,
                conflict_tokens: 0,
            })
        }),
        ("claimed score", |trace| {
            trace.plan.scores[0].utility_micros =
                trace.plan.scores[0].utility_micros.map(|value| value + 1);
            trace.manifest.plan_digest = must(canonical_digest(&trace.plan, &mut allowance()));
        }),
        ("trial token count", |trace| {
            trace.plan.scores[0].trial_input_tokens += 1;
            trace.manifest.plan_digest = must(canonical_digest(&trace.plan, &mut allowance()));
        }),
        ("ordered base", |trace| trace.base.control.swap(0, 1)),
        ("claimed final wire", |trace| {
            trace.plan.wire_digest = ContentDigest::from_bytes([82; 32]);
            trace.manifest.assembly.wire_digest = trace.plan.wire_digest;
            trace.manifest.plan_digest = must(canonical_digest(&trace.plan, &mut allowance()));
        }),
    ];
    for (name, change) in changes {
        let mut changed = cold(&record, &request.base);
        change(&mut changed);
        assert!(replay(&changed, &mut replay_allowance()).is_err(), "{name}");
    }
    // The unchanged observation is still independently recomputed successfully.
    complete(&retained);
}

#[test]
fn replay_recomputes_positive_raw_pressure_and_outgoing_overflow() {
    let original = source(
        "early",
        claim(1),
        "An exact early original includes the satellite nickname.",
    );
    let filler = source(
        "hot",
        claim(1),
        &"An unrelated recent exchange fills the active window. ".repeat(100),
    );
    let mut request = input();
    request
        .base
        .hot
        .push(message("hot", &filler.evidence, OutgoingRole::User));
    let provider = fixture(
        vec![situation_candidate(), raw_candidate("raw", "early")],
        vec![original, filler],
    );
    let baseline = must(compile(&request, &provider, &Stop));
    let full = recorded(&request, &provider);
    assert!(full.assembly.outgoing.input_tokens > baseline.outgoing.input_tokens + 1);
    request.budget.max_input_tokens = baseline.outgoing.input_tokens + 1;
    let limited = recorded(&request, &provider);
    assert!(limited.plan.seed_ids.is_empty());
    assert!(
        limited
            .plan
            .scores
            .iter()
            .any(|score| score.utility_micros.is_some() && !score.outgoing_fits)
    );
    let retained = cold(&limited, &request.base);
    let pressure = retained
        .observation
        .raw_recall_pressure
        .as_ref()
        .expect("actual positive raw pressure");
    assert_eq!(
        pressure.candidate_input_tokens,
        full.assembly.outgoing.input_tokens
    );
    drop(provider);
    let replayed = complete(&retained);
    assert_eq!(
        RouterReplayPressure::from(
            replayed
                .assembly
                .raw_recall_pressure
                .as_ref()
                .expect("recomputed raw pressure")
        ),
        *pressure
    );
    assert_eq!(replayed.assembly.outgoing, limited.assembly.outgoing);
    let mut changed = cold(&limited, &request.base);
    changed
        .observation
        .raw_recall_pressure
        .as_mut()
        .expect("pressure")
        .candidate_input_tokens += 1;
    assert!(replay(&changed, &mut replay_allowance()).is_err());
    let mut omitted = cold(&limited, &request.base);
    omitted.observation.raw_recall_pressure = None;
    assert!(replay(&omitted, &mut replay_allowance()).is_err());
}

#[test]
fn rehashed_nonfirst_variant_costs_and_generated_only_pack_still_require_real_recomputation() {
    let (request, provider) = replay_fixture(false, 850_000);
    let record = recorded(&request, &provider);
    type Change = fn(&mut ColdTrace);
    for (name, change) in [
        (
            "nonfirst block cost",
            (|trace| preparation_a(trace).variants[1].block_tokens += 1) as Change,
        ),
        (
            "nonfirst evidence cost",
            (|trace| preparation_a(trace).variants[1].evidence_tokens += 1) as Change,
        ),
        (
            "nonfirst block counting input",
            (|trace| preparation_a(trace).variants[1].block_token_handles.clear()) as Change,
        ),
    ] {
        let mut changed = cold(&record, &request.base);
        change(&mut changed);
        let prepared = preparation(&mut changed);
        prepared.digest = must(prepared.commitment(&mut allowance()));
        changed.observation.preparation_digest = prepared.digest;
        assert!(
            matches!(replay(&changed, &mut replay_allowance()), Err(ContextError::InvalidRequest(ref reason))
            if reason.contains("retained prepared costs")),
            "{name}"
        );
    }
    // A provider-free generated-only pack exercises source_count/no-memory.
    // Rehashing changes consistency metadata, never an accepted owner history.
    let mut empty_request = input();
    empty_request
        .context
        .required_facets
        .push(PackFacetRequirement {
            name: "unestablished-generated-only-facet".into(),
            minimum_confidence_micros: 1_000_000,
            require_evidence: true,
        });
    let generated = recorded(&empty_request, &fixture(Vec::new(), Vec::new()));
    assert!(generated.assembly.context.pack.no_memory.is_some());
    let mut changed = cold(&generated, &empty_request.base);
    complete(&changed);
    let prepared = preparation(&mut changed);
    assert!(
        prepared
            .units
            .iter()
            .flat_map(|unit| &unit.variants)
            .all(|variant| variant.generated)
    );
    prepared.units[0].variants[0].generated = false;
    prepared.digest = must(prepared.commitment(&mut allowance()));
    changed.observation.preparation_digest = prepared.digest;
    assert!(
        replay(&changed, &mut replay_allowance()).is_err(),
        "generated-only canonical pack must be recomputed, not inferred from Unknown kind"
    );
}

#[derive(Debug, Default)]
struct ReplayTokenizer(AtomicUsize);

impl TokenCounter for ReplayTokenizer {
    fn id(&self) -> &str {
        ReferenceTokenizer::ID
    }
    fn count_tokens(&self, text: &str) -> Result<u32> {
        self.0.fetch_add(1, Ordering::SeqCst);
        ReferenceTokenizer.count_tokens(text)
    }
}

#[derive(Debug)]
struct UpperBoundEncoder<'a>(ReferenceOutgoingEncoder<'a>);

impl OutgoingEncoder for UpperBoundEncoder<'_> {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn tokenizer_id(&self) -> &str {
        self.0.tokenizer_id()
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> Result<EncodedOutgoing> {
        let mut outgoing = self.0.encode(messages, budget)?;
        outgoing.count_kind = RequestCountKind::ConservativeUpperBound;
        Ok(outgoing)
    }
}

#[test]
fn detached_replay_preserves_legacy_unavailability_and_shared_budget_cancellation() {
    let (request, provider) = replay_fixture(false, 850_000);
    let record = recorded(&request, &provider);
    let retained = cold(&record, &request.base);
    let encoder = UpperBoundEncoder(ReferenceOutgoingEncoder(&ReferenceTokenizer));
    let upper_bound = must(
        must(ContextCompiler::new([7; 32])).compile_assembly_with_router_replay(
            &request,
            &provider,
            &ReferenceTokenizer,
            &encoder,
            &R0Scorer,
            &mut allowance(),
        ),
    );
    assert_eq!(
        upper_bound.plan.count_kind,
        RequestCountKind::ConservativeUpperBound
    );
    let upper_bound = cold(&upper_bound, &request.base);
    let RouterHistoricalReplayResult::Complete(result) = must(ContextCompiler::replay_router_r0(
        &upper_bound.request,
        &upper_bound.plan,
        &upper_bound.manifest,
        &upper_bound.base,
        &upper_bound.material,
        &upper_bound.observation,
        &ReferenceTokenizer,
        &encoder,
        &mut replay_allowance(),
    )) else {
        panic!("same upper-bound encoder replay must remain available");
    };
    assert_eq!(result.material_wire, RouterMaterialStatus::Verified);
    assert_eq!(
        result.token_count,
        RouterMaterialStatus::Unavailable(
            crate::router::RouterMaterialUnavailableReason::NonExactRequestCount
        )
    );
    for policy in [false, true] {
        let legacy = if policy {
            must(
                must(ContextCompiler::new([7; 32])).compile_assembly_with_router_policy(
                    &request,
                    &provider,
                    &ReferenceTokenizer,
                    &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                    &R0Scorer,
                    &mut allowance(),
                ),
            )
        } else {
            must(routed(&request, &provider, &R0Scorer))
        };
        assert!(legacy.replay_observation.is_none());
        assert!(matches!(
            ContextCompiler::replay_router_r0(
                &legacy.request,
                &legacy.plan,
                &legacy.manifest,
                &request.base,
                &legacy.prepared_material,
                &retained.observation,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut allowance(),
            ),
            Ok(RouterHistoricalReplayResult::Unavailable(
                RouterReplayUnavailableReason::MissingReplayPreparation
            ))
        ));
    }
    let non_r0 = must(
        must(ContextCompiler::new([7; 32])).compile_assembly_with_router_replay(
            &request,
            &provider,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &Stop,
            &mut allowance(),
        ),
    );
    let non_r0 = cold(&non_r0, &request.base);
    assert!(matches!(
        replay(&non_r0, &mut allowance()),
        Ok(RouterHistoricalReplayResult::Unavailable(
            RouterReplayUnavailableReason::UnsupportedScorerProvenance
        ))
    ));
    assert!(matches!(
        ContextCompiler::replay_router_r0(
            &retained.request,
            &retained.plan,
            &retained.manifest,
            &retained.base,
            &retained.material,
            &retained.observation,
            &ReferenceTokenizer,
            &TextProtocol { upper_bound: true },
            &mut allowance(),
        ),
        Ok(RouterHistoricalReplayResult::Unavailable(
            RouterReplayUnavailableReason::UnsupportedRuntimeProfile
        ))
    ));
    let mut used = replay_allowance();
    let before = (used.remaining_work(), used.remaining_bytes());
    assert!(matches!(
        replay(&retained, &mut used),
        Ok(RouterHistoricalReplayResult::Complete(_))
    ));
    assert!(used.remaining_work() < before.0);
    assert!(used.remaining_bytes() < before.1);
    let prepared = retained
        .material
        .prepared_policy
        .as_ref()
        .expect("policy")
        .replay
        .as_ref()
        .expect("preparation");
    let mut only_selector = QueryBudget::new(
        prepared.selector_work,
        prepared.selector_bytes,
        std::time::Duration::from_secs(20),
        Default::default(),
    );
    assert!(
        matches!(
            replay(&retained, &mut only_selector),
            Err(ContextError::BudgetExceeded(_))
        ),
        "the same caller must fund reconstruction and the reserved selector"
    );
    let counter = ReplayTokenizer::default();
    for (work, bytes, cancelled) in [(0, 4096, false), (4096, 1, false), (4096, 4096, true)] {
        let cancellation = contextdb_recall::QueryCancellation::default();
        if cancelled {
            cancellation.cancel();
        }
        let mut budget =
            QueryBudget::new(work, bytes, std::time::Duration::from_secs(5), cancellation);
        assert!(matches!(
            ContextCompiler::replay_router_r0(
                &retained.request,
                &retained.plan,
                &retained.manifest,
                &retained.base,
                &retained.material,
                &retained.observation,
                &counter,
                &ReferenceOutgoingEncoder(&counter),
                &mut budget,
            ),
            Err(ContextError::BudgetExceeded(_))
        ));
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            0,
            "admission precedes tokenizer work"
        );
    }
    let mut oversized = cold(&record, &request.base);
    oversized.base.control[0].text = "x".repeat(crate::router::MAX_RECORD_BYTES + 1);
    assert!(matches!(
        replay(&oversized, &mut replay_allowance()),
        Err(ContextError::BudgetExceeded(_))
    ));
}
