//! Actual owner installation, protected learned trials and current admission.

use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use contextdb_context::router::{RouterHistoricalReplayResult, RouterReplayUnavailableReason};
use contextdb_core::{NodeId, OriginalSourceSpan, Purpose};
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{
    AcceptedRouterTracePort, AcceptedRouterTraceReadResult, AssertionMutation,
    ReadAcceptedRouterTraceRequest,
};
use contextdb_storage::ReadSnapshot;

use super::*;

struct Observer {
    inputs: Mutex<Vec<serde_json::Value>>,
    revision_changed: AtomicBool,
    unavailable: AtomicBool,
    denial: Mutex<Option<(Weak<NativeService>, Vec<contextdb_core::ObservationId>)>>,
}

impl Observer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inputs: Mutex::new(Vec::new()),
            revision_changed: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            denial: Mutex::new(None),
        })
    }
    fn calls(&self) -> usize {
        self.inputs.lock().expect("observed callback count").len()
    }
}

impl fmt::Debug for Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixtureSemanticObserver")
            .finish_non_exhaustive()
    }
}

impl ContextScorer for Observer {
    fn id(&self) -> &str {
        "native-fixture-semantic"
    }
    fn revision(&self) -> &str {
        if self.revision_changed.load(Ordering::SeqCst) {
            "changed"
        } else {
            "fixture-v1"
        }
    }
    fn latency_limit_micros(&self) -> u64 {
        9_000_000
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<u64>> {
        panic!("semantic installation must never use scalar route")
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        allowance: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        assert!(unit.budget.remaining_work <= allowance.remaining_work());
        assert!(unit.budget.remaining_bytes <= allowance.remaining_bytes());
        assert!(unit.budget.remaining_scorer_micros < self.latency_limit_micros());
        let bytes = unit.model_input_json(allowance)?;
        self.inputs
            .lock()
            .expect("fixture observations")
            .push(serde_json::from_slice(&bytes).expect("strict actual model projection"));
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ContextError::RouterScore(
                "fixture backend unavailable".into(),
            ));
        }
        if let Some((owner, candidates)) = self.denial.lock().expect("fault hook").take() {
            let service = owner.upgrade().expect("live fixture owner");
            let trial_roots: BTreeSet<_> = unit
                .trial
                .pack
                .evidence
                .iter()
                .filter_map(|evidence| evidence.original_span.as_ref().map(|span| span.event_id))
                .collect();
            let denied = *candidates
                .iter()
                .find(|id| !trial_roots.contains(id))
                .expect("actual root outside this proposed closure");
            let key = crate::digest_bytes(denied.to_string().as_bytes());
            let mut tx = service
                .engine
                .begin_write()
                .expect("explicit current ACL fault fixture");
            let mut policy: crate::StoredObservationPolicy = crate::decode(
                &tx.get(&service.keyspaces.observations_policy, key.as_bytes())
                    .expect("current policy")
                    .expect("accepted root"),
                "fixture policy",
            )
            .expect("metadata");
            policy.access.retrievable = false;
            tx.put(
                &service.keyspaces.observations_policy,
                key.into_bytes(),
                encode(&policy).expect("denied metadata"),
            )
            .expect("current ACL fault");
            tx.commit(Durability::Sync).expect("fault Sync");
        }
        // Target-independent STOP fixture; this verifies the native boundary,
        // not the quality or behavior of a trained Kev model.
        Ok(None)
    }
}

struct Owner {
    service: Arc<NativeService>,
    root: tempfile::TempDir,
    _ledger_root: tempfile::TempDir,
    _keys_root: tempfile::TempDir,
    ledger: Arc<crate::NativeSuppressionLedger>,
    keys: Arc<crate::NativeCustodyKeys>,
}

fn owner(observer: &Arc<Observer>) -> Owner {
    let root = tempfile::tempdir().expect("native fixture");
    let (ledger_root, ledger) = crate::suppression::tests::authority("native-semantic");
    let (keys_root, keys) = crate::encryption::tests::authority("native-semantic");
    let service = NativeService::open_encrypted(
        root.path(),
        "native-semantic",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted owner");
    let service = Arc::new(
        service
            .with_preparation_scorer(observer.clone())
            .expect("trusted immutable install"),
    );
    Owner {
        service,
        root,
        _ledger_root: ledger_root,
        _keys_root: keys_root,
        ledger,
        keys,
    }
}

fn assertion_for(
    source: &CaptureRequest,
    value: &str,
    subject: u128,
) -> contextdb_core::SourceAssertion {
    let mut assertion = crate::assertions::tests::assertion(source, value, 0, None, Vec::new());
    assertion.key.subject =
        NodeId::from_uuid(uuid::Uuid::from_u128(subject)).expect("fixture subject");
    assertion.claim.subject = assertion.key.subject;
    assertion.revision.envelope.ownership.allowed_purposes =
        BTreeSet::from([Purpose::Conversation]);
    assertion
}

fn states(service: &NativeService, source: &CaptureRequest, plan: &mut PrepareContextRequest) {
    let known = assertion_for(source, "local-only", 20);
    let first = assertion_for(source, "keep proposal open", 22);
    let second = assertion_for(source, "close proposal", 22);
    let mut conflict_policy = crate::assertions::tests::policy(source);
    conflict_policy.key = first.key.clone();
    let mut unknown_policy = crate::assertions::tests::policy(source);
    unknown_policy.key.subject =
        NodeId::from_uuid(uuid::Uuid::from_u128(23)).expect("unknown slot");
    crate::assertions::tests::publish(
        service,
        source,
        "semantic-natural-states",
        vec![
            AssertionMutation::Policy {
                policy: crate::assertions::tests::policy(source),
            },
            AssertionMutation::Policy {
                policy: conflict_policy,
            },
            AssertionMutation::Policy {
                policy: unknown_policy,
            },
            AssertionMutation::Assert {
                assertion: Box::new(known),
            },
            AssertionMutation::Assert {
                assertion: Box::new(first),
            },
            AssertionMutation::Assert {
                assertion: Box::new(second),
            },
        ],
    );
    plan.memory_budget.max_blocks = 12;
}

#[test]
fn installed_semantic_owner_accepts_natural_mandatory_state_and_cold_protected_history() {
    for profile in [
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        let observer = Observer::new();
        let f = owner(&observer);
        let accepted = capture::accepted_semantic_fixture(&f.service, profile, states);
        assert!(
            observer.calls() >= 2,
            "real losing raw proposals are observed before STOP"
        );
        let retained = envelope(&accepted.prepared);
        assert_eq!(retained.origins.states.len(), 3);
        assert!(
            retained.origins.originals.contains(
                &accepted
                    .prepared
                    .messages
                    .iter()
                    .find(|message| message.zone == OutgoingZone::CurrentTurn)
                    .expect("actual current source")
                    .originals[0]
                    .span
                    .event_id
            )
        );
        assert!(
            retained.origins.originals.len() >= 3,
            "losing raw roots remain in custody"
        );
        assert!(!accepted.prepared.context_pack.sections.decisions.is_empty());
        assert!(!accepted.prepared.context_pack.sections.conflicts.is_empty());
        assert!(!accepted.prepared.context_pack.sections.unknowns.is_empty());
        let inputs = observer.inputs.lock().expect("actual projections");
        for input in inputs.iter() {
            let text = input.to_string();
            assert!(text.contains("local-only"));
            assert!(text.contains("keep proposal open") && text.contains("close proposal"));
            for forbidden in [
                "supporting_claims",
                "native_record",
                "native_value",
                "known_at_commit",
                "state:",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "native locator metadata must stay outside learned projection"
                );
            }
            for state in &retained.origins.states {
                assert!(!text.contains(&state.key.subject.to_string()));
            }
        }
        drop(inputs);
        let calls = observer.calls();
        drop(f.service);
        let cold = NativeService::open_encrypted(
            f.root.path(),
            "native-semantic",
            [7; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("cold owner without executing a scorer");
        let AcceptedRouterTraceReadResult::Complete(read) = cold
            .read_accepted_router_trace(
                ReadAcceptedRouterTraceRequest {
                    context: accepted.context.clone(),
                    receipt: accepted.acceptance.receipt.clone(),
                },
                &mut budget(),
            )
            .expect("actual protected cold read")
        else {
            panic!("accepted complete material");
        };
        assert_eq!(
            observer.calls(),
            calls,
            "history reading never invokes learned inference"
        );
        assert_eq!(read.request.binding.scorer, observer.id());
        assert_eq!(read.lineage.originals, retained.origins.originals);
        if let Some(observation) = &read.replay_observation {
            assert!(matches!(
                ContextCompiler::replay_router_r0(
                    &read.request,
                    &read.plan,
                    &read.manifest,
                    &read.base,
                    &read.material,
                    observation,
                    &ReferenceTokenizer,
                    &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                    &mut budget()
                )
                .expect("explicit replay availability"),
                RouterHistoricalReplayResult::Unavailable(
                    RouterReplayUnavailableReason::UnsupportedScorerProvenance
                )
            ));
        }
    }
}

fn direct_plan(
    service: &NativeService,
) -> (PrepareContextRequest, Vec<contextdb_core::ObservationId>) {
    let mut current = source(
        1,
        "Current task: retain decisions and source-backed constraints.",
    );
    current.context = request(&current).context;
    current
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    service
        .append_event(current.clone())
        .expect("current capture");
    let mut ids = Vec::new();
    for (sequence, text) in [
        (2, "Earlier amber proposal."),
        (3, "Earlier cobalt proposal."),
    ] {
        let mut original = source(sequence, text);
        original.context = current.context.clone();
        ids.push(original.event.event_id);
        service
            .append_event(original)
            .expect("independent losing source");
    }
    prepare_catalog(service, &current, true);
    let mut plan = request(&current);
    let digest = current.event.payload.digest().expect("source digest");
    let text = "Current task: retain decisions and source-backed constraints.";
    plan.base.current.push(OutgoingMessage {
        id: BlockId::new("current-task").expect("id"),
        zone: OutgoingZone::CurrentTurn,
        role: OutgoingRole::User,
        text: text.into(),
        originals: vec![VisibleOriginal {
            span: OriginalSourceSpan {
                event_id: current.event.event_id,
                payload_digest: digest,
                start: 0,
                end: text.len() as u64,
                span_digest: digest,
            },
            text_start: 0,
            text_end: text.len() as u64,
        }],
        tool_calls: Vec::new(),
        tool_result: None,
    });
    plan.raw_queries.push(IndexedQuery {
        filter: RawFilter {
            event_ids: ids.iter().copied().collect(),
            ..Default::default()
        },
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 2 },
    });
    ids.push(current.event.event_id);
    (plan, ids)
}

#[test]
fn every_callback_denies_changed_losing_and_base_roots_with_original_service_error() {
    for base_only in [true, false] {
        let observer = Observer::new();
        let f = owner(&observer);
        let (plan, mut roots) = direct_plan(&f.service);
        if base_only {
            roots = vec![roots[2]];
        } else {
            roots.truncate(2);
        }
        *observer.denial.lock().expect("install test fault") =
            Some((Arc::downgrade(&f.service), roots));
        let error = f
            .service
            .prepare_context(
                plan,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget(),
            )
            .expect_err("next callback rechecks whole processed frontier");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            observer.calls(),
            1,
            "denied root never reaches another backend call"
        );
        // The explicit ACL fault does not change the raw epoch or scope frontier;
        // this refusal therefore requires whole current-origin authorization.
    }
}

#[test]
fn trusted_install_and_processing_admission_refuse_before_any_learned_callback() {
    let observer = Observer::new();
    let f = owner(&observer);
    let (plan, roots) = direct_plan(&f.service);
    let mut off = plan.clone();
    off.router_trace_profile = RouterTraceProfile::Off;
    assert_eq!(
        f.service
            .prepare_context(
                off,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget()
            )
            .expect_err("explicit protected profile needed")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut denied = plan.clone();
    denied
        .context
        .capability_grants
        .remove(&Capability::ModelProcessing);
    assert_eq!(
        f.service
            .prepare_context(
                denied,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget()
            )
            .expect_err("trace retention is not a processing grant")
            .code,
        ErrorCode::Unauthorized
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    assert!(
        f.service
            .prepare_context(
                plan.clone(),
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut cancelled
            )
            .is_err()
    );
    let mut empty = QueryBudget::new(0, 0, Duration::from_secs(30), Default::default());
    assert!(
        f.service
            .prepare_context(
                plan.clone(),
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut empty
            )
            .is_err()
    );
    f.service
        .publish_memory_from_sources(
            publication(&plan.context, "match"),
            &BTreeSet::from([roots[2]]),
            &mut budget(),
        )
        .expect("actual generic source-aware publication");
    let mut opaque = plan.clone();
    opaque.memory_query = Some(memory_query());
    assert_eq!(
        f.service
            .prepare_context(
                opaque,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget()
            )
            .expect_err("arbitrary native generic fields have no natural model adapter")
            .code,
        ErrorCode::Unsupported
    );
    observer.revision_changed.store(true, Ordering::SeqCst);
    assert_eq!(
        f.service
            .prepare_context(
                plan,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget()
            )
            .expect_err("immutable backend binding changed")
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(observer.calls(), 0);
    let plain_root = tempfile::tempdir().expect("uninstalled owner");
    assert!(
        NativeService::open(plain_root.path(), "scalar-install", [7; 32])
            .expect("plain owner")
            .with_preparation_scorer(Arc::new(R0Scorer))
            .is_err()
    );
    let unavailable = Observer::new();
    unavailable.unavailable.store(true, Ordering::SeqCst);
    let refused_owner = owner(&unavailable);
    let (refused_plan, _) = direct_plan(&refused_owner.service);
    assert_eq!(
        refused_owner
            .service
            .prepare_context(
                refused_plan,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget()
            )
            .expect_err("failed immutable backend cannot silently select with R0")
            .code,
        ErrorCode::ProviderUnavailable
    );
    assert_eq!(unavailable.calls(), 1);
}
