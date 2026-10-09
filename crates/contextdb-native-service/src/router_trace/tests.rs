//! Real native preparation gates; the protected envelope is not reader input.

use std::collections::BTreeSet;

use contextdb_context::*;
use contextdb_core::{ContextPackId, RawFilter, RecallIntent, TimestampMicros};
use contextdb_recall::{IndexedQuery, IndexedSelection, RecallLimits, RecallMode, RecallStatus};
use contextdb_service::{
    Capability, CapturePort, CaptureRequest, CognitiveMemoryService, CorrectRequest, ErrorCode,
    GetMemoryRequest, PrepareContextPort, PrepareContextRequest, PrepareRecallQuery,
    PreparedContext, RouterTraceProfile,
};
use contextdb_storage::{Durability, SnapshotSelector, StorageEngine, WriteTransaction};

use super::*;
pub(super) use crate::record_sources::tests::{budget, input, publication};
use crate::{NativeService, encode, history_key};

pub(in crate::router_trace) mod capture;
mod lifecycle;
mod lifecycle_v2;
mod semantic;

pub(super) fn request(source: &CaptureRequest) -> PrepareContextRequest {
    let mut context = source.context.clone();
    context
        .capability_grants
        .extend([Capability::Runtime, Capability::ReadConflict]);
    PrepareContextRequest {
        context,
        pack_id: ContextPackId::new(),
        purpose: PackPurpose::Conversation,
        known_at: None,
        valid_at: Some(TimestampMicros(1_000_000)),
        after_receipt: None,
        raw_queries: Vec::new(),
        memory_query: None,
        required_facets: Vec::new(),
        memory_budget: ContextBudgets {
            hard_tokens: 14_000,
            soft_tokens: 12_000,
            max_blocks: 64,
            max_evidence_blocks: 128,
            max_raw_evidence_tokens: 10_000,
            max_history_tokens: 10_000,
            max_conflict_tokens: 10_000,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 128,
        },
        model_profile: ModelProfile {
            id: "native-reference-json".into(),
            family: "reference".into(),
            tokenizer_id: ReferenceTokenizer::ID.into(),
            renderer: RendererKind::Compact,
            max_context_tokens: 32_000,
            reserved_output_tokens: 4_000,
            preferred_structured_format: StructuredFormat::CompactText,
            supports_tool_results: true,
            supports_native_citations: false,
            supports_prompt_caching: false,
            position_profile: PositionProfile::CriticalFirst,
            instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
            max_schema_complexity: 64,
            external_processing: false,
        },
        base: OutgoingBase {
            working: Vec::new(),
            control: Vec::new(),
            hot: Vec::new(),
            current: Vec::new(),
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: 27_000,
            safety_tokens: 1_000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
        explicit_memory_request: true,
        router_trace_profile: RouterTraceProfile::Required,
    }
}

pub(super) fn prepare(service: &NativeService, request: PrepareContextRequest) -> PreparedContext {
    service
        .prepare_context(
            request,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &mut budget(),
        )
        .expect("actual native preparation")
}

pub(super) fn envelope(prepared: &PreparedContext) -> RouterEnvelope {
    let trace = prepared
        .router_trace
        .as_ref()
        .expect("protected Required envelope");
    trace.validate().expect("bounded attachment");
    let envelope: RouterEnvelope =
        serde_json::from_str(&trace.canonical_json).expect("canonical prepared envelope");
    envelope
        .validate(&mut budget())
        .expect("protected commitments");
    envelope
}

pub(super) fn source(sequence: u64, text: &str) -> CaptureRequest {
    let mut source = input(sequence, text);
    source.context.request.purpose = "conversation".into();
    source
}

pub(super) fn prepare_catalog(service: &NativeService, source: &CaptureRequest, raw: bool) {
    service
        .initialize_state_catalog(&source.context, &mut budget())
        .expect("native catalog");
    if raw {
        assert!(
            service
                .project_originals(&source.context, false, 256, &mut budget())
                .expect("native raw projection")
                .caught_up
        );
    }
}

pub(super) fn memory_query() -> PrepareRecallQuery {
    PrepareRecallQuery {
        query: "record sentinel match".into(),
        intent: RecallIntent::Continuity,
        mode: RecallMode::Required,
        limits: RecallLimits {
            max_nodes_examined: 100,
            max_seed_candidates: 1,
            max_graph_hops: 2,
            max_frontier_per_hop: 8,
            max_evidence_units: 8,
            max_context_tokens: 4000,
            deadline_micros: 20_000_000,
        },
        query_vector: None,
    }
}

#[test]
fn required_preserves_off_reader_wire_and_retains_discarded_raw_material() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-reader");
    let service =
        NativeService::open_with_suppression(directory.path(), "trace-reader", [7; 32], ledger)
            .expect("actual native owner");
    let first = source(1, "First independent attributed original: amber.");
    let second = source(2, "Second independent attributed original: cobalt.");
    service.append_event(first.clone()).expect("first original");
    service
        .append_event(second.clone())
        .expect("second original");
    prepare_catalog(&service, &first, true);
    let mut plan = request(&first);
    // Situation + one pending-interpretation marker + one optional raw block.
    plan.memory_budget.max_blocks = 3;
    plan.raw_queries.push(IndexedQuery {
        filter: RawFilter {
            event_ids: BTreeSet::from([first.event.event_id, second.event.event_id]),
            ..Default::default()
        },
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 2 },
    });
    let mut off = plan.clone();
    off.router_trace_profile = RouterTraceProfile::Off;
    let off = prepare(&service, off);
    let required = prepare(&service, plan);
    assert!(off.router_trace.is_none());
    assert_eq!(off.outgoing.wire, required.outgoing.wire);
    assert_eq!(off.outgoing.input_tokens, required.outgoing.input_tokens);
    assert_eq!(off.context_pack.sections, required.context_pack.sections);
    assert_eq!(required.context_pack.sections.raw_observations.len(), 1);
    let retained = envelope(&required);
    let raw: Vec<_> = retained
        .materials
        .candidates
        .iter()
        .filter(|candidate| candidate.kind == PackBlockKind::RawObservation)
        .collect();
    assert_eq!(
        raw.len(),
        2,
        "trace retains the compiler's actual optional inventory"
    );
    assert_eq!(
        raw.iter()
            .filter(|candidate| retained.plan.selected_ids.contains(&candidate.id))
            .count(),
        1
    );
    assert!(retained.origins.originals.contains(&first.event.event_id));
    assert!(retained.origins.originals.contains(&second.event.event_id));
    assert!(retained.materials.evidence.iter().any(|item| {
        item.original_span
            .as_ref()
            .is_some_and(|span| span.event_id == first.event.event_id)
    }));
    assert!(retained.materials.evidence.iter().any(|item| {
        item.original_span
            .as_ref()
            .is_some_and(|span| span.event_id == second.event.event_id)
    }));
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    service
        .authorize_router_trace_controls(
            &snapshot,
            &first.context,
            &retained.origins,
            &mut budget(),
        )
        .expect("all inspected raw origins currently authorized");
    service
        .verify_native(true)
        .expect("native deep verification");
}

#[test]
fn generic_trace_retains_inspected_unselected_origin_and_canonical_non_uuid_data() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-generic-frontier");
    let service = NativeService::open_with_suppression(
        directory.path(),
        "trace-generic-frontier",
        [7; 32],
        ledger,
    )
    .expect("actual native owner");
    let first = source(1, "Source of the matching memory.");
    let second = source(2, "Independent source of the unselected memory.");
    service.append_event(first.clone()).expect("first source");
    service.append_event(second.clone()).expect("second source");
    for (source, id) in [(&first, "match"), (&second, "unrelated-archive-item")] {
        service
            .publish_memory_from_sources(
                publication(&source.context, id),
                &BTreeSet::from([source.event.event_id]),
                &mut budget(),
            )
            .expect("native source-aware publication");
    }
    prepare_catalog(&service, &first, false);
    let mut plan = request(&first);
    plan.memory_query = Some(memory_query());
    let prepared = prepare(&service, plan);
    let retained = envelope(&prepared);
    assert_eq!(
        retained
            .generic_discovery
            .as_ref()
            .expect("observed generic query")
            .inspected_records,
        2
    );
    assert_eq!(retained.retrieval_origins.records.len(), 2);
    assert!(
        retained
            .retrieval_origins
            .originals
            .contains(&first.event.event_id)
    );
    assert!(
        retained
            .retrieval_origins
            .originals
            .contains(&second.event.event_id)
    );
    let generic: Vec<_> = retained
        .materials
        .candidates
        .iter()
        .filter(|candidate| candidate.id.as_str().starts_with("native:"))
        .collect();
    assert_eq!(
        generic.len(),
        1,
        "one ranked hit does not replace the complete inspected origin set"
    );
    assert!(
        generic[0].memory_refs.is_empty(),
        "non-UUID address is retained without fabricated typed IDs"
    );
    assert_eq!(
        generic[0].representations[0].fields["typed_reference"],
        "unavailable"
    );
    assert_eq!(generic[0].kind, PackBlockKind::Unknown);
    assert_eq!(
        generic[0].instruction_capability,
        InstructionCapability::None
    );
    assert!(generic[0].representations[0].fields["native_value"].contains("record sentinel match"));
    assert!(
        prepared
            .messages
            .iter()
            .any(|message| message.text.contains("record sentinel match"))
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    service
        .authorize_router_trace_controls(
            &snapshot,
            &first.context,
            &retained.origins,
            &mut budget(),
        )
        .expect("unselected generic origin is also an authorization dependency");
    service
        .verify_native(true)
        .expect("native deep verification");
}

#[test]
fn current_generic_head_denial_omits_record_before_poisoned_historical_body() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-generic-denial");
    let service = NativeService::open_with_suppression(
        directory.path(),
        "trace-generic-denial",
        [7; 32],
        ledger,
    )
    .expect("actual native owner");
    let source = source(1, "Still independently readable raw memory origin.");
    service.append_event(source.clone()).expect("source");
    service
        .publish_memory_from_sources(
            publication(&source.context, "match"),
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("source-aware publication");
    prepare_catalog(&service, &source, false);
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let policy = service
        .load_head(&snapshot, "match")
        .expect("policy lookup")
        .expect("native policy");
    drop(snapshot);
    let mut denied = policy.clone();
    denied.access.retrievable = false;
    let mut tx = service
        .engine
        .begin_write()
        .expect("fixture fault transaction");
    tx.put(
        &service.keyspaces.policy_head,
        policy.record_digest.as_bytes().to_vec(),
        encode(&denied).expect("policy bytes"),
    )
    .expect("current metadata denial");
    tx.put(
        &service.keyspaces.content_history,
        history_key(&policy.record_digest, policy.revision),
        b"poisoned historical content".to_vec(),
    )
    .expect("historical body fault");
    tx.commit(Durability::Sync).expect("fixture fault commit");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    service
        .authorized_capture_policy(&snapshot, &source.context, source.event.event_id)
        .expect("raw root remains independently authorized");
    drop(snapshot);
    let mut plan = request(&source);
    plan.memory_query = Some(memory_query());
    let retained = envelope(&prepare(&service, plan));
    assert_eq!(
        retained
            .generic_discovery
            .as_ref()
            .expect("generic query")
            .inspected_records,
        0
    );
    assert!(retained.retrieval_origins.records.is_empty());
    assert!(
        !retained
            .materials
            .candidates
            .iter()
            .any(|candidate| candidate.id.as_str().starts_with("native:"))
    );
}

#[test]
fn newer_native_correction_preserves_old_trace_material_and_immutable_origin() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-historical");
    let service =
        NativeService::open_with_suppression(directory.path(), "trace-historical", [7; 32], ledger)
            .expect("actual native owner");
    let first = source(1, "Original source of the historical memory.");
    service
        .append_event(first.clone())
        .expect("original source");
    service
        .publish_memory_from_sources(
            publication(&first.context, "match"),
            &BTreeSet::from([first.event.event_id]),
            &mut budget(),
        )
        .expect("initial native memory");
    prepare_catalog(&service, &first, false);
    let mut plan = request(&first);
    plan.memory_query = Some(memory_query());
    let prepared = prepare(&service, plan);
    let frozen_json = prepared
        .router_trace
        .as_ref()
        .expect("trace")
        .canonical_json
        .clone();
    let retained = envelope(&prepared);
    let old = service
        .get_memory(GetMemoryRequest {
            context: first.context.clone(),
            record_id: "match".into(),
            at_commit: None,
        })
        .expect("old native material");
    let correction = source(
        2,
        "A newer captured correction replaces the remembered value.",
    );
    service
        .append_event(correction.clone())
        .expect("new correction source");
    let mut replacement = old.document;
    replacement.id = "updated-memory".into();
    replacement.value = serde_json::json!({"text": "new cobalt value"});
    replacement.search_text = Some("new cobalt value".into());
    replacement.links.supersedes.insert("match".into());
    service
        .correct_memory_from_sources(
            CorrectRequest {
                context: first.context.clone(),
                idempotency_key: "replace-memory".into(),
                target_id: "match".into(),
                replacement,
            },
            &BTreeSet::from([correction.event.event_id]),
            &mut budget(),
        )
        .expect("actual native correction");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("new native snapshot");
    service
        .verify_router_trace_controls(&snapshot, &retained.origins, &mut budget())
        .expect("closed transaction interval is not corruption of the immutable birth");
    service
        .authorize_router_trace_controls(
            &snapshot,
            &first.context,
            &retained.origins,
            &mut budget(),
        )
        .expect("old accepted trace remains readable under unchanged current permissions");
    assert_eq!(
        prepared
            .router_trace
            .as_ref()
            .expect("trace")
            .canonical_json,
        frozen_json
    );
    assert!(retained.materials.candidates.iter().any(|candidate| {
        candidate.representations.iter().any(|representation| {
            representation
                .fields
                .get("native_value")
                .is_some_and(|value| value.contains("record sentinel match"))
        })
    }));
    assert!(!frozen_json.contains("new cobalt value"));
    service
        .verify_native(true)
        .expect("native historical replay");
}

#[test]
fn explicit_never_gate_is_lazy_and_generic_off_profile_refuses() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-gate");
    let service =
        NativeService::open_with_suppression(directory.path(), "trace-gate", [7; 32], ledger)
            .expect("actual native owner");
    let source = source(1, "Retained user original.");
    service.append_event(source.clone()).expect("source");
    // This intentionally unregistered legacy row cannot enter complete generic
    // discovery. A Never gate must not inspect it or manufacture an origin.
    service
        .publish_memory(publication(&source.context, "match"))
        .expect("legacy publication");
    prepare_catalog(&service, &source, false);
    let mut plan = request(&source);
    let mut query = memory_query();
    query.mode = RecallMode::Never;
    plan.memory_query = Some(query);
    let mut off = plan.clone();
    off.router_trace_profile = RouterTraceProfile::Off;
    assert_eq!(
        service
            .prepare_context(
                off,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &mut budget()
            )
            .expect_err("generic discovery is an explicit protected profile")
            .code,
        ErrorCode::InvalidArgument
    );
    let retained = envelope(&prepare(&service, plan));
    let observation = retained.generic_discovery.expect("observed skipped query");
    assert_eq!(observation.status, RecallStatus::Skipped);
    assert_eq!(observation.inspected_records, 0);
    assert!(retained.retrieval_origins.records.is_empty());
}

#[test]
fn complete_generic_ceiling_refuses_before_the_101st_native_record_body() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority, ledger) = crate::suppression::tests::authority("trace-generic-ceiling");
    let service = NativeService::open_with_suppression(
        directory.path(),
        "trace-generic-ceiling",
        [7; 32],
        ledger,
    )
    .expect("actual native owner");
    let source = source(
        1,
        "Independently accepted common origin of this bounded corpus.",
    );
    service
        .append_event(source.clone())
        .expect("retained original");
    let sources = BTreeSet::from([source.event.event_id]);
    let ids: Vec<_> = (0..101).map(|index| format!("record-{index:03}")).collect();
    for id in &ids {
        service
            .publish_memory_from_sources(publication(&source.context, id), &sources, &mut budget())
            .expect("actual source-aware native record");
    }
    prepare_catalog(&service, &source, false);
    // Policy-route ordering is by native address commitment, not display name.
    let last = ids
        .iter()
        .max_by_key(|id| crate::digest_bytes(id.as_bytes()))
        .expect("101 records");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let policy = service
        .load_head(&snapshot, last)
        .expect("policy")
        .expect("last record");
    drop(snapshot);
    let mut tx = service
        .engine
        .begin_write()
        .expect("fixture fault transaction");
    tx.put(
        &service.keyspaces.content_history,
        history_key(&policy.record_digest, policy.revision),
        b"poisoned record beyond the complete inspection bound".to_vec(),
    )
    .expect("fixture body fault");
    tx.commit(Durability::Sync).expect("fixture fault commit");
    let mut plan = request(&source);
    plan.memory_query = Some(memory_query());
    let error = service
        .prepare_context(
            plan,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &mut budget(),
        )
        .expect_err("never truncate a complete generic frontier");
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    assert!(!error.retryable);
    assert!(
        error.message.contains("100 records"),
        "the complete-frontier bound wins before corrupted content"
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    service
        .authorized_capture_policy(&snapshot, &source.context, source.event.event_id)
        .expect("previously accepted user original remains independently permitted");
}
