//! Current controls for the whole inherited closure precede immutable bodies.

use std::sync::Arc;

use contextdb_core::{
    EventKind, EventProvenance, EventRole, ModelOutputFormat, PredicateId, RevisionNumber, Validate,
};
use contextdb_service::{CapturePort, CaptureRequest, PrepareContextRequest, ReadOriginalRequest};
use contextdb_storage::{Durability, SnapshotSelector, StorageEngine, WriteTransaction};

use super::*;
use crate::router_trace::tests::{budget, capture, envelope, memory_query, publication, source};

fn generic_setup(
    service: &NativeService,
    source: &CaptureRequest,
    plan: &mut PrepareContextRequest,
) {
    service
        .publish_memory_from_sources(
            publication(&source.context, "ordering-match"),
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("actual source-aware generic publication");
    plan.memory_query = Some(memory_query());
}

#[test]
fn inherited_generic_body_waits_for_later_outer_state_authority_denial() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("trace-nested-order");
    let (_key_directory, keys) = crate::encryption::tests::authority("trace-nested-order");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "trace-nested-order",
            [7; 32],
            ledger,
            keys,
        )
        .expect("actual encrypted owner"),
    );
    let accepted = capture::accepted_fixture_with_setup(&service, generic_setup);
    let frozen = envelope(&accepted.prepared);
    assert_eq!(frozen.origins.records.len(), 1);

    let pending = accepted
        .checkpoint
        .checkpoint
        .pending_model
        .as_ref()
        .expect("owned call");
    let mut derived = source(
        4,
        "A captured output inherits its complete protected invocation.",
    );
    derived.context = accepted.context.clone();
    derived.event.producer_id = accepted.checkpoint.checkpoint.producer_id;
    derived.event.producer_sequence = accepted.checkpoint.checkpoint.next_sequence + 1;
    derived.event.kind = EventKind::ModelResponseCompleted;
    derived.event.role = EventRole::Assistant;
    derived.event.run_id = accepted.request.event.run_id;
    derived.event.session_id = accepted.request.event.session_id;
    derived
        .event
        .parent_event_ids
        .insert(accepted.request.event.event_id);
    derived.event.provenance = Some(EventProvenance::ModelOutput {
        model_call_id: pending.call_id,
        request_event_id: accepted.request.event.event_id,
        format: ModelOutputFormat::PlainText,
        tool_calls: Vec::new(),
    });
    service
        .append_event(derived.clone())
        .expect("actual captured derived output");

    let mut authority_source = accepted.request.clone();
    authority_source.event = service
        .read_original(ReadOriginalRequest {
            context: accepted.context.clone(),
            event_id: *frozen.origins.originals.first().expect("accepted original"),
            after_receipt: None,
        })
        .expect("genuine accepted authority source")
        .event;
    assert_eq!(authority_source.event.role, EventRole::User);
    let first_policy = crate::assertions::tests::policy(&authority_source);
    first_policy.validate().expect("valid User decision grant");
    let mut second_policy = first_policy.clone();
    second_policy.key.predicate =
        PredicateId::from_uuid(uuid::Uuid::from_u128(22)).expect("second slot");
    let first = crate::assertions::tests::publish(
        &service,
        &authority_source,
        "initial-ordering-slots",
        vec![
            AssertionMutation::Policy {
                policy: first_policy.clone(),
            },
            AssertionMutation::Policy {
                policy: second_policy.clone(),
            },
        ],
    );
    let workspace = digest_bytes(derived.context.request.workspace_id.as_bytes());
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("accepted authorities");
    let authority = |key: &StateKey| {
        service
            .authority_at(
                &snapshot,
                &workspace,
                key,
                first.workspace_commit,
                &mut budget(),
            )
            .expect("historical authority")
            .expect("accepted slot")
    };
    let first_authority = authority(&first_policy.key);
    let second_authority = authority(&second_policy.key);
    let inherited = service
        .stored_router_trace_controls(&snapshot, derived.event.event_id)
        .expect("actual derived custody")
        .expect("inherited generic controls");
    assert_eq!(inherited.records, frozen.origins.records);
    service
        .authorize_derived_custody_with_budget(
            &snapshot,
            &derived.context,
            derived.event.event_id,
            &mut budget(),
        )
        .expect("real inherited custody is initially admitted");
    drop(snapshot);

    // This is an actual accepted authority policy update under another principal,
    // not a new public ACL mutation API or a fault that rewrites historical ACLs.
    let mut narrower = authority_source.clone();
    narrower.context.request.subject_id = "another-ordering-owner".into();
    narrower.context.request.audiences =
        BTreeSet::from([narrower.context.request.subject_id.clone()]);
    second_policy.version = RevisionNumber::new(2).expect("second authority version");
    second_policy.grants[0].source.actor_id = "another-decision-actor".into();
    second_policy.grants[0].source.adapter_id = "another-decision-adapter".into();
    second_policy
        .validate()
        .expect("valid replacement User decision grant");
    crate::assertions::tests::publish(
        &service,
        &narrower,
        "narrow-later-ordering-slot",
        vec![AssertionMutation::Policy {
            policy: second_policy.clone(),
        }],
    );

    let prefix = state_prefix(&workspace, &first_policy.key).expect("state label prefix");
    let label_key = format!("{prefix}00000000000000000000000000000001").into_bytes();
    let label = MutationLabel {
        commit: first.workspace_commit,
        sources: BTreeSet::from([derived.event.event_id]),
        body_key: b"ordering-fixture-unused-state-body".to_vec(),
        body_digest: digest_bytes(b"ordering fixture metadata-only label"),
        envelope: None,
        pruned_at: None,
    };
    let first_state = TraceStateControl {
        workspace: workspace.clone(),
        key: first_policy.key,
        authority_commit: first_authority.commit,
        authority_digest: canonical_digest(&first_authority).expect("first authority commitment"),
        mutations: vec![TraceStateMutationControl {
            label_key: label_key.clone(),
            commit: label.commit,
            body_digest: label.body_digest.clone(),
            sources: label.sources.clone(),
        }],
    };
    let second_state = TraceStateControl {
        workspace,
        key: second_policy.key,
        authority_commit: second_authority.commit,
        authority_digest: canonical_digest(&second_authority).expect("second authority commitment"),
        mutations: Vec::new(),
    };
    let mut controls = frozen.origins.clone();
    controls.originals.insert(derived.event.event_id);
    controls.states = vec![first_state, second_state];
    controls
        .validate()
        .expect("bounded whole declared frontier");

    let record = &frozen.origins.records[0];
    let mut tx = service
        .engine
        .begin_write()
        .expect("explicit fixture faults");
    // Only this first-state label is a metadata-only fixture injection. Its
    // source, inherited generic controls and both authority histories above were
    // accepted through public ports; no state assertion publication is claimed.
    tx.put(
        &service.keyspaces.continuous,
        label_key,
        encode(&label).expect("label bytes"),
    )
    .expect("fixture nested source label");
    tx.put(
        &service.keyspaces.content_history,
        history_key(&record.control.record_digest, record.control.revision),
        b"poisoned inherited historical generic body".to_vec(),
    )
    .expect("fixture body poison behind current state denial");
    tx.commit(Durability::Sync).expect("fixture Sync");

    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current read snapshot");
    assert_eq!(
        service
            .authorize_router_trace_controls(
                &snapshot,
                &derived.context,
                &frozen.origins,
                &mut budget()
            )
            .expect_err("poison is reached when the generic closure alone is authorized")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        service
            .authorize_router_trace_controls(&snapshot, &derived.context, &controls, &mut budget())
            .expect_err("later outer authority denial precedes nested inherited body verification")
            .code,
        ErrorCode::PermissionDenied
    );
}
