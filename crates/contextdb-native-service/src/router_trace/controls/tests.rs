use super::*;
use contextdb_core::{MemorySubjectId, RevisionNumber};
use contextdb_service::{AssertionPort, CapturePort, CognitiveMemoryService, ResolveStateRequest};
use contextdb_storage::{Durability, SnapshotSelector, StorageEngine, WriteTransaction};

use crate::record_sources::tests::{budget, input, publication};

#[test]
fn generic_current_head_denial_precedes_historical_content_and_survives_raw_permission() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority_directory, ledger) = crate::suppression::tests::authority("trace-generic");
    let (_key_directory, keys) = crate::encryption::tests::authority("trace-generic");
    let service =
        NativeService::open_encrypted(directory.path(), "trace-generic", [7; 32], ledger, keys)
            .expect("encrypted native owner");
    let source = input(1, "independent captured generic origin");
    service.append_event(source.clone()).expect("original");
    let sources = BTreeSet::from([source.event.event_id]);
    service
        .publish_memory_from_sources(
            publication(&source.context, "generic"),
            &sources,
            &mut budget(),
        )
        .expect("accepted source-aware record");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let policy = service
        .load_head(&snapshot, "generic")
        .expect("policy")
        .expect("accepted record");
    let record = service
        .router_record_control(&snapshot, &policy, &mut budget())
        .expect("exact native origin");
    let controls = RouterTraceControls {
        records: vec![record],
        originals: sources,
        ..Default::default()
    };
    service
        .authorize_router_trace_controls(&snapshot, &source.context, &controls, &mut budget())
        .expect("complete current permissions");

    // Fixture fault deliberately changes only current metadata and poisons the
    // historical content. This tests policy-before-content, not a new ACL writer.
    let mut denied = policy.clone();
    denied.access.retrievable = false;
    let mut tx = service.engine.begin_write().expect("fixture transaction");
    tx.put(
        &service.keyspaces.policy_head,
        policy.record_digest.as_bytes().to_vec(),
        encode(&denied).expect("policy bytes"),
    )
    .expect("current denial");
    tx.put(
        &service.keyspaces.content_history,
        history_key(&policy.record_digest, policy.revision),
        b"poisoned fixture content".to_vec(),
    )
    .expect("poisoned body");
    tx.commit(Durability::Sync).expect("fixture commit");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current snapshot");
    service
        .authorized_capture_policy(&snapshot, &source.context, source.event.event_id)
        .expect("raw root still readable");
    assert_eq!(
        service
            .authorize_router_trace_controls(&snapshot, &source.context, &controls, &mut budget())
            .expect_err("latest generic policy closes disclosure before poisoned content")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn unregistered_record_never_becomes_a_source_free_trace_origin() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority_directory, ledger) = crate::suppression::tests::authority("trace-unregistered");
    let service = NativeService::open_with_suppression(
        directory.path(),
        "trace-unregistered",
        [7; 32],
        ledger,
    )
    .expect("native owner");
    let source = input(1, "retained original");
    service.append_event(source.clone()).expect("original");
    service
        .publish_memory(publication(&source.context, "unclassified"))
        .expect("legacy record");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let policy = service
        .load_head(&snapshot, "unclassified")
        .expect("policy")
        .expect("record");
    assert!(
        service
            .record_source_policies(&snapshot, &policy)
            .expect("legacy policies")
            .is_empty()
    );
    assert_eq!(
        service
            .router_record_control(&snapshot, &policy, &mut budget())
            .expect_err("complete trace requires retained declaration")
            .code,
        ErrorCode::EvidenceRequired
    );
}

#[test]
fn accepted_state_authority_change_closes_current_use_without_changing_historical_identity() {
    let directory = tempfile::tempdir().expect("native directory");
    let service =
        NativeService::open(directory.path(), "trace-state", [7; 32]).expect("native owner");
    let source = crate::assertions::tests::capture(1, "native decision support");
    service.append_event(source.clone()).expect("original");
    let key = crate::assertions::tests::key(&source);
    let assertion = crate::assertions::tests::assertion(&source, "kept", 0, None, vec![]);
    let pipeline = assertion.revision.envelope.derivation.pipeline.clone();
    let first = crate::assertions::tests::publish(
        &service,
        &source,
        "initial-state",
        vec![
            AssertionMutation::Policy {
                policy: crate::assertions::tests::policy(&source),
            },
            AssertionMutation::Assert {
                assertion: Box::new(assertion),
            },
        ],
    );
    let view = service
        .resolve_state(
            ResolveStateRequest {
                context: source.context.clone(),
                key: key.clone(),
                known_at: None,
                valid_at: TimestampMicros(1),
                after_receipt: None,
            },
            &mut budget(),
        )
        .expect("actual owner state view");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let state = service
        .router_state_control(&snapshot, &source.context, &key, &view, &mut budget())
        .expect("exact state origins");
    let controls = RouterTraceControls {
        originals: state
            .mutations
            .iter()
            .flat_map(|mutation| mutation.sources.iter().copied())
            .collect(),
        states: vec![state],
        ..Default::default()
    };
    service
        .authorize_router_trace_controls(&snapshot, &source.context, &controls, &mut budget())
        .expect("initial current authority");
    let mut changed_context = source.context.clone();
    changed_context.request.subject_id = MemorySubjectId::new().to_string();
    changed_context.request.audiences =
        BTreeSet::from([changed_context.request.subject_id.clone()]);
    let mut next = crate::assertions::tests::policy(&source);
    next.version = RevisionNumber::new(2).expect("second authority version");
    service
        .publish_assertions(
            contextdb_service::PublishAssertionsRequest {
                context: changed_context,
                idempotency_key: "narrow-current-authority".into(),
                scope: key.scope,
                expected_scope_epoch: first.workspace_commit,
                covered_through: first.workspace_commit,
                pipeline,
                interpretations: vec![],
                mutations: vec![AssertionMutation::Policy { policy: next }],
                after_receipt: None,
            },
            &mut budget(),
        )
        .expect("accepted next authority under narrower host principal");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current snapshot");
    service
        .verify_router_trace_controls(&snapshot, &controls, &mut budget())
        .expect("historical authority and mutation identity unchanged");
    service
        .authorized_capture_policy(&snapshot, &source.context, source.event.event_id)
        .expect("raw root remains readable");
    assert_eq!(
        service
            .authorize_router_trace_controls(&snapshot, &source.context, &controls, &mut budget())
            .expect_err("current state authority closes historical derived disclosure")
            .code,
        ErrorCode::PermissionDenied
    );
    service
        .verify_native(true)
        .expect("legitimate accepted history remains valid");
}

#[test]
fn accepted_router_trace_cannot_lose_the_whole_custody_family_and_optional_markers() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_authority_directory, ledger) =
        crate::suppression::tests::authority("trace-custody-fence");
    let (_key_directory, keys) = crate::encryption::tests::authority("trace-custody-fence");
    let service = std::sync::Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "trace-custody-fence",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted native owner"),
    );
    let accepted = crate::router_trace::tests::capture::accepted_fixture(&service);
    service
        .verify_native(true)
        .expect("actual accepted trace has complete custody");

    let mut tx = service
        .engine
        .begin_write()
        .expect("fixture fault transaction");
    let receipts = tx
        .scan_prefix(&service.keyspaces.continuous, b"receipt/")
        .expect("accepted capture metadata");
    let mut traced = 0;
    for row in receipts {
        let mut expected: serde_json::Value =
            decode(&row.value, "fixture capture metadata").expect("capture metadata");
        if expected["recovery"]["router_trace"].is_object() {
            traced += 1;
            assert_eq!(
                expected["receipt"]["event_id"],
                serde_json::json!(accepted.request.event.event_id)
            );
        }
        assert_eq!(expected["custody_version"], serde_json::json!(1));
        expected
            .as_object_mut()
            .expect("capture object")
            .remove("custody_version");
        // Preserve the exact native field order and all journal-bound recovery
        // bytes. A generic JSON reserialization could fail canonical validation
        // before reaching the missing-custody invariant this fault exercises.
        let bytes = String::from_utf8(row.value)
            .expect("native UTF-8 metadata")
            .replacen("\"custody_version\":1,", "", 1)
            .into_bytes();
        assert_eq!(
            decode::<serde_json::Value>(&bytes, "stripped fixture metadata")
                .expect("stripped metadata"),
            expected,
        );
        tx.put(&service.keyspaces.continuous, row.key, bytes)
            .expect("remove optional custody marker");
    }
    assert_eq!(traced, 1, "fixture accepted exactly one protected request");
    let custody = tx
        .scan_prefix(&service.keyspaces.continuous, b"custody/")
        .expect("whole custody family");
    assert!(!custody.is_empty());
    for row in custody {
        tx.delete(&service.keyspaces.continuous, row.key)
            .expect("remove custody family");
    }
    tx.commit(Durability::Sync).expect("fixture fault commit");

    let error = service
        .verify_native(true)
        .expect_err("Required history cannot degrade into unclassified legacy capture");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert_eq!(
        error.message,
        "protected router capture requires its custody marker"
    );
}
