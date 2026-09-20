use super::*;
use std::{sync::Arc, time::Duration};

use contextdb_core::{
    AgentRunId, EventKind, EventPayload, EventProvenance, EventRole, ModelCallId,
    ModelOutputFormat, ModelRequestManifest, OriginalSourceSpan, RequestPart, SessionId,
    ToolCallId,
};
use contextdb_service::{CapturePort, CaptureRequest, PayloadPort, StagePayloadRequest};

use crate::capture::tests::request;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn stage(service: &NativeService, input: &CaptureRequest, text: &str) -> OriginalPayloadRef {
    service
        .stage_payload(StagePayloadRequest {
            context: input.context.clone(),
            idempotency_key: text.into(),
            block_id: ContentBlockId::new(),
            bytes: text.as_bytes().to_vec(),
        })
        .expect("stage")
        .reference
}
fn staged(sequence: u64, reference: &OriginalPayloadRef) -> CaptureRequest {
    let mut input = request(sequence, "placeholder");
    input.event.payload = EventPayload::Staged {
        reference: reference.clone(),
        media_type: "text/plain".into(),
    };
    input
}
fn source_ids(report: &NativeDeletionLineage) -> BTreeSet<ObservationId> {
    report
        .sources
        .iter()
        .map(|source| source.receipt.event_id)
        .collect()
}

#[test]
fn shared_original_reaches_earlier_owners_and_descendants_but_retains_independent_novel_blocks() {
    let dir = tempfile::tempdir().expect("directory");
    let (_keys_dir, keys) = encryption::tests::authority("lineage");
    let (_ledger_dir, ledger) = suppression::tests::authority("lineage");
    let service =
        NativeService::open_encrypted(dir.path(), "lineage", [7; 32], ledger.clone(), keys.clone())
            .expect("open");
    let input = request(1, "source_sentinel_75182");
    let block = stage(&service, &input, "source_sentinel_75182");
    let early = staged(1, &block);
    service.append_event(early.clone()).expect("earlier owner");
    let novel = stage(&service, &input, "independent_novel_sentinel_75382");
    let independent = staged(2, &novel);
    service
        .append_event(independent.clone())
        .expect("independent owner");
    let orphan = stage(&service, &input, "request_only_novel_sentinel_86928");
    let mut call = request(3, "placeholder");
    call.context.capability_grants.insert(Capability::Runtime);
    let call_id = ModelCallId::new();
    let wire =
        b"source_sentinel_75182independent_novel_sentinel_75382request_only_novel_sentinel_86928";
    call.event.role = EventRole::Host;
    call.event.kind = EventKind::ModelRequested;
    call.event.run_id = Some(AgentRunId::new());
    call.event.session_id = Some(SessionId::new());
    call.event.provenance = Some(EventProvenance::ModelRequest {
        model_call_id: call_id,
    });
    call.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id: call_id,
            renderer: "test/v1".into(),
            wire_digest: digest(wire),
            byte_length: wire.len() as u64,
            parts: vec![
                RequestPart::Source {
                    span: OriginalSourceSpan {
                        event_id: early.event.event_id,
                        payload_digest: block.digest,
                        start: 0,
                        end: block.byte_length,
                        span_digest: block.digest,
                    },
                },
                RequestPart::StoredNovel {
                    payload: novel.clone(),
                },
                RequestPart::StoredNovel {
                    payload: orphan.clone(),
                },
            ],
        },
    };
    service
        .append_event(call.clone())
        .expect("request before selected root");
    let mut output = request(4, "derived_sentinel_78196");
    output.context.capability_grants.insert(Capability::Runtime);
    output.event.kind = EventKind::ModelResponseCompleted;
    output.event.role = EventRole::Assistant;
    output.event.run_id = call.event.run_id;
    output.event.session_id = call.event.session_id;
    output.event.parent_event_ids.insert(call.event.event_id);
    output.event.provenance = Some(EventProvenance::ModelOutput {
        model_call_id: call_id,
        request_event_id: call.event.event_id,
        format: ModelOutputFormat::PlainText,
        tool_calls: vec![],
    });
    service.append_event(output.clone()).expect("model result");
    let mut tool = request(5, "tool_action_sentinel_78145");
    tool.event.kind = EventKind::ToolRequested;
    tool.event.role = EventRole::Host;
    tool.event.parent_event_ids.insert(output.event.event_id);
    tool.event.provenance = Some(EventProvenance::Tool {
        call_id: ToolCallId::new(),
        request_event_id: tool.event.event_id,
        action_digest: tool.event.payload.digest().expect("action"),
    });
    service.append_event(tool.clone()).expect("tool intent");
    let mut result = request(6, "tool_result_sentinel_74283");
    result.event.kind = EventKind::ToolCompleted;
    result.event.role = EventRole::Tool;
    result.event.parent_event_ids.insert(tool.event.event_id);
    result.event.provenance = tool.event.provenance.clone();
    service.append_event(result.clone()).expect("tool outcome");
    let selected = staged(7, &block);
    service
        .append_event(selected.clone())
        .expect("later selected owner");
    let mut same_bytes = request(8, "source_sentinel_75182");
    same_bytes
        .event
        .parent_event_ids
        .insert(early.event.event_id);
    service
        .append_event(same_bytes.clone())
        .expect("independent bytes with a causal-only link");
    let mut revision = request(9, "replacement_sentinel_86341");
    revision.event.kind = EventKind::MessageEdited;
    revision.event.supersedes_event_id = Some(early.event.event_id);
    service.append_event(revision.clone()).expect("replacement");
    let expected = [&early, &call, &output, &tool, &result, &selected, &revision]
        .map(|input| input.event.event_id)
        .into_iter()
        .collect();
    let roots = BTreeSet::from([selected.event.event_id]);
    let report = service
        .inspect_original_deletion(&selected.context, &roots, &mut budget())
        .expect("exact source lineage");
    assert_eq!(source_ids(&report), expected);
    assert_eq!(
        report
            .payloads
            .iter()
            .map(|p| p.block_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([block.block_id, orphan.block_id])
    );
    assert_eq!(report.retained_shared_payloads, vec![novel]);
    let request_only = service
        .inspect_original_deletion(
            &call.context,
            &BTreeSet::from([call.event.event_id]),
            &mut budget(),
        )
        .expect("request occurrence lineage");
    assert_eq!(
        source_ids(&request_only),
        [&call, &output, &tool, &result]
            .map(|event| event.event.event_id)
            .into_iter()
            .collect()
    );
    assert_eq!(request_only.payloads, vec![orphan]);
    assert_eq!(
        request_only.retained_shared_payloads,
        report.retained_shared_payloads
    );
    assert!(
        !String::from_utf8(encode(&report).expect("report"))
            .expect("JSON")
            .contains("sentinel")
    );
    assert!(
        service
            .load_captured_original(
                &service
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .expect("read"),
                selected.event.event_id
            )
            .is_ok(),
        "inspection does not remove or suppress"
    );
    service
        .verify_native(true)
        .expect("unchanged native closure");
    let backup = service
        .create_backup(CreateBackupRequest {
            context: selected.context.clone(),
        })
        .expect("backup");
    let restored_dir = tempfile::tempdir().expect("restore directory");
    let restored = NativeService::open_encrypted(
        restored_dir.path(),
        "lineage",
        [9; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: selected.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    assert_eq!(
        restored
            .inspect_original_deletion(&selected.context, &roots, &mut budget())
            .expect("restored lineage"),
        report
    );
    drop(service);
    let reopened = NativeService::open_encrypted(dir.path(), "lineage", [8; 32], ledger, keys)
        .expect("reopen");
    assert_eq!(
        reopened
            .inspect_original_deletion(&selected.context, &roots, &mut budget())
            .expect("reopened lineage"),
        report
    );
    reopened
        .revoke_original(
            &selected.context,
            selected.event.event_id,
            "explicit-revocation",
            &mut budget(),
        )
        .expect("revoke");
    assert_eq!(
        source_ids(
            &reopened
                .inspect_original_deletion(&selected.context, &roots, &mut budget())
                .expect("inventory after revocation")
        ),
        expected
    );
}

#[test]
fn inspection_rejects_budget_exhaustion_foreign_roots_and_a_concurrent_revision() {
    let dir = tempfile::tempdir().expect("directory");
    let service = Arc::new(NativeService::open(dir.path(), "lineage", [7; 32]).expect("open"));
    let input = request(1, "source");
    service.append_event(input.clone()).expect("capture");
    let roots = BTreeSet::from([input.event.event_id]);
    for mut limit in [
        QueryBudget::new(0, 1_000_000, Duration::from_secs(10), Default::default()),
        QueryBudget::new(1_000_000, 1, Duration::from_secs(10), Default::default()),
        QueryBudget::new(1_000_000, 1_000_000, Duration::ZERO, Default::default()),
    ] {
        assert_eq!(
            service
                .inspect_original_deletion(&input.context, &roots, &mut limit)
                .expect_err("no partial result")
                .code,
            ErrorCode::BudgetExhausted
        );
    }
    let cancellation = contextdb_recall::QueryCancellation::default();
    let mut limit = QueryBudget::new(
        1_000_000,
        1_000_000,
        Duration::from_secs(10),
        cancellation.clone(),
    );
    cancellation.cancel();
    assert_eq!(
        service
            .inspect_original_deletion(&input.context, &roots, &mut limit)
            .expect_err("cancelled")
            .code,
        ErrorCode::BudgetExhausted
    );
    let mut denied = input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        service
            .inspect_original_deletion(&denied, &roots, &mut budget())
            .expect_err("admin required")
            .code,
        ErrorCode::Unauthorized
    );
    let mut foreign = input.context.clone();
    foreign.request.workspace_id = contextdb_core::WorkspaceId::new().to_string();
    assert_eq!(
        service
            .inspect_original_deletion(&foreign, &roots, &mut budget())
            .expect_err("foreign root")
            .code,
        ErrorCode::PermissionDenied
    );
    let sequence = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("read")
        .sequence();
    service
        .inspect_original_deletion(&input.context, &roots, &mut budget())
        .expect("read-only inspection");
    assert_eq!(
        service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("read")
            .sequence(),
        sequence
    );
    let concurrent = Arc::clone(&service);
    let mut revision = request(2, "new revision");
    revision.event.kind = EventKind::MessageEdited;
    revision.event.supersedes_event_id = Some(input.event.event_id);
    let revised_id = revision.event.event_id;
    BEFORE_CURRENT_CHECK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            concurrent
                .append_event(revision)
                .expect("concurrent revision");
        }))
    });
    assert_eq!(
        service
            .inspect_original_deletion(&input.context, &roots, &mut budget())
            .expect_err("stale inventory")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        source_ids(
            &service
                .inspect_original_deletion(&input.context, &roots, &mut budget())
                .expect("new lineage")
        ),
        BTreeSet::from([input.event.event_id, revised_id])
    );
}

#[test]
fn source_inventory_uses_the_complete_journal_prefix_instead_of_outbox_or_search_routes() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "lineage", [7; 32]).expect("open");
    let root = request(1, "root");
    for index in 1..=260 {
        service
            .append_event(request(index, "independent capture"))
            .expect("capture across page boundary");
    }
    let mut revision = request(261, "replacement");
    revision.event.kind = EventKind::MessageEdited;
    revision.event.supersedes_event_id = Some(root.event.event_id);
    service.append_event(revision.clone()).expect("revision");
    let roots = BTreeSet::from([root.event.event_id]);
    let baseline = service
        .inspect_original_deletion(&root.context, &roots, &mut budget())
        .expect("paged scan");
    assert_eq!(
        source_ids(&baseline),
        BTreeSet::from([root.event.event_id, revision.event.event_id])
    );
    let workspace = digest_bytes(root.context.request.workspace_id.as_bytes());
    let mut tx = service.engine.begin_write().expect("write");
    tx.delete(
        &service.keyspaces.continuous,
        capture::work_key(&workspace, 261),
    )
    .expect("remove derived outbox fixture");
    tx.commit(Durability::Sync).expect("damage");
    assert_eq!(
        service
            .inspect_original_deletion(&root.context, &roots, &mut budget())
            .expect("accepted journal still contains descendant"),
        baseline
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("read");
    for (space, key) in [
        (
            &service.keyspaces.workspace_map,
            workspace_map_key(&workspace, 257),
        ),
        (&service.keyspaces.events, 261_u64.to_be_bytes().to_vec()),
        (
            &service.keyspaces.continuous,
            format!("receipt/{}", revision.event.event_id).into_bytes(),
        ),
    ] {
        let saved = snapshot.get(space, &key).expect("save").expect("present");
        let mut tx = service.engine.begin_write().expect("write");
        tx.delete(space, key.clone())
            .expect("remove authoritative row");
        tx.commit(Durability::Sync).expect("damage");
        assert!(
            service
                .inspect_original_deletion(&root.context, &roots, &mut budget())
                .is_err(),
            "missing accepted authority cannot become a partial report"
        );
        let mut tx = service.engine.begin_write().expect("write");
        tx.put(space, key, saved).expect("repair row");
        tx.commit(Durability::Sync).expect("repair");
    }
    let mut frame: StoredEvent = decode(
        &snapshot
            .get(&service.keyspaces.events, &261_u64.to_be_bytes())
            .expect("frame")
            .expect("present"),
        "frame",
    )
    .expect("decode");
    frame.operation = "not_a_capture".into();
    frame.accepted_original = None;
    frame.event_digest = event_digest(&frame).expect("rehashed frame");
    let mut tx = service.engine.begin_write().expect("write");
    tx.put(
        &service.keyspaces.events,
        261_u64.to_be_bytes().to_vec(),
        encode(&frame).expect("frame"),
    )
    .expect("tamper");
    tx.commit(Durability::Sync).expect("damage");
    assert_eq!(
        service
            .inspect_original_deletion(&root.context, &roots, &mut budget())
            .expect_err("a rehashed frame cannot hide an accepted capture from inventory")
            .code,
        ErrorCode::IntegrityFailure
    );
}
