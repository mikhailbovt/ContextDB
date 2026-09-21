use super::*;
use contextdb_core::{
    AgentRunId, ContentBlockId, ContentDigest, EventKind, EventPayload, EventProvenance, EventRole,
    ModelCallId, ModelRequestManifest, OriginalPayloadRef, RequestPart, SessionId,
};
use contextdb_service::{CaptureRequest, PayloadPort, StagePayloadRequest};

fn source(sequence: u64, payload: &OriginalPayloadRef) -> CaptureRequest {
    let mut input = request(sequence, "staged original");
    input.event.payload = EventPayload::Staged {
        reference: payload.clone(),
        media_type: "application/octet-stream".into(),
    };
    input
}

fn stage(native: &NativeService, context: &AuthenticatedRequestContext) -> OriginalPayloadRef {
    native
        .stage_payload(StagePayloadRequest {
            context: context.clone(),
            block_id: ContentBlockId::new(),
            idempotency_key: "selected-block".into(),
            bytes: vec![43; 256 * 1024 + 17],
        })
        .expect("staged bytes")
        .reference
}

fn remove(native: &NativeService, input: &CaptureRequest) -> NativeRemovalRequestReceipt {
    native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("retained selection")
}

fn finish(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    removal: &NativeRemovalRequestReceipt,
    original: &BackupResponse,
) -> NativeBackupCleanupProgress {
    for _ in 0..32 {
        let progress = native
            .advance_removal_backup(context, removal, original, &mut budget())
            .expect("older archive cleanup");
        if matches!(
            progress.stage,
            NativeBackupCleanupStage::Available | NativeBackupCleanupStage::Unchanged
        ) {
            return progress;
        }
    }
    panic!("fixture did not finish");
}

fn native(root: &Path) -> (tempfile::TempDir, tempfile::TempDir, NativeService) {
    let (key_dir, keys) = crate::encryption::tests::authority("local-removal");
    let (ledger_dir, ledger) = crate::suppression::tests::authority("local-removal");
    let native = NativeService::open_encrypted(root, "local-removal", [7; 32], ledger, keys)
        .expect("native");
    (key_dir, ledger_dir, native)
}

#[test]
fn local_removal_cleans_staged_bytes_before_capture_and_keeps_empty_archives_unchanged() {
    let root = tempfile::tempdir().expect("root");
    let (_keys, _ledger, main) = native(&root.path().join("main"));
    let context = request(1, "").context;
    let empty = archive(&main, &context);
    let payload = stage(&main, &context);
    let before_capture = archive(&main, &context);
    let input = source(1, &payload);
    main.append_event(input.clone())
        .expect("owning capture after old archive");
    let removal = remove(&main, &input);
    let worker = open(&main, &root.path().join("older"));
    restore(&worker, &context, &before_capture);
    let local = worker
        .read_original_removal_local_inventory(&context, &removal, &mut budget())
        .expect("local absence and present bytes");
    assert!(local.sources.is_empty());
    assert_eq!(local.absent_sources, removal.roots);
    assert_eq!(local.payloads, vec![payload.clone()]);
    let ready = finish(&worker, &context, &removal, &before_capture);
    assert_eq!(ready.stage, NativeBackupCleanupStage::Available);
    assert_eq!(
        ready.replacement.as_ref().expect("proof").pruning.sources,
        0
    );
    assert_eq!(
        ready.replacement.as_ref().expect("proof").pruning.payloads,
        1
    );
    let clean = retained(&worker, &context, &removal, &ready);
    drop(worker);
    let worker = open(&main, &root.path().join("older"));
    worker.verify_native(true).expect("cold cleaned replay");
    assert!(
        worker
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("view")
            .scan_prefix(
                &worker.keyspaces.continuous,
                format!("payload/chunk/{}/", payload.block_id).as_bytes()
            )
            .expect("chunks")
            .is_empty()
    );
    let target = open(&main, &root.path().join("clean"));
    restore(&target, &context, &clean);
    target.verify_native(true).expect("clean restore");
    let old_empty = open(&main, &root.path().join("empty"));
    restore(&old_empty, &context, &empty);
    let absent = old_empty
        .read_original_removal_local_inventory(&context, &removal, &mut budget())
        .expect("proved empty prefix");
    assert!(absent.sources.is_empty() && absent.payloads.is_empty());
    assert_eq!(absent.absent_payloads, BTreeSet::from([payload.block_id]));
    assert_eq!(
        finish(&old_empty, &context, &removal, &empty).stage,
        NativeBackupCleanupStage::Unchanged
    );
}

#[test]
fn local_removal_cleans_an_earlier_shared_owner_when_the_selected_root_is_absent() {
    let root = tempfile::tempdir().expect("root");
    let (_keys, _ledger, main) = native(&root.path().join("main"));
    let context = request(1, "").context;
    let payload = stage(&main, &context);
    let earlier = source(1, &payload);
    main.append_event(earlier.clone()).expect("earlier owner");
    let old = archive(&main, &context);
    let selected = source(2, &payload);
    main.append_event(selected.clone()).expect("later root");
    let removal = remove(&main, &selected);
    let worker = open(&main, &root.path().join("worker"));
    restore(&worker, &context, &old);
    let local = worker
        .read_original_removal_local_inventory(&context, &removal, &mut budget())
        .expect("retained co-owner");
    assert_eq!(
        local
            .sources
            .iter()
            .map(|s| s.receipt.event_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([earlier.event.event_id])
    );
    assert_eq!(
        local.absent_sources,
        BTreeSet::from([selected.event.event_id])
    );
    let ready = finish(&worker, &context, &removal, &old);
    assert_eq!(ready.stage, NativeBackupCleanupStage::Available);
    let proof = ready.replacement.as_ref().expect("actual replacement");
    assert_eq!(proof.pruning.sources, 1);
    assert_eq!(proof.pruning.payloads, 1);
    worker
        .verify_native(true)
        .expect("complete replay without either body");
    retained(&worker, &context, &removal, &ready);
}

#[test]
fn local_removal_preserves_globally_shared_novel_bytes_before_the_independent_owner_exists() {
    let root = tempfile::tempdir().expect("root");
    let (_keys, _ledger, main) = native(&root.path().join("main"));
    let mut selected = request(1, "model request");
    selected
        .context
        .capability_grants
        .insert(Capability::Runtime);
    let context = &selected.context;
    let payload = stage(&main, context);
    let model_call_id = ModelCallId::new();
    selected.event.role = EventRole::Host;
    selected.event.kind = EventKind::ModelRequested;
    selected.event.run_id = Some(AgentRunId::new());
    selected.event.session_id = Some(SessionId::new());
    selected.event.provenance = Some(EventProvenance::ModelRequest { model_call_id });
    selected.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id,
            renderer: "fixture/v1".into(),
            wire_digest: payload.digest,
            byte_length: payload.byte_length,
            parts: vec![RequestPart::StoredNovel {
                payload: payload.clone(),
            }],
        },
    };
    main.append_event(selected.clone())
        .expect("selected assembly");
    let old = archive(&main, context);
    main.append_event(source(2, &payload))
        .expect("later independent owner");
    let removal = remove(&main, &selected);
    let worker = open(&main, &root.path().join("worker"));
    restore(&worker, context, &old);
    let local = worker
        .read_original_removal_local_inventory(context, &removal, &mut budget())
        .expect("global ownership preserved");
    assert!(local.payloads.is_empty());
    assert_eq!(local.retained_shared_payloads, vec![payload.clone()]);
    let ready = finish(&worker, context, &removal, &old);
    assert_eq!(ready.stage, NativeBackupCleanupStage::Available);
    assert_eq!(
        ready.replacement.as_ref().expect("proof").pruning.payloads,
        0
    );
    let snapshot = worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let bytes: Vec<_> = snapshot
        .scan_prefix(
            &worker.keyspaces.continuous,
            format!("payload/chunk/{}/", payload.block_id).as_bytes(),
        )
        .expect("independent bytes remain exact")
        .into_iter()
        .flat_map(|entry| entry.value)
        .collect();
    assert_eq!(bytes.len() as u64, payload.byte_length);
    assert_eq!(
        ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
        payload.digest
    );
    worker
        .verify_native(true)
        .expect("pruned request and retained novel bytes replay");
}

#[test]
fn local_removal_absence_rejects_orphan_capture_and_payload_rows() {
    let root = tempfile::tempdir().expect("root");
    let (_keys, _ledger, main) = native(&root.path().join("main"));
    let context = request(1, "").context;
    let empty = archive(&main, &context);
    let payload = stage(&main, &context);
    let selected = source(1, &payload);
    main.append_event(selected.clone()).expect("capture");
    let removal = remove(&main, &selected);
    let original = digest_bytes(selected.event.event_id.to_string().as_bytes()).into_bytes();
    for (name, space, key) in [
        (
            "receipt",
            main.keyspaces.continuous.clone(),
            format!("receipt/{}", selected.event.event_id).into_bytes(),
        ),
        (
            "body",
            main.keyspaces.observations_content.clone(),
            original.clone(),
        ),
        (
            "policy",
            main.keyspaces.observations_policy.clone(),
            original,
        ),
        (
            "payload",
            main.keyspaces.continuous.clone(),
            format!("payload/header/{}", payload.block_id).into_bytes(),
        ),
        (
            "chunk",
            main.keyspaces.continuous.clone(),
            format!("payload/chunk/{}/orphan", payload.block_id).into_bytes(),
        ),
        (
            "payload-pruning",
            main.keyspaces.continuous.clone(),
            format!("payload/pruned/{}", payload.block_id).into_bytes(),
        ),
    ] {
        let worker = open(&main, &root.path().join(name));
        restore(&worker, &context, &empty);
        assert!(
            worker
                .read_original_removal_local_inventory(&context, &removal, &mut budget())
                .is_ok()
        );
        let mut tx = worker.engine.begin_write().expect("inject orphan row");
        tx.put(&space, key, b"orphan".to_vec())
            .expect("injected encrypted row");
        tx.commit(Durability::Sync).expect("fixture corruption");
        let before = worker.engine.head_sequence().expect("head");
        assert!(
            worker
                .read_original_removal_local_inventory(&context, &removal, &mut budget())
                .is_err(),
            "{name} must not become absence"
        );
        assert_eq!(worker.engine.head_sequence().expect("unchanged"), before);
    }
}
