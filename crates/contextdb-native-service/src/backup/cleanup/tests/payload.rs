use super::*;
use contextdb_core::{ContentBlockId, EventPayload};
use contextdb_service::{PayloadPort, StagePayloadRequest};

#[test]
fn archive_cleanup_reclaims_indexes_resumes_chunks_and_retains_a_multipage_replacement() {
    let root = tempfile::tempdir().expect("root");
    let (_key_directory, keys) = crate::encryption::tests::authority("cleanup-payload");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("cleanup-payload");
    let main = NativeService::open_encrypted(
        root.path().join("native"),
        "cleanup-payload",
        [7; 32],
        ledger,
        keys,
    )
    .expect("native");
    let selected = request(1, "selected searchable original");
    let context = &selected.context;
    main.append_event(selected.clone())
        .expect("inline selected");
    let mut blocks = Vec::new();
    for (sequence, size, byte) in [(2, 256 * 1024 + 17, 41), (3, 700 * 1024 + 17, 43)] {
        let mut input = request(sequence, "staged original");
        let payload = main
            .stage_payload(StagePayloadRequest {
                context: context.clone(),
                idempotency_key: format!("payload-{sequence}"),
                block_id: ContentBlockId::new(),
                bytes: vec![byte; size],
            })
            .expect("stage")
            .reference;
        input.event.payload = EventPayload::Staged {
            reference: payload.clone(),
            media_type: "application/octet-stream".into(),
        };
        main.append_event(input.clone())
            .expect("capture staged bytes before removal");
        blocks.push((input.event.event_id, payload));
    }
    main.append_event(request(4, "independent searchable original"))
        .expect("independent inline");
    while !main
        .maintain_custody(context, 256, &mut budget())
        .expect("custody")
        .caught_up
    {}
    assert!(
        main.project_originals(context, true, 256, &mut budget())
            .expect("initial index")
            .caught_up
    );
    assert!(
        !main
            .project_originals(context, true, 1, &mut budget())
            .expect("unfinished old generation")
            .caught_up
    );
    let old = archive(&main, context);
    let removal = main
        .request_original_removal(
            context,
            &BTreeSet::from([selected.event.event_id, blocks[0].0]),
            "cleanup-payload",
            &mut budget(),
        )
        .expect("retained request");
    let main_digest = main.verify_native(true).expect("main").archive_digest;
    let path = root.path().join("cleanup");
    let mut worker = open(&main, &path);
    restore(&worker, context, &old);
    let mut stages = Vec::new();
    let mut partial_artifact = None;
    let ready = loop {
        assert!(
            stages.len() < 48,
            "finite bounded fixture progress: {stages:?}"
        );
        let step = worker
            .advance_removal_backup(context, &removal, &old, &mut budget())
            .expect("advance");
        stages.push(step.stage);
        if step.stage == NativeBackupCleanupStage::Available {
            break step;
        }
        if step.stage == NativeBackupCleanupStage::Originals {
            // Seed an accepted partial operation, then let discovery resume it
            // after reopening. Batch-size boundaries have their own owner tests.
            let prefix = worker
                .prune_original_payload(context, &removal, blocks[0].1.block_id, 1, &mut budget())
                .expect("partial chunk cleanup");
            assert!(!prefix.complete);
            let snapshot = worker
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("partial chunks");
            let prefix = format!("payload/chunk/{}/", blocks[0].1.block_id);
            assert_eq!(
                snapshot
                    .scan_prefix(&worker.keyspaces.continuous, prefix.as_bytes())
                    .expect("remaining chunks")
                    .len(),
                1
            );
        }
        if step.stage == NativeBackupCleanupStage::Payload {
            let replacement = worker
                .create_removal_backup(context, &removal, &old, &mut budget())
                .expect("verified replacement");
            let prefix = worker
                .retain_removal_backup(context, &removal, &replacement, 0, 1, &mut budget())
                .expect("partial artifact");
            assert!(!prefix.complete);
            partial_artifact = Some((replacement.replacement, prefix));
        }
        if matches!(
            step.stage,
            NativeBackupCleanupStage::Originals | NativeBackupCleanupStage::Payload
        ) {
            drop(worker);
            worker = open(&main, &path);
        }
    };
    assert!(
        stages
            .iter()
            .filter(|stage| **stage == NativeBackupCleanupStage::RawIndex)
            .count()
            >= 3,
        "reclaim stale build, replace active, reclaim obsolete generation: {stages:?}"
    );
    assert_eq!(
        stages
            .iter()
            .filter(|stage| **stage == NativeBackupCleanupStage::Payload)
            .count(),
        1
    );
    let (replacement, partial) = partial_artifact.expect("recovered artifact prefix");
    assert_eq!(ready.replacement.as_ref(), Some(&replacement));
    assert_eq!(replacement.pruning.payloads, 2);
    assert!(
        ready
            .artifact
            .as_ref()
            .expect("complete bytes")
            .stored_pages
            > partial.stored_pages
    );
    let clean = worker
        .read_retained_removal_backup(
            context,
            &removal,
            &ready.replacement.as_ref().expect("proof").receipt,
            &ready.artifact.as_ref().expect("bytes").receipt,
            &mut budget(),
        )
        .expect("complete readback");
    let restored = open(&main, &root.path().join("clean"));
    restore(&restored, context, &clean);
    restored.verify_native(true).expect("full clean restore");
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let prefix = format!("payload/chunk/{}/", blocks[0].1.block_id);
    assert!(
        snapshot
            .scan_prefix(&restored.keyspaces.continuous, prefix.as_bytes())
            .expect("selected chunks removed")
            .is_empty()
    );
    let prefix = format!("payload/chunk/{}/", blocks[1].1.block_id);
    let independent = snapshot
        .scan_prefix(&restored.keyspaces.continuous, prefix.as_bytes())
        .expect("independent chunks");
    assert_eq!(
        independent.iter().map(|row| row.value.len()).sum::<usize>(),
        700 * 1024 + 17
    );
    assert!(
        independent
            .iter()
            .all(|row| row.value.iter().all(|byte| *byte == 43))
    );
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let state: crate::raw_index::IndexState = restored
        .raw_value(&snapshot, &crate::raw_index::state_key(&workspace))
        .expect("index state")
        .expect("index");
    assert!(state.building.is_none() && state.reclaiming.is_none());
    assert_eq!(
        crate::raw_index::retained_generations(&state)
            .expect("generations")
            .len(),
        1
    );
    let generation = state.active.expect("clean active index");
    for id in removal.roots.iter() {
        assert!(
            snapshot
                .get(
                    &restored.keyspaces.continuous,
                    &crate::raw_index::doc_key(&workspace, generation, *id)
                )
                .expect("selected index body")
                .is_none()
        );
    }
    assert!(
        snapshot
            .get(
                &restored.keyspaces.continuous,
                &crate::raw_index::doc_key(
                    &workspace,
                    generation,
                    request(4, "independent searchable original").event.event_id
                )
            )
            .expect("independent index body")
            .is_some()
    );
    assert_eq!(
        main.verify_native(true)
            .expect("main unchanged")
            .archive_digest,
        main_digest
    );
}
