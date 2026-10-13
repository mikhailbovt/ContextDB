use super::*;
use crate::record_sources::tests::{input, publication};
use contextdb_service::{ForgetMode, ForgetRequest};

#[test]
fn archive_cleanup_requires_explicit_origins_and_resumes_after_their_declaration() {
    let root = tempfile::tempdir().expect("root");
    let (_keys_directory, keys) = crate::encryption::tests::authority("cleanup-origins");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("cleanup-origins");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "cleanup-origins",
        [7; 32],
        ledger,
        keys,
    )
    .expect("native");
    let input = input(1, "selected original");
    let context = &input.context;
    native.append_event(input.clone()).expect("capture");
    native
        .publish_memory(publication(context, "unclassified"))
        .expect("unclassified record");
    let old = archive(&native, context);
    let removal = native
        .request_original_removal(
            context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    let worker = open(&native, &root.path().join("cleanup"));
    restore(&worker, context, &old);
    let mut required_origins = false;
    for _ in 0..16 {
        match worker.advance_removal_backup(context, &removal, &old, &mut budget()) {
            Ok(progress) => {
                assert!(!matches!(
                    progress.stage,
                    NativeBackupCleanupStage::Available | NativeBackupCleanupStage::Originals
                ));
            }
            Err(error) => {
                assert_eq!(error.code, ErrorCode::EvidenceRequired);
                required_origins = true;
                break;
            }
        }
    }
    assert!(required_origins, "unknown origins must stop cleanup");
    let before = worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before");
    assert!(
        before
            .get(
                &worker.keyspaces.content_history,
                &history_key(&digest_bytes(b"unclassified"), 1)
            )
            .expect("unclassified body preserved")
            .is_some()
    );
    assert!(
        before
            .get(
                &worker.keyspaces.observations_content,
                digest_bytes(input.event.event_id.to_string().as_bytes()).as_bytes()
            )
            .expect("original preserved")
            .is_some()
    );
    drop(before);
    worker
        .bind_record_sources(context, "unclassified", 1, &removal.roots, &mut budget())
        .expect("explicit administrative classification");
    let (_, ready) = complete(&worker, context, &removal, &old);
    assert_eq!(
        ready.replacement.as_ref().expect("proof").pruning.records,
        1
    );
    retained(&worker, context, &removal, &ready);
}

#[test]
fn archive_cleanup_prepares_whole_legacy_mutation_groups_before_pruning() {
    let root = tempfile::tempdir().expect("root");
    let (_keys_directory, keys) = crate::encryption::tests::authority("cleanup-legacy");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("cleanup-legacy");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "cleanup-legacy",
        [7; 32],
        ledger,
        keys,
    )
    .expect("native");
    let input = input(1, "selected original");
    let context = &input.context;
    native.append_event(input.clone()).expect("capture");
    native
        .publish_memory(publication(context, "legacy"))
        .expect("birth");
    native
        .forget(ForgetRequest {
            context: context.clone(),
            idempotency_key: "retract".into(),
            target_id: "legacy".into(),
            mode: ForgetMode::Retract,
            reason: "requested".into(),
        })
        .expect("closure and copied revision");
    // Synthetic historical encoding, not evidence from an old released binary.
    crate::record_journal::controls::preparation::tests::strip_controls(&native);
    let roots = BTreeSet::from([input.event.event_id]);
    for revision in [1, 2] {
        native
            .bind_record_sources(context, "legacy", revision, &roots, &mut budget())
            .expect("explicit origins");
    }
    let old = archive(&native, context);
    let removal = native
        .request_original_removal(context, &roots, "remove", &mut budget())
        .expect("request");
    let worker = open(&native, &root.path().join("cleanup"));
    restore(&worker, context, &old);
    let (stages, ready) = complete(&worker, context, &removal, &old);
    assert_eq!(
        stages
            .iter()
            .filter(|stage| **stage == NativeBackupCleanupStage::Records)
            .count(),
        4,
        "two whole-group preparations followed by two body prunes"
    );
    assert_eq!(
        ready.replacement.as_ref().expect("proof").pruning.records,
        2
    );
    let clean = retained(&worker, context, &removal, &ready);
    let restored = open(&native, &root.path().join("clean"));
    restore(&restored, context, &clean);
    restored
        .verify_native(true)
        .expect("prepared historical groups remain replayable");
}
