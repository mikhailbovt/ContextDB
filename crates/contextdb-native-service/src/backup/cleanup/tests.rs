use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{budget, fixture};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use std::{path::Path, sync::Arc};

mod payload;
mod records;

fn archive(native: &NativeService, context: &AuthenticatedRequestContext) -> BackupResponse {
    native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("archive")
}

fn open(native: &NativeService, path: &Path) -> NativeService {
    NativeService::open_encrypted(
        path,
        &native.database_id,
        [9; 32],
        native.suppression.as_ref().expect("suppression").clone(),
        native.engine.keys.as_ref().expect("keys").clone(),
    )
    .expect("owner")
}

fn restore(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    archive: &BackupResponse,
) {
    native
        .restore_backup(RestoreBackupRequest {
            context: context.clone(),
            format: archive.format.clone(),
            bytes: archive.bytes.clone(),
            digest: archive.digest.clone(),
        })
        .expect("actual pristine restore");
}

fn complete(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
    original: &BackupResponse,
) -> (Vec<NativeBackupCleanupStage>, NativeBackupCleanupProgress) {
    let mut stages = Vec::new();
    for _ in 0..64 {
        let progress = native
            .advance_removal_backup(context, request, original, &mut budget())
            .expect("cleanup advance");
        stages.push(progress.stage);
        if progress.stage == NativeBackupCleanupStage::Available {
            return (stages, progress);
        }
        assert_ne!(progress.stage, NativeBackupCleanupStage::Unchanged);
    }
    panic!("cleanup did not finish: {stages:?}");
}

fn retained(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
    progress: &NativeBackupCleanupProgress,
) -> BackupResponse {
    assert_eq!(progress.stage, NativeBackupCleanupStage::Available);
    let artifact = progress.artifact.as_ref().expect("stored bytes");
    assert!(artifact.complete);
    native
        .read_retained_removal_backup(
            context,
            request,
            &progress.replacement.as_ref().expect("replacement").receipt,
            &artifact.receipt,
            &mut budget(),
        )
        .expect("complete verified readback")
}

#[test]
fn archive_cleanup_restores_a_divergent_branch_and_resumes_without_changing_main() {
    let f = fixture();
    let context = &f.input.context;
    let base = archive(&f.native, context);
    let fork = open(&f.native, &f.root.path().join("fork"));
    restore(&fork, context, &base);
    let independent = request(3, "independent archive branch original");
    fork.append_event(independent.clone())
        .expect("archive branch");
    let old = archive(&fork, context);
    drop(fork);
    f.native
        .append_event(request(3, "different current main branch"))
        .expect("main diverges");
    f.native
        .append_event(request(4, "a higher sequence is insufficient"))
        .expect("later main");
    let main = f.native.verify_native(true).expect("main before");
    assert!(
        f.native
            .advance_removal_backup(context, &f.removal, &old, &mut budget())
            .is_err()
    );
    assert_eq!(
        f.native
            .verify_native(true)
            .expect("unchanged main")
            .archive_digest,
        main.archive_digest
    );

    let path = f.root.path().join("cleanup");
    let mut worker = open(&f.native, &path);
    restore(&worker, context, &old);
    let mut stages = Vec::new();
    let ready = loop {
        assert!(stages.len() < 32, "bounded fixture progress");
        let step = worker
            .advance_removal_backup(context, &f.removal, &old, &mut budget())
            .expect("advance");
        stages.push(step.stage);
        drop(worker);
        worker = open(&f.native, &path);
        worker
            .verify_native(true)
            .expect("cold replay after every accepted step");
        if step.stage == NativeBackupCleanupStage::Available {
            break step;
        }
        assert_ne!(step.stage, NativeBackupCleanupStage::Unchanged);
    };
    assert!(stages.contains(&NativeBackupCleanupStage::SourceControls));
    assert!(stages.contains(&NativeBackupCleanupStage::Custody));
    assert!(stages.contains(&NativeBackupCleanupStage::Originals));
    assert_eq!(
        worker
            .advance_removal_backup(context, &f.removal, &old, &mut budget())
            .expect("exact retry"),
        ready
    );
    let clean = retained(&worker, context, &f.removal, &ready);
    let restored = open(&f.native, &f.root.path().join("clean"));
    restore(&restored, context, &clean);
    restored
        .verify_native(true)
        .expect("complete native replay");
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        snapshot
            .get(
                &restored.keyspaces.observations_content,
                digest_bytes(f.input.event.event_id.to_string().as_bytes()).as_bytes()
            )
            .expect("selected")
            .is_none()
    );
    assert!(
        snapshot
            .get(
                &restored.keyspaces.observations_content,
                digest_bytes(independent.event.event_id.to_string().as_bytes()).as_bytes()
            )
            .expect("independent")
            .is_some()
    );
    let unchanged = restored
        .advance_removal_backup(context, &f.removal, &clean, &mut budget())
        .expect("already clean");
    assert_eq!(unchanged.stage, NativeBackupCleanupStage::Unchanged);
    assert!(unchanged.replacement.is_none() && unchanged.artifact.is_none());
    assert_eq!(
        f.native
            .verify_native(true)
            .expect("main after")
            .archive_digest,
        main.archive_digest
    );
}

#[test]
fn archive_cleanup_discovers_closed_revisions_and_candidate_graph_bodies() {
    let (_directory, keys) = crate::encryption::tests::authority("record-witness");
    let f = crate::record_journal::controls::witness::tests::fixture_with_keys(Some(keys));
    let old = archive(&f.service, &f.context);
    let worker = open(&f.service, &f.root.path().join("cleanup"));
    restore(&worker, &f.context, &old);
    let independent_key = history_key(&digest_bytes(b"independent-record"), 1);
    let before = worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before");
    let independent = before
        .get(&worker.keyspaces.content_history, &independent_key)
        .expect("independent")
        .expect("body");
    drop(before);
    let (stages, ready) = complete(&worker, &f.context, &f.removal, &old);
    assert!(stages.contains(&NativeBackupCleanupStage::Records));
    assert_eq!(
        ready.replacement.as_ref().expect("proof").pruning.records,
        5
    );
    let clean = retained(&worker, &f.context, &f.removal, &ready);
    let restored = open(&f.service, &f.root.path().join("clean"));
    restore(&restored, &f.context, &clean);
    restored
        .verify_native(true)
        .expect("time and graph semantics survive cleanup");
    let after = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after");
    assert_eq!(
        after
            .get(&restored.keyspaces.content_history, &independent_key)
            .expect("independent preserved"),
        Some(independent)
    );
    for (id, revision) in [
        ("private-record", 1),
        ("private-record", 2),
        ("PRIVATE-PARENT", 1),
        ("PRIVATE-CHILD", 1),
    ] {
        assert!(
            after
                .get(
                    &restored.keyspaces.content_history,
                    &history_key(&digest_bytes(id.as_bytes()), revision)
                )
                .expect("selected revision")
                .is_none()
        );
    }
}

#[test]
fn archive_cleanup_discovers_selected_assertions_and_preserves_mixed_mutations() {
    let f = crate::assertions::retention::witness::tests::fixture();
    let context = &f.first.context;
    let old = archive(&f.native, context);
    let worker = open(&f.native, &f.root.path().join("cleanup"));
    restore(&worker, context, &old);
    let (stages, ready) = complete(&worker, context, &f.removal, &old);
    assert!(stages.contains(&NativeBackupCleanupStage::Assertions));
    assert_eq!(
        ready
            .replacement
            .as_ref()
            .expect("proof")
            .pruning
            .assertions,
        1
    );
    let clean = retained(&worker, context, &f.removal, &ready);
    let restored = open(&f.native, &f.root.path().join("clean"));
    restore(&restored, context, &clean);
    restored
        .verify_native(true)
        .expect("full mixed semantic history");
    let values = restored
        .read_assertion_key_inventory(context, &f.witness, &mut budget())
        .expect("preservation evidence")
        .value_ownership
        .expect("classified versions");
    assert!(values.addresses.values().flatten().any(|entry| matches!(
        &entry.disposition, crate::NativeAssertionValueDisposition::PreserveIndependent { mutations }
            if mutations == &BTreeSet::from([0, 2, 3])
    )));
}

#[test]
fn archive_cleanup_checks_authority_and_budget_before_mutation() {
    let f = fixture();
    let old = archive(&f.native, &f.input.context);
    let before = f.native.verify_native(true).expect("before");
    let mut malformed = old.clone();
    malformed.bytes.clear();
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .advance_removal_backup(&denied, &f.removal, &malformed, &mut budget())
            .expect_err("admin before archive bytes")
            .code,
        ErrorCode::Unauthorized
    );
    let mut foreign = f.input.context.clone();
    foreign.request.workspace_id = "foreign-workspace".into();
    assert!(
        f.native
            .advance_removal_backup(&foreign, &f.removal, &old, &mut budget())
            .is_err()
    );
    let mut wrong = f.removal.clone();
    wrong.digest = "ab".repeat(32);
    assert!(
        f.native
            .advance_removal_backup(&f.input.context, &wrong, &old, &mut budget())
            .is_err()
    );
    assert!(
        f.native
            .advance_removal_backup(&f.input.context, &f.removal, &malformed, &mut budget())
            .is_err()
    );
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .advance_removal_backup(&f.input.context, &f.removal, &old, &mut empty)
            .expect_err("bounded before mutation")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        f.native.verify_native(true).expect("after").archive_digest,
        before.archive_digest
    );
}

#[test]
fn archive_cleanup_rejects_an_unretained_descendant_before_preparing_sources() {
    let root = tempfile::tempdir().expect("root");
    let (_keys_directory, keys) = crate::encryption::tests::authority("cleanup-lineage");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("cleanup-lineage");
    let main = NativeService::open_encrypted(
        root.path().join("native"),
        "cleanup-lineage",
        [7; 32],
        ledger,
        keys,
    )
    .expect("native");
    let input = request(1, "selected original");
    main.append_event(input.clone()).expect("source");
    let base = archive(&main, &input.context);
    let fork = open(&main, &root.path().join("fork"));
    restore(&fork, &input.context, &base);
    let mut revision = request(2, "an archived edit absent from current main");
    revision.event.kind = contextdb_core::EventKind::MessageEdited;
    revision.event.supersedes_event_id = Some(input.event.event_id);
    fork.append_event(revision)
        .expect("capture descendant before removal");
    let old = archive(&fork, &input.context);
    let removal = main
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("main request has no archived descendant");
    let before = fork.verify_native(true).expect("before");
    assert_eq!(
        fork.advance_removal_backup(&input.context, &removal, &old, &mut budget())
            .expect_err("requires expanded retained authority")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert_eq!(
        fork.verify_native(true).expect("unchanged").archive_digest,
        before.archive_digest
    );
}

#[test]
fn archive_cleanup_rechecks_the_native_head_before_publishing_availability() {
    let f = fixture();
    let old = archive(&f.native, &f.input.context);
    loop {
        let progress = f
            .native
            .advance_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
            .expect("advance");
        if progress.stage == NativeBackupCleanupStage::Originals {
            break;
        }
        assert_ne!(progress.stage, NativeBackupCleanupStage::Available);
    }
    let key_head = f
        .keys
        .backup_catalog_page(0, None, 256)
        .expect("catalog")
        .revision;
    let native = Arc::clone(&f.native);
    BEFORE_COMPLETION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            native
                .append_event(request(3, "concurrent native publication"))
                .expect("racing write");
        }))
    });
    assert_eq!(
        f.native
            .advance_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
            .expect_err("revalidate changed native head")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("unchanged catalog")
            .revision,
        key_head
    );
    let (_, ready) = complete(&f.native, &f.input.context, &f.removal, &old);
    retained(&f.native, &f.input.context, &f.removal, &ready);
}
