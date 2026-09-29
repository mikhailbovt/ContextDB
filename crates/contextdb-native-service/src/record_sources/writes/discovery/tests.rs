use std::time::Duration;

use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, CognitiveMemoryService, OwnedRunPort};

use super::*;
use crate::record_sources::tests::{budget, catch_up, get, input, publication};

mod runtime;

fn pending_write(
    service: &NativeService,
    context: &AuthenticatedRequestContext,
    source: ObservationId,
    id: &str,
) -> StoredEvent {
    let cancellation = QueryCancellation::default();
    let token = cancellation.clone();
    AFTER_NATIVE_SYNC.with(|slot| slot.replace(Some(Box::new(move || token.cancel()))));
    let mut interrupted = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    service
        .publish_memory_from_sources(
            publication(context, id),
            &BTreeSet::from([source]),
            &mut interrupted,
        )
        .expect_err("stop after native acceptance");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    snapshot
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("events")
        .into_iter()
        .map(|row| decode::<StoredEvent>(&row.value, "event").expect("event"))
        .rfind(|event| event.operation == PUBLISH)
        .expect("accepted record")
}

#[test]
fn archive_cleanup_finishes_an_interrupted_record_origin_transfer_before_pruning() {
    use contextdb_service::{CreateBackupRequest, RestoreBackupRequest};
    let root = tempfile::tempdir().expect("root");
    let (_keys_directory, keys) = encryption::tests::authority("cleanup-pending");
    let (_ledger_directory, ledger) = suppression::tests::authority("cleanup-pending");
    let service = NativeService::open_encrypted(
        root.path().join("native"),
        "cleanup-pending",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let source = input(1, "selected source");
    let context = &source.context;
    service.append_event(source.clone()).expect("capture");
    pending_write(&service, context, source.event.event_id, "pending");
    let old = service
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("archive with pending transfer");
    let removal = service
        .request_original_removal(
            context,
            &BTreeSet::from([source.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("removal");
    let worker = NativeService::open_encrypted(
        root.path().join("cleanup"),
        "cleanup-pending",
        [9; 32],
        ledger,
        keys,
    )
    .expect("separate owner");
    worker
        .restore_backup(RestoreBackupRequest {
            context: context.clone(),
            format: old.format.clone(),
            bytes: old.bytes.clone(),
            digest: old.digest.clone(),
        })
        .expect("actual restore");
    assert_eq!(
        worker
            .advance_removal_backup(context, &removal, &old, &mut budget())
            .expect("repair first")
            .stage,
        NativeBackupCleanupStage::RecordOrigins
    );
    assert!(
        worker
            .pending_record_source_writes(context, None, 256, &mut budget())
            .expect("no pending origin")
            .pending
            .is_empty()
    );
    let mut ready = None;
    for _ in 0..16 {
        let progress = worker
            .advance_removal_backup(context, &removal, &old, &mut budget())
            .expect("continue cleanup");
        if progress.stage == NativeBackupCleanupStage::Available {
            ready = Some(progress);
            break;
        }
    }
    let ready = ready.expect("available replacement");
    assert_eq!(ready.replacement.expect("proof").pruning.records, 1);
    assert!(ready.artifact.expect("bytes").complete);
    worker
        .verify_native(true)
        .expect("origin completion and pruning remain replayable");
}

#[test]
fn paged_discovery_and_repair_follow_the_workspace_journal_across_appends() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("record-discovery");
    let service =
        NativeService::open_with_suppression(root.path(), "record-discovery", [7; 32], ledger)
            .expect("native");
    let source = input(1, "source");
    service.append_event(source.clone()).expect("capture");
    let pending = pending_write(&service, &source.context, source.event.event_id, "pending");
    let mut first = service
        .pending_record_source_writes(&source.context, None, 1, &mut budget())
        .expect("first page");
    let frontier = first.scan_head;
    service
        .append_event(input(2, "new history while old frontier is scanned"))
        .expect("capture");
    let mut other = input(1, "different workspace");
    other.event.event_id = ObservationId::new();
    other.event.producer_id = contextdb_core::StreamId::new();
    other.event.workspace_id = contextdb_core::WorkspaceId::new();
    other.context.request.workspace_id = other.event.workspace_id.to_string();
    service.append_event(other).expect("interleaved workspace");
    let mut found = first.pending.clone();
    while !first.caught_up {
        first = service
            .pending_record_source_writes(
                &source.context,
                Some(&first.continuation),
                1,
                &mut budget(),
            )
            .expect("next page");
        assert_eq!(first.scan_head, frontier);
        assert_eq!(first.scanned, 1);
        found.extend(&first.pending);
    }
    assert_eq!(found, [pending.workspace_commit]);
    assert_eq!(
        get(&service, &source.context, "pending")
            .expect_err("discovery is read-only")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        service
            .repair_record_source_writes(
                &source.context,
                Some(&first.continuation),
                1,
                &mut budget()
            )
            .expect_err("discovery cannot mint repair progress")
            .code,
        ErrorCode::InvalidContinuation
    );
    let mut cursor = None;
    let mut repaired = Vec::new();
    loop {
        let page = service
            .repair_record_source_writes(&source.context, cursor.as_deref(), 1, &mut budget())
            .expect("repair page");
        repaired.extend(page.completed);
        cursor = Some(page.continuation);
        if page.caught_up {
            break;
        }
    }
    assert_eq!(repaired.len(), 1);
    assert_eq!(repaired[0].commit_seq, pending.workspace_commit);
    get(&service, &source.context, "pending")
        .expect("recovery needs no request or commit from caller");
    let incremental = service
        .repair_record_source_writes(&source.context, cursor.as_deref(), 256, &mut budget())
        .expect("new frontier");
    assert!(incremental.caught_up);
    assert!(incremental.completed.is_empty());
    assert!(incremental.scan_head > frontier);
    service
        .verify_native(true)
        .expect("journal and completion closure");
}

#[test]
fn cursor_is_bound_to_authority_database_mode_and_the_restored_history() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("discovery-restore");
    let (_key_root, keys) = encryption::tests::authority("discovery-restore");
    let service = NativeService::open_encrypted(
        root.path().join("native"),
        "discovery-restore",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let source = input(1, "source");
    service.append_event(source.clone()).expect("capture");
    let old = service
        .create_backup(CreateBackupRequest {
            context: source.context.clone(),
        })
        .expect("older archive");
    pending_write(&service, &source.context, source.event.event_id, "pending");
    let page = service
        .pending_record_source_writes(&source.context, None, 1, &mut budget())
        .expect("page");
    for changed in ["subject", "workspace", "scope", "session", "purpose"] {
        let mut context = source.context.clone();
        match changed {
            "subject" => context.request.subject_id.push('x'),
            "workspace" => context.request.workspace_id.push('x'),
            "scope" => {
                context.request.scopes.insert("different".into());
            }
            "session" => context.session_id = Some("different".into()),
            _ => context.request.purpose.push('x'),
        }
        assert_eq!(
            service
                .pending_record_source_writes(&context, Some(&page.continuation), 1, &mut budget())
                .expect_err("cursor authority")
                .code,
            ErrorCode::InvalidContinuation
        );
    }
    let other = NativeService::open(root.path().join("other"), "other-database", [7; 32])
        .expect("same key, different database");
    assert_eq!(
        other
            .pending_record_source_writes(
                &source.context,
                Some(&page.continuation),
                1,
                &mut budget()
            )
            .expect_err("database binding")
            .code,
        ErrorCode::InvalidContinuation
    );
    let restored = NativeService::open_encrypted(
        root.path().join("restored"),
        "discovery-restore",
        [7; 32],
        ledger,
        keys,
    )
    .expect("restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: source.context.clone(),
            format: old.format,
            bytes: old.bytes,
            digest: old.digest,
        })
        .expect("old restore");
    assert_eq!(
        restored
            .pending_record_source_writes(
                &source.context,
                Some(&page.continuation),
                1,
                &mut budget()
            )
            .expect_err("newer cursor cannot skip an older restore")
            .code,
        ErrorCode::SnapshotExpired
    );
    let restarted = restored
        .pending_record_source_writes(&source.context, None, 256, &mut budget())
        .expect("new enumeration");
    assert!(restarted.pending.is_empty());
    assert!(restarted.caught_up);
}

#[test]
fn absent_workspace_maps_or_receipts_never_turn_into_an_empty_recovery_page() {
    for missing in ["mapping", "head", "receipt", "intent", "event"] {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("discovery-missing");
        let service =
            NativeService::open_with_suppression(root.path(), "discovery-missing", [7; 32], ledger)
                .expect("native");
        let source = input(1, "source");
        service.append_event(source.clone()).expect("capture");
        let event = pending_write(&service, &source.context, source.event.event_id, "pending");
        let mut tx = service.engine.begin_write().expect("transaction");
        let key = authenticated_idempotency_key(PUBLISH, &source.context, "publish-pending")
            .expect("key");
        let (keyspace, key) = match missing {
            "mapping" => (
                &service.keyspaces.workspace_map,
                workspace_map_key(&event.workspace_digest, 1),
            ),
            "head" => (
                &service.keyspaces.workspace,
                event.workspace_digest.as_bytes().to_vec(),
            ),
            "receipt" => (&service.keyspaces.idempotency, key),
            "intent" => (
                &service.keyspaces.continuous,
                intent_key(event.global_commit),
            ),
            _ => (
                &service.keyspaces.events,
                event.global_commit.to_be_bytes().to_vec(),
            ),
        };
        tx.delete(keyspace, key).expect("missing control fixture");
        tx.commit(Durability::Sync).expect("commit");
        assert_eq!(
            service
                .pending_record_source_writes(&source.context, None, 256, &mut budget())
                .expect_err("corruption must not hide pending work")
                .code,
            ErrorCode::IntegrityFailure
        );
    }
}

#[test]
fn a_lost_completion_locator_cannot_cause_a_second_accepted_completion() {
    for missing in ["locator", "locator-and-declaration", "locator-and-binding"] {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("completion-locator");
        let service = NativeService::open_with_suppression(
            root.path(),
            "completion-locator",
            [7; 32],
            ledger,
        )
        .expect("native");
        let source = input(1, "source");
        service.append_event(source.clone()).expect("capture");
        let response = service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &BTreeSet::from([source.event.event_id]),
                &mut budget(),
            )
            .expect("complete record");
        let mut tx = service.engine.begin_write().expect("transaction");
        let (_, event) = service
            .recovery_event(
                &tx,
                &digest_bytes(source.context.request.workspace_id.as_bytes()),
                response.commit_seq,
                &mut budget(),
            )
            .expect("accepted write");
        let before = service.global_head(&tx).expect("head");
        if missing != "locator" {
            let mut completion = service
                .record_write_completion(&tx, &event)
                .expect("completion locator")
                .expect("completed event");
            if missing == "locator-and-declaration" {
                completion.accepted_record_write_completion = None;
            } else {
                completion
                    .accepted_record_write_completion
                    .as_mut()
                    .expect("declaration")
                    .write_global_commit = 1;
            }
            completion.event_digest = event_digest(&completion).expect("rehashed fixture");
            tx.put(
                &service.keyspaces.events,
                completion.global_commit.to_be_bytes().to_vec(),
                encode(&completion).expect("damaged completion"),
            )
            .expect("lose journal declaration");
        }
        tx.delete(
            &service.keyspaces.continuous,
            completion_key(event.global_commit),
        )
        .expect("lose locator only");
        tx.commit(Durability::Sync).expect("commit");
        assert_eq!(
            service
                .resume_record_source_write(&source.context, response.commit_seq, &mut budget())
                .expect_err("later accepted completion must be found")
                .code,
            ErrorCode::IntegrityFailure
        );
        assert_eq!(
            service
                .repair_record_source_writes(&source.context, None, 256, &mut budget())
                .expect_err("paged repair also refuses corrupt completion")
                .code,
            ErrorCode::IntegrityFailure
        );
        let snapshot = service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(service.global_head(&snapshot).expect("head"), before);
    }
}

#[test]
fn budgets_and_cancellation_stop_before_decoding_control_bodies_or_advancing_repair() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("discovery-budget");
    let service =
        NativeService::open_with_suppression(root.path(), "discovery-budget", [7; 32], ledger)
            .expect("native");
    let source = input(1, "source");
    service.append_event(source.clone()).expect("capture");
    let event = pending_write(&service, &source.context, source.event.event_id, "pending");
    let mut tx = service.engine.begin_write().expect("transaction");
    let key = intent_key(event.global_commit);
    tx.put(&service.keyspaces.continuous, key, vec![b'x'; 1024 * 1024])
        .expect("large malformed metadata");
    tx.commit(Durability::Sync).expect("commit");
    let mut limited = QueryBudget::new(
        10_000,
        64 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    );
    assert_eq!(
        service
            .pending_record_source_writes(&source.context, None, 256, &mut limited)
            .expect_err("bytes charged before decode")
            .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    assert_eq!(
        service
            .repair_record_source_writes(&source.context, None, 1, &mut cancelled)
            .expect_err("cancelled before discovery")
            .code,
        ErrorCode::BudgetExhausted
    );
    let mut no_admin = source.context.clone();
    no_admin.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        service
            .pending_record_source_writes(&no_admin, None, 256, &mut budget())
            .expect_err("no administrative recovery grant")
            .code,
        ErrorCode::Unauthorized
    );
}

#[test]
fn owned_host_automatically_repairs_and_keeps_partial_scan_progress_between_budgets() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("automatic-record-recovery");
    let path = root.path().join("native");
    let service = NativeService::open_with_suppression(
        &path,
        "automatic-record-recovery",
        [7; 32],
        ledger.clone(),
    )
    .expect("native");
    let source = input(1, "source");
    service.append_event(source.clone()).expect("capture");
    service
        .initialize_record_sources(&source.context, &mut budget())
        .expect("activate");
    catch_up(&service, &source.context);
    for ordinal in 2..=150 {
        service
            .append_event(input(ordinal, "intervening capture"))
            .expect("capture");
    }
    pending_write(&service, &source.context, source.event.event_id, "pending");
    let mut context = source.context.clone();
    context.capability_grants.insert(Capability::Runtime);
    let mut small = QueryBudget::new(
        160,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    );
    service
        .recover_record_writes(&context, &mut small)
        .expect_err("stop between bounded pages");
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    assert_eq!(
        service.record_write_recovery.lock().expect("cache").0[&workspace]
            .after
            .commit,
        64
    );
    assert_eq!(
        get(&service, &context, "pending")
            .expect_err("unvisited group remains closed")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .recover_record_writes(&context, &mut budget())
        .expect("automatic continuation");
    get(&service, &context, "pending").expect("group recovered without individual request");
    let mut small = QueryBudget::new(
        80,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    );
    service
        .recover_record_writes(&context, &mut small)
        .expect("incremental completed prefix");
    service.verify_native(true).expect("repaired state");
    drop(service);
    let reopened =
        NativeService::open_with_suppression(path, "automatic-record-recovery", [7; 32], ledger)
            .expect("reopen");
    assert!(
        reopened
            .record_write_recovery
            .lock()
            .expect("cache")
            .0
            .is_empty()
    );
    reopened
        .recover_record_writes(&context, &mut budget())
        .expect("reopen rechecks authoritative history");
    get(&reopened, &context, "pending").expect("still available");
}
