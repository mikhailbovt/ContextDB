//! Restore, crash-window and authority-identity regressions.

use super::*;
use contextdb_core::RawFilter;
use contextdb_recall::{IndexedQuery, IndexedRecallProvider, IndexedSelection, QueryCancellation};
use contextdb_service::{
    CapturePort, CaptureRequest, RawRecallBudget, RawRecallPort, RawRecallRequest,
    ReadOriginalRequest,
};
use std::{process::Command, sync::Arc, time::Duration};

pub(crate) fn authority(database: &str) -> (tempfile::TempDir, Arc<NativeSuppressionLedger>) {
    let directory = tempfile::tempdir().expect("external authority directory");
    let ledger = NativeSuppressionLedger::create(directory.path().join("ledger"), database)
        .expect("new external authority");
    (directory, ledger)
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn read(
    service: &NativeService,
    input: &CaptureRequest,
) -> ServiceResult<contextdb_service::CapturedOriginal> {
    service.read_original(ReadOriginalRequest {
        context: input.context.clone(),
        event_id: input.event.event_id,
        after_receipt: None,
    })
}

fn restore(
    service: &NativeService,
    input: &CaptureRequest,
    archive: &BackupResponse,
) -> ServiceResult<RestoreBackupResponse> {
    service.restore_backup(RestoreBackupRequest {
        context: input.context.clone(),
        format: archive.format.clone(),
        bytes: archive.bytes.clone(),
        digest: archive.digest.clone(),
    })
}

fn catch_up(service: &NativeService, input: &CaptureRequest) {
    while !service
        .maintain_custody(&input.context, 2, &mut budget())
        .expect("propagate custody")
        .caught_up
    {}
    let mut rebuild = true;
    while !service
        .project_originals(&input.context, rebuild, 2, &mut budget())
        .expect("current index")
        .caught_up
    {
        rebuild = false;
    }
}

#[test]
fn old_backup_cannot_revive_newer_denials_or_recapture_an_absent_suppressed_id() {
    let root = tempfile::tempdir().expect("native directories");
    let (_authority_directory, ledger) = authority("suppression-db");
    let (_key_directory, keys) = encryption::tests::authority("suppression-db");
    let service = NativeService::open_encrypted(
        root.path().join("source"),
        "suppression-db",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("source");
    let secret = capture::tests::request(1, "original_secret_7319");
    let mut derived = capture::tests::request(2, "derived_secret_7319");
    derived.event.supersedes_event_id = Some(secret.event.event_id);
    let independent = capture::tests::request(3, "unrelated_original");
    for input in [&secret, &derived, &independent] {
        service.append_event(input.clone()).expect("capture");
    }
    catch_up(&service, &secret);
    let archive = service
        .create_backup(CreateBackupRequest {
            context: secret.context.clone(),
        })
        .expect("backup before either denial");
    let absent = capture::tests::request(4, "post_backup_secret");
    service
        .append_event(absent.clone())
        .expect("later original");
    for input in [&secret, &absent] {
        service
            .revoke_original(
                &input.context,
                input.event.event_id,
                &format!("deny-{}", input.event.event_id),
                &mut budget(),
            )
            .expect("durable external denial");
    }
    let target_path = root.path().join("restored");
    let restored = NativeService::open_encrypted(
        &target_path,
        "suppression-db",
        [9; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("target with current authority");
    restore(&restored, &secret, &archive).expect("install old backup behind disclosure barrier");
    for input in [&secret, &derived, &independent] {
        assert_eq!(
            read(&restored, input)
                .expect_err("no early disclosure")
                .code,
            ErrorCode::IndexTooStale
        );
    }
    restored
        .verify_native(true)
        .expect("pending restore is internally consistent");
    drop(restored);
    let restored = NativeService::open_encrypted(
        &target_path,
        "suppression-db",
        [10; 32],
        ledger.clone(),
        keys,
    )
    .expect("pending gate survives restart");
    assert_eq!(
        read(&restored, &derived)
            .expect_err("restart cannot clear gate")
            .code,
        ErrorCode::IndexTooStale
    );
    let first = restored
        .maintain_suppression(&secret.context, 1, &mut budget())
        .expect("first bounded pass");
    assert_eq!(
        (first.processed, first.through, first.caught_up),
        (1, 1, false)
    );
    assert_eq!(
        read(&restored, &independent)
            .expect_err("partial prefix is not admission")
            .code,
        ErrorCode::IndexTooStale
    );
    let last = restored
        .maintain_suppression(&secret.context, 1, &mut budget())
        .expect("absent source denial");
    assert_eq!((last.processed, last.through, last.caught_up), (1, 2, true));
    assert_eq!(
        restored
            .append_event(absent)
            .expect_err("suppressed ID cannot be recaptured")
            .code,
        ErrorCode::PermissionDenied
    );
    catch_up(&restored, &secret);
    for input in [&secret, &derived] {
        assert_eq!(
            read(&restored, input)
                .expect_err("current inherited denial")
                .code,
            ErrorCode::PermissionDenied
        );
    }
    assert_eq!(
        read(&restored, &independent)
            .expect("unrelated source remains usable")
            .event,
        independent.event
    );
    let historical = restored
        .recall_originals(RawRecallRequest {
            context: secret.context.clone(),
            filter: RawFilter::default(),
            text: None,
            known_at: Some(archive.commit_seq),
            after_receipt: None,
            page_size: 32,
            budget: RawRecallBudget::default(),
            continuation: None,
        })
        .expect("historical index under current permissions");
    assert_eq!(historical.hits.len(), 1);
    assert_eq!(
        historical.hits[0].source.event_id,
        independent.event.event_id
    );
    let before = restored
        .verify_native(true)
        .expect("reconciled closure")
        .commit_seq;
    assert_eq!(
        restored
            .maintain_suppression(&secret.context, 256, &mut budget())
            .expect("idle")
            .processed,
        0
    );
    assert_eq!(
        restored
            .verify_native(true)
            .expect("idle verification")
            .commit_seq,
        before
    );
    let provider = restored.indexed_recall_provider(&independent.context);
    let view = provider
        .open_view(None, &mut budget())
        .expect("view before remote denial");
    let query = IndexedQuery {
        filter: RawFilter::default(),
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 4 },
    };
    assert_eq!(
        provider
            .candidates(&view, &query, &mut budget())
            .expect("initial view")
            .hits
            .len(),
        1
    );
    service
        .revoke_original(
            &independent.context,
            independent.event.event_id,
            "later-live-denial",
            &mut budget(),
        )
        .expect("authority advances after restore");
    assert_eq!(
        read(&restored, &independent)
            .expect_err("restore is not a permanent freshness exemption")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        provider
            .candidates(&view, &query, &mut budget())
            .expect_err("pinned physical view still checks current external authority")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn external_denial_crash_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_SUPPRESSION_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let identity = std::env::var("CONTEXTDB_SUPPRESSION_CRASH_AUTHORITY")
        .expect("identity")
        .parse()
        .expect("UUID");
    let ledger = NativeSuppressionLedger::open(root.join("ledger"), "crash-suppression", identity)
        .expect("retained ledger");
    let service = NativeService::open_with_suppression(
        root.join("native"),
        "crash-suppression",
        [7; 32],
        ledger,
    )
    .expect("native authority");
    AFTER_EXTERNAL_COMMIT
        .with(|hook| *hook.borrow_mut() = Some(Box::new(|| std::process::exit(73))));
    let input = capture::tests::request(1, "crash_window_secret");
    service
        .revoke_original(
            &input.context,
            input.event.event_id,
            "crash-after-external-sync",
            &mut budget(),
        )
        .expect("crash hook must terminate first");
    panic!("crash hook did not execute");
}

#[test]
fn process_crash_after_external_sync_leaves_a_durable_disclosure_barrier() {
    let root = tempfile::tempdir().expect("root");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "crash-suppression")
        .expect("ledger");
    let identity = ledger.authority_id();
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "crash-suppression",
        [7; 32],
        ledger.clone(),
    )
    .expect("native");
    let input = capture::tests::request(1, "crash_window_secret");
    service.append_event(input.clone()).expect("capture");
    drop(service);
    drop(ledger);
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "suppression::tests::external_denial_crash_child",
            "--nocapture",
        ])
        .env("CONTEXTDB_SUPPRESSION_CRASH_ROOT", root.path())
        .env(
            "CONTEXTDB_SUPPRESSION_CRASH_AUTHORITY",
            identity.to_string(),
        )
        .status()
        .expect("child");
    assert_eq!(status.code(), Some(73));
    assert!(
        NativeService::open(root.path().join("native"), "crash-suppression", [7; 32]).is_err(),
        "ledger omission cannot downgrade a bound database"
    );
    let ledger =
        NativeSuppressionLedger::open(root.path().join("ledger"), "crash-suppression", identity)
            .expect("reopen independent authority");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "crash-suppression",
        [8; 32],
        ledger,
    )
    .expect("reopen primary");
    assert_eq!(
        read(&service, &input)
            .expect_err("native policy predates accepted denial")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .verify_native(true)
        .expect("unfinished recovery remains verifiable");
    service
        .maintain_suppression(&input.context, 1, &mut budget())
        .expect("complete durable denial");
    catch_up(&service, &input);
    assert_eq!(
        read(&service, &input)
            .expect_err("denial after recovery")
            .code,
        ErrorCode::PermissionDenied
    );
    service.verify_native(true).expect("recovered closure");
}

#[test]
fn missing_wrong_and_legacy_authorities_fail_before_restore_and_lost_progress_is_detected() {
    let root = tempfile::tempdir().expect("root");
    let (_external, ledger) = authority("binding-db");
    let service = NativeService::open_with_suppression(
        root.path().join("source"),
        "binding-db",
        [7; 32],
        ledger.clone(),
    )
    .expect("source");
    let input = capture::tests::request(1, "authority_bound_secret");
    service.append_event(input.clone()).expect("capture");
    let archive = service
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("backup");
    let (_wrong_external, wrong) = authority("binding-db");
    let wrong_target = NativeService::open_with_suppression(
        root.path().join("wrong"),
        "binding-db",
        [7; 32],
        wrong,
    )
    .expect("wrong authority target");
    assert!(restore(&wrong_target, &input, &archive).is_err());
    assert_eq!(
        wrong_target
            .verify_native(true)
            .expect("no partial restore")
            .commit_seq,
        0
    );
    assert!(
        NativeSuppressionLedger::open(
            root.path().join("missing"),
            "binding-db",
            ledger.authority_id()
        )
        .is_err()
    );
    assert!(
        !root.path().join("missing").exists(),
        "opening an unavailable authority must not create one"
    );
    let legacy = NativeService::open(root.path().join("legacy"), "binding-db", [7; 32])
        .expect("legacy source");
    legacy.append_event(input.clone()).expect("legacy capture");
    let legacy_archive = legacy
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("unbound archival backup");
    let legacy_target =
        NativeService::open(root.path().join("legacy-target"), "binding-db", [7; 32])
            .expect("legacy target");
    assert_eq!(
        restore(&legacy_target, &input, &legacy_archive)
            .expect_err("cannot assert current permissions from an unbound archive")
            .code,
        ErrorCode::Unsupported
    );
    assert_eq!(
        legacy_target
            .verify_native(true)
            .expect("pristine")
            .commit_seq,
        0
    );
    service
        .revoke_original(&input.context, input.event.event_id, "deny", &mut budget())
        .expect("deny");
    let mut tx = service
        .engine
        .begin_write()
        .expect("injected metadata loss");
    tx.delete(
        &service.keyspaces.continuous,
        applied_key(&digest_bytes(input.context.request.workspace_id.as_bytes())),
    )
    .expect("lose applied checkpoint");
    tx.commit(Durability::Sync).expect("inject");
    assert_eq!(
        read(&service, &input)
            .expect_err("loss never opens disclosure")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("journal reconstructs required checkpoint")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn bounded_reconciliation_rechecks_new_external_denials_and_budget_before_publication() {
    let root = tempfile::tempdir().expect("root");
    let (_external, ledger) = authority("concurrent-suppression");
    let source = Arc::new(
        NativeService::open_with_suppression(
            root.path().join("source"),
            "concurrent-suppression",
            [7; 32],
            ledger.clone(),
        )
        .expect("source"),
    );
    let first = capture::tests::request(1, "first_source");
    let second = capture::tests::request(2, "second_source");
    source.append_event(first.clone()).expect("first");
    source.append_event(second.clone()).expect("second");
    let archive = source
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("backup");
    source
        .revoke_original(&first.context, first.event.event_id, "first", &mut budget())
        .expect("first denial");
    let target = NativeService::open_with_suppression(
        root.path().join("target"),
        "concurrent-suppression",
        [7; 32],
        ledger,
    )
    .expect("target");
    restore(&target, &first, &archive).expect("pending restore");
    let before = target.verify_native(true).expect("before").commit_seq;
    let mut tiny = QueryBudget::new(0, 0, Duration::from_secs(30), QueryCancellation::default());
    assert_eq!(
        target
            .maintain_suppression(&first.context, 1, &mut tiny)
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        target
            .verify_native(true)
            .expect("no partial budget publication")
            .commit_seq,
        before
    );
    let concurrent = source.clone();
    let concurrent_input = second.clone();
    BEFORE_NATIVE_PUBLISH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::thread::spawn(move || {
                concurrent
                    .revoke_original(
                        &concurrent_input.context,
                        concurrent_input.event.event_id,
                        "concurrent-second",
                        &mut budget(),
                    )
                    .expect("concurrent external denial")
            })
            .join()
            .expect("thread");
        }))
    });
    let progress = target
        .maintain_suppression(&first.context, 1, &mut budget())
        .expect("publish prepared prefix");
    assert!(
        !progress.caught_up,
        "a newer external head is never skipped"
    );
    assert_eq!(
        read(&target, &second)
            .expect_err("new deny keeps barrier closed")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(
        target
            .maintain_suppression(&first.context, 1, &mut budget())
            .expect("next prefix")
            .caught_up
    );
    catch_up(&target, &first);
    assert_eq!(
        read(&target, &second).expect_err("second denied").code,
        ErrorCode::PermissionDenied
    );
    target.verify_native(true).expect("concurrent closure");
}

#[test]
fn competing_native_owners_cannot_skip_an_external_denial_between_check_and_commit() {
    let root = tempfile::tempdir().expect("root");
    let (_external, ledger) = authority("competing-owners");
    let source = NativeService::open_with_suppression(
        root.path().join("source"),
        "competing-owners",
        [7; 32],
        ledger.clone(),
    )
    .expect("source");
    let first = capture::tests::request(1, "first_secret");
    let second = capture::tests::request(2, "second_secret");
    source.append_event(first.clone()).expect("first");
    source.append_event(second.clone()).expect("second");
    let archive = source
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("backup");
    let replica = Arc::new(
        NativeService::open_with_suppression(
            root.path().join("replica"),
            "competing-owners",
            [8; 32],
            ledger.clone(),
        )
        .expect("replica"),
    );
    restore(&replica, &first, &archive).expect("replica restore");
    let concurrent = replica.clone();
    let concurrent_input = second.clone();
    BEFORE_EXTERNAL_COMMIT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::thread::spawn(move || {
                concurrent
                    .revoke_original(
                        &concurrent_input.context,
                        concurrent_input.event.event_id,
                        "competing",
                        &mut budget(),
                    )
                    .expect("competing denial")
            })
            .join()
            .expect("thread");
        }))
    });
    assert_eq!(
        source
            .revoke_original(&first.context, first.event.event_id, "local", &mut budget())
            .expect_err("stale external compare")
            .code,
        ErrorCode::IndexTooStale
    );
    let workspace = digest_bytes(first.context.request.workspace_id.as_bytes());
    assert_eq!(ledger.current(&workspace).expect("external head").epoch, 1);
    assert!(
        !ledger
            .denied(&workspace, first.event.event_id)
            .expect("uncommitted denial")
    );
    assert_eq!(
        read(&source, &second)
            .expect_err("cannot skip competing suppression")
            .code,
        ErrorCode::IndexTooStale
    );
    source
        .maintain_suppression(&first.context, 1, &mut budget())
        .expect("import competing denial");
    source
        .revoke_original(&first.context, first.event.event_id, "local", &mut budget())
        .expect("retry after synchronization");
    catch_up(&source, &first);
    for input in [&first, &second] {
        assert_eq!(
            read(&source, input)
                .expect_err("both denials enforced")
                .code,
            ErrorCode::PermissionDenied
        );
    }
    source.verify_native(true).expect("two-owner closure");
}
