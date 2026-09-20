use std::{process::Command, sync::Arc, time::Duration};

use contextdb_core::ScopeId;
use contextdb_recall::{
    ProviderRequest, QueryCancellation, RecallPrincipal, RecallProvider, RecallSensitivity,
};
use contextdb_service::{CapturePort, CognitiveMemoryService};

use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn input(sequence: u64, text: &str) -> contextdb_service::CaptureRequest {
    let mut input = capture::tests::request(sequence, text);
    input.context.capability_grants.extend([
        Capability::Correct,
        Capability::ReadMemory,
        Capability::Forget,
    ]);
    input
}

fn publication(context: &AuthenticatedRequestContext, id: &str) -> PublishMemoryRequest {
    PublishMemoryRequest {
        context: context.clone(),
        idempotency_key: format!("publish-{id}"),
        memory_id: id.into(),
        value: serde_json::json!({"text": format!("record sentinel {id}")}),
        search_text: format!("record sentinel {id}"),
    }
}

fn get(
    service: &NativeService,
    context: &AuthenticatedRequestContext,
    id: &str,
) -> ServiceResult<MemoryRecord> {
    service.get_memory(GetMemoryRequest {
        context: context.clone(),
        record_id: id.into(),
        at_commit: None,
    })
}

fn catch_up(service: &NativeService, context: &AuthenticatedRequestContext) {
    while !service
        .maintain_suppression(context, 2, &mut budget())
        .expect("current suppression")
        .caught_up
    {}
    while !service
        .maintain_custody(context, 2, &mut budget())
        .expect("current source custody")
        .caught_up
    {}
    while !service
        .maintain_record_sources(context, 1, &mut budget())
        .expect("current record sources")
        .caught_up
    {}
}

fn assert_public_recall(service: &NativeService, context: &AuthenticatedRequestContext) {
    let recalled = service
        .recall(RecallRequest {
            context: context.request.clone(),
            query: "record sentinel".into(),
            page_size: 10,
            at_commit: None,
            continuation: None,
        })
        .expect("ordinary recall");
    assert_eq!(recalled.hits.len(), 1);
    assert_eq!(recalled.hits[0].id, "independent");
    let provider = NativeRecallProvider::new(service, &context.request.workspace_id);
    let corpus = provider
        .authorized_corpus(&ProviderRequest {
            snapshot: provider.snapshot(None).expect("provider snapshot"),
            principal: RecallPrincipal {
                subject: context.request.subject_id.clone(),
                audiences: context.request.audiences.clone(),
                workspace: context.request.workspace_id.clone(),
                scopes: context.request.scopes.clone(),
                purpose: context.request.purpose.clone(),
                clearance: RecallSensitivity::Confidential,
            },
            filter_digest: "record-origin-fixture".into(),
        })
        .expect("provider origin gate");
    assert_eq!(corpus.documents().len(), 1);
    assert!(corpus.relations().is_empty());
}

#[test]
fn encrypted_restore_keeps_current_origins_and_denies_before_record_materialization() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_directory, ledger) = suppression::tests::authority("record-origins");
    let (_keys_directory, keys) = encryption::tests::authority("record-origins");
    let native_path = root.path().join("native");
    let service = NativeService::open_encrypted(
        &native_path,
        "record-origins",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let mut restricted = input(1, "private captured source");
    let private = ScopeId::new();
    restricted.event.scope_ids = BTreeSet::from([private]);
    restricted
        .context
        .request
        .scopes
        .insert(private.to_string());
    let independent = input(2, "independent captured source");
    service
        .append_event(restricted.clone())
        .expect("private original");
    service
        .append_event(independent.clone())
        .expect("independent original");
    let narrow = independent.context.clone();
    let wide = restricted.context.clone();
    let before_records = service
        .create_backup(CreateBackupRequest {
            context: wide.clone(),
        })
        .expect("archive before records existed");
    for id in ["restricted", "independent", "unclassified"] {
        service
            .publish_memory(publication(&narrow, id))
            .expect("legacy record");
    }
    let oldest = service
        .create_backup(CreateBackupRequest {
            context: wide.clone(),
        })
        .expect("archive without any local provenance");
    let first = service
        .bind_record_sources(
            &wide,
            "restricted",
            1,
            &BTreeSet::from([restricted.event.event_id]),
            &mut budget(),
        )
        .expect("complete host declaration");
    assert_eq!(first.epoch, 1);
    service
        .bind_record_sources(
            &narrow,
            "independent",
            1,
            &BTreeSet::from([independent.event.event_id]),
            &mut budget(),
        )
        .expect("independent host declaration");
    assert_eq!(
        get(&service, &narrow, "independent")
            .expect_err("pending authority")
            .code,
        ErrorCode::IndexTooStale
    );
    let progress = service
        .maintain_record_sources(&wide, 1, &mut budget())
        .expect("first page");
    assert_eq!(progress.through, 1);
    assert!(!progress.caught_up);
    let partial = service
        .create_backup(CreateBackupRequest {
            context: wide.clone(),
        })
        .expect("partial provenance archive");
    drop(service);
    let service = NativeService::open_encrypted(
        &native_path,
        "record-origins",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen partial progress");
    catch_up(&service, &wide);
    assert_eq!(
        get(&service, &narrow, "restricted")
            .expect_err("source scopes retained")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(get(&service, &wide, "restricted").is_ok());
    assert_eq!(
        get(&service, &wide, "unclassified")
            .expect_err("unknown is not independent")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert_public_recall(&service, &narrow);
    assert!(
        service
            .publish_memory(publication(&narrow, "independent"))
            .expect("accepted exact retry")
            .replayed
    );
    assert_eq!(
        service
            .publish_memory(publication(&narrow, "new-unclassified"))
            .expect_err("writer requires provenance")
            .code,
        ErrorCode::Unsupported
    );
    service
        .revoke_original(
            &wide,
            restricted.event.event_id,
            "deny-private-origin",
            &mut budget(),
        )
        .expect("revoke original");
    catch_up(&service, &wide);
    assert_eq!(
        get(&service, &wide, "restricted")
            .expect_err("source revocation")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(get(&service, &narrow, "independent").is_ok());
    assert_eq!(
        service
            .get_timeline(GetTimelineRequest {
                context: wide.clone(),
                record_id: "restricted".into(),
                expected_kind: MemoryRecordKind::SemanticObject,
                at_commit: None,
                max_revisions: 10,
            })
            .expect_err("historical disclosure remains denied")
            .code,
        ErrorCode::NotFound
    );

    let content_key = history_key(&digest_bytes(b"restricted"), 1);
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let original = snapshot
        .get(&service.keyspaces.content_history, &content_key)
        .expect("get")
        .expect("content");
    drop(snapshot);
    let mut tx = service.engine.begin_write().expect("tx");
    tx.put(
        &service.keyspaces.content_history,
        content_key.clone(),
        b"invalid content must not be decoded".to_vec(),
    )
    .expect("corrupt denied content");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        get(&service, &wide, "restricted")
            .expect_err("authorization precedes materialization")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_public_recall(&service, &narrow);
    let mut tx = service.engine.begin_write().expect("tx");
    tx.put(&service.keyspaces.content_history, content_key, original)
        .expect("repair fixture");
    tx.commit(Durability::Sync).expect("commit");
    service.verify_native(true).expect("current deep closure");
    let current = service
        .create_backup(CreateBackupRequest {
            context: wide.clone(),
        })
        .expect("current archive");
    for (ordinal, archive) in [oldest, partial, current].into_iter().enumerate() {
        let restored = NativeService::open_encrypted(
            root.path().join(format!("restore-{ordinal}")),
            "record-origins",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: wide.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore actual archive bytes");
        if ordinal < 2 {
            assert_eq!(
                get(&restored, &narrow, "independent")
                    .expect_err("old archive is gated")
                    .code,
                ErrorCode::IndexTooStale
            );
        }
        catch_up(&restored, &wide);
        assert_eq!(
            get(&restored, &wide, "restricted")
                .expect_err("archive cannot restore withdrawn source")
                .code,
            ErrorCode::PermissionDenied
        );
        assert!(get(&restored, &narrow, "independent").is_ok());
        assert_public_recall(&restored, &narrow);
        restored
            .verify_native(true)
            .expect("restored current closure");
    }
    let restored = NativeService::open_encrypted(
        root.path().join("before-records"),
        "record-origins",
        [7; 32],
        ledger,
        keys,
    )
    .expect("early target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: wide.clone(),
            format: before_records.format,
            bytes: before_records.bytes,
            digest: before_records.digest,
        })
        .expect("pre-record archive");
    catch_up(&restored, &wide);
    assert_eq!(
        get(&restored, &narrow, "independent")
            .expect_err("later absent record is not fabricated")
            .code,
        ErrorCode::NotFound
    );
    restored
        .verify_native(true)
        .expect("retained declarations with legitimate local absence");
}

#[test]
fn provenance_exit_after_authority_sync_fixture() {
    let Ok(path) = std::env::var("CONTEXTDB_RECORD_SOURCE_CRASH_FIXTURE") else {
        return;
    };
    let root = Path::new(&path);
    let ledger =
        NativeSuppressionLedger::create(root.join("ledger"), "origin-crash").expect("ledger");
    std::fs::write(root.join("authority"), ledger.authority_id().to_string()).expect("identity");
    let service =
        NativeService::open_with_suppression(root.join("native"), "origin-crash", [7; 32], ledger)
            .expect("native");
    let input = input(1, "durable origin before process exit");
    service.append_event(input.clone()).expect("capture");
    service
        .publish_memory(publication(&input.context, "record"))
        .expect("record");
    AFTER_AUTHORITY_SYNC.with(|hook| hook.replace(Some(Box::new(|| std::process::exit(77)))));
    service
        .bind_record_sources(
            &input.context,
            "record",
            1,
            &BTreeSet::from([input.event.event_id]),
            &mut budget(),
        )
        .expect("process must exit");
    panic!("crash hook was not reached");
}

#[test]
fn external_sync_survives_process_exit_without_reopening_disclosure() {
    let root = tempfile::tempdir().expect("root");
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "record_sources::tests::provenance_exit_after_authority_sync_fixture",
            "--nocapture",
        ])
        .env("CONTEXTDB_RECORD_SOURCE_CRASH_FIXTURE", root.path())
        .status()
        .expect("run actual child process");
    assert_eq!(status.code(), Some(77));
    let authority = std::fs::read_to_string(root.path().join("authority"))
        .expect("authority")
        .parse()
        .expect("UUID");
    let ledger =
        NativeSuppressionLedger::open(root.path().join("ledger"), "origin-crash", authority)
            .expect("retained authority");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "origin-crash",
        [7; 32],
        ledger,
    )
    .expect("recover native");
    let input = input(1, "durable origin before process exit");
    assert_eq!(
        get(&service, &input.context, "record")
            .expect_err("no applied native prefix")
            .code,
        ErrorCode::IndexTooStale
    );
    let receipt = service
        .bind_record_sources(
            &input.context,
            "record",
            1,
            &BTreeSet::from([input.event.event_id]),
            &mut budget(),
        )
        .expect("exact authority retry");
    assert_eq!(receipt.epoch, 1);
    catch_up(&service, &input.context);
    assert!(get(&service, &input.context, "record").is_ok());
    service
        .verify_native(true)
        .expect("recovered native closure");
}

#[test]
fn concurrent_capture_cancellation_and_missing_progress_cannot_accept_partial_provenance() {
    let root = tempfile::tempdir().expect("root");
    let (_directory, ledger) = suppression::tests::authority("origin-race");
    let service = Arc::new(
        NativeService::open_with_suppression(
            root.path().join("native"),
            "origin-race",
            [7; 32],
            ledger.clone(),
        )
        .expect("native"),
    );
    let first = input(1, "first captured origin");
    service.append_event(first.clone()).expect("capture");
    service
        .publish_memory(publication(&first.context, "record"))
        .expect("record");
    let workspace = digest_bytes(first.context.request.workspace_id.as_bytes());
    let writer = service.clone();
    BEFORE_PUBLICATION.with(|hook| {
        hook.replace(Some(Box::new(move || {
            writer
                .append_event(input(2, "concurrent capture"))
                .expect("concurrent commit");
        })))
    });
    assert_eq!(
        service
            .bind_record_sources(
                &first.context,
                "record",
                1,
                &BTreeSet::from([first.event.event_id]),
                &mut budget()
            )
            .expect_err("workspace changed")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(
        ledger
            .current_record_sources(&workspace)
            .expect("head")
            .is_none()
    );
    assert_eq!(
        service
            .bind_record_sources(
                &first.context,
                "record",
                1,
                &BTreeSet::from([input(2, "").event.event_id]),
                &mut budget()
            )
            .expect_err("source cannot postdate record")
            .code,
        ErrorCode::InvalidArgument
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(10, 1024 * 1024, Duration::from_secs(30), cancellation);
    assert!(
        service
            .bind_record_sources(
                &first.context,
                "record",
                1,
                &BTreeSet::from([first.event.event_id]),
                &mut cancelled
            )
            .is_err()
    );
    assert!(
        ledger
            .current_record_sources(&workspace)
            .expect("head")
            .is_none()
    );
    service
        .bind_record_sources(
            &first.context,
            "record",
            1,
            &BTreeSet::from([first.event.event_id]),
            &mut budget(),
        )
        .expect("bind");
    let writer = service.clone();
    BEFORE_APPLY.with(|hook| {
        hook.replace(Some(Box::new(move || {
            writer
                .append_event(input(3, "another concurrent capture"))
                .expect("concurrent commit");
        })))
    });
    assert_eq!(
        service
            .maintain_record_sources(&first.context, 2, &mut budget())
            .expect_err("no partial application")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        service
            .record_sources_applied(
                &service
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .expect("snapshot"),
                &workspace
            )
            .expect("applied")
            .epoch,
        0
    );
    catch_up(&service, &first.context);
    service.verify_native(true).expect("accepted progress");
    let mut tx = service.engine.begin_write().expect("tx");
    tx.delete(&service.keyspaces.continuous, applied_key(&workspace))
        .expect("lose progress family");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        get(&service, &first.context, "record")
            .expect_err("lost progress cannot reopen")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("accepted application cannot disappear")
            .code,
        ErrorCode::IntegrityFailure
    );
}
