use std::{process::Command, sync::Arc, time::Duration};

use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, CognitiveMemoryService};

use super::*;
use crate::record_sources::tests::{budget, catch_up, get, input, publication};

fn accepted(service: &NativeService) -> Vec<StoredEvent> {
    service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("events")
        .into_iter()
        .map(|row| decode::<StoredEvent>(&row.value, "event").expect("event"))
        .filter(|event| event.operation == PUBLISH)
        .collect()
}

#[test]
fn exact_retry_receipt_cannot_redirect_to_a_different_accepted_group() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("retry-binding");
    let service =
        NativeService::open_with_suppression(root.path(), "retry-binding", [7; 32], ledger)
            .expect("native");
    let source = input(1, "source for two independent publications");
    service.append_event(source.clone()).expect("capture");
    let sources = BTreeSet::from([source.event.event_id]);
    let first = publication(&source.context, "first");
    service
        .publish_memory_from_sources(first.clone(), &sources, &mut budget())
        .expect("first");
    let second = service
        .publish_memory_from_sources(
            publication(&source.context, "second"),
            &sources,
            &mut budget(),
        )
        .expect("second");
    let key = authenticated_idempotency_key(PUBLISH, &first.context, &first.idempotency_key)
        .expect("retry key");
    let mut tx = service.engine.begin_write().expect("transaction");
    let mut receipt: StoredIdempotency = decode(
        &tx.get(&service.keyspaces.idempotency, &key)
            .expect("read")
            .expect("receipt"),
        "retry",
    )
    .expect("decode");
    let mut redirected: MutationResponse =
        decode(&receipt.response_bytes, "response").expect("decode");
    redirected.commit_seq = second.commit_seq;
    receipt.response_bytes = encode(&redirected).expect("encode");
    receipt.response_digest = digest_bytes(&receipt.response_bytes);
    tx.put(
        &service.keyspaces.idempotency,
        key,
        encode(&receipt).expect("encode"),
    )
    .expect("replace fixture");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        service
            .publish_memory_from_sources(first, &sources, &mut budget())
            .expect_err("receipt must name its exact accepted group")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(accepted(&service).len(), 2);
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("deep verification binds the original retry receipt")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn source_admission_rejects_missing_grants_inherited_denials_and_exhausted_budget() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("source-admission");
    let service = NativeService::open_with_suppression(
        root.path(),
        "source-admission",
        [7; 32],
        ledger.clone(),
    )
    .expect("native");
    let mut private = input(1, "private upstream material");
    let private_scope = contextdb_core::ScopeId::new();
    private.event.scope_ids = BTreeSet::from([private_scope]);
    private
        .context
        .request
        .scopes
        .insert(private_scope.to_string());
    service
        .append_event(private.clone())
        .expect("private capture");
    let mut child = input(
        2,
        "replacement text does not declassify its private predecessor",
    );
    let narrow = child.context.clone();
    child.context = private.context.clone();
    child.event.supersedes_event_id = Some(private.event.event_id);
    service
        .append_event(child.clone())
        .expect("derived capture");
    let sources = BTreeSet::from([child.event.event_id]);
    let mut no_admin = child.context.clone();
    no_admin.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        service
            .publish_memory_from_sources(publication(&no_admin, "record"), &sources, &mut budget())
            .expect_err("trusted host capability")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        service
            .publish_memory_from_sources(publication(&narrow, "record"), &sources, &mut budget())
            .expect_err("inherited source policy")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        service
            .publish_memory_from_sources(
                publication(&child.context, "record"),
                &BTreeSet::new(),
                &mut budget()
            )
            .expect_err("origins mandatory")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut empty = QueryBudget::new(0, 0, Duration::from_secs(30), QueryCancellation::default());
    assert_eq!(
        service
            .publish_memory_from_sources(
                publication(&child.context, "record"),
                &sources,
                &mut empty
            )
            .expect_err("shared admission budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert!(accepted(&service).is_empty());
    let workspace = digest_bytes(child.context.request.workspace_id.as_bytes());
    assert!(
        ledger
            .current_record_sources(&workspace)
            .expect("retained state")
            .is_none()
    );
    service
        .publish_memory_from_sources(
            publication(&child.context, "record"),
            &sources,
            &mut budget(),
        )
        .expect("authorized complete origins");
    assert_eq!(
        get(&service, &narrow, "record")
            .expect_err("inherited source denial after publication")
            .code,
        ErrorCode::PermissionDenied
    );
    service
        .verify_native(true)
        .expect("inherited origin closure");
}

#[test]
fn manual_origin_repair_cannot_replace_an_accepted_pending_intent() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("origin-intent");
    let service =
        NativeService::open_with_suppression(root.path(), "origin-intent", [7; 32], ledger.clone())
            .expect("native");
    let first = input(1, "actual input");
    let second = input(2, "unrelated input already captured before publication");
    service.append_event(first.clone()).expect("first capture");
    service
        .append_event(second.clone())
        .expect("second capture");
    let cancelled = QueryCancellation::default();
    let token = cancelled.clone();
    AFTER_NATIVE_SYNC.with(|slot| slot.replace(Some(Box::new(move || token.cancel()))));
    service
        .publish_memory_from_sources(
            publication(&first.context, "record"),
            &BTreeSet::from([first.event.event_id]),
            &mut QueryBudget::new(
                1_000_000,
                128 * 1024 * 1024,
                Duration::from_secs(30),
                cancelled,
            ),
        )
        .expect_err("accepted pending intent");
    let event = accepted(&service).remove(0);
    assert_eq!(
        service
            .bind_record_sources(
                &first.context,
                "record",
                1,
                &BTreeSet::from([second.event.event_id]),
                &mut budget()
            )
            .expect_err("cannot overwrite accepted inputs")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(
        ledger
            .retained_record_sources(&event.workspace_digest, &digest_bytes(b"record"), 1)
            .expect("binding")
            .is_none()
    );
    service
        .resume_record_source_write(&first.context, event.workspace_commit, &mut budget())
        .expect("original intent still recoverable");
    service.verify_native(true).expect("exact repaired origins");
}

#[test]
fn restoring_before_acceptance_cannot_reuse_an_externally_reserved_record_id() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("restored-identity");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "restored-identity",
        [7; 32],
        ledger.clone(),
    )
    .expect("native");
    let source = input(1, "source preserved in the older archive");
    service.append_event(source.clone()).expect("capture");
    let archive = service
        .create_backup(CreateBackupRequest {
            context: source.context.clone(),
        })
        .expect("pre-acceptance archive");
    let sources = BTreeSet::from([source.event.event_id]);
    service
        .publish_memory_from_sources(
            publication(&source.context, "reserved"),
            &sources,
            &mut budget(),
        )
        .expect("original publication");
    let restored = NativeService::open_with_suppression(
        root.path().join("restored"),
        "restored-identity",
        [7; 32],
        ledger,
    )
    .expect("restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: source.context.clone(),
            format: archive.format,
            bytes: archive.bytes,
            digest: archive.digest,
        })
        .expect("restore old archive");
    catch_up(&restored, &source.context);
    assert_eq!(
        restored
            .publish_memory_from_sources(
                publication(&source.context, "reserved"),
                &sources,
                &mut budget()
            )
            .expect_err("retained identity remains reserved")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(accepted(&restored).is_empty());
    assert_eq!(
        get(&restored, &source.context, "reserved")
            .expect_err("no fabricated missing record")
            .code,
        ErrorCode::NotFound
    );
    restored
        .publish_memory_from_sources(
            publication(&source.context, "independent"),
            &sources,
            &mut budget(),
        )
        .expect("new independent identity remains available");
    restored
        .verify_native(true)
        .expect("old backup with current identity reservations");
}

#[test]
fn explicit_source_publication_activates_transfers_and_replays_one_acceptance() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("sourced-write");
    let service =
        NativeService::open_with_suppression(root.path(), "sourced-write", [7; 32], ledger.clone())
            .expect("native");
    let source = input(1, "even incidental original text is retained");
    service.append_event(source.clone()).expect("capture");
    let sources = BTreeSet::from([source.event.event_id]);
    let response = service
        .publish_memory_from_sources(
            publication(&source.context, "record"),
            &sources,
            &mut budget(),
        )
        .expect("source-aware publication");
    assert!(!response.replayed);
    assert!(get(&service, &source.context, "record").is_ok());
    let events = accepted(&service);
    assert_eq!(events.len(), 1);
    let binding = ledger
        .retained_record_sources(&events[0].workspace_digest, &digest_bytes(b"record"), 1)
        .expect("binding")
        .expect("retained");
    assert_eq!(
        binding.record_control().expect("control").transaction_from,
        events[0].global_commit
    );
    assert_eq!(
        binding
            .record_control()
            .expect("control")
            .sources
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        sources
    );
    let replay = service
        .publish_memory_from_sources(
            publication(&source.context, "record"),
            &sources,
            &mut budget(),
        )
        .expect("exact retry");
    assert!(replay.replayed);
    assert_eq!(replay.commit_seq, response.commit_seq);
    assert_eq!(replay.request_digest, response.request_digest);
    let completed = service
        .resume_record_source_write(&source.context, response.commit_seq, &mut budget())
        .expect("receipt recovery");
    assert!(completed.completed_at > response.commit_seq);
    assert_eq!(accepted(&service).len(), 1);
    assert_eq!(
        service
            .publish_memory(publication(&source.context, "legacy"))
            .expect_err("unclassified writes closed")
            .code,
        ErrorCode::Unsupported
    );
    let other = input(2, "different captured input");
    service.append_event(other.clone()).expect("second capture");
    assert_eq!(
        service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &BTreeSet::from([other.event.event_id]),
                &mut budget()
            )
            .expect_err("origins bind retry identity")
            .code,
        ErrorCode::IdempotencyConflict
    );
    service.verify_native(true).expect("complete deep closure");
}

#[test]
fn interrupted_handoffs_stay_closed_after_catchup_restart_and_encrypted_restore() {
    for stop in 0..3 {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("write-recovery");
        let (_key_root, keys) = encryption::tests::authority("write-recovery");
        let service = NativeService::open_encrypted(
            root.path().join("native"),
            "write-recovery",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native");
        let source = input(1, "record write interrupted at a durability boundary");
        service.append_event(source.clone()).expect("capture");
        let sources = BTreeSet::from([source.event.event_id]);
        let cancelled = QueryCancellation::default();
        let token = cancelled.clone();
        let hook: Box<dyn FnOnce()> = Box::new(move || token.cancel());
        match stop {
            0 => AFTER_NATIVE_SYNC.with(|slot| slot.replace(Some(hook))),
            1 => AFTER_ORIGIN_SYNC.with(|slot| slot.replace(Some(hook))),
            _ => BEFORE_COMPLETION.with(|slot| slot.replace(Some(hook))),
        };
        let mut interrupted = QueryBudget::new(
            1_000_000,
            128 * 1024 * 1024,
            Duration::from_secs(30),
            cancelled,
        );
        let error = service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &sources,
                &mut interrupted,
            )
            .expect_err("interrupted handoff");
        let events = accepted(&service);
        assert_eq!(events.len(), 1);
        let commit = events[0].workspace_commit;
        assert_eq!(
            error.partial_result_refs.as_ref(),
            [format!(
                "record-write:{}:{commit}",
                events[0].workspace_digest
            )]
        );
        // Even complete external transfer and manual prefix application cannot
        // substitute for the mutation group's durable completion.
        catch_up(&service, &source.context);
        assert_eq!(
            get(&service, &source.context, "record")
                .expect_err("group remains closed")
                .code,
            ErrorCode::IndexTooStale
        );
        service.verify_native(true).expect("valid incomplete group");
        let archive = service
            .create_backup(CreateBackupRequest {
                context: source.context.clone(),
            })
            .expect("incomplete encrypted backup");
        service
            .append_event(input(
                2,
                "conversation continues while record repair is pending",
            ))
            .expect("independent capture");
        drop(service);
        let service = NativeService::open_encrypted(
            root.path().join("native"),
            "write-recovery",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restart");
        let replay = service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &sources,
                &mut budget(),
            )
            .expect("recover exact request");
        assert!(replay.replayed);
        assert_eq!(replay.commit_seq, commit);
        assert_eq!(accepted(&service).len(), 1);
        assert!(get(&service, &source.context, "record").is_ok());
        service.verify_native(true).expect("restarted completion");
        let restored = NativeService::open_encrypted(
            root.path().join("restored"),
            "write-recovery",
            [7; 32],
            ledger,
            keys,
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: source.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore pending bytes against current authority");
        catch_up(&restored, &source.context);
        assert_eq!(
            get(&restored, &source.context, "record")
                .expect_err("restore cannot invent completion")
                .code,
            ErrorCode::IndexTooStale
        );
        restored
            .resume_record_source_write(&source.context, commit, &mut budget())
            .expect("recover without original request");
        assert!(get(&restored, &source.context, "record").is_ok());
        assert_eq!(accepted(&restored).len(), 1);
        restored.verify_native(true).expect("restored completion");
    }
}

#[test]
fn revoked_accepted_input_can_finish_repair_without_reopening_disclosure() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("revoked-write");
    let service =
        NativeService::open_with_suppression(root.path(), "revoked-write", [7; 32], ledger)
            .expect("native");
    let source = input(1, "source later revoked");
    service.append_event(source.clone()).expect("capture");
    let cancellation = QueryCancellation::default();
    let token = cancellation.clone();
    AFTER_NATIVE_SYNC.with(|slot| slot.replace(Some(Box::new(move || token.cancel()))));
    let mut interrupted = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    let sources = BTreeSet::from([source.event.event_id]);
    service
        .publish_memory_from_sources(
            publication(&source.context, "record"),
            &sources,
            &mut interrupted,
        )
        .expect_err("interrupt");
    service
        .revoke_original(
            &source.context,
            source.event.event_id,
            "revoke-write-input",
            &mut budget(),
        )
        .expect("revoke");
    catch_up(&service, &source.context);
    assert!(
        service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &sources,
                &mut budget()
            )
            .expect("repair accepted write after revocation")
            .replayed
    );
    assert_eq!(
        get(&service, &source.context, "record")
            .expect_err("source remains denied")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        service
            .publish_memory_from_sources(
                publication(&source.context, "new"),
                &sources,
                &mut budget()
            )
            .expect_err("revoked source cannot create new record")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(accepted(&service).len(), 1);
    service
        .verify_native(true)
        .expect("revocation-compatible completion");
}

#[test]
fn preparation_cas_and_concurrent_identical_retry_do_not_duplicate_births() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("racing-write");
    let service = Arc::new(
        NativeService::open_with_suppression(root.path(), "racing-write", [7; 32], ledger)
            .expect("native"),
    );
    let source = input(1, "source for a racing publication");
    service.append_event(source.clone()).expect("capture");
    let sources = BTreeSet::from([source.event.event_id]);
    let other = service.clone();
    BEFORE_PUBLICATION.with(|slot| {
        slot.replace(Some(Box::new(move || {
            std::thread::spawn(move || other.append_event(input(2, "actual concurrent capture")))
                .join()
                .expect("thread")
                .expect("capture");
        })))
    });
    assert_eq!(
        service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &sources,
                &mut budget()
            )
            .expect_err("stale preparation")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(accepted(&service).is_empty());
    assert_eq!(
        get(&service, &source.context, "record")
            .expect_err("no partial record")
            .code,
        ErrorCode::NotFound
    );
    let other = service.clone();
    let other_context = source.context.clone();
    let other_sources = sources.clone();
    BEFORE_PUBLICATION.with(|slot| {
        slot.replace(Some(Box::new(move || {
            std::thread::spawn(move || {
                other.publish_memory_from_sources(
                    publication(&other_context, "record"),
                    &other_sources,
                    &mut budget(),
                )
            })
            .join()
            .expect("thread")
            .expect("same publication");
        })))
    });
    let replay = service
        .publish_memory_from_sources(
            publication(&source.context, "record"),
            &sources,
            &mut budget(),
        )
        .expect("racing replay");
    assert!(replay.replayed);
    assert_eq!(accepted(&service).len(), 1);
    service.verify_native(true).expect("racing closure");
}

#[test]
fn accepted_origin_and_completion_families_cannot_silently_disappear() {
    for remove in ["intent", "completion", "family", "orphan"] {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("lost-write");
        let service =
            NativeService::open_with_suppression(root.path(), "lost-write", [7; 32], ledger)
                .expect("native");
        let source = input(1, "source whose accepted metadata must remain exact");
        service.append_event(source.clone()).expect("capture");
        service
            .publish_memory_from_sources(
                publication(&source.context, "record"),
                &BTreeSet::from([source.event.event_id]),
                &mut budget(),
            )
            .expect("publication");
        let event = accepted(&service).remove(0);
        let mut tx = service.engine.begin_write().expect("transaction");
        if matches!(remove, "intent" | "family") {
            tx.delete(
                &service.keyspaces.continuous,
                intent_key(event.global_commit),
            )
            .expect("delete intent");
        }
        if matches!(remove, "completion" | "family") {
            tx.delete(
                &service.keyspaces.continuous,
                completion_key(event.global_commit),
            )
            .expect("delete completion");
        }
        if remove == "orphan" {
            tx.put(
                &service.keyspaces.continuous,
                b"record-write/orphan".to_vec(),
                b"{}".to_vec(),
            )
            .expect("orphan");
        }
        tx.commit(Durability::Sync).expect("commit corruption");
        assert_eq!(
            service
                .verify_native(true)
                .expect_err("exact family closure")
                .code,
            ErrorCode::IntegrityFailure
        );
        if remove == "completion" {
            assert_eq!(
                get(&service, &source.context, "record")
                    .expect_err("missing completion closes disclosure")
                    .code,
                ErrorCode::IndexTooStale
            );
        }
        if matches!(remove, "intent" | "family") {
            assert_eq!(
                get(&service, &source.context, "record")
                    .expect_err("intent loss closes disclosure before the body")
                    .code,
                ErrorCode::IntegrityFailure
            );
        }
    }
}

#[test]
fn accepted_write_process_exit_fixture() {
    let Ok(path) = std::env::var("CONTEXTDB_ACCEPTED_WRITE_CRASH_FIXTURE") else {
        return;
    };
    let root = Path::new(&path);
    let ledger = NativeSuppressionLedger::create(root.join("ledger"), "accepted-write-crash")
        .expect("authority");
    std::fs::write(root.join("authority"), ledger.authority_id().to_string()).expect("identity");
    let service = NativeService::open_with_suppression(
        root.join("native"),
        "accepted-write-crash",
        [7; 32],
        ledger,
    )
    .expect("native");
    let source = input(1, "native acceptance must survive process exit");
    service.append_event(source.clone()).expect("capture");
    AFTER_NATIVE_SYNC.with(|slot| slot.replace(Some(Box::new(|| std::process::exit(77)))));
    service
        .publish_memory_from_sources(
            publication(&source.context, "record"),
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("must exit");
    panic!("durability hook was not reached");
}

#[test]
fn actual_process_exit_preserves_pending_group_and_exact_retry() {
    let root = tempfile::tempdir().expect("root");
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "record_sources::writes::tests::accepted_write_process_exit_fixture",
            "--nocapture",
        ])
        .env("CONTEXTDB_ACCEPTED_WRITE_CRASH_FIXTURE", root.path())
        .status()
        .expect("child process");
    assert_eq!(status.code(), Some(77));
    let authority = std::fs::read_to_string(root.path().join("authority"))
        .expect("identity")
        .parse()
        .expect("UUID");
    let ledger = NativeSuppressionLedger::open(
        root.path().join("ledger"),
        "accepted-write-crash",
        authority,
    )
    .expect("retained authority");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "accepted-write-crash",
        [7; 32],
        ledger,
    )
    .expect("recover native");
    let source = input(1, "native acceptance must survive process exit");
    let event = accepted(&service).remove(0);
    assert_eq!(
        get(&service, &source.context, "record")
            .expect_err("durable incomplete group")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .append_event(input(2, "capture after the interrupted process"))
        .expect("capture continues");
    let replay = service
        .publish_memory_from_sources(
            publication(&source.context, "record"),
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("recover original acceptance");
    assert!(replay.replayed);
    assert_eq!(replay.commit_seq, event.workspace_commit);
    assert_eq!(accepted(&service).len(), 1);
    service
        .verify_native(true)
        .expect("actual crash recovery closure");
}
