use std::{process::Command, sync::Arc, time::Duration};

use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, CognitiveMemoryService, StructuredMemoryKind};

use super::*;
use crate::record_sources::tests::{budget, catch_up, input, publication};

fn proposal(
    context: &AuthenticatedRequestContext,
    id: &str,
    parents: &[&str],
    predecessors: &[&str],
) -> ProposeMemoryRequest {
    ProposeMemoryRequest {
        context: context.clone(),
        idempotency_key: format!("proposal-{id}"),
        candidate_id: id.into(),
        semantic_kind: StructuredMemoryKind::Fact,
        value: serde_json::json!({"text": format!("candidate body {id}")}),
        search_text: format!("candidate body {id}"),
        parent_candidate_ids: parents.iter().map(|id| (*id).into()).collect(),
        supersedes_candidate_ids: predecessors.iter().map(|id| (*id).into()).collect(),
    }
}

fn read(
    service: &NativeService,
    context: &AuthenticatedRequestContext,
    id: &str,
    at: Option<u64>,
) -> ServiceResult<MemoryRecord> {
    service.get_candidate(GetMemoryRequest {
        context: context.clone(),
        record_id: id.into(),
        at_commit: at,
    })
}

fn forget(context: &AuthenticatedRequestContext, id: &str) -> ForgetRequest {
    ForgetRequest {
        context: context.clone(),
        idempotency_key: format!("retract-{id}"),
        target_id: id.into(),
        mode: ForgetMode::Retract,
        reason: "owner_requested".into(),
    }
}

pub(super) fn origins(
    service: &NativeService,
    context: &AuthenticatedRequestContext,
    id: &str,
    revision: u32,
) -> BTreeSet<ObservationId> {
    service
        .suppression
        .as_ref()
        .expect("authority")
        .retained_record_sources(
            &digest_bytes(context.request.workspace_id.as_bytes()),
            &digest_bytes(id.as_bytes()),
            revision,
        )
        .expect("binding")
        .expect("retained origins")
        .record_control()
        .expect("record")
        .sources
        .keys()
        .copied()
        .collect()
}

pub(super) fn accepted(service: &NativeService, operation: &str) -> Vec<StoredEvent> {
    service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("journal")
        .into_iter()
        .map(|row| decode::<StoredEvent>(&row.value, "event").expect("event"))
        .filter(|event| event.operation == operation)
        .collect()
}

fn seed(
    service: &NativeService,
) -> (
    AuthenticatedRequestContext,
    Vec<ObservationId>,
    ProposeMemoryResponse,
) {
    let context = input(1, "input1").context;
    let mut ids = Vec::new();
    for ordinal in 1..=4 {
        let source = input(ordinal, &format!("input{ordinal}"));
        ids.push(source.event.event_id);
        service.append_event(source).expect("capture");
    }
    service
        .propose_memory_from_sources(
            proposal(&context, "parent", &[], &[]),
            &BTreeSet::from([ids[0]]),
            &mut budget(),
        )
        .expect("parent");
    let old = service
        .propose_memory_from_sources(
            proposal(&context, "old", &["parent"], &[]),
            &BTreeSet::from([ids[1]]),
            &mut budget(),
        )
        .expect("old candidate and edge");
    (context, ids, old)
}

#[test]
fn concurrent_identical_supersession_replays_the_complete_original_group() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("group-race");
    let service = Arc::new(
        NativeService::open_with_suppression(root.path(), "group-race", [7; 32], ledger)
            .expect("native"),
    );
    let (context, ids, _) = seed(&service);
    let request = proposal(&context, "new", &["parent"], &["old"]);
    let other = service.clone();
    let other_request = request.clone();
    let sources = BTreeSet::from([ids[2]]);
    let other_sources = sources.clone();
    BEFORE_PUBLICATION.with(|slot| {
        slot.replace(Some(Box::new(move || {
            std::thread::spawn(move || {
                other.propose_memory_from_sources(other_request, &other_sources, &mut budget())
            })
            .join()
            .expect("thread")
            .expect("concurrent supersession");
        })))
    });
    let response = service
        .propose_memory_from_sources(request, &sources, &mut budget())
        .expect("identical racing retry");
    assert!(response.mutation.replayed);
    assert_eq!(accepted(&service, PROPOSE).len(), 3);
    assert_eq!(
        origins(&service, &context, "old", 2),
        BTreeSet::from([ids[1], ids[2]])
    );
    service
        .verify_native(true)
        .expect("one complete supersession");
}

#[test]
fn rehashed_incomplete_copied_origins_are_rejected_before_retained_transfer() {
    for omit_previous in [false, true] {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("group-forgery");
        let service = NativeService::open_with_suppression(
            root.path(),
            "group-forgery",
            [7; 32],
            ledger.clone(),
        )
        .expect("native");
        let (context, ids, _) = seed(&service);
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
            .propose_memory_from_sources(
                proposal(&context, "new", &["parent"], &["old"]),
                &BTreeSet::from([ids[2]]),
                &mut interrupted,
            )
            .expect_err("stop before origins transfer");
        let mut event = accepted(&service, PROPOSE).pop().expect("accepted");
        let mut tx = service.engine.begin_write().expect("transaction");
        let mut intent: RecordWriteIntent = decode(
            &tx.get(
                &service.keyspaces.continuous,
                &intent_key(event.global_commit),
            )
            .expect("read")
            .expect("intent"),
            "intent",
        )
        .expect("decode");
        if omit_previous {
            intent.group.as_mut().expect("group").previous.clear();
        } else {
            let copied = intent
                .origins
                .iter_mut()
                .find(|control| control.revision == 2)
                .expect("copied revision");
            copied.sources.remove(&ids[1]);
        }
        let bytes = encode(&intent).expect("encode");
        event
            .accepted_record_write
            .as_mut()
            .expect("reference")
            .digest = digest_bytes(&bytes);
        event.event_digest = event_digest(&event).expect("rehash");
        tx.put(
            &service.keyspaces.continuous,
            intent_key(event.global_commit),
            bytes,
        )
        .expect("rehashed fixture");
        tx.put(
            &service.keyspaces.events,
            event.global_commit.to_be_bytes().to_vec(),
            encode(&event).expect("encode"),
        )
        .expect("event fixture");
        tx.commit(Durability::Sync).expect("commit");
        assert_eq!(
            service
                .resume_record_source_write(&context, event.workspace_commit, &mut budget())
                .expect_err("semantic origin closure, beyond self-consistent hashes")
                .code,
            ErrorCode::IntegrityFailure
        );
        for control in &intent.origins {
            assert!(
                ledger
                    .retained_record_sources(
                        &event.workspace_digest,
                        &control.record_digest,
                        control.revision
                    )
                    .expect("binding")
                    .is_none()
            );
        }
    }
}

#[test]
fn group_exit_after_first_transfer_fixture() {
    let Ok(path) = std::env::var("CONTEXTDB_SOURCE_GROUP_CRASH_FIXTURE") else {
        return;
    };
    let root = Path::new(&path);
    let ledger =
        NativeSuppressionLedger::create(root.join("ledger"), "group-crash").expect("authority");
    std::fs::write(root.join("authority"), ledger.authority_id().to_string()).expect("identity");
    let service =
        NativeService::open_with_suppression(root.join("native"), "group-crash", [7; 32], ledger)
            .expect("native");
    let (context, ids, _) = seed(&service);
    AFTER_ORIGIN_SYNC.with(|slot| slot.replace(Some(Box::new(|| std::process::exit(79)))));
    service
        .propose_memory_from_sources(
            proposal(&context, "new", &["parent"], &["old"]),
            &BTreeSet::from([ids[2]]),
            &mut budget(),
        )
        .expect("process must exit");
    panic!("partial-transfer boundary was not reached");
}

#[test]
fn actual_process_exit_leaves_one_transferred_origin_and_no_partial_disclosure() {
    let root = tempfile::tempdir().expect("root");
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "record_sources::writes::groups::tests::group_exit_after_first_transfer_fixture",
            "--nocapture",
        ])
        .env("CONTEXTDB_SOURCE_GROUP_CRASH_FIXTURE", root.path())
        .status()
        .expect("child");
    assert_eq!(status.code(), Some(79));
    let authority = std::fs::read_to_string(root.path().join("authority"))
        .expect("identity")
        .parse()
        .expect("UUID");
    let ledger =
        NativeSuppressionLedger::open(root.path().join("ledger"), "group-crash", authority)
            .expect("retained authority");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "group-crash",
        [7; 32],
        ledger.clone(),
    )
    .expect("restart");
    let context = input(1, "input1").context;
    let event = accepted(&service, PROPOSE).pop().expect("group");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let intent: RecordWriteIntent = decode(
        &snapshot
            .get(
                &service.keyspaces.continuous,
                &intent_key(event.global_commit),
            )
            .expect("read")
            .expect("intent"),
        "intent",
    )
    .expect("decode");
    let transferred = intent
        .origins
        .iter()
        .filter(|control| {
            ledger
                .retained_record_sources(
                    &event.workspace_digest,
                    &control.record_digest,
                    control.revision,
                )
                .expect("binding")
                .is_some()
        })
        .count();
    assert_eq!(transferred, 1);
    assert_eq!(intent.origins.len(), 3);
    catch_up(&service, &context);
    assert_eq!(
        read(&service, &context, "new", None)
            .expect_err("whole group remains undisclosed")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .append_event(input(5, "capture continues after actual process exit"))
        .expect("capture");
    service
        .resume_record_source_write(&context, event.workspace_commit, &mut budget())
        .expect("recover complete group");
    assert!(read(&service, &context, "new", None).is_ok());
    assert_eq!(accepted(&service, PROPOSE).len(), 3);
    service
        .verify_native(true)
        .expect("actual partial-transfer recovery");
}

#[test]
fn supersession_and_retraction_keep_copied_origins_without_tainting_independent_successors() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("record-groups");
    let service =
        NativeService::open_with_suppression(root.path(), "record-groups", [7; 32], ledger)
            .expect("native");
    let (context, ids, old) = seed(&service);
    let replacement = service
        .propose_memory_from_sources(
            proposal(&context, "new", &["parent"], &["old"]),
            &BTreeSet::from([ids[2]]),
            &mut budget(),
        )
        .expect("atomic supersession");
    assert!(!replacement.canonical);
    assert_eq!(
        accepted(&service, PROPOSE)
            .last()
            .expect("group")
            .accepted_records
            .len(),
        5
    );
    assert_eq!(
        origins(&service, &context, "old", 1),
        BTreeSet::from([ids[1]])
    );
    assert_eq!(
        origins(&service, &context, "old", 2),
        BTreeSet::from([ids[1], ids[2]])
    );
    assert_eq!(
        origins(&service, &context, "new", 1),
        BTreeSet::from([ids[2]])
    );
    assert_eq!(
        origins(&service, &context, &replacement.candidate_edge_ids[0], 1),
        BTreeSet::from([ids[2]])
    );
    assert_eq!(
        origins(&service, &context, &old.candidate_edge_ids[0], 1),
        BTreeSet::from([ids[1]])
    );
    let superseded = read(&service, &context, "old", None).expect("superseded revision");
    assert_eq!(superseded.document.lifecycle, MemoryLifecycle::Superseded);
    assert_eq!(
        superseded.document.value,
        serde_json::json!({"text": "candidate body old"})
    );
    assert!(
        service
            .recall(RecallRequest {
                context: context.request.clone(),
                query: "candidate body".into(),
                page_size: 10,
                at_commit: None,
                continuation: None
            })
            .expect("ordinary recall")
            .hits
            .is_empty()
    );
    service
        .revoke_original(&context, ids[1], "revoke-old-body", &mut budget())
        .expect("revoke predecessor input");
    catch_up(&service, &context);
    assert_eq!(
        read(&service, &context, "old", None)
            .expect_err("copied old text remains restricted")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(read(&service, &context, "new", None).is_ok());
    let removed = service
        .retract_from_sources(
            forget(&context, "new"),
            &BTreeSet::from([ids[3]]),
            &mut budget(),
        )
        .expect("atomic candidate retraction");
    assert_eq!(
        origins(&service, &context, "new", 2),
        BTreeSet::from([ids[2], ids[3]])
    );
    assert_eq!(
        read(&service, &context, "new", None)
            .expect("retracted revision")
            .document
            .lifecycle,
        MemoryLifecycle::Retracted
    );
    let replay = service
        .retract_from_sources(
            forget(&context, "new"),
            &BTreeSet::from([ids[3]]),
            &mut budget(),
        )
        .expect("retraction retry");
    assert!(replay.replayed);
    assert_eq!(replay.commit_seq, removed.commit_seq);
    service
        .verify_native(true)
        .expect("complete copied-origin and graph closure");
}

#[test]
fn partially_transferred_groups_keep_new_and_historical_records_closed_across_encrypted_restore() {
    for boundary in 0..3 {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("group-restore");
        let (_key_root, keys) = encryption::tests::authority("group-restore");
        let service = NativeService::open_encrypted(
            root.path().join("native"),
            "group-restore",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native");
        let (context, ids, old) = seed(&service);
        let request = proposal(&context, "new", &["parent"], &["old"]);
        let cancellation = QueryCancellation::default();
        let token = cancellation.clone();
        let hook: Box<dyn FnOnce()> = Box::new(move || token.cancel());
        match boundary {
            0 => AFTER_NATIVE_SYNC.with(|slot| slot.replace(Some(hook))),
            1 => AFTER_ORIGIN_SYNC.with(|slot| slot.replace(Some(hook))),
            _ => BEFORE_COMPLETION.with(|slot| slot.replace(Some(hook))),
        };
        let mut interrupted = QueryBudget::new(
            1_000_000,
            128 * 1024 * 1024,
            Duration::from_secs(30),
            cancellation,
        );
        service
            .propose_memory_from_sources(
                request.clone(),
                &BTreeSet::from([ids[2]]),
                &mut interrupted,
            )
            .expect_err("interrupt group transfer");
        let event = accepted(&service, PROPOSE).pop().expect("accepted group");
        catch_up(&service, &context);
        for (id, at) in [
            ("new", None),
            ("old", None),
            ("old", Some(old.mutation.commit_seq)),
        ] {
            assert_eq!(
                read(&service, &context, id, at)
                    .expect_err("whole group awaits completion")
                    .code,
                ErrorCode::IndexTooStale
            );
        }
        assert!(read(&service, &context, "parent", None).is_ok());
        service
            .verify_native(true)
            .expect("valid interrupted group");
        let archive = service
            .create_backup(CreateBackupRequest {
                context: context.clone(),
            })
            .expect("encrypted pending archive");
        service
            .append_event(input(5, "conversation can continue during handoff"))
            .expect("independent capture");
        let replay = service
            .propose_memory_from_sources(request, &BTreeSet::from([ids[2]]), &mut budget())
            .expect("same accepted group");
        assert!(replay.mutation.replayed);
        assert_eq!(replay.mutation.commit_seq, event.workspace_commit);
        assert_eq!(accepted(&service, PROPOSE).len(), 3);
        let restored = NativeService::open_encrypted(
            root.path().join("restored"),
            "group-restore",
            [7; 32],
            ledger,
            keys,
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore actual pending group");
        catch_up(&restored, &context);
        assert_eq!(
            read(&restored, &context, "new", None)
                .expect_err("manual catchup is not completion")
                .code,
            ErrorCode::IndexTooStale
        );
        restored
            .resume_record_source_write(&context, event.workspace_commit, &mut budget())
            .expect("recover without original request");
        assert!(read(&restored, &context, "new", None).is_ok());
        assert_eq!(
            origins(&restored, &context, "old", 2),
            BTreeSet::from([ids[1], ids[2]])
        );
        restored
            .verify_native(true)
            .expect("restored source group closure");
    }
}

#[test]
fn source_retraction_of_explicit_memory_copies_the_original_body_and_origins() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("explicit-retraction");
    let service =
        NativeService::open_with_suppression(root.path(), "explicit-retraction", [7; 32], ledger)
            .expect("native");
    let first = input(1, "original text");
    let second = input(2, "withdraw that memory");
    service
        .append_event(first.clone())
        .expect("original capture");
    service
        .append_event(second.clone())
        .expect("withdrawal capture");
    service
        .publish_memory_from_sources(
            publication(&first.context, "record"),
            &BTreeSet::from([first.event.event_id]),
            &mut budget(),
        )
        .expect("source-aware explicit memory");
    service
        .retract_from_sources(
            forget(&first.context, "record"),
            &BTreeSet::from([second.event.event_id]),
            &mut budget(),
        )
        .expect("versioned retraction");
    let record =
        record_sources::tests::get(&service, &first.context, "record").expect("retracted body");
    assert_eq!(record.revision, 2);
    assert_eq!(record.document.lifecycle, MemoryLifecycle::Retracted);
    assert_eq!(
        origins(&service, &first.context, "record", 2),
        BTreeSet::from([first.event.event_id, second.event.event_id])
    );
    service
        .verify_native(true)
        .expect("explicit retraction closure");
}

#[test]
fn hidden_incident_edge_cannot_be_omitted_or_decoded_by_source_aware_writers() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("hidden-edge");
    let service = NativeService::open_with_suppression(root.path(), "hidden-edge", [7; 32], ledger)
        .expect("native");
    let sources: Vec<_> = (1..=3)
        .map(|ordinal| input(ordinal, &format!("source{ordinal}")))
        .collect();
    for source in &sources {
        service.append_event(source.clone()).expect("capture");
    }
    let context = &sources[0].context;
    service
        .propose_memory(proposal(context, "parent", &[], &[]))
        .expect("legacy parent");
    let child = service
        .propose_memory(proposal(context, "child", &["parent"], &[]))
        .expect("legacy child");
    for (id, origin) in [
        ("parent", sources[0].event.event_id),
        ("child", sources[0].event.event_id),
        (
            child.candidate_edge_ids[0].as_str(),
            sources[1].event.event_id,
        ),
    ] {
        service
            .bind_record_sources(context, id, 1, &BTreeSet::from([origin]), &mut budget())
            .expect("complete migration declaration");
    }
    catch_up(&service, context);
    service
        .revoke_original(
            context,
            sources[1].event.event_id,
            "deny-edge-input",
            &mut budget(),
        )
        .expect("revoke only the edge input");
    catch_up(&service, context);
    let key = history_key(&digest_bytes(child.candidate_edge_ids[0].as_bytes()), 1);
    let mut tx = service.engine.begin_write().expect("transaction");
    let original = tx
        .get(&service.keyspaces.content_history, &key)
        .expect("read")
        .expect("edge body");
    tx.put(
        &service.keyspaces.content_history,
        key.clone(),
        b"malformed hidden edge".to_vec(),
    )
    .expect("fixture corruption");
    tx.commit(Durability::Sync).expect("commit");
    let new_sources = BTreeSet::from([sources[2].event.event_id]);
    assert_eq!(
        service
            .propose_memory_from_sources(
                proposal(context, "new", &["parent"], &[]),
                &new_sources,
                &mut budget()
            )
            .expect_err("graph cannot silently omit a hidden edge")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        service
            .retract_from_sources(forget(context, "parent"), &new_sources, &mut budget())
            .expect_err("source authorization precedes edge body decoding")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(accepted(&service, PROPOSE).is_empty());
    assert!(accepted(&service, RETRACT).is_empty());
    assert_eq!(
        read(&service, context, "parent", None)
            .expect("target unchanged")
            .document
            .lifecycle,
        MemoryLifecycle::Active
    );
    let mut tx = service.engine.begin_write().expect("transaction");
    tx.put(&service.keyspaces.content_history, key, original)
        .expect("restore fixture");
    tx.commit(Durability::Sync).expect("commit");
    service
        .verify_native(true)
        .expect("no partial structural mutation");
}

#[test]
fn source_union_overflow_rejects_the_whole_group_before_native_acceptance() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("group-bound");
    let service = NativeService::open_with_suppression(root.path(), "group-bound", [7; 32], ledger)
        .expect("native");
    let context = input(1, "input").context;
    let mut sources = BTreeSet::new();
    for ordinal in 1..=65 {
        let source = input(ordinal, &format!("input{ordinal}"));
        sources.insert(source.event.event_id);
        service.append_event(source).expect("capture");
    }
    let newest = sources.pop_last().expect("new trigger");
    service
        .propose_memory_from_sources(proposal(&context, "old", &[], &[]), &sources, &mut budget())
        .expect("64 complete input origins");
    let before = service.verify_native(false).expect("head").commit_seq;
    assert_eq!(
        service
            .propose_memory_from_sources(
                proposal(&context, "new", &[], &["old"]),
                &BTreeSet::from([newest]),
                &mut budget()
            )
            .expect_err("65 copied origins cannot be truncated")
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        service.verify_native(false).expect("head").commit_seq,
        before
    );
    assert_eq!(
        read(&service, &context, "old", None)
            .expect("predecessor unchanged")
            .document
            .lifecycle,
        MemoryLifecycle::Active
    );
    assert_eq!(
        read(&service, &context, "new", None)
            .expect_err("successor rolled back")
            .code,
        ErrorCode::NotFound
    );
    service
        .verify_native(true)
        .expect("no accepted partial group");
}
