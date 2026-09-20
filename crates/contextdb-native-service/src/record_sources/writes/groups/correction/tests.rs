use std::time::Duration;

use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, CognitiveMemoryService, DomainTimeRange, MemoryLinks};

use super::super::tests::{accepted, origins};
use super::*;
use crate::record_sources::tests::{budget, catch_up, get, input, publication};

struct Fixture {
    context: AuthenticatedRequestContext,
    sources: Vec<ObservationId>,
    request: CorrectRequest,
    edges: Vec<MemoryDocument>,
    before: u64,
}

fn seed(service: &NativeService) -> Fixture {
    seed_with_left_origins(service, 1)
}

#[test]
fn record_pruning_preserves_correction_copy_proofs_and_independent_successors() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_directory, ledger) = suppression::tests::authority("pruned-correction");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "pruned-correction",
        [7; 32],
        ledger,
    )
    .expect("native");
    let f = seed(&service);
    let inputs = BTreeSet::from([f.sources[3]]);
    let mut original = service
        .correct_memory_from_sources(f.request.clone(), &inputs, &mut budget())
        .expect("correct");
    original.replayed = true;
    let new_left = hierarchy_edge_id("parent", "new").expect("left");
    let new_right = hierarchy_edge_id("new", "child").expect("right");
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let independent: Vec<_> = ["new", new_right.as_str(), f.edges[1].id.as_str()]
        .into_iter()
        .map(|id| {
            let key = history_key(&digest_bytes(id.as_bytes()), 1);
            let bytes = before
                .get(&service.keyspaces.content_history, &key)
                .expect("independent");
            (key, bytes)
        })
        .collect();
    let removal = service
        .request_original_removal(
            &f.context,
            &BTreeSet::from([f.sources[1]]),
            "remove-left",
            &mut budget(),
        )
        .expect("request");
    for id in [new_left.as_str(), f.edges[0].id.as_str()] {
        let witness = service
            .prepare_record_removal(&f.context, &removal, id, 1, f.sources[1], &mut budget())
            .expect("witness");
        service
            .prune_record_revision(&f.context, &witness, &mut budget())
            .expect("prune copied edge");
        service
            .verify_native(true)
            .expect("correction copy proof after each erasure");
    }
    let after = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    for (key, bytes) in independent {
        assert_eq!(
            after
                .get(&service.keyspaces.content_history, &key)
                .expect("independent"),
            bytes
        );
    }
    assert_eq!(
        service
            .correct_memory_from_sources(f.request, &inputs, &mut budget())
            .expect("original correction receipt"),
        original
    );
}

fn seed_with_left_origins(service: &NativeService, left_origins: usize) -> Fixture {
    let context = input(1, "original").context;
    let mut sources = Vec::new();
    for ordinal in 1..=(left_origins as u64 + 4) {
        let source = input(ordinal, &format!("independent source {ordinal}"));
        sources.push(source.event.event_id);
        service.append_event(source).expect("capture");
    }
    for id in ["parent", "old", "child"] {
        service
            .publish_memory(publication(&context, id))
            .expect("legacy vertex");
    }
    let old = get(service, &context, "old").expect("old target");
    let mut edges = Vec::new();
    // Import a valid legacy canonical hierarchy, with distinct captured inputs
    // for each edge. The public proposal port intentionally cannot publish it.
    for (source, target) in [("parent", "old"), ("old", "child")] {
        let mut document = old.document.clone();
        document.id = hierarchy_edge_id(source, target).expect("edge ID");
        document.kind = MemoryRecordKind::Edge;
        document.links = MemoryLinks {
            source: Some(source.into()),
            target: Some(target.into()),
            predicate: Some(HIERARCHY_PARENT_PREDICATE.into()),
            evidence: BTreeSet::from([format!("evidence-{source}-{target}")]),
            supersedes: BTreeSet::from([format!("older-{source}-{target}")]),
            ..MemoryLinks::default()
        };
        document.valid_time = DomainTimeRange {
            from: Some(10),
            to: Some(20),
        };
        document.attributes.insert(
            "copied".into(),
            serde_json::json!(format!("{source}/{target}")),
        );
        document.value = serde_json::json!({"legacy_edge": [source, target]});
        document.search_text = None;
        let mut tx = service.engine.begin_write().expect("transaction");
        let mut frame = service
            .begin_frame(&tx, &context.request.workspace_id, true)
            .expect("frame");
        frame.state.watermarks.graph = frame.state.watermarks.journal;
        let record = MemoryRecord {
            document: document.clone(),
            revision: 1,
            transaction_from: frame.global_commit,
            transaction_to: None,
        };
        service
            .put_record(&mut tx, &policy_for(&record).expect("policy"), &record)
            .expect("record");
        let digest = canonical_digest(&document).expect("digest");
        let key =
            authenticated_idempotency_key("publish_memory", &context, &document.id).expect("key");
        let response = MutationResponse {
            commit_seq: frame.state.watermarks.journal,
            replayed: false,
            request_digest: digest.clone(),
            watermarks: frame.state.watermarks.clone(),
        };
        service
            .finish_frame(&mut tx, &frame, "publish_memory", &key, &digest, &response)
            .expect("journal");
        tx.commit(Durability::Sync).expect("commit");
        edges.push(document);
    }
    for (id, index) in [
        ("old", 0),
        ("parent", 4),
        ("child", 4),
        (&edges[0].id, 1),
        (&edges[1].id, 2),
    ] {
        let mut inputs = BTreeSet::from([sources[index]]);
        if index == 1 {
            inputs.extend(&sources[5..]);
        }
        service
            .bind_record_sources(&context, id, 1, &inputs, &mut budget())
            .expect("complete migration declaration");
    }
    catch_up(service, &context);
    service
        .verify_native(true)
        .expect("valid legacy hierarchy and provenance");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let before = service
        .workspace_state(&snapshot, &context.request.workspace_id)
        .expect("workspace")
        .watermarks
        .journal;
    let mut replacement = old.document;
    replacement.id = "new".into();
    replacement.value = serde_json::json!({"text": "fully supplied correction"});
    replacement.search_text = Some("fully supplied correction".into());
    replacement.links.supersedes.insert("old".into());
    Fixture {
        context: context.clone(),
        sources,
        edges,
        before,
        request: CorrectRequest {
            context,
            idempotency_key: "correction".into(),
            target_id: "old".into(),
            replacement,
        },
    }
}

fn read_at(
    service: &NativeService,
    fixture: &Fixture,
    id: &str,
    at: Option<u64>,
) -> ServiceResult<MemoryRecord> {
    service
        .get_timeline(GetTimelineRequest {
            context: fixture.context.clone(),
            record_id: id.into(),
            expected_kind: if id.starts_with("hierarchy-edge:") {
                MemoryRecordKind::Edge
            } else {
                MemoryRecordKind::SemanticObject
            },
            at_commit: at,
            max_revisions: 10,
        })
        .and_then(|timeline| timeline.revisions.into_iter().next().ok_or_else(not_found))
}

fn new_edges() -> [String; 2] {
    [
        hierarchy_edge_id("parent", "new").expect("left edge"),
        hierarchy_edge_id("new", "child").expect("right edge"),
    ]
}

fn interrupt(service: &NativeService, fixture: &Fixture, boundary: usize) -> StoredEvent {
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
    let error = service
        .correct_memory_from_sources(
            fixture.request.clone(),
            &BTreeSet::from([fixture.sources[3]]),
            &mut interrupted,
        )
        .expect_err("interrupted handoff");
    let event = accepted(service, CORRECT)
        .pop()
        .expect("accepted correction");
    assert_eq!(
        error.partial_result_refs.as_ref(),
        [format!(
            "record-write:{}:{}",
            event.workspace_digest, event.workspace_commit
        )]
    );
    event
}

#[test]
fn correction_copies_each_edges_origins_and_keeps_the_supplied_successor_independent() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("correction-origins");
    let service =
        NativeService::open_with_suppression(root.path(), "correction-origins", [7; 32], ledger)
            .expect("native");
    let fixture = seed(&service);
    let inputs = BTreeSet::from([fixture.sources[3]]);
    let response = service
        .correct_memory_from_sources(fixture.request.clone(), &inputs, &mut budget())
        .expect("correct");
    let event = accepted(&service, CORRECT).pop().expect("one group");
    assert_eq!(event.accepted_records.len(), 6);
    assert_eq!(origins(&service, &fixture.context, "new", 1), inputs);
    let ids = new_edges();
    for (index, id) in ids.iter().enumerate() {
        let old = &fixture.edges[index];
        let new = read_at(&service, &fixture, id, None).expect("rewired edge");
        assert_eq!(
            origins(&service, &fixture.context, id, 1),
            BTreeSet::from([fixture.sources[index + 1], fixture.sources[3]])
        );
        assert_eq!(new.document.attributes, old.attributes);
        assert_eq!(new.document.valid_time, old.valid_time);
        assert_eq!(new.document.links.evidence, old.links.evidence);
        assert_eq!(
            new.document.links.supersedes,
            old.links
                .supersedes
                .union(&BTreeSet::from([old.id.clone()]))
                .cloned()
                .collect()
        );
        assert_eq!(
            read_at(&service, &fixture, &old.id, None)
                .expect("closed edge")
                .transaction_to,
            Some(event.global_commit)
        );
    }
    assert_eq!(
        read_at(&service, &fixture, "old", None)
            .expect("closed target")
            .transaction_to,
        Some(event.global_commit)
    );
    assert_eq!(
        read_at(&service, &fixture, "old", Some(fixture.before))
            .expect("history")
            .transaction_to,
        None
    );
    let mut replay = service
        .correct_memory_from_sources(fixture.request.clone(), &inputs, &mut budget())
        .expect("exact retry");
    assert!(replay.replayed);
    replay.replayed = false;
    assert_eq!(replay, response);
    for source in [fixture.sources[0], fixture.sources[1]] {
        service
            .revoke_original(
                &fixture.context,
                source,
                &format!("withdraw-copy-source-{source}"),
                &mut budget(),
            )
            .expect("revoke");
        catch_up(&service, &fixture.context);
    }
    assert_eq!(
        read_at(&service, &fixture, &ids[0], None)
            .expect_err("copied source remains binding")
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        read_at(&service, &fixture, "old", Some(fixture.before))
            .expect_err("historical source also denied")
            .code,
        ErrorCode::NotFound
    );
    for id in ["new", "parent", "child", &ids[1]] {
        read_at(&service, &fixture, id, None).expect("independent input remains readable");
    }
    assert!(
        service
            .correct_memory_from_sources(fixture.request, &inputs, &mut budget())
            .expect("accepted retry survives withdrawal")
            .replayed
    );
    assert_eq!(accepted(&service, CORRECT).len(), 1);
    service
        .verify_native(true)
        .expect("complete correction with revocations");
}

#[test]
fn interrupted_correction_closes_the_whole_group_and_restores_exact_copy_witnesses() {
    for boundary in 0..3 {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("correction-recovery");
        let (_custody, keys) = encryption::tests::authority("correction-recovery");
        let service = NativeService::open_encrypted(
            root.path().join("native"),
            "correction-recovery",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native");
        let fixture = seed(&service);
        let event = interrupt(&service, &fixture, boundary);
        catch_up(&service, &fixture.context);
        for id in [
            "new",
            "old",
            &new_edges()[0],
            &new_edges()[1],
            &fixture.edges[0].id,
            &fixture.edges[1].id,
        ] {
            assert_eq!(
                read_at(&service, &fixture, id, None)
                    .expect_err("group awaits completion")
                    .code,
                ErrorCode::IndexTooStale
            );
        }
        assert_eq!(
            read_at(&service, &fixture, "old", Some(fixture.before))
                .expect_err("historical closure also waits")
                .code,
            ErrorCode::IndexTooStale
        );
        get(&service, &fixture.context, "parent").expect("unmodified vertex remains available");
        service
            .verify_native(true)
            .expect("valid pending correction");
        let backup = service
            .create_backup(CreateBackupRequest {
                context: fixture.context.clone(),
            })
            .expect("pending encrypted backup");
        service
            .append_event(input(6, "capture can continue during correction repair"))
            .expect("capture");
        let restored = NativeService::open_encrypted(
            root.path().join("restored"),
            "correction-recovery",
            [7; 32],
            ledger,
            keys,
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: fixture.context.clone(),
                format: backup.format,
                bytes: backup.bytes,
                digest: backup.digest,
            })
            .expect("restore");
        catch_up(&restored, &fixture.context);
        assert_eq!(
            get(&restored, &fixture.context, "new")
                .expect_err("restore cannot invent completion")
                .code,
            ErrorCode::IndexTooStale
        );
        let receipt = restored
            .resume_record_source_write(&fixture.context, event.workspace_commit, &mut budget())
            .expect("recover without original request");
        assert_eq!(receipt.commit_seq, event.workspace_commit);
        assert_eq!(
            restored
                .resume_record_source_write(&fixture.context, event.workspace_commit, &mut budget())
                .expect("repeat recovery"),
            receipt
        );
        get(&restored, &fixture.context, "new").expect("completed successor");
        for (index, id) in new_edges().iter().enumerate() {
            read_at(&restored, &fixture, id, None).expect("completed edge");
            assert_eq!(
                origins(&restored, &fixture.context, id, 1),
                BTreeSet::from([fixture.sources[index + 1], fixture.sources[3]])
            );
        }
        restored
            .verify_native(true)
            .expect("verified restored correction");
    }
}

#[test]
fn rehashed_wrong_or_incomplete_copy_witnesses_are_rejected_before_transfer() {
    for corruption in ["missing", "swapped", "target", "origin"] {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("correction-corruption");
        let service = NativeService::open_with_suppression(
            root.path(),
            "correction-corruption",
            [7; 32],
            ledger.clone(),
        )
        .expect("native");
        let fixture = seed(&service);
        let mut event = interrupt(&service, &fixture, 0);
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
        let correction = intent
            .group
            .as_mut()
            .expect("group")
            .correction
            .as_mut()
            .expect("correction");
        match corruption {
            "missing" => {
                correction.rewires.pop_first();
            }
            "swapped" => {
                let keys: Vec<_> = correction.rewires.keys().cloned().collect();
                let first = correction.rewires[&keys[0]].clone();
                let second = correction.rewires[&keys[1]].clone();
                correction.rewires.insert(keys[0].clone(), second);
                correction.rewires.insert(keys[1].clone(), first);
            }
            "target" => {
                correction.target = correction.rewires.values().next().expect("edge").clone()
            }
            _ => {
                intent
                    .origins
                    .iter_mut()
                    .find(|control| {
                        control.record_digest == digest_bytes(new_edges()[0].as_bytes())
                    })
                    .expect("copied edge")
                    .sources
                    .remove(&fixture.sources[1]);
            }
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
        .expect("intent fixture");
        tx.put(
            &service.keyspaces.events,
            event.global_commit.to_be_bytes().to_vec(),
            encode(&event).expect("encode"),
        )
        .expect("event fixture");
        tx.commit(Durability::Sync).expect("commit");
        assert_eq!(
            service
                .resume_record_source_write(&fixture.context, event.workspace_commit, &mut budget())
                .expect_err("exact copy proof required")
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
                    .expect("lookup")
                    .is_none()
            );
        }
    }
}

#[test]
fn correction_denies_target_and_incident_edge_sources_before_body_decoding() {
    for target in [true, false] {
        let root = tempfile::tempdir().expect("root");
        let (_authority, ledger) = suppression::tests::authority("correction-denial");
        let service =
            NativeService::open_with_suppression(root.path(), "correction-denial", [7; 32], ledger)
                .expect("native");
        let fixture = seed(&service);
        let inputs = BTreeSet::from([fixture.sources[3]]);
        let mut no_admin = fixture.request.clone();
        no_admin
            .context
            .capability_grants
            .remove(&Capability::Admin);
        assert_eq!(
            service
                .correct_memory_from_sources(no_admin, &inputs, &mut budget())
                .expect_err("trusted host grant required")
                .code,
            ErrorCode::Unauthorized
        );
        let (id, source) = if target {
            ("old", fixture.sources[0])
        } else {
            (fixture.edges[0].id.as_str(), fixture.sources[1])
        };
        service
            .revoke_original(&fixture.context, source, "withdraw", &mut budget())
            .expect("revoke");
        catch_up(&service, &fixture.context);
        let key = history_key(&digest_bytes(id.as_bytes()), 1);
        let mut tx = service.engine.begin_write().expect("transaction");
        let bytes = tx
            .get(&service.keyspaces.content_history, &key)
            .expect("read")
            .expect("body");
        tx.put(
            &service.keyspaces.content_history,
            key.clone(),
            b"malformed denied body".to_vec(),
        )
        .expect("fixture");
        tx.commit(Durability::Sync).expect("commit");
        assert_eq!(
            service
                .correct_memory_from_sources(fixture.request, &inputs, &mut budget())
                .expect_err("denial precedes materialization")
                .code,
            ErrorCode::PermissionDenied
        );
        assert!(accepted(&service, CORRECT).is_empty());
        let mut tx = service.engine.begin_write().expect("transaction");
        tx.put(&service.keyspaces.content_history, key, bytes)
            .expect("restore fixture");
        tx.commit(Durability::Sync).expect("commit");
        service.verify_native(true).expect("no partial correction");
    }
}

#[test]
fn copied_edge_origin_overflow_rejects_the_complete_correction_before_acceptance() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("correction-overflow");
    let service =
        NativeService::open_with_suppression(root.path(), "correction-overflow", [7; 32], ledger)
            .expect("native");
    let fixture = seed_with_left_origins(&service, 64);
    let error = service
        .correct_memory_from_sources(
            fixture.request.clone(),
            &BTreeSet::from([fixture.sources[3]]),
            &mut budget(),
        )
        .expect_err("65 sources cannot be truncated");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(accepted(&service, CORRECT).is_empty());
    assert_eq!(
        get(&service, &fixture.context, "old")
            .expect("target unchanged")
            .transaction_to,
        None
    );
    assert_eq!(
        get(&service, &fixture.context, "new")
            .expect_err("successor absent")
            .code,
        ErrorCode::NotFound
    );
    for edge in &fixture.edges {
        assert_eq!(
            read_at(&service, &fixture, &edge.id, None)
                .expect("edge unchanged")
                .transaction_to,
            None
        );
    }
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        service
            .workspace_state(&snapshot, &fixture.context.request.workspace_id)
            .expect("state")
            .watermarks
            .journal,
        fixture.before
    );
    service
        .verify_native(true)
        .expect("complete transaction was rejected");
}

#[test]
fn concurrent_identical_corrections_accept_one_group_and_replay_the_exact_response() {
    use std::sync::{Arc, Barrier};
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("correction-concurrent");
    let service = Arc::new(
        NativeService::open_with_suppression(root.path(), "correction-concurrent", [7; 32], ledger)
            .expect("native"),
    );
    let fixture = seed(&service);
    let gate = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let service = service.clone();
            let gate = gate.clone();
            let request = fixture.request.clone();
            let inputs = BTreeSet::from([fixture.sources[3]]);
            std::thread::spawn(move || {
                BEFORE_PUBLICATION.with(|slot| {
                    slot.replace(Some(Box::new(move || {
                        gate.wait();
                    })))
                });
                service
                    .correct_memory_from_sources(request, &inputs, &mut budget())
                    .expect("concurrent correction")
            })
        })
        .collect();
    let mut responses: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .collect();
    assert_ne!(responses[0].replayed, responses[1].replayed);
    for response in &mut responses {
        response.replayed = false;
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(accepted(&service, CORRECT).len(), 1);
    get(&service, &fixture.context, "new").expect("one completed successor");
    service
        .verify_native(true)
        .expect("one complete correction");
}

#[test]
fn source_aware_correction_without_hierarchy_edges_has_an_exact_target_witness() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("plain-correction");
    let service =
        NativeService::open_with_suppression(root.path(), "plain-correction", [7; 32], ledger)
            .expect("native");
    let old = input(1, "first fact");
    let new = input(2, "corrected fact");
    service.append_event(old.clone()).expect("capture");
    service.append_event(new.clone()).expect("capture");
    service
        .publish_memory_from_sources(
            publication(&old.context, "old"),
            &BTreeSet::from([old.event.event_id]),
            &mut budget(),
        )
        .expect("first fact");
    let mut replacement = get(&service, &old.context, "old")
        .expect("old fact")
        .document;
    replacement.id = "new".into();
    replacement.links.supersedes.insert("old".into());
    replacement.value = serde_json::json!({"text": "corrected fact"});
    replacement.search_text = Some("corrected fact".into());
    service
        .correct_memory_from_sources(
            CorrectRequest {
                context: new.context.clone(),
                idempotency_key: "correct".into(),
                target_id: "old".into(),
                replacement,
            },
            &BTreeSet::from([new.event.event_id]),
            &mut budget(),
        )
        .expect("correct");
    assert_eq!(accepted(&service, CORRECT)[0].accepted_records.len(), 2);
    assert_eq!(
        origins(&service, &new.context, "new", 1),
        BTreeSet::from([new.event.event_id])
    );
    service
        .verify_native(true)
        .expect("source-aware target birth and closure");
}
