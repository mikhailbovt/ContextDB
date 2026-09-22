use super::*;
use crate::capture::tests::request;
use contextdb_core::{
    EventKind, EventPayload, EventProvenance, EventRole, ModelCallId, ModelOutputFormat,
    ModelRequestManifest, OriginalSourceSpan, RequestPart,
};
use contextdb_service::{CapturePort, ReadOriginalRequest};

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        256 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        Default::default(),
    )
}

#[test]
fn primary_pruning_preserves_replay_across_partial_restart_and_both_archive_generations() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("primary-pruning");
    let (_keys_dir, keys) = encryption::tests::authority("primary-pruning");
    let path = root.path().join("native");
    let native = NativeService::open_encrypted(
        &path,
        "primary-pruning",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let source = request(1, "originalsecretprunex");
    native.append_event(source.clone()).expect("capture source");
    let mut call = request(2, "placeholder");
    let call_id = ModelCallId::new();
    let source_digest = source.event.payload.digest().expect("digest");
    call.context.capability_grants.insert(Capability::Runtime);
    call.event.role = EventRole::Host;
    call.event.kind = EventKind::ModelRequested;
    call.event.run_id = Some(contextdb_core::AgentRunId::new());
    call.event.session_id = Some(contextdb_core::SessionId::new());
    call.event.provenance = Some(EventProvenance::ModelRequest {
        model_call_id: call_id,
    });
    call.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id: call_id,
            renderer: "renderer-secret-pruned".into(),
            wire_digest: source_digest,
            byte_length: 20,
            parts: vec![RequestPart::Source {
                span: OriginalSourceSpan {
                    event_id: source.event.event_id,
                    payload_digest: source_digest,
                    start: 0,
                    end: 20,
                    span_digest: source_digest,
                },
            }],
        },
    };
    native.append_event(call.clone()).expect("captured request");
    let mut output = request(3, "derivedsecretpruney");
    output.context.capability_grants.insert(Capability::Runtime);
    output.event.role = EventRole::Assistant;
    output.event.kind = EventKind::ModelResponseCompleted;
    output.event.run_id = call.event.run_id;
    output.event.session_id = call.event.session_id;
    output.event.provenance = Some(EventProvenance::ModelOutput {
        model_call_id: call_id,
        request_event_id: call.event.event_id,
        format: ModelOutputFormat::PlainText,
        tool_calls: Vec::new(),
    });
    output.event.parent_event_ids.insert(call.event.event_id);
    native.append_event(output.clone()).expect("output");
    let independent = request(4, "independentretainedz");
    native
        .append_event(independent.clone())
        .expect("independent");
    native
        .project_originals(&source.context, false, 256, &mut budget())
        .expect("old index");
    let old = native
        .create_backup(CreateBackupRequest {
            context: source.context.clone(),
        })
        .expect("old archive");
    let old_logical = native
        .verify_native(true)
        .expect("old logical closure")
        .archive_digest;
    let removal = native
        .request_original_removal(
            &source.context,
            &BTreeSet::from([source.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("removal");
    let targets = BTreeSet::from([
        source.event.event_id,
        call.event.event_id,
        output.event.event_id,
    ]);
    let key_witness = native
        .retain_original_key_removal(&source.context, &removal, &mut budget())
        .expect("retain original version decisions before pruning");
    assert_eq!(
        key_witness
            .dispositions
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        targets
    );
    native
        .prepare_original_removal_sources(&source.context, &removal, &targets, &mut budget())
        .expect("prepare all sources");
    native
        .maintain_custody(&source.context, 256, &mut budget())
        .expect("denied custody");
    assert_eq!(
        native
            .prune_original_sources(
                &source.context,
                &removal,
                &BTreeSet::from([source.event.event_id]),
                &mut budget()
            )
            .expect_err("old index needs originals")
            .code,
        ErrorCode::IndexTooStale
    );
    native
        .project_originals(&source.context, true, 256, &mut budget())
        .expect("index without sources");
    for _ in 0..10 {
        let progress = native
            .reclaim_raw_generations(&source.context, 1024, &mut budget())
            .expect("reclaim");
        if progress.finished && progress.retained_generations == 1 {
            break;
        }
    }
    let first = native
        .prune_original_sources(
            &source.context,
            &removal,
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("first primary deletion");
    let partial = native
        .verify_native(true)
        .expect("assembly and output bodies still verify from prepared control");
    drop(native);
    let native = NativeService::open_encrypted(
        &path,
        "primary-pruning",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen partial pruning");
    assert_eq!(
        native
            .prune_original_sources(
                &source.context,
                &removal,
                &BTreeSet::from([source.event.event_id]),
                &mut budget()
            )
            .expect("first retry"),
        first
    );
    assert_eq!(
        native
            .verify_native(true)
            .expect("same partial state")
            .archive_digest,
        partial.archive_digest
    );
    native
        .prune_original_sources(
            &source.context,
            &removal,
            &BTreeSet::from([call.event.event_id]),
            &mut budget(),
        )
        .expect("prune request before output");
    native
        .verify_native(true)
        .expect("output witness survives request pruning");
    native
        .prune_original_sources(
            &source.context,
            &removal,
            &BTreeSet::from([output.event.event_id]),
            &mut budget(),
        )
        .expect("prune output");
    let pruned_witness = native
        .retain_original_key_removal(&source.context, &removal, &mut budget())
        .expect("retain decisions after native pruning");
    assert!(
        pruned_witness
            .dispositions
            .values()
            .flatten()
            .all(
                |key| key.action == NativePrimaryKeyAction::AssessRetainedCopies
                    && key.acknowledged_instances.is_empty()
                    && !key.versions.is_empty()
            )
    );
    assert_eq!(
        native
            .read_original_key_removal(
                &source.context,
                &removal,
                &key_witness.receipt,
                &mut budget()
            )
            .expect("old acknowledged copies remain historical evidence"),
        key_witness
    );
    let clean = native
        .create_backup(CreateBackupRequest {
            context: source.context.clone(),
        })
        .expect("new archive verifies remaining bytes");
    assert_ne!(
        native
            .verify_native(true)
            .expect("new logical closure")
            .archive_digest,
        old_logical
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    for id in &targets {
        assert!(
            snapshot
                .get(
                    &native.keyspaces.observations_content,
                    digest_bytes(id.to_string().as_bytes()).as_bytes()
                )
                .expect("row")
                .is_none()
        );
    }
    assert_eq!(
        native
            .load_captured_original(&snapshot, independent.event.event_id)
            .expect("independent exact original")
            .event,
        independent.event
    );
    for keyspace in native.keyspaces.all() {
        for row in snapshot.scan_prefix(keyspace, b"").expect("logical rows") {
            let text = String::from_utf8_lossy(&row.value);
            assert!(
                !text.contains("originalsecretprunex")
                    && !text.contains("derivedsecretpruney")
                    && !text.contains("renderer-secret-pruned")
            );
        }
    }
    drop(snapshot);
    let later_removal = native
        .request_original_removal(
            &source.context,
            &BTreeSet::from([independent.event.event_id]),
            "remove independent later",
            &mut budget(),
        )
        .expect("new lineage inspection crosses pruned history");
    native
        .prepare_original_removal_sources(
            &source.context,
            &later_removal,
            &BTreeSet::from([independent.event.event_id]),
            &mut budget(),
        )
        .expect("later preparation");
    native
        .maintain_custody(&source.context, 1, &mut budget())
        .expect("replay pruned first source");
    native
        .maintain_custody(&source.context, 256, &mut budget())
        .expect("finish custody after pruning");
    native
        .verify_native(true)
        .expect("later revocation replays pruned metadata");
    for (name, archive) in [("old", old), ("new", clean)] {
        let restored = NativeService::open_encrypted(
            root.path().join(name),
            "primary-pruning",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: source.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore exact archive");
        restored.verify_native(true).expect("restored closure");
        for witness in [&key_witness, &pruned_witness] {
            assert_eq!(
                restored
                    .read_original_key_removal(
                        &source.context,
                        &removal,
                        &witness.receipt,
                        &mut budget()
                    )
                    .expect("saved decisions survive both archive generations"),
                *witness
            );
        }
        let current_keys = restored
            .retain_original_key_removal(&source.context, &removal, &mut budget())
            .expect("fresh decisions include restored old copies");
        assert!(
            current_keys
                .dispositions
                .values()
                .flatten()
                .all(
                    |key| key.action == NativePrimaryKeyAction::RemoveAcknowledgedCopies
                        && key.acknowledged_instances.len() == 1
                )
        );
        assert_eq!(
            restored
                .read_original(ReadOriginalRequest {
                    context: source.context.clone(),
                    event_id: source.event.event_id,
                    after_receipt: None
                })
                .expect_err("archive cannot reopen disclosure")
                .code,
            ErrorCode::IndexTooStale
        );
        if name == "new" {
            assert_eq!(
                restored
                    .prune_original_sources(
                        &source.context,
                        &removal,
                        &BTreeSet::from([source.event.event_id]),
                        &mut budget()
                    )
                    .expect("restored exact cleanup receipt"),
                first
            );
        }
    }
}

#[test]
fn undeclared_body_loss_marker_loss_resurrection_and_changed_policy_fail_verification() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("prune-damage");
    let native = NativeService::open_with_suppression(root.path(), "prune-damage", [7; 32], ledger)
        .expect("native");
    let source = request(1, "body corruption sentinel");
    native.append_event(source.clone()).expect("source");
    let removal = native
        .request_original_removal(
            &source.context,
            &BTreeSet::from([source.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    native
        .prepare_original_removal_sources(
            &source.context,
            &removal,
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("prepare");
    native
        .maintain_custody(&source.context, 256, &mut budget())
        .expect("custody");
    let observation = digest_bytes(source.event.event_id.to_string().as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let body = snapshot
        .get(
            &native.keyspaces.observations_content,
            observation.as_bytes(),
        )
        .expect("body")
        .expect("present");
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(
        &native.keyspaces.observations_content,
        observation.as_bytes().to_vec(),
    )
    .expect("remove undeclared");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("missing body is not pruning")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.observations_content,
        observation.as_bytes().to_vec(),
        body.clone(),
    )
    .expect("repair");
    tx.commit(Durability::Sync).expect("commit");
    native
        .prune_original_sources(
            &source.context,
            &removal,
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("prune");
    native.verify_native(true).expect("pruned closure");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let marker = snapshot
        .get(&native.keyspaces.continuous, &pruned_key(&observation))
        .expect("marker")
        .expect("present");
    let policy = native
        .pruning_policy(&snapshot, source.event.event_id)
        .expect("policy");
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(&native.keyspaces.continuous, pruned_key(&observation))
        .expect("lose marker");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native.verify_native(true).expect_err("lost marker").code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        pruned_key(&observation),
        marker,
    )
    .expect("restore marker");
    tx.put(
        &native.keyspaces.observations_content,
        observation.as_bytes().to_vec(),
        body,
    )
    .expect("resurrect body");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("tombstoned body resurrected")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(
        &native.keyspaces.observations_content,
        observation.as_bytes().to_vec(),
    )
    .expect("repair body");
    let mut changed = policy.clone();
    changed.content_digest = "a".repeat(64);
    tx.put(
        &native.keyspaces.observations_policy,
        observation.as_bytes().to_vec(),
        encode(&changed).expect("policy"),
    )
    .expect("change policy");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("original policy commitment changed")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.observations_policy,
        observation.as_bytes().to_vec(),
        encode(&policy).expect("policy"),
    )
    .expect("repair policy");
    tx.commit(Durability::Sync).expect("commit");
    native
        .verify_native(true)
        .expect("repaired exact tombstone");
    let overlap = native
        .request_original_removal(
            &source.context,
            &BTreeSet::from([source.event.event_id]),
            "overlapping request",
            &mut budget(),
        )
        .expect("inspect pruned source again");
    native
        .prepare_original_removal_sources(
            &source.context,
            &overlap,
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("prepare existing tombstone under new request");
    native
        .maintain_custody(&source.context, 256, &mut budget())
        .expect("overlap custody");
    native
        .prune_original_sources(
            &source.context,
            &overlap,
            &BTreeSet::from([source.event.event_id]),
            &mut budget(),
        )
        .expect("overlap preserves first tombstone");
    native
        .verify_native(true)
        .expect("both request publications remain bound");
}

#[test]
fn concurrent_capture_and_exhausted_budget_leave_no_partial_pruning() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("prune-race");
    let native = std::sync::Arc::new(
        NativeService::open_with_suppression(root.path(), "prune-race", [7; 32], ledger)
            .expect("native"),
    );
    let source = request(1, "source remains on failed pruning");
    native.append_event(source.clone()).expect("source");
    let ids = BTreeSet::from([source.event.event_id]);
    let removal = native
        .request_original_removal(&source.context, &ids, "remove", &mut budget())
        .expect("request");
    native
        .prepare_original_removal_sources(&source.context, &removal, &ids, &mut budget())
        .expect("prepare");
    native
        .maintain_custody(&source.context, 256, &mut budget())
        .expect("custody");
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        native
            .prune_original_sources(&source.context, &removal, &ids, &mut empty)
            .is_err()
    );
    let competing = native.clone();
    BEFORE_PUBLICATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            competing
                .append_event(request(2, "concurrent independent capture"))
                .expect("append between analysis and publication");
        }))
    });
    assert_eq!(
        native
            .prune_original_sources(&source.context, &removal, &ids, &mut budget())
            .expect_err("changed accepted history")
            .code,
        ErrorCode::IndexTooStale
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        native
            .load_captured_original(&snapshot, source.event.event_id)
            .expect("still present")
            .event,
        source.event
    );
    assert!(
        snapshot
            .scan_prefix(&native.keyspaces.continuous, b"removal/pruned/")
            .expect("markers")
            .is_empty()
    );
    drop(snapshot);
    native
        .prune_original_sources(&source.context, &removal, &ids, &mut budget())
        .expect("retry with current world");
    native.verify_native(true).expect("no half pruning");
}
