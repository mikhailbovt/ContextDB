use super::*;
use crate::record_journal::controls::preparation::tests::strip_controls;

#[test]
fn nonretrievable_legacy_cleanup_preserves_policy_and_encrypted_archive_recovery() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("denied-legacy");
    let (_key_directory, keys) = encryption::tests::authority("denied-legacy");
    let path = root.path().join("native");
    let native = NativeService::open_encrypted(
        &path,
        "denied-legacy",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let captured = input(1, "removed original");
    let independent = input(2, "independent original");
    native.append_event(captured.clone()).expect("capture");
    native.append_event(independent.clone()).expect("capture");
    let context = captured.context;
    let source = captured.event.event_id;
    native
        .publish_memory(publication(&context, "independent"))
        .expect("seed");
    let independent_record = native
        .get_memory(GetMemoryRequest {
            context: context.clone(),
            record_id: "independent".into(),
            at_commit: None,
        })
        .expect("independent");
    // Import a valid denied legacy revision: the public publish port derives
    // retrievable labels. This fixture is not attributed to a historical binary.
    let mut record = independent_record.clone();
    record.document.id = "denied-record".into();
    record.document.access.retrievable = false;
    let mut tx = native.engine.begin_write().expect("transaction");
    let frame = native
        .begin_frame(&tx, &context.request.workspace_id, true)
        .expect("frame");
    record.transaction_from = frame.global_commit;
    native
        .put_record(&mut tx, &policy_for(&record).expect("policy"), &record)
        .expect("import");
    let request = canonical_digest(&record.document).expect("digest");
    let response = MutationResponse {
        commit_seq: frame.state.watermarks.journal,
        replayed: false,
        request_digest: request.clone(),
        watermarks: frame.state.watermarks.clone(),
    };
    native
        .finish_frame(
            &mut tx,
            &frame,
            "publish_memory",
            request.as_bytes(),
            &request,
            &response,
        )
        .expect("accept");
    tx.commit(Durability::Sync).expect("commit");
    strip_controls(&native);
    let old = native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("encrypted archive before classification and removal");
    let before = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let digest = digest_bytes(b"denied-record");
    let policy_key = history_key(&digest, 1);
    let policy_bytes = before
        .get(&native.keyspaces.policy_history, &policy_key)
        .expect("policy")
        .expect("policy row");
    let mutation_key = format!(
        "semantic/record/{:020}/{digest}/{:010}",
        record.transaction_from, 1
    )
    .into_bytes();
    let mutation_bytes = before
        .get(&native.keyspaces.continuous, &mutation_key)
        .expect("mutation")
        .expect("body");
    let mut tx = native.engine.begin_write().expect("transaction");
    tx.put(
        &native.keyspaces.continuous,
        mutation_key.clone(),
        b"corrupt body".to_vec(),
    )
    .expect("corruption fixture");
    tx.commit(Durability::Sync).expect("fixture");
    for restriction in ["admin", "scope", "purpose", "audience", "clearance"] {
        let mut denied = context.clone();
        match restriction {
            "admin" => {
                denied.capability_grants.remove(&Capability::Admin);
            }
            "scope" => {
                denied.request.scopes = BTreeSet::from(["outside".into()]);
            }
            "purpose" => {
                denied.request.purpose = "outside".into();
            }
            "audience" => {
                denied.request.subject_id = "outsider".into();
                denied.request.audiences.clear();
            }
            "clearance" => {
                denied.request.clearance = Sensitivity::Public;
            }
            _ => unreachable!(),
        }
        let expected = if restriction == "admin" {
            ErrorCode::Unauthorized
        } else {
            ErrorCode::PermissionDenied
        };
        assert_eq!(
            native
                .bind_record_sources(
                    &denied,
                    "denied-record",
                    1,
                    &BTreeSet::from([source]),
                    &mut budget()
                )
                .expect_err(restriction)
                .code,
            expected
        );
        assert_eq!(
            native
                .prepare_record_controls(&denied, response.commit_seq, &mut budget())
                .expect_err(restriction)
                .code,
            expected
        );
    }
    let mut tx = native.engine.begin_write().expect("transaction");
    tx.put(&native.keyspaces.continuous, mutation_key, mutation_bytes)
        .expect("restore original bytes");
    tx.commit(Durability::Sync).expect("restore fixture");
    native
        .bind_record_sources(
            &context,
            "independent",
            1,
            &BTreeSet::from([independent.event.event_id]),
            &mut budget(),
        )
        .expect("independent origin");
    let origin = native
        .bind_record_sources(
            &context,
            "denied-record",
            1,
            &BTreeSet::from([source]),
            &mut budget(),
        )
        .expect("classify denied revision");
    let preparation = native
        .prepare_record_controls(&context, response.commit_seq, &mut budget())
        .expect("prepare denied revision");
    native
        .maintain_record_sources(&context, 256, &mut budget())
        .expect("apply classified origins before testing the stored read policy");
    let prepared = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        prepared
            .get(&native.keyspaces.policy_history, &policy_key)
            .expect("policy"),
        Some(policy_bytes.clone())
    );
    assert_eq!(
        native
            .get_memory(GetMemoryRequest {
                context: context.clone(),
                record_id: "denied-record".into(),
                at_commit: None
            })
            .expect_err("ordinary disclosure remains denied")
            .code,
        ErrorCode::PermissionDenied
    );
    let targets = BTreeSet::from([source]);
    let removal = native
        .request_original_removal(&context, &targets, "remove", &mut budget())
        .expect("removal");
    let primary_keys = native
        .read_original_key_inventory(&context, &removal, &mut budget())
        .expect("primary keys before cleanup")
        .sources;
    assert_eq!(primary_keys.len(), 1);
    assert_eq!(primary_keys[&source].len(), 1);
    let witness = native
        .prepare_record_removal(
            &context,
            &removal,
            "denied-record",
            1,
            source,
            &mut budget(),
        )
        .expect("witness");
    native
        .prune_record_revision(&context, &witness, &mut budget())
        .expect("prune denied revision");
    assert_eq!(
        native
            .bind_record_sources(&context, "denied-record", 1, &targets, &mut budget())
            .expect("origin retry after erasure"),
        origin
    );
    assert_eq!(
        native
            .prepare_record_controls(&context, response.commit_seq, &mut budget())
            .expect("preparation retry after erasure"),
        preparation
    );
    native
        .prepare_original_removal_sources(&context, &removal, &targets, &mut budget())
        .expect("prepare original");
    native
        .maintain_custody(&context, 256, &mut budget())
        .expect("custody");
    native
        .project_originals(&context, true, 256, &mut budget())
        .expect("raw index");
    for _ in 0..10 {
        let progress = native
            .reclaim_raw_generations(&context, 1024, &mut budget())
            .expect("raw copies");
        if progress.finished && progress.retained_generations == 1 {
            break;
        }
    }
    native
        .prune_original_sources(&context, &removal, &targets, &mut budget())
        .expect("primary cleanup");
    native.verify_native(true).expect("encrypted cleanup");
    assert_eq!(
        native
            .read_original_key_inventory(&context, &removal, &mut budget())
            .expect("removed primary retains all allocated key identities")
            .sources,
        primary_keys
    );
    let cleaned = native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("cleaned encrypted archive");
    drop((before, prepared, native));
    let native = NativeService::open_encrypted(
        &path,
        "denied-legacy",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("actual encrypted reopen");
    native
        .verify_native(true)
        .expect("reopened encrypted cleanup");
    for (index, archive) in [old, cleaned].into_iter().enumerate() {
        let restored = NativeService::open_encrypted(
            root.path().join(format!("restore-{index}")),
            "denied-legacy",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("encrypted restore with current authority");
        restored
            .prepare_record_controls(&context, response.commit_seq, &mut budget())
            .expect("prepare or retry restored denied revision");
        restored
            .prune_record_revision(&context, &witness, &mut budget())
            .expect("prune or retry restored denied revision");
        restored
            .verify_native(true)
            .expect("restored encrypted graph/history");
        let snapshot = restored
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(
            snapshot
                .get(&restored.keyspaces.policy_history, &policy_key)
                .expect("policy"),
            Some(policy_bytes.clone())
        );
        let policy = restored
            .load_head(&snapshot, "independent")
            .expect("head")
            .expect("policy");
        assert_eq!(
            restored
                .load_content(&snapshot, &policy)
                .expect("retained independent record"),
            independent_record
        );
        assert!(
            restored
                .get_memory(GetMemoryRequest {
                    context: context.clone(),
                    record_id: "denied-record".into(),
                    at_commit: None
                })
                .is_err()
        );
    }
}
