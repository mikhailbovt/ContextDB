use super::*;
use crate::capture::tests::request;
use contextdb_service::{CapturePort, CreateBackupRequest, RestoreBackupRequest};

#[test]
fn retained_multi_chunk_inventory_rejects_missing_targets_and_a_rehashed_partial_copy() {
    let root = tempfile::tempdir().expect("root");
    let ledger_path = root.path().join("ledger");
    let ledger = NativeSuppressionLedger::create(&ledger_path, "inventory").expect("ledger");
    let authority = ledger.authority_id();
    let native = NativeService::open_with_suppression(
        root.path().join("native"),
        "inventory",
        [7; 32],
        ledger.clone(),
    )
    .expect("native");
    let first = request(
        1,
        "source inventory content stays in the native original only",
    );
    native.append_event(first.clone()).expect("first");
    let mut previous = first.event.event_id;
    for sequence in 2..=520 {
        let mut input = request(
            sequence,
            "source inventory content stays in the native original only",
        );
        input.event.supersedes_event_id = Some(previous);
        previous = input.event.event_id;
        native.append_event(input).expect("descendant");
    }
    let mut budget = inventory::verification_budget();
    let roots = BTreeSet::from([first.event.event_id]);
    let receipt = native
        .request_original_removal(&first.context, &roots, "all", &mut budget)
        .expect("request with exact inventory");
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let event = ledger
        .read_removal_event(&snapshot, receipt.sequence)
        .expect("event");
    let Operation::Request { intent } = event.operation else {
        panic!("request expected")
    };
    let retained = ledger
        .read_removal_inventory(&snapshot, &intent, &mut budget)
        .expect("inventory");
    assert_eq!(retained.sources.len(), 520);
    assert!(
        encode(&retained).expect("bytes").len() > 256 * 1024,
        "cross a storage chunk"
    );
    assert!(
        !String::from_utf8(encode(&retained).expect("bytes"))
            .expect("JSON")
            .contains("content stays in the native original")
    );
    let stored_rows = inventory::rows(&retained, &mut budget).expect("rows");
    let last_denial = denied_key(&intent.workspace, previous);
    let denial = snapshot
        .get(&ledger.rows, &last_denial)
        .expect("get")
        .expect("denial");
    drop(snapshot);
    drop(native);
    ledger.verify().expect("complete retained closure");
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.delete(&ledger.rows, last_denial.clone())
        .expect("lose descendant denial");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger.verify().expect_err("missing target deny").code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(&ledger.rows, last_denial, denial)
        .expect("repair fixture");
    // The chunk header is recomputed, so only the request's retained commitment
    // can expose this forged inventory that quietly drops its last descendant.
    let mut partial = retained.clone();
    partial.sources.pop();
    for (key, value) in inventory::rows(&partial, &mut budget).expect("forged chunks") {
        tx.put(&ledger.rows, key, value).expect("mutate");
    }
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger
            .verify()
            .expect_err("request commitment catches omitted target")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    for (key, value) in &stored_rows {
        tx.put(&ledger.rows, key.clone(), value.clone())
            .expect("repair fixture");
    }
    tx.commit(Durability::Sync).expect("repair");
    ledger.verify().expect("repaired fixture");
    let mut tx = ledger.engine.begin_write().expect("tx");
    for key in stored_rows.keys() {
        tx.delete(&ledger.rows, key.clone())
            .expect("lose full inventory");
    }
    tx.commit(Durability::Sync).expect("commit");
    drop(ledger);
    assert_eq!(
        NativeSuppressionLedger::open(ledger_path, "inventory", authority)
            .expect_err("whole family loss is not an empty inventory")
            .code,
        ErrorCode::IntegrityFailure
    );
}

fn create_legacy(path: &Path, database: &str) -> Arc<NativeSuppressionLedger> {
    std::fs::create_dir(path).expect("directory");
    let engine = FjallStorage::open(path).expect("engine");
    let rows = keyspace("contextdb_suppression").expect("rows");
    let identity = Identity {
        version: 1,
        authority: ObservationId::new().as_uuid(),
        database: digest_bytes(database.as_bytes()),
    };
    let mut tx = engine.begin_write().expect("tx");
    tx.put(
        &rows,
        b"identity".to_vec(),
        encode(&identity).expect("identity"),
    )
    .expect("put");
    tx.commit(Durability::Sync).expect("commit");
    drop(engine);
    NativeSuppressionLedger::open(path, database, identity.authority).expect("legacy open")
}

#[test]
fn legacy_authority_keeps_ordinary_data_but_native_binding_rejects_a_retention_downgrade() {
    let root = tempfile::tempdir().expect("root");
    let legacy = create_legacy(&root.path().join("legacy"), "compatibility");
    let input = request(1, "legacy data remains readable");
    let native = NativeService::open_with_suppression(
        root.path().join("old-native"),
        "compatibility",
        [7; 32],
        legacy.clone(),
    )
    .expect("legacy native");
    native
        .append_event(input.clone())
        .expect("ordinary capture");
    let mut budget = inventory::verification_budget();
    assert_eq!(
        native
            .request_original_removal(
                &input.context,
                &BTreeSet::from([input.event.event_id]),
                "legacy-removal",
                &mut budget
            )
            .expect_err("explicit migration required")
            .code,
        ErrorCode::FormatIncompatible
    );
    native
        .read_original(contextdb_service::ReadOriginalRequest {
            context: input.context.clone(),
            event_id: input.event.event_id,
            after_receipt: None,
        })
        .expect("legacy original");
    native
        .revoke_original(
            &input.context,
            input.event.event_id,
            "legacy-revoke",
            &mut budget,
        )
        .expect("ordinary revocation remains supported");
    native
        .verify_native(true)
        .expect("legacy complete verification");
    drop(native);
    let ledger_path = root.path().join("current");
    let ledger = NativeSuppressionLedger::create(&ledger_path, "compatibility").expect("current");
    let native_path = root.path().join("new-native");
    let native = NativeService::open_with_suppression(
        &native_path,
        "compatibility",
        [7; 32],
        ledger.clone(),
    )
    .expect("current native");
    native.append_event(input.clone()).expect("original");
    let archive = native
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("archive before removal");
    native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "current-removal",
            &mut budget,
        )
        .expect("request");
    drop(native);
    let authority = ledger.authority_id();
    let mut downgraded = ledger.identity.clone();
    downgraded.version = 1;
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let rows = snapshot
        .scan_prefix(&ledger.rows, b"removal/")
        .expect("rows");
    drop(snapshot);
    let mut tx = ledger.engine.begin_write().expect("tx");
    for row in rows {
        tx.delete(&ledger.rows, row.key)
            .expect("remove format family");
    }
    tx.put(
        &ledger.rows,
        b"identity".to_vec(),
        encode(&downgraded).expect("identity"),
    )
    .expect("downgrade");
    tx.commit(Durability::Sync).expect("commit");
    drop(ledger);
    let downgraded = NativeSuppressionLedger::open(ledger_path, "compatibility", authority)
        .expect("looks like legacy authority");
    assert_eq!(
        NativeService::open_with_suppression(
            &native_path,
            "compatibility",
            [7; 32],
            downgraded.clone()
        )
        .expect_err("native retains required authority format")
        .code,
        ErrorCode::FormatIncompatible
    );
    let target = NativeService::open_with_suppression(
        root.path().join("restore"),
        "compatibility",
        [7; 32],
        downgraded,
    )
    .expect("legacy target");
    assert_eq!(
        target
            .restore_backup(RestoreBackupRequest {
                context: input.context,
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest
            })
            .expect_err("archive binds required format too")
            .code,
        ErrorCode::FormatIncompatible
    );
}
