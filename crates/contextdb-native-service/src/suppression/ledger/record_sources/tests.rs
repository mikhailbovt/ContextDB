use std::time::Duration;

use contextdb_recall::QueryCancellation;

use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn control(workspace: &str, record: &str) -> RecordSourceControl {
    RecordSourceControl {
        workspace: digest_bytes(workspace.as_bytes()),
        record_digest: digest_bytes(record.as_bytes()),
        revision: 1,
        transaction_from: 2,
        birth_digest: digest_bytes(b"record birth"),
        document_digest: digest_bytes(b"record document"),
        scopes: BTreeSet::from(["scope".into()]),
        sources: BTreeMap::from([(
            ObservationId::new(),
            ContentDigest::from_bytes(*blake3::hash(b"source control").as_bytes()),
        )]),
    }
}

#[test]
fn retained_origins_are_bounded_interleaved_exact_and_loss_detectable() {
    let directory = tempfile::tempdir().expect("root");
    let ledger = NativeSuppressionLedger::create(directory.path().join("ledger"), "record-ledger")
        .expect("ledger");
    let mut first = control("workspace-a", "record-a");
    // Two individually valid declarations exceed one page's byte budget.
    first.scopes = (0..240)
        .map(|index| format!("{index:04}{}", "x".repeat(900)))
        .collect();
    let mut second = first.clone();
    second.record_digest = digest_bytes(b"record-b");
    let other = control("workspace-b", "record-c");
    let a = ledger
        .bind_record_origin(&first, &mut budget())
        .expect("first");
    let b = ledger
        .bind_record_origin(&other, &mut budget())
        .expect("interleaved workspace");
    let c = ledger
        .bind_record_origin(&second, &mut budget())
        .expect("second");
    assert_eq!(a.checkpoint.epoch, 1);
    assert_eq!(b.checkpoint.epoch, 1);
    assert_eq!(c.checkpoint.epoch, 2);
    assert_eq!(
        ledger
            .bind_record_origin(&first, &mut budget())
            .expect("exact retry"),
        a
    );
    let from = ledger
        .record_sources_genesis(&first.workspace)
        .expect("genesis");
    let page = ledger
        .record_sources_batch(&first.workspace, &from, 256, &mut budget())
        .expect("byte-bounded page");
    assert_eq!(page.len(), 1);
    let next = ledger
        .record_sources_batch(&first.workspace, &page[0].checkpoint, 256, &mut budget())
        .expect("remaining page");
    assert_eq!(next, vec![c]);
    let mut conflict = first.clone();
    conflict.document_digest = digest_bytes(b"different body");
    assert_eq!(
        ledger
            .bind_record_origin(&conflict, &mut budget())
            .expect_err("immutable declaration")
            .code,
        ErrorCode::InvalidArgument
    );
    ledger.verify().expect("complete authority closure");
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let head_bytes = snapshot
        .get(&ledger.rows, HEAD)
        .expect("head")
        .expect("head bytes");
    let mut damaged: Head = decode(&head_bytes, "head").expect("decode");
    damaged.workspaces.remove(&first.workspace);
    drop(snapshot);
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(
        &ledger.rows,
        HEAD.to_vec(),
        encode(&damaged).expect("damaged head"),
    )
    .expect("lose workspace membership");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger
            .current_record_sources(&first.workspace)
            .expect_err("head membership corruption cannot imply legacy access")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(&ledger.rows, HEAD.to_vec(), head_bytes)
        .expect("repair head");
    tx.commit(Durability::Sync).expect("commit");
    let key = record_key(&first.workspace, &first.record_digest, 1);
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(
        &ledger.rows,
        key.clone(),
        encode(&b.global_sequence).expect("wrong index"),
    )
    .expect("redirect");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger
            .retained_record_sources(&first.workspace, &first.record_digest, 1)
            .expect_err("index cannot select another workspace")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(
        &ledger.rows,
        key,
        encode(&a.global_sequence).expect("index"),
    )
    .expect("repair");
    tx.commit(Durability::Sync).expect("commit");
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let rows = snapshot
        .scan_prefix(&ledger.rows, b"record-sources/")
        .expect("whole family");
    drop(snapshot);
    let mut tx = ledger.engine.begin_write().expect("tx");
    for row in rows {
        tx.delete(&ledger.rows, row.key).expect("lose registry");
    }
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger
            .current_record_sources(&first.workspace)
            .expect_err("loss is not legacy access")
            .code,
        ErrorCode::IntegrityFailure
    );
    let authority = ledger.authority_id();
    drop(ledger);
    assert_eq!(
        NativeSuppressionLedger::open(directory.path().join("ledger"), "record-ledger", authority)
            .expect_err("reopen missing genesis")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn genuine_version_two_authority_keeps_retention_and_requires_explicit_provenance_migration() {
    use contextdb_service::CapturePort;
    let directory = tempfile::tempdir().expect("root");
    let path = directory.path().join("v2");
    std::fs::create_dir(&path).expect("directory");
    let engine = FjallStorage::open(&path).expect("engine");
    let rows = keyspace("contextdb_suppression").expect("rows");
    let identity = Identity {
        version: 2,
        authority: ObservationId::new().as_uuid(),
        database: digest_bytes(b"v2-origins"),
    };
    let mut tx = engine.begin_write().expect("tx");
    tx.put(
        &rows,
        b"identity".to_vec(),
        encode(&identity).expect("identity"),
    )
    .expect("put");
    tx.put(
        &rows,
        removal::HEAD.to_vec(),
        encode(&removal::genesis(&identity).expect("v2 genesis")).expect("encode"),
    )
    .expect("put");
    tx.commit(Durability::Sync).expect("commit");
    drop(engine);
    let ledger =
        NativeSuppressionLedger::open(&path, "v2-origins", identity.authority).expect("genuine v2");
    let service = NativeService::open_with_suppression(
        directory.path().join("native"),
        "v2-origins",
        [7; 32],
        ledger.clone(),
    )
    .expect("v2 bound native");
    let input = capture::tests::request(1, "retained v2 original");
    service
        .append_event(input.clone())
        .expect("ordinary capture remains available");
    assert_eq!(
        service
            .bind_record_sources(
                &input.context,
                "record",
                1,
                &BTreeSet::from([input.event.event_id]),
                &mut budget()
            )
            .expect_err("migration cannot be inferred")
            .code,
        ErrorCode::FormatIncompatible
    );
    service
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "v2-request",
            &mut budget(),
        )
        .expect("existing retention remains supported");
    service.verify_native(true).expect("v2 native closure");
    ledger.verify().expect("v2 authority closure");
    drop(service);
    drop(ledger);
    NativeSuppressionLedger::open(path, "v2-origins", identity.authority)
        .expect("reopen original v2 identity");
}
