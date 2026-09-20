use super::*;
use crate::capture::tests::request;
use contextdb_service::{CapturePort, CreateBackupRequest, RestoreBackupRequest};

#[test]
fn payload_membership_pages_reject_shared_blocks_redirects_corruption_and_family_loss() {
    use contextdb_core::{
        ContentBlockId, EventKind, EventPayload, EventProvenance, EventRole, ModelCallId,
        ModelRequestManifest, RequestPart,
    };
    use contextdb_service::{Capability, PayloadPort, StagePayloadRequest};
    let root = tempfile::tempdir().expect("root");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "payload-pages")
        .expect("ledger");
    let native = NativeService::open_with_suppression(
        root.path().join("native"),
        "payload-pages",
        [7; 32],
        ledger.clone(),
    )
    .expect("native");
    let mut owner = request(1, "shared owner");
    let shared = native
        .stage_payload(StagePayloadRequest {
            context: owner.context.clone(),
            idempotency_key: "shared".into(),
            block_id: ContentBlockId::new(),
            bytes: vec![42],
        })
        .expect("shared")
        .reference;
    owner.event.payload = EventPayload::Staged {
        reference: shared.clone(),
        media_type: "application/octet-stream".into(),
    };
    native
        .append_event(owner.clone())
        .expect("independent owner");
    let mut wire = Vec::new();
    let mut parts = Vec::new();
    for index in 0..260 {
        let bytes = vec![(index % 251) as u8];
        wire.extend_from_slice(&bytes);
        let payload = native
            .stage_payload(StagePayloadRequest {
                context: owner.context.clone(),
                idempotency_key: format!("selected-{index}"),
                block_id: ContentBlockId::new(),
                bytes,
            })
            .expect("selected block")
            .reference;
        parts.push(RequestPart::StoredNovel { payload });
    }
    parts.push(RequestPart::StoredNovel {
        payload: shared.clone(),
    });
    wire.push(42);
    let mut call = request(2, "placeholder");
    let model_call_id = ModelCallId::new();
    call.context.capability_grants.insert(Capability::Runtime);
    call.event.kind = EventKind::ModelRequested;
    call.event.role = EventRole::Host;
    call.event.provenance = Some(EventProvenance::ModelRequest { model_call_id });
    call.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id,
            renderer: "payload-pages/v1".into(),
            byte_length: wire.len() as u64,
            wire_digest: ContentDigest::from_bytes(*blake3::hash(&wire).as_bytes()),
            parts,
        },
    };
    native.append_event(call.clone()).expect("request owner");
    let mut budget = inventory::verification_budget();
    let request = native
        .request_original_removal(
            &call.context,
            &BTreeSet::from([call.event.event_id]),
            "remove request",
            &mut budget,
        )
        .expect("retained request");
    let workspace = digest_bytes(call.context.request.workspace_id.as_bytes());
    let checkpoint = RemovalCheckpoint {
        sequence: request.sequence,
        digest: request.digest.clone(),
    };
    let (_, inventory) = ledger
        .retained_removal_inventory(&workspace, &checkpoint, &mut budget)
        .expect("inventory");
    assert_eq!(inventory.payloads.len(), 260);
    assert_eq!(inventory.retained_shared_payloads, vec![shared.clone()]);
    let selected = inventory.payloads.last().expect("last page");
    assert_eq!(
        ledger
            .removal_payload(&workspace, &checkpoint, selected.block_id, &mut budget)
            .expect("bounded last-page proof"),
        *selected
    );
    assert!(
        ledger
            .removal_payload(&workspace, &checkpoint, shared.block_id, &mut budget)
            .is_err()
    );
    let locator = format!(
        "removal/control/{}/payload/{}",
        inventory.digest, selected.block_id
    )
    .into_bytes();
    let shared_locator = format!(
        "removal/control/{}/payload/{}",
        inventory.digest, shared.block_id
    )
    .into_bytes();
    let page = format!("removal/control/{}/payload-page/00000001", inventory.digest).into_bytes();
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let saved_locator = snapshot
        .get(&ledger.rows, &locator)
        .expect("locator")
        .expect("present");
    let saved_page = snapshot
        .get(&ledger.rows, &page)
        .expect("page")
        .expect("present");
    drop(snapshot);
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(
        &ledger.rows,
        locator.clone(),
        encode(&0_usize).expect("locator"),
    )
    .expect("redirect");
    tx.put(
        &ledger.rows,
        shared_locator.clone(),
        encode(&0_usize).expect("locator"),
    )
    .expect("forge shared target");
    tx.commit(Durability::Sync).expect("commit");
    assert!(
        ledger
            .removal_payload(&workspace, &checkpoint, selected.block_id, &mut budget)
            .is_err()
    );
    assert!(
        ledger
            .removal_payload(&workspace, &checkpoint, shared.block_id, &mut budget)
            .is_err()
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(&ledger.rows, locator.clone(), saved_locator)
        .expect("repair locator");
    tx.delete(&ledger.rows, shared_locator)
        .expect("repair shared target");
    let mut changed = saved_page.clone();
    changed[10] ^= 1;
    tx.put(&ledger.rows, page.clone(), changed)
        .expect("corrupt page");
    tx.commit(Durability::Sync).expect("commit");
    assert!(
        ledger
            .removal_payload(&workspace, &checkpoint, selected.block_id, &mut budget)
            .is_err()
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(&ledger.rows, page, saved_page).expect("repair page");
    tx.commit(Durability::Sync).expect("commit");
    ledger.verify().expect("exact page closure");
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let rows = snapshot
        .scan_prefix(
            &ledger.rows,
            format!("removal/control/{}/payload", inventory.digest).as_bytes(),
        )
        .expect("payload pages and locators");
    drop(snapshot);
    let mut tx = ledger.engine.begin_write().expect("tx");
    for row in &rows {
        tx.delete(&ledger.rows, row.key.clone())
            .expect("lose family");
    }
    tx.commit(Durability::Sync).expect("commit");
    assert!(
        ledger.verify().is_err(),
        "request-bound pages cannot disappear together"
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    for row in rows {
        tx.put(&ledger.rows, row.key, row.value)
            .expect("restore family");
    }
    tx.commit(Durability::Sync).expect("commit");
    ledger.verify().expect("restored exact authority");
}

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
    let Operation::Request { intent, .. } = event.operation else {
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
    let checkpoint = RemovalCheckpoint {
        sequence: receipt.sequence,
        digest: receipt.digest.clone(),
    };
    ledger
        .removal_source(&intent.workspace, &checkpoint, previous, &mut budget)
        .expect("accepted last-page source");
    let locator = format!("removal/control/{}/source/{previous}", retained.digest).into_bytes();
    let page_key = format!("removal/control/{}/page/00000002", retained.digest).into_bytes();
    let snapshot = ledger
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let saved_locator = snapshot
        .get(&ledger.rows, &locator)
        .expect("locator")
        .expect("present");
    let saved_page = snapshot
        .get(&ledger.rows, &page_key)
        .expect("page")
        .expect("present");
    drop(snapshot);
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(
        &ledger.rows,
        locator.clone(),
        encode(&0_usize).expect("locator"),
    )
    .expect("redirect locator");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger
            .removal_source(&intent.workspace, &checkpoint, previous, &mut budget)
            .expect_err("point lookup cannot substitute a different accepted source")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(&ledger.rows, locator, saved_locator)
        .expect("repair locator");
    let mut corrupted = saved_page.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    tx.put(&ledger.rows, page_key.clone(), corrupted)
        .expect("corrupt source page");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        ledger
            .removal_source(&intent.workspace, &checkpoint, previous, &mut budget)
            .expect_err("point lookup verifies the page against the immutable request")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = ledger.engine.begin_write().expect("tx");
    tx.put(&ledger.rows, page_key, saved_page)
        .expect("repair page");
    tx.commit(Durability::Sync).expect("repair");
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
