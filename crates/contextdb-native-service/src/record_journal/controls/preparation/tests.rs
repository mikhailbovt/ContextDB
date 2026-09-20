use super::super::tests::{context, event, request};
use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        Default::default(),
    )
}

fn rehash<T: WriteTransaction>(service: &NativeService, tx: &mut T) {
    let mut previous = None;
    for row in tx
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("events")
    {
        let mut event: StoredEvent = decode(&row.value, "event").expect("event");
        event.previous_event_digest = previous;
        event.event_digest = event_digest(&event).expect("hash");
        previous = Some(event.event_digest.clone());
        tx.put(
            &service.keyspaces.events,
            row.key,
            encode(&event).expect("event"),
        )
        .expect("event");
    }
    tx.put(
        &service.keyspaces.meta,
        META_EVENT_DIGEST_KEY.to_vec(),
        previous.expect("head").into_bytes(),
    )
    .expect("terminal");
}

// Synthetic pre-control wire format, not an archive attributed to an old binary.
fn legacy(service: &NativeService) -> MutationResponse {
    let original = service.publish_memory(request()).expect("publish");
    service
        .forget(ForgetRequest {
            context: context(),
            idempotency_key: "legacy-retract".into(),
            target_id: request().memory_id,
            mode: ForgetMode::Retract,
            reason: "requested".into(),
        })
        .expect("closure and new revision");
    let mut independent = request();
    independent.context.request.workspace_id = "another-workspace".into();
    independent.memory_id = "independent".into();
    independent.idempotency_key = "independent".into();
    service
        .publish_memory(independent)
        .expect("interleaved workspace");
    let mut tx = service.engine.begin_write().expect("transaction");
    for row in tx
        .scan_prefix(&service.keyspaces.continuous, super::super::PREFIX)
        .expect("controls")
    {
        tx.delete(&service.keyspaces.continuous, row.key)
            .expect("remove new controls");
    }
    for row in tx
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("events")
    {
        let mut event: StoredEvent = decode(&row.value, "event").expect("event");
        for reference in &mut event.accepted_records {
            reference.control_digest = None;
        }
        tx.put(
            &service.keyspaces.events,
            row.key,
            encode(&event).expect("event"),
        )
        .expect("event");
    }
    rehash(service, &mut tx);
    let mut manifest = service.raw_manifest(&tx).expect("manifest");
    manifest.features.remove(CONTROL_FEATURE);
    manifest.checksum = manifest_checksum(&manifest).expect("checksum");
    tx.put(
        &service.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("manifest");
    tx.commit(Durability::Sync).expect("legacy fixture");
    service.verify_native(true).expect("valid legacy format");
    original
}

#[test]
fn whole_legacy_groups_keep_original_history_receipts_and_restore() {
    let root = tempfile::tempdir().expect("root");
    let service = NativeService::open(root.path().join("source"), "prepare-controls", [7; 32])
        .expect("native");
    let original = legacy(&service);
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let events = before
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("original history");
    let scopes = service.record_scope_epochs(&before).expect("scopes");
    let closed = service
        .prepare_record_controls(&context(), 2, &mut budget())
        .expect("prepare closures");
    assert_eq!(
        closed,
        NativeRecordControlPreparationReceipt {
            record_commit: 2,
            prepared_at: 3,
            mutations: 2
        }
    );
    let birth = service
        .prepare_record_controls(&context(), 1, &mut budget())
        .expect("prepare birth");
    assert_eq!(birth.mutations, 1);
    assert_eq!(birth.prepared_at, 4);
    assert_eq!(
        service
            .prepare_record_controls(&context(), 2, &mut budget())
            .expect("exact retry"),
        closed
    );
    let after = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(service.global_head(&after).expect("head"), 5);
    assert_eq!(
        service
            .record_control_activation(&after)
            .expect("activation"),
        None
    );
    for row in &events {
        assert_eq!(
            after
                .get(&service.keyspaces.events, &row.key)
                .expect("event"),
            Some(row.value.clone())
        );
    }
    assert_eq!(service.record_scope_epochs(&after).expect("scopes"), scopes);
    for row in after
        .scan_prefix(&service.keyspaces.continuous, PREFIX)
        .expect("controls")
    {
        let text = String::from_utf8(row.value).expect("JSON");
        for body in [
            "PRIVATE-VALUE-CONTENT",
            "PRIVATE-LEXICAL-CONTENT",
            "private-record-name",
        ] {
            assert!(!text.contains(body));
        }
    }
    service.verify_native(true).expect("all prepared controls");
    let backup = service
        .create_backup(CreateBackupRequest { context: context() })
        .expect("backup");
    let restored = NativeService::open(root.path().join("restored"), "prepare-controls", [7; 32])
        .expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: context(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    assert_eq!(
        restored
            .prepare_record_controls(&context(), 1, &mut budget())
            .expect("restored retry"),
        birth
    );
    let mut expected = original;
    expected.replayed = true;
    assert_eq!(
        restored
            .publish_memory(request())
            .expect("original exact retry"),
        expected
    );
    let mut new = request();
    new.memory_id = "new-record".into();
    new.idempotency_key = "new-record".into();
    restored
        .publish_memory(new)
        .expect("new direct controls after preparation");
    restored
        .verify_native(true)
        .expect("mixed old prepared and new controls");
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        restored
            .record_control_activation(&snapshot)
            .expect("activation"),
        Some(6)
    );
    assert_eq!(event(&restored, &snapshot, 1), event(&service, &before, 1));
    // Losing this cache must not repeat preparation or replace its accepted receipt.
    let preparation = event(&restored, &snapshot, 5);
    let mut tx = restored.engine.begin_write().expect("transaction");
    tx.delete(
        &restored.keyspaces.idempotency,
        preparation.request_digest.into_bytes(),
    )
    .expect("remove preparation cache");
    tx.commit(Durability::Sync).expect("cache-loss fixture");
    assert_eq!(
        restored
            .prepare_record_controls(&context(), 1, &mut budget())
            .expect("accepted receipt survives cache loss"),
        birth
    );
    let latest = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(restored.global_head(&latest).expect("unchanged head"), 6);
}

#[test]
fn preparation_metadata_loss_cannot_create_a_duplicate_publication() {
    for mutation in [
        "locator",
        "declaration",
        "redirected",
        "control",
        "feature",
        "orphan",
        "forged-control",
    ] {
        let root = tempfile::tempdir().expect("root");
        let service =
            NativeService::open(root.path(), "corrupt-preparation", [7; 32]).expect("native");
        legacy(&service);
        service
            .prepare_record_controls(&context(), 1, &mut budget())
            .expect("prepare");
        let mut tx = service.engine.begin_write().expect("transaction");
        let original = event(&service, &tx, 1);
        let key = prepared_key(&original.accepted_records[0].key).expect("key");
        match mutation {
            "locator" => tx
                .delete(&service.keyspaces.continuous, group_key(1))
                .expect("delete"),
            "declaration" | "redirected" => {
                tx.delete(&service.keyspaces.continuous, group_key(1))
                    .expect("delete locator");
                let mut accepted = event(&service, &tx, 4);
                if mutation == "declaration" {
                    accepted.accepted_record_control_preparation = None;
                } else {
                    accepted
                        .accepted_record_control_preparation
                        .as_mut()
                        .expect("publication")
                        .source_global = 2;
                }
                tx.put(
                    &service.keyspaces.events,
                    4u64.to_be_bytes().to_vec(),
                    encode(&accepted).expect("event"),
                )
                .expect("event");
                rehash(&service, &mut tx);
            }
            "control" => tx
                .delete(&service.keyspaces.continuous, key)
                .expect("delete"),
            "feature" => {
                let mut manifest = service.raw_manifest(&tx).expect("manifest");
                manifest.features.remove(FEATURE);
                manifest.checksum = manifest_checksum(&manifest).expect("hash");
                tx.put(
                    &service.keyspaces.meta,
                    META_MANIFEST_KEY.to_vec(),
                    encode(&manifest).expect("manifest"),
                )
                .expect("manifest");
            }
            "orphan" => tx
                .put(
                    &service.keyspaces.continuous,
                    b"record-prepared/unknown".to_vec(),
                    b"{}".to_vec(),
                )
                .expect("orphan"),
            "forged-control" => {
                let mut control: RecordControl = decode(
                    &tx.get(&service.keyspaces.continuous, &key)
                        .expect("row")
                        .expect("control"),
                    "control",
                )
                .expect("control");
                control.attributes_digest = "ab".repeat(32);
                let bytes = encode(&control).expect("control");
                let mut accepted = event(&service, &tx, 4);
                let publication = accepted
                    .accepted_record_control_preparation
                    .as_mut()
                    .expect("publication");
                publication.controls[0].control_digest = Some(digest_bytes(&bytes));
                accepted.response_digest = canonical_digest(publication).expect("response digest");
                tx.put(&service.keyspaces.continuous, key, bytes)
                    .expect("control");
                tx.put(
                    &service.keyspaces.events,
                    4u64.to_be_bytes().to_vec(),
                    encode(&accepted).expect("event"),
                )
                .expect("event");
                rehash(&service, &mut tx);
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fixture");
        let snapshot = service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        service
            .verify_event_chain(&snapshot, 4)
            .expect("valid event chain isolates control failure");
        assert_eq!(
            service
                .verify_record_control_preparations(&snapshot)
                .and_then(|_| service.verify_record_mutations(&snapshot))
                .expect_err(mutation)
                .code,
            ErrorCode::IntegrityFailure
        );
        if mutation != "orphan" {
            assert_eq!(
                service
                    .prepare_record_controls(&context(), 1, &mut budget())
                    .expect_err(mutation)
                    .code,
                ErrorCode::IntegrityFailure
            );
        }
        let latest = service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(service.global_head(&latest).expect("head"), 4, "{mutation}");
    }
}

#[test]
fn preparation_budget_authority_and_workspace_cas_leave_no_partial_controls() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("native");
    let service =
        std::sync::Arc::new(NativeService::open(&path, "prepare-cas", [7; 32]).expect("native"));
    legacy(&service);
    let mut denied = context();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        service
            .prepare_record_controls(&denied, 1, &mut budget())
            .expect_err("admin")
            .code,
        ErrorCode::Unauthorized
    );
    let mut exhausted =
        QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        service
            .prepare_record_controls(&context(), 1, &mut exhausted)
            .is_err()
    );
    let cancellation = contextdb_recall::QueryCancellation::default();
    let cancel = cancellation.clone();
    BEFORE_PUBLICATION.with(|slot| slot.replace(Some(Box::new(move || cancel.cancel()))));
    let mut cancelled = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancellation,
    );
    assert!(
        service
            .prepare_record_controls(&context(), 1, &mut cancelled)
            .is_err()
    );
    let writer = service.clone();
    BEFORE_PUBLICATION.with(|slot| {
        slot.replace(Some(Box::new(move || {
            let mut request = request();
            request.memory_id = "concurrent".into();
            request.idempotency_key = "concurrent".into();
            writer
                .publish_memory(request)
                .expect("concurrent publication");
        })))
    });
    assert_eq!(
        service
            .prepare_record_controls(&context(), 1, &mut budget())
            .expect_err("CAS")
            .code,
        ErrorCode::IndexTooStale
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        snapshot
            .scan_prefix(&service.keyspaces.continuous, PREFIX)
            .expect("rows")
            .is_empty()
    );
    assert!(
        !service
            .raw_manifest(&snapshot)
            .expect("manifest")
            .features
            .contains(FEATURE)
    );
    service
        .prepare_record_controls(&context(), 1, &mut budget())
        .expect("fresh retry");
    service
        .verify_native(true)
        .expect("prepared old and concurrent new controls");
}

#[test]
fn prepared_scope_replay_does_not_authorize_missing_record_bodies() {
    let root = tempfile::tempdir().expect("root");
    let service = NativeService::open(root.path(), "prepared-scopes", [7; 32]).expect("native");
    legacy(&service);
    service
        .prepare_record_controls(&context(), 1, &mut budget())
        .expect("prepare");
    let mut tx = service.engine.begin_write().expect("transaction");
    let scopes = service.record_scope_epochs(&tx).expect("scopes");
    let accepted = event(&service, &tx, 1);
    tx.delete(
        &service.keyspaces.continuous,
        accepted.accepted_records[0].key.clone(),
    )
    .expect("remove body");
    tx.commit(Durability::Sync).expect("fixture");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        service
            .record_scope_epochs(&snapshot)
            .expect("scope controls"),
        scopes
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("no pruning acceptance")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn preparation_denies_policy_before_decoding_a_corrupt_body() {
    let root = tempfile::tempdir().expect("root");
    let service = NativeService::open(root.path(), "preparation-policy", [7; 32]).expect("native");
    legacy(&service);
    let mut tx = service.engine.begin_write().expect("transaction");
    let original = event(&service, &tx, 1);
    tx.put(
        &service.keyspaces.continuous,
        original.accepted_records[0].key.clone(),
        b"not JSON".to_vec(),
    )
    .expect("corrupt body");
    tx.commit(Durability::Sync).expect("fixture");
    let mut denied = context();
    denied.request.scopes = BTreeSet::from(["outside".into()]);
    assert_eq!(
        service
            .prepare_record_controls(&denied, 1, &mut budget())
            .expect_err("policy before body")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        service
            .prepare_record_controls(&context(), 1, &mut budget())
            .expect_err("accepted digest before decode")
            .code,
        ErrorCode::IntegrityFailure
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(service.global_head(&snapshot).expect("unchanged head"), 3);
    assert!(
        snapshot
            .scan_prefix(&service.keyspaces.continuous, PREFIX)
            .expect("controls")
            .is_empty()
    );
}
