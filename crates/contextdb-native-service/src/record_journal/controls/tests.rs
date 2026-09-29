use super::*;

pub(super) fn context() -> AuthenticatedRequestContext {
    crate::tests::authenticated(
        "record-control-test",
        "control-workspace",
        "owner",
        [
            Capability::Admin,
            Capability::Correct,
            Capability::Observe,
            Capability::ReadMemory,
            Capability::Forget,
        ],
    )
}

pub(super) fn request() -> PublishMemoryRequest {
    PublishMemoryRequest {
        context: context(),
        idempotency_key: "original-publication".into(),
        memory_id: "private-record-name".into(),
        value: serde_json::json!({"private-value-key": "PRIVATE-VALUE-CONTENT"}),
        search_text: "PRIVATE-LEXICAL-CONTENT".into(),
    }
}

fn get(service: &NativeService, id: &str) -> MemoryRecord {
    service
        .get_memory(GetMemoryRequest {
            context: context(),
            record_id: id.into(),
            at_commit: None,
        })
        .expect("record")
}

pub(super) fn event<S: ReadSnapshot>(
    service: &NativeService,
    snapshot: &S,
    global: u64,
) -> StoredEvent {
    decode(
        &snapshot
            .get(&service.keyspaces.events, &global.to_be_bytes())
            .expect("read event")
            .expect("accepted event"),
        "event",
    )
    .expect("event")
}

#[test]
fn controls_bind_births_closures_and_copied_revisions_across_restore() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("native");
    let service = NativeService::open(&path, "record-controls", [7; 32]).expect("native");
    let original = service.publish_memory(request()).expect("publish");
    let old = get(&service, "private-record-name");
    let mut replacement = old.document.clone();
    replacement.id = "private-successor-name".into();
    replacement.links.supersedes.insert(old.document.id.clone());
    replacement.value = serde_json::json!("PRIVATE-SUCCESSOR-CONTENT");
    replacement.attributes.insert(
        "PRIVATE-ATTRIBUTE-NAME".into(),
        serde_json::json!("PRIVATE-ATTRIBUTE-CONTENT"),
    );
    replacement.vector = Some(vec![86753.125, 25486.375]);
    service
        .correct(CorrectRequest {
            context: context(),
            idempotency_key: "correct-record".into(),
            target_id: old.document.id.clone(),
            replacement,
        })
        .expect("correct");
    service
        .forget(ForgetRequest {
            context: context(),
            idempotency_key: "retract-record".into(),
            target_id: "private-successor-name".into(),
            mode: ForgetMode::Retract,
            reason: "requested".into(),
        })
        .expect("retract");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let activation = service
        .record_control_activation(&snapshot)
        .expect("activation");
    assert_eq!(activation, Some(1));
    let mut controls = Vec::new();
    for global in 1..=3 {
        let event = event(&service, &snapshot, global);
        for reference in &event.accepted_records {
            controls.push(
                service
                    .record_mutation_control(&snapshot, &event, reference, activation)
                    .expect("bound control")
                    .expect("new format"),
            );
        }
    }
    assert_eq!(controls.len(), 5);
    assert_eq!(
        controls
            .iter()
            .filter(|control| control.policy.transaction_to.is_some())
            .count(),
        2
    );
    let retained = String::from_utf8(encode(&controls).expect("controls")).expect("UTF8");
    for body in [
        "private-record-name",
        "private-successor-name",
        "private-value-key",
        "PRIVATE-VALUE-CONTENT",
        "PRIVATE-LEXICAL-CONTENT",
        "PRIVATE-SUCCESSOR-CONTENT",
        "PRIVATE-ATTRIBUTE-NAME",
        "PRIVATE-ATTRIBUTE-CONTENT",
        "86753.125",
        "25486.375",
    ] {
        assert!(!retained.contains(body), "control retained {body}");
    }
    let expected_scopes = service.record_scope_epochs(&snapshot).expect("epochs");
    drop(snapshot);
    service.verify_native(true).expect("live control closure");
    let backup = service
        .create_backup(CreateBackupRequest { context: context() })
        .expect("backup");
    drop(service);
    let reopened = NativeService::open(path, "record-controls", [7; 32]).expect("reopen");
    reopened.verify_native(true).expect("reopened controls");
    let restored = NativeService::open(root.path().join("restored"), "record-controls", [7; 32])
        .expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: context(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        restored
            .record_scope_epochs(&snapshot)
            .expect("restored epochs"),
        expected_scopes
    );
    let mut expected = original;
    expected.replayed = true;
    assert_eq!(
        restored
            .publish_memory(request())
            .expect("exact original retry"),
        expected
    );
    restored.verify_native(true).expect("restored controls");
}

#[test]
fn missing_forged_or_orphaned_controls_never_become_a_legacy_fallback() {
    for damaged in [
        "control",
        "activation",
        "commitment",
        "forged",
        "orphan",
        "future-activation",
    ] {
        let root = tempfile::tempdir().expect("root");
        let service =
            NativeService::open(root.path(), "damaged-record-controls", [7; 32]).expect("native");
        service.publish_memory(request()).expect("publish");
        let mut tx = service.engine.begin_write().expect("transaction");
        let mut accepted = event(&service, &tx, 1);
        let reference = &mut accepted.accepted_records[0];
        let key = control_key(&reference.key).expect("control key");
        match damaged {
            "control" => tx
                .delete(&service.keyspaces.continuous, key)
                .expect("remove control"),
            "activation" => tx
                .delete(&service.keyspaces.continuous, ACTIVATED.to_vec())
                .expect("remove activation"),
            "commitment" => reference.control_digest = None,
            "forged" => {
                let mut control: RecordControl = decode(
                    &tx.get(&service.keyspaces.continuous, &key)
                        .expect("read")
                        .expect("control"),
                    "control",
                )
                .expect("decode");
                control.attributes_digest = "12".repeat(32);
                let bytes = encode(&control).expect("rehashed control");
                reference.control_digest = Some(digest_bytes(&bytes));
                tx.put(&service.keyspaces.continuous, key, bytes)
                    .expect("forge control");
            }
            "orphan" => tx
                .put(
                    &service.keyspaces.continuous,
                    b"record-control/orphan".to_vec(),
                    b"unclaimed".to_vec(),
                )
                .expect("orphan"),
            _ => tx
                .put(
                    &service.keyspaces.continuous,
                    ACTIVATED.to_vec(),
                    encode(&2u64).expect("future"),
                )
                .expect("future activation"),
        }
        accepted.event_digest = event_digest(&accepted).expect("rehashed event");
        tx.put(
            &service.keyspaces.events,
            1u64.to_be_bytes().to_vec(),
            encode(&accepted).expect("event"),
        )
        .expect("event update");
        tx.put(
            &service.keyspaces.meta,
            META_EVENT_DIGEST_KEY.to_vec(),
            accepted.event_digest.as_bytes().to_vec(),
        )
        .expect("terminal digest");
        tx.commit(Durability::Sync).expect("corruption fixture");
        let snapshot = service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        service
            .verify_event_chain(&snapshot, 1)
            .expect("fixture preserves a valid journal chain");
        assert_eq!(
            service.verify_native(true).expect_err(damaged).code,
            ErrorCode::IntegrityFailure
        );
    }
}

#[test]
fn scope_replay_uses_accepted_controls_but_missing_unpruned_bodies_still_fail_verification() {
    let root = tempfile::tempdir().expect("root");
    let service =
        NativeService::open(root.path(), "control-scope-replay", [7; 32]).expect("native");
    service.publish_memory(request()).expect("publish");
    let mut tx = service.engine.begin_write().expect("transaction");
    let before = service.record_scope_epochs(&tx).expect("original scopes");
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
            .expect("content-free scope replay"),
        before
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("no authorized pruning transition")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn legacy_mutation_references_keep_their_exact_encoding() {
    let bytes = format!("{{\"key\":[1,2,3],\"digest\":\"{}\"}}", "ab".repeat(32));
    let reference: RecordMutationRef =
        decode(bytes.as_bytes(), "legacy reference").expect("legacy");
    assert!(reference.control_digest.is_none());
    assert_eq!(
        encode(&reference).expect("legacy encoding"),
        bytes.as_bytes()
    );
}

#[test]
fn legacy_archive_and_new_closures_keep_distinct_control_activation() {
    let root = tempfile::tempdir().expect("root");
    let service = NativeService::open(
        root.path().join("legacy"),
        "legacy-record-controls",
        [7; 32],
    )
    .expect("native");
    let original = service.publish_memory(request()).expect("publish");
    // Reproduce the pre-control wire format; the original payload/receipt stay exact.
    let mut tx = service.engine.begin_write().expect("transaction");
    let mut accepted = event(&service, &tx, 1);
    tx.delete(
        &service.keyspaces.continuous,
        control_key(&accepted.accepted_records[0].key).expect("key"),
    )
    .expect("legacy has no control row");
    tx.delete(&service.keyspaces.continuous, ACTIVATED.to_vec())
        .expect("legacy has no activation");
    accepted.accepted_records[0].control_digest = None;
    accepted.event_digest = event_digest(&accepted).expect("legacy event digest");
    tx.put(
        &service.keyspaces.events,
        1u64.to_be_bytes().to_vec(),
        encode(&accepted).expect("event"),
    )
    .expect("legacy event");
    tx.put(
        &service.keyspaces.meta,
        META_EVENT_DIGEST_KEY.to_vec(),
        accepted.event_digest.as_bytes().to_vec(),
    )
    .expect("terminal digest");
    let mut manifest = service.raw_manifest(&tx).expect("manifest");
    manifest.features.remove(CONTROL_FEATURE);
    manifest.checksum = manifest_checksum(&manifest).expect("checksum");
    tx.put(
        &service.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("legacy feature set");
    tx.commit(Durability::Sync).expect("legacy-format fixture");
    service.verify_native(true).expect("legacy still verifies");
    let backup = service
        .create_backup(CreateBackupRequest { context: context() })
        .expect("legacy archive");
    let restored = NativeService::open(
        root.path().join("restored"),
        "legacy-record-controls",
        [7; 32],
    )
    .expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: context(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore pre-control format");
    restored
        .forget(ForgetRequest {
            context: context(),
            idempotency_key: "new-retraction".into(),
            target_id: request().memory_id,
            mode: ForgetMode::Retract,
            reason: "requested".into(),
        })
        .expect("new write over legacy record");
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        restored
            .record_control_activation(&snapshot)
            .expect("activation"),
        Some(2)
    );
    assert_eq!(event(&restored, &snapshot, 1), accepted);
    let newer = event(&restored, &snapshot, 2);
    assert_eq!(newer.accepted_records.len(), 2);
    assert!(
        newer
            .accepted_records
            .iter()
            .all(|reference| reference.control_digest.is_some())
    );
    let mut expected = original;
    expected.replayed = true;
    assert_eq!(
        restored
            .publish_memory(request())
            .expect("original receipt preserved"),
        expected
    );
    restored.verify_native(true).expect("mixed old/new journal");
}
