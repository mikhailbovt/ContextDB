use super::*;

#[test]
fn closed_revision_key_inventory_preserves_all_body_families_through_pruning_and_restore() {
    let (_keys_dir, keys) = encryption::tests::authority("record-witness");
    let f = fixture_with_keys(Some(keys.clone()));
    let witness = prepare(&f, "private-record", 1).expect("closed revision witness");
    let before = f
        .service
        .read_record_key_inventory(&f.context, &witness, &mut budget())
        .expect("closed body families");
    assert_eq!(before.bodies.len(), 3);
    assert_eq!(
        before.bodies[&NativeRecordBodyKind::ContentHistory].len(),
        2
    );
    assert_eq!(before.bodies[&NativeRecordBodyKind::AcceptedBirth].len(), 1);
    assert_eq!(
        before.bodies[&NativeRecordBodyKind::AcceptedClosure].len(),
        1
    );
    let selected_ids: BTreeSet<_> = before
        .bodies
        .values()
        .flatten()
        .map(|key| key.key_id)
        .collect();
    assert_eq!(selected_ids.len(), 4);
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let independent_address = encryption::address(
        &f.service.keyspaces.content_history,
        &history_key(&digest_bytes(b"independent-record"), 1),
    );
    assert!(
        before
            .bodies
            .values()
            .flatten()
            .all(|entry| entry.address_digest != independent_address)
    );
    let independent = snapshot
        .get(
            &f.service.keyspaces.content_history,
            &history_key(&digest_bytes(b"independent-record"), 1),
        )
        .expect("independent body");
    drop(snapshot);
    let old = f
        .service
        .create_backup(CreateBackupRequest {
            context: f.context.clone(),
        })
        .expect("full encrypted archive");
    f.service
        .prune_record_revision(&f.context, &witness, &mut budget())
        .expect("prune closed revision");
    assert_eq!(
        f.service
            .read_record_key_inventory(&f.context, &witness, &mut budget())
            .expect("keys retained after body removal")
            .bodies,
        before.bodies
    );
    let cleaned = f
        .service
        .create_backup(CreateBackupRequest {
            context: f.context.clone(),
        })
        .expect("cleaned encrypted archive");
    drop(f.service);
    let reopened = NativeService::open_encrypted(
        f.root.path().join("native"),
        "record-witness",
        [8; 32],
        f.ledger.clone(),
        keys.clone(),
    )
    .expect("native reopen");
    assert_eq!(
        reopened
            .read_record_key_inventory(&f.context, &witness, &mut budget())
            .expect("key families after reopen")
            .bodies,
        before.bodies
    );
    for (name, archive) in [("old", old), ("cleaned", cleaned)] {
        let restored = NativeService::open_encrypted(
            f.root.path().join(name),
            "record-witness",
            [9; 32],
            f.ledger.clone(),
            keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: f.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore exact encrypted archive");
        assert_eq!(
            restored
                .read_record_key_inventory(&f.context, &witness, &mut budget())
                .expect("key families after restore")
                .bodies,
            before.bodies
        );
        let snapshot = restored
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(
            snapshot
                .get(
                    &restored.keyspaces.content_history,
                    &history_key(&digest_bytes(b"independent-record"), 1)
                )
                .expect("independent body"),
            independent
        );
    }
}
