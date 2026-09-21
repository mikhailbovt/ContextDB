use super::*;

#[test]
fn closed_revision_key_inventory_preserves_all_body_families_through_pruning_and_restore() {
    let (keys_dir, keys) = encryption::tests::authority("record-witness");
    let f = fixture_with_keys(Some(keys.clone()));
    let witness = prepare(&f, "private-record", 1).expect("closed revision witness");
    let before = f
        .service
        .read_record_key_inventory(&f.context, &witness, &mut budget())
        .expect("closed body families");
    let decisions = f
        .service
        .retain_record_key_removal(&f.context, &f.removal, &witness, &mut budget())
        .expect("retained revision decisions");
    assert_eq!(decisions.dispositions.values().flatten().count(), 4);
    assert_eq!(
        f.service
            .retain_record_key_removal(&f.context, &f.removal, &witness, &mut budget())
            .expect("exact retry"),
        decisions
    );
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
    let cleaned_decisions = f
        .service
        .retain_record_key_removal(&f.context, &f.removal, &witness, &mut budget())
        .expect("cleaned revision decisions");
    assert!(
        cleaned_decisions
            .dispositions
            .values()
            .flatten()
            .all(|key| key.action == NativeOwnedKeyAction::AssessRetainedCopies)
    );
    let key_id = keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.service, f.ledger, keys));
    let keys = NativeCustodyKeys::open(
        keys_dir.path().join("keys"),
        "record-witness",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([79; 32])).expect("master"),
    )
    .expect("actual keys reopen");
    let ledger = NativeSuppressionLedger::open(
        f.ledger_directory.path().join("ledger"),
        "record-witness",
        ledger_id,
    )
    .expect("actual removal authority reopen");
    let reopened = NativeService::open_encrypted(
        f.root.path().join("native"),
        "record-witness",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native reopen");
    for saved in [&decisions, &cleaned_decisions] {
        assert_eq!(
            reopened
                .read_record_key_removal(
                    &f.context,
                    &f.removal,
                    &witness,
                    &saved.receipt,
                    &mut budget()
                )
                .expect("both authorities preserve old decisions"),
            *saved
        );
    }
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
            ledger.clone(),
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
        for saved in [&decisions, &cleaned_decisions] {
            assert_eq!(
                restored
                    .read_record_key_removal(
                        &f.context,
                        &f.removal,
                        &witness,
                        &saved.receipt,
                        &mut budget()
                    )
                    .expect("exact decisions across old and cleaned archives"),
                *saved
            );
        }
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

#[test]
fn owned_record_decisions_require_revision_policy_and_exact_owner() {
    let (_keys_dir, keys) = encryption::tests::authority("record-witness");
    let f = fixture_with_keys(Some(keys));
    let owner = prepare(&f, "private-record", 1).expect("owner");
    let saved = f
        .service
        .retain_record_key_removal(&f.context, &f.removal, &owner, &mut budget())
        .expect("decisions");
    for fault in ["admin", "scope", "purpose", "audience", "clearance"] {
        let mut denied = f.context.clone();
        match fault {
            "admin" => {
                denied.capability_grants.remove(&Capability::Admin);
            }
            "scope" => denied.request.scopes.clear(),
            "purpose" => denied.request.purpose = "forbidden".into(),
            "audience" => {
                denied.request.subject_id = "outsider".into();
                denied.request.audiences.clear();
            }
            "clearance" => denied.request.clearance = Sensitivity::Public,
            _ => unreachable!(),
        }
        assert!(
            f.service
                .retain_record_key_removal(&denied, &f.removal, &owner, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.service
                .read_record_key_removal(&denied, &f.removal, &owner, &saved.receipt, &mut budget())
                .is_err(),
            "{fault}"
        );
    }
    let other = prepare(&f, "PRIVATE-PARENT", 1).expect("another selected owner");
    assert_eq!(
        f.service
            .read_record_key_removal(
                &f.context,
                &f.removal,
                &other,
                &saved.receipt,
                &mut budget()
            )
            .expect_err("owner is bound")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut foreign = owner;
    foreign.removal_sequence += 1;
    assert!(
        f.service
            .retain_record_key_removal(&f.context, &f.removal, &foreign, &mut budget())
            .is_err()
    );
}
