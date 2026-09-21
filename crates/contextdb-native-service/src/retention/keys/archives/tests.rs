use super::*;
use crate::retention::keys::witness::tests::{budget, fixture};

#[test]
fn removal_archive_join_preserves_old_copies_after_prune_restore_and_authority_reopen() {
    let f = fixture();
    let selection = NativeRemovalKeySelection::Originals;
    let before = f
        .native
        .read_removal_backup_inventory(&f.input.context, &f.removal, &selection, &mut budget())
        .expect("no archives yet");
    assert!(before.backups.archives.is_empty());
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("full archive");
    let full = f
        .native
        .read_removal_backup_inventory(&f.input.context, &f.removal, &selection, &mut budget())
        .expect("full join");
    let disposition = full
        .dispositions
        .values()
        .flatten()
        .next()
        .expect("selected key");
    assert_eq!(full.backups.archives.len(), 1);
    assert_eq!(
        full.backups.archives[0].copies.len(),
        1,
        "independent original excluded"
    );
    assert_eq!(
        full.backups.archives[0].copies[0].version,
        disposition.versions[0]
    );
    let targets = BTreeSet::from([f.input.event.event_id]);
    f.native
        .prepare_original_removal_sources(&f.input.context, &f.removal, &targets, &mut budget())
        .expect("prepare");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(&f.input.context, &f.removal, &targets, &mut budget())
        .expect("prune primary");
    let cleaned = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("cleaned archive");
    let report = f
        .native
        .read_removal_backup_inventory(&f.input.context, &f.removal, &selection, &mut budget())
        .expect("historical obligation");
    assert_eq!(
        report
            .dispositions
            .values()
            .flatten()
            .next()
            .expect("key")
            .action,
        NativeOwnedKeyAction::AssessRetainedCopies
    );
    assert_eq!(report.backups.archives[0], full.backups.archives[0]);
    assert_eq!(
        report.backups.archives[1].registration.archive_digest,
        cleaned.digest
    );
    assert!(report.backups.archives[1].contents.is_some());
    assert!(report.backups.archives[1].copies.is_empty());
    let text = String::from_utf8(encode(&report).expect("json")).expect("utf8");
    assert!(!text.contains("original-witness-sentinel"));
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("keys reopened");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("ledger reopened");
    for (name, backup) in [("old", old), ("cleaned", cleaned)] {
        let restored = NativeService::open_encrypted(
            f.root.path().join(name),
            "primary-decisions",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("new native instance");
        restored
            .restore_backup(RestoreBackupRequest {
                context: f.input.context.clone(),
                bytes: backup.bytes,
                format: backup.format,
                digest: backup.digest,
            })
            .expect("restore");
        let current = restored
            .read_removal_backup_inventory(&f.input.context, &f.removal, &selection, &mut budget())
            .expect("restored archive obligations");
        assert_eq!(
            current.backups, report.backups,
            "native import does not rewrite archive coverage"
        );
        assert_eq!(current.dispositions.len(), report.dispositions.len());
        restored
            .verify_native(true)
            .expect("independent history preserved");
    }
}

#[test]
fn removal_archive_join_requires_policy_budget_and_all_publication_frontiers() {
    for race in ["issuance", "allocation", "use"] {
        let f = fixture();
        let selection = NativeRemovalKeySelection::Originals;
        let mut denied = f.input.context.clone();
        denied.capability_grants.remove(&Capability::Admin);
        assert_eq!(
            f.native
                .read_removal_backup_inventory(&denied, &f.removal, &selection, &mut budget())
                .expect_err("current admin")
                .code,
            ErrorCode::Unauthorized
        );
        let mut wrong = f.input.context.clone();
        wrong.request.workspace_id = "foreign-workspace".into();
        assert!(
            f.native
                .read_removal_backup_inventory(&wrong, &f.removal, &selection, &mut budget())
                .is_err()
        );
        let mut empty =
            QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
        assert_eq!(
            f.native
                .read_removal_backup_inventory(&f.input.context, &f.removal, &selection, &mut empty)
                .expect_err("budget")
                .code,
            ErrorCode::BudgetExhausted
        );
        let native = f.native.clone();
        let context = f.input.context.clone();
        BEFORE_ARCHIVE_FENCE.with(|hook| {
            hook.replace(Some(Box::new(move || {
                if race == "issuance" {
                    native
                        .create_backup(CreateBackupRequest { context })
                        .expect("concurrent issuance");
                } else {
                    let mut tx = native.engine.begin_write().expect("tx");
                    let space = keyspace("archive-race").expect("space");
                    if race == "allocation" {
                        tx.put(&space, b"key".to_vec(), b"value".to_vec())
                            .expect("allocation");
                    } else {
                        tx.delete(&space, b"absent".to_vec()).expect("use only");
                    }
                    tx.commit(Durability::Sync).expect("concurrent use");
                }
            })))
        });
        assert_eq!(
            f.native
                .read_removal_backup_inventory(
                    &f.input.context,
                    &f.removal,
                    &selection,
                    &mut budget()
                )
                .expect_err("stale independent frontier")
                .code,
            ErrorCode::IndexTooStale
        );
        f.native
            .read_removal_backup_inventory(&f.input.context, &f.removal, &selection, &mut budget())
            .expect("fresh report");
    }
}

#[test]
fn removal_archive_join_uses_exact_payload_and_raw_ownership() {
    let f = owned::tests::fixture();
    f.native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("payload archive");
    let payload = f
        .native
        .read_removal_backup_inventory(
            &f.input.context,
            &f.removal,
            &NativeRemovalKeySelection::Payload {
                block_id: f.payload.block_id,
            },
            &mut budget(),
        )
        .expect("chunks");
    assert_eq!(payload.dispositions.len(), 2);
    assert_eq!(payload.backups.archives[0].copies.len(), 2);
    let f = raw_index::copies::tests::fixture();
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.first.context.clone(),
        })
        .expect("raw archive");
    while !raw_index::copies::tests::reclaim(&f, 64).finished {}
    let removal = raw_index::inventory::tests::request(&f);
    let frontier = f
        .native
        .read_reclaimed_raw_key_inventory(&f.first.context, &removal, &mut budget())
        .expect("GC prefix")
        .observation_frontier();
    let pages = raw_index::inventory::tests::gather(&f.native, &f.first.context, &removal);
    for selection in [
        NativeRemovalKeySelection::ReclaimedRaw { frontier },
        NativeRemovalKeySelection::InspectedRaw {
            inventory: pages.last().expect("terminal").receipt.clone(),
        },
    ] {
        let report = f
            .native
            .read_removal_backup_inventory(&f.first.context, &removal, &selection, &mut budget())
            .expect("raw key archives");
        let archive = report
            .backups
            .archives
            .iter()
            .find(|archive| archive.registration.archive_digest == old.digest)
            .expect("full archive");
        assert!(!archive.copies.is_empty());
        let NativeRemovalKeyInventory::Owned(owned) = &report.key_inventory else {
            panic!("owned raw inventory")
        };
        let sources = match &owned.owner {
            NativeOwnedKeyOwner::ReclaimedRaw { sources, .. }
            | NativeOwnedKeyOwner::InspectedRaw { sources, .. } => sources,
            _ => panic!("raw owner"),
        };
        assert_eq!(
            sources.keys().copied().collect::<Vec<_>>(),
            vec![f.first.event.event_id]
        );
        for copy in &archive.copies {
            assert!(
                report.dispositions[&copy.address_digest]
                    .iter()
                    .any(|key| key.allocation.key_id == copy.version.key_id)
            );
        }
    }
}
