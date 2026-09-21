use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use contextdb_service::CapturePort;

fn ids(f: &Fixture) -> BTreeSet<Uuid> {
    f.witness
        .dispositions
        .values()
        .flatten()
        .map(|key| key.allocation.key_id)
        .collect()
}

fn source_key(sequence: u64) -> Vec<u8> {
    digest_bytes(request(sequence, "").event.event_id.to_string().as_bytes()).into_bytes()
}

fn prune(f: &Fixture, removal: &NativeRemovalRequestReceipt) {
    f.native
        .prepare_original_removal_sources(&f.input.context, removal, &removal.roots, &mut budget())
        .expect("prepare");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(&f.input.context, removal, &removal.roots, &mut budget())
        .expect("prune");
}

fn archive(f: &Fixture) -> BackupResponse {
    f.native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive")
}

fn replacement(
    f: &Fixture,
    removal: &NativeRemovalRequestReceipt,
    old: &BackupResponse,
) -> NativeRemovalBackup {
    let result = f
        .native
        .create_removal_backup(&f.input.context, removal, old, &mut budget())
        .expect("replacement");
    assert!(
        f.native
            .retain_removal_backup(&f.input.context, removal, &result, 0, 16, &mut budget())
            .expect("retained bytes")
            .complete
    );
    result
}

fn retire(f: &Fixture) -> ServiceResult<NativeKeyRetirement> {
    f.native.retire_removal_keys(
        &f.input.context,
        &f.removal,
        &NativeRemovalKeySelection::Originals,
        &ids(f),
        &mut budget(),
    )
}

#[test]
fn retirement_denies_old_views_and_archives_after_cold_authority_reopen() {
    let f = fixture();
    let view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old view");
    let selected = source_key(1);
    let independent = source_key(2);
    let space = f.native.keyspaces.observations_content.clone();
    let kept = view
        .get(&space, &independent)
        .expect("independent bytes")
        .expect("present");
    let old = archive(&f);
    prune(&f, &f.removal);
    let clean = replacement(&f, &f.removal, &old);
    let catalog = f
        .keys
        .key_catalog_page(None, 1, &mut budget())
        .expect("catalog prefix");
    let accepted = retire(&f).expect("current refusal");
    assert!(catalog.continuation.is_some());
    f.keys
        .key_catalog_page(catalog.continuation.as_deref(), 1, &mut budget())
        .expect("retirement does not change immutable allocation enumeration");
    assert_eq!(
        accepted
            .keys
            .iter()
            .map(|key| key.key_id)
            .collect::<BTreeSet<_>>(),
        ids(&f)
    );
    assert!(
        view.get(&space, &selected)
            .expect_err("old snapshot must consult current custody")
            .to_string()
            .contains("retired")
    );
    assert_eq!(
        view.get(&space, &independent)
            .expect("old independent view"),
        Some(kept.clone())
    );
    drop(view);
    assert_eq!(retire(&f).expect("exact retry"), accepted);
    f.native
        .append_event(request(3, "independent allocation after retirement"))
        .expect("new keys");
    assert_eq!(
        f.keys
            .key_retirement(&accepted.receipt, &mut budget())
            .expect("anchor survives allocation"),
        accepted
    );
    assert_eq!(retire(&f).expect("retry after unrelated growth"), accepted);
    let encoded = String::from_utf8(encode(&accepted).expect("receipt JSON")).expect("text");
    assert!(!encoded.contains("original-witness-sentinel"));
    let key_authority = f.keys.authority_id();
    let ledger_authority = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_authority,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("cold key authority");
    let ledger = NativeSuppressionLedger::open(
        f.root.path().join("ledger"),
        "primary-decisions",
        ledger_authority,
    )
    .expect("cold removal authority");
    assert_eq!(
        keys.key_retirement(&accepted.receipt, &mut budget())
            .expect("durable refusal"),
        accepted
    );
    for (name, archive, allowed) in [("old", old, false), ("clean", clean.backup, true)] {
        let restored = NativeService::open_encrypted(
            f.root.path().join(name),
            "primary-decisions",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("fresh target");
        let before = restored.engine.head_sequence().expect("native head");
        let result = restored.restore_backup(RestoreBackupRequest {
            context: f.input.context.clone(),
            bytes: archive.bytes,
            format: archive.format,
            digest: archive.digest,
        });
        if allowed {
            result.expect("clean archive restores");
            restored.verify_native(true).expect("full native replay");
            assert_eq!(
                restored
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .expect("view")
                    .get(&space, &independent)
                    .expect("independent preserved"),
                Some(kept.clone())
            );
        } else {
            assert!(result.is_err(), "retired source key cannot be restored");
            assert_eq!(restored.engine.head_sequence().expect("unchanged"), before);
        }
    }
}

#[test]
fn retirement_invalidates_staged_ciphertext_import_before_native_preparation() {
    let f = fixture();
    let space = f.native.keyspaces.observations_content.clone();
    let selected = source_key(1);
    let ciphertext = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view")
        .inner
        .get(&space, &selected)
        .expect("ciphertext")
        .expect("present");
    let target = NativeStorage::open(&f.root.path().join("pending-import"), Some(f.keys.clone()))
        .expect("registered target");
    let before = target.head_sequence().expect("genesis");
    let mut pending = target.begin_write().expect("start before retirement");
    pending
        .put_ciphertext(&space, selected.clone(), ciphertext)
        .expect("stage permitted old key");
    prune(&f, &f.removal);
    retire(&f).expect("no acknowledged import");
    let usage = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("use frontier")
        .native_use;
    assert!(
        pending
            .commit(Durability::Sync)
            .expect_err("staged import is stale")
            .to_string()
            .contains("retirement changed")
    );
    assert_eq!(
        target.head_sequence().expect("no native publication"),
        before
    );
    assert!(
        target
            .begin_read(SnapshotSelector::Latest)
            .expect("empty target")
            .get(&space, &selected)
            .expect("no copied value")
            .is_none()
    );
    assert_eq!(
        f.native
            .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
            .expect("no preparation published")
            .native_use,
        usage
    );
}

#[test]
fn retirement_waits_for_a_complete_preserved_archive() {
    let f = fixture();
    for sequence in 3..=4 {
        f.native
            .append_event(request(sequence, &"i".repeat(200 * 1024)))
            .expect("independent originals force a multi-page artifact");
    }
    let old = archive(&f);
    let view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old view");
    prune(&f, &f.removal);
    assert!(retire(&f).is_err(), "no verified replacement");
    let clean = f
        .native
        .create_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
        .expect("replacement proof");
    assert!(
        retire(&f).is_err(),
        "a proof without retained bytes is insufficient"
    );
    let prefix = f
        .native
        .retain_removal_backup(&f.input.context, &f.removal, &clean, 0, 1, &mut budget())
        .expect("first page");
    assert!(!prefix.complete);
    assert!(retire(&f).is_err(), "partial bytes are insufficient");
    assert!(
        view.get(&f.native.keyspaces.observations_content, &source_key(1))
            .expect("no premature retirement")
            .is_some()
    );
    assert!(
        f.native
            .retain_removal_backup(
                &f.input.context,
                &f.removal,
                &clean,
                prefix.stored_pages,
                16,
                &mut budget()
            )
            .expect("remaining pages")
            .complete
    );
    retire(&f).expect("complete independently available replacement");
    assert!(
        view.get(&f.native.keyspaces.observations_content, &source_key(1))
            .is_err()
    );
}

#[test]
fn retirement_losing_to_an_import_must_reassess_the_new_native_copy() {
    let f = fixture();
    let space = f.native.keyspaces.observations_content.clone();
    let row = source_key(1);
    let ciphertext = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view")
        .inner
        .get(&space, &row)
        .expect("ciphertext")
        .expect("present");
    let target = std::sync::Arc::new(
        NativeStorage::open(&f.root.path().join("winning-import"), Some(f.keys.clone()))
            .expect("registered target"),
    );
    prune(&f, &f.removal);
    let importing = target.clone();
    let imported_space = space.clone();
    let imported_row = row.clone();
    BEFORE_RETIREMENT_FENCE.with(|hook| {
        hook.replace(Some(Box::new(move || {
            let mut tx = importing.begin_write().expect("concurrent import");
            tx.put_ciphertext(&imported_space, imported_row, ciphertext)
                .expect("stage");
            tx.commit(Durability::Sync)
                .expect("import wins custody publication");
        })))
    });
    assert_eq!(
        retire(&f).expect_err("use frontier changed").code,
        ErrorCode::IndexTooStale
    );
    assert!(
        retire(&f).is_err(),
        "fresh evidence sees the acknowledged imported copy"
    );
    assert!(
        target
            .begin_read(SnapshotSelector::Latest)
            .expect("imported view")
            .get(&space, &row)
            .expect("no early refusal")
            .is_some()
    );
    let mut tx = target.begin_write().expect("remove the imported copy");
    tx.delete(&space, row).expect("delete");
    tx.commit(Durability::Sync).expect("tracked removal");
    retire(&f).expect("retry after all native copies are removed");
}

#[test]
fn retirement_requires_policy_removed_native_copies_and_fresh_publication_frontiers() {
    let f = fixture();
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .retire_removal_keys(
                &denied,
                &f.removal,
                &NativeRemovalKeySelection::Originals,
                &ids(&f),
                &mut budget()
            )
            .expect_err("admin")
            .code,
        ErrorCode::Unauthorized
    );
    assert!(retire(&f).is_err(), "acknowledged original still exists");
    let old_view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old view");
    prune(&f, &f.removal);
    let native = f.native.clone();
    BEFORE_RETIREMENT_FENCE.with(|hook| {
        hook.replace(Some(Box::new(move || {
            native
                .append_event(request(3, "concurrent independent publication"))
                .expect("growth");
        })))
    });
    assert_eq!(
        retire(&f).expect_err("fresh custody frontiers").code,
        ErrorCode::IndexTooStale
    );
    assert!(
        old_view
            .get(&f.native.keyspaces.observations_content, &source_key(1))
            .expect("no early refusal")
            .is_some()
    );
    assert!(
        f.native
            .retire_removal_keys(
                &f.input.context,
                &f.removal,
                &NativeRemovalKeySelection::Originals,
                &BTreeSet::from([Uuid::from_u128(99999)]),
                &mut budget()
            )
            .is_err()
    );
    retire(&f).expect("retry with complete current evidence");
}

#[test]
fn sequential_retirements_preserve_archives_through_separately_authorized_removals() {
    let f = fixture();
    f.native
        .append_event(request(3, "never-remove-independent-original"))
        .expect("independent");
    let old = archive(&f);
    prune(&f, &f.removal);
    let middle = replacement(&f, &f.removal, &old);
    let first = retire(&f).expect("first key refused");
    let second_id = request(2, "").event.event_id;
    let second = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([second_id]),
            "second removal",
            &mut budget(),
        )
        .expect("second authority");
    let keys: BTreeSet<_> = f
        .native
        .read_original_key_inventory(&f.input.context, &second, &mut budget())
        .expect("second ownership")
        .sources
        .values()
        .flatten()
        .map(|key| key.key_id)
        .collect();
    prune(&f, &second);
    let clean = replacement(&f, &second, &middle.backup);
    let report = f
        .native
        .read_removal_backup_inventory(
            &f.input.context,
            &second,
            &NativeRemovalKeySelection::Originals,
            &mut budget(),
        )
        .expect("cross-request preservation");
    assert!(
        matches!(&report.preservation[&1], NativeBackupPreservation::Preserved { path, .. }
        if path.replacements == [middle.replacement.receipt.clone(), clean.replacement.receipt.clone()])
    );
    let accepted = f
        .native
        .retire_removal_keys(
            &f.input.context,
            &second,
            &NativeRemovalKeySelection::Originals,
            &keys,
            &mut budget(),
        )
        .expect("second refusal without decrypting the first source");
    assert_eq!(accepted.receipt.sequence, first.receipt.sequence + 1);
    let earlier = f
        .native
        .read_removal_backup_inventory(
            &f.input.context,
            &f.removal,
            &NativeRemovalKeySelection::Originals,
            &mut budget(),
        )
        .expect("reassess the earlier source after a different key retirement");
    let middle_archive = &earlier.backups.archives[1];
    assert!(
        middle_archive
            .artifact
            .as_ref()
            .expect("complete bytes remain")
            .complete
    );
    assert!(
        !middle_archive.keys_available,
        "unselected second source key is now retired"
    );
    assert!(earlier.backups.archives[2].keys_available);
    assert_eq!(
        earlier.backups.frontier.retirements,
        Some(accepted.receipt.clone())
    );
    let NativeBackupPreservation::Preserved { path, artifact } = &earlier.preservation[&1] else {
        panic!("earlier source must retain a readable route");
    };
    assert_eq!(
        path.target_sequence,
        clean.replacement.target.registration.sequence
    );
    assert_eq!(
        path.replacements,
        [
            middle.replacement.receipt.clone(),
            clean.replacement.receipt.clone()
        ]
    );
    let available = f
        .native
        .read_retained_removal_backup(
            &f.input.context,
            &second,
            &clean.replacement.receipt,
            artifact,
            &mut budget(),
        )
        .expect("route ends at actual readable archive bytes");
    assert_eq!(available, clean.backup);
    let view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current view");
    assert!(
        view.get(&f.native.keyspaces.observations_content, &source_key(3))
            .expect("independent remains decryptable")
            .is_some()
    );
    f.native
        .verify_native(true)
        .expect("complete current replay");
    assert_eq!(
        f.keys
            .key_retirement(&first.receipt, &mut budget())
            .expect("first receipt remains"),
        first
    );
}
