use contextdb_service::{
    BackupResponse, CapturePort, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};
use std::collections::BTreeMap;

use super::*;
use crate::raw_index::copies::tests::{Fixture, budget, fixture};

pub(super) fn populated() -> Fixture {
    let f = fixture();
    for sequence in 3..32 {
        f.native
            .append_event(crate::capture::tests::request(
                sequence,
                &format!("archive-membership-private-{sequence} incidental detail"),
            ))
            .expect("capture");
    }
    f.native
        .project_originals(&f.first.context, false, 64, &mut budget())
        .expect("index");
    f
}

pub(super) fn archive(f: &Fixture) -> BackupResponse {
    f.native
        .create_backup(CreateBackupRequest {
            context: f.first.context.clone(),
        })
        .expect("archive")
}

fn inventory(f: &Fixture, archive: &BackupResponse) -> NativeBackupContentsInventory {
    f.keys
        .backup_contents(&archive.digest, &mut budget())
        .expect("contents")
        .expect("accepted")
}

fn copies(
    keys: &NativeCustodyKeys,
    inventory: &NativeBackupContentsInventory,
) -> Vec<NativeBackupKeyCopy> {
    let mut copies = Vec::new();
    for page in 0..inventory.pages {
        let result = keys
            .backup_contents_page(&inventory.receipt, page, &mut budget())
            .expect("page");
        assert_eq!(result.inventory, *inventory);
        assert_eq!(
            result.next_page,
            (page + 1 < inventory.pages).then_some(page + 1)
        );
        assert!(result.copies.len() <= PAGE_ROWS);
        copies.extend(result.copies);
    }
    assert_eq!(copies.len() as u64, inventory.rows);
    copies
}

#[test]
fn archive_contents_match_every_physical_version_and_survive_old_restore_and_reopen() {
    let f = populated();
    let old = archive(&f);
    let inventory = inventory(&f, &old);
    assert!(inventory.pages > 1, "real multi-page archive");
    let rows = copies(&f.keys, &inventory);
    let actual: BTreeMap<_, _> = rows
        .into_iter()
        .map(|copy| (copy.address_digest, copy.version))
        .collect();
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let mut expected = BTreeMap::new();
    for space in f.native.keyspaces.all() {
        for entry in snapshot
            .inner
            .scan_prefix(space, b"")
            .expect("physical rows")
        {
            let value = snapshot
                .get(space, &entry.key)
                .expect("logical value")
                .expect("present");
            let version = NativeKeyUseVersion {
                key_id: Uuid::from_slice(&entry.value[VALUE_MAGIC.len()..VALUE_MAGIC.len() + 16])
                    .expect("cipher UUID"),
                ciphertext_digest: crate::digest_bytes(&entry.value),
                value_digest: crate::digest_bytes(&value),
                ciphertext_bytes: entry.value.len() as u64,
            };
            assert!(
                expected
                    .insert(address(space, &entry.key), version)
                    .is_none()
            );
        }
    }
    assert_eq!(actual, expected);
    drop(snapshot);
    let json = String::from_utf8(encode(&actual).expect("JSON")).expect("UTF8");
    assert!(!json.contains("archive-membership-private"));
    assert!(!json.contains("rawcopysentinelprivate"));
    f.native
        .append_event(crate::capture::tests::request(
            32,
            "later independent original",
        ))
        .expect("later use");
    let before = f.keys.engine.head_sequence().expect("custody head");
    assert_eq!(
        f.native
            .retain_backup_contents(&f.first.context, &old, &mut budget())
            .expect("historical retry"),
        inventory
    );
    assert_eq!(
        f.keys.engine.head_sequence().expect("no duplicate sync"),
        before
    );
    for (name, backup) in [("empty", &f.empty), ("old", &old)] {
        let restored = crate::NativeService::open_encrypted(
            f.root.path().join(name),
            "raw-copies",
            [8; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: f.first.context.clone(),
                bytes: backup.bytes.clone(),
                format: backup.format.clone(),
                digest: backup.digest.clone(),
            })
            .expect("older encrypted restore");
        assert_eq!(
            f.keys
                .backup_contents(&old.digest, &mut budget())
                .expect("retained membership"),
            Some(inventory.clone())
        );
        assert_eq!(
            restored
                .retain_backup_contents(&f.first.context, &old, &mut budget())
                .expect("old archive on different native instance"),
            inventory
        );
    }
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.keys_directory.path().join("keys"),
        "raw-copies",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([79; 32])).expect("master"),
    )
    .expect("custody reopened");
    let ledger = crate::NativeSuppressionLedger::open(
        f.ledger_directory.path().join("ledger"),
        "raw-copies",
        ledger_id,
    )
    .expect("ledger reopened");
    let native = crate::NativeService::open_encrypted(
        f.root.path().join("native"),
        "raw-copies",
        [9; 32],
        ledger,
        keys.clone(),
    )
    .expect("native reopened");
    assert_eq!(
        native
            .retain_backup_contents(&f.first.context, &old, &mut budget())
            .expect("reopened exact archive"),
        inventory
    );
    assert_eq!(copies(&keys, &inventory).len() as u64, inventory.rows);
}

// Construct the original, pre-contents v4 registry wire shape without changing
// valid archive bytes, registered archive digests or retained encryption history.
pub(super) fn legacy_registry(keys: &NativeCustodyKeys, keep_issuance: bool) {
    let mut tx = keys.engine.begin_write().expect("tx");
    let mut head = if keep_issuance {
        keys.backup_head(&tx).expect("head")
    } else {
        Head::default()
    };
    head.contents = None;
    let prefix: &[u8] = if keep_issuance {
        b"backup/contents/"
    } else {
        b"backup/"
    };
    for row in tx.scan_prefix(&keys.rows, prefix).expect("fixture rows") {
        tx.delete(&keys.rows, row.key).expect("remove fixture rows");
    }
    let old_head = encode(&head).expect("old header");
    assert!(
        !String::from_utf8(old_head)
            .expect("UTF8")
            .contains("contents")
    );
    tx.put(
        &keys.rows,
        HEAD.to_vec(),
        keys.seal_backup_record(HEAD, &head)
            .expect("old sealed head"),
    )
    .expect("head");
    tx.commit(Durability::Sync).expect("legacy fixture");
    keys.verify().expect("valid pre-contents registry");
}

#[test]
fn archive_contents_backfill_requires_verified_issued_bytes_and_rolls_back_partial_pages() {
    let f = populated();
    let old = archive(&f);
    let previous = inventory(&f, &old);
    let rows = copies(&f.keys, &previous);
    assert!(rows.len() > PAGE_ROWS);
    legacy_registry(&f.keys, true);
    assert!(
        f.keys
            .backup_contents(&old.digest, &mut budget())
            .expect("legacy coverage")
            .is_none()
    );
    let before = f.keys.engine.head_sequence().expect("head");
    let mut denied = f.first.context.clone();
    denied
        .capability_grants
        .remove(&contextdb_service::Capability::Admin);
    let mut malformed = old.clone();
    malformed.bytes.clear();
    assert_eq!(
        f.native
            .retain_backup_contents(&denied, &malformed, &mut budget())
            .expect_err("authorization before inspection")
            .code,
        ErrorCode::Unauthorized
    );
    let mut wrong = old.clone();
    wrong.commit_seq += 1;
    assert!(
        f.native
            .retain_backup_contents(&f.first.context, &wrong, &mut budget())
            .is_err()
    );
    wrong = old.clone();
    *wrong.bytes.last_mut().expect("footer") ^= 1;
    assert!(
        f.native
            .retain_backup_contents(&f.first.context, &wrong, &mut budget())
            .is_err()
    );
    let mut tiny = QueryBudget::new(0, 0, std::time::Duration::from_secs(1), Default::default());
    assert_eq!(
        f.native
            .retain_backup_contents(&f.first.context, &old, &mut tiny)
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    let partial = rows
        .iter()
        .take(PAGE_ROWS)
        .cloned()
        .map(Ok)
        .chain(std::iter::once(Err(crate::exhausted(
            "stop after staged page",
        ))));
    assert_eq!(
        f.keys
            .accept_backup_contents(
                &old,
                &previous.registration.logical_digest,
                partial,
                false,
                &mut budget()
            )
            .expect_err("interrupted backfill")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        f.keys
            .engine
            .head_sequence()
            .expect("no partial acceptance"),
        before
    );
    assert!(
        f.keys
            .backup_contents(&old.digest, &mut budget())
            .expect("still unknown")
            .is_none()
    );
    f.keys.verify().expect("no orphan staged pages");
    let retained = f
        .native
        .retain_backup_contents(&f.first.context, &old, &mut budget())
        .expect("real backfill");
    assert_eq!(retained.registration, previous.registration);
    assert_eq!(copies(&f.keys, &retained), rows);
    assert_eq!(retained.contents_digest, previous.contents_digest);
    assert!(
        f.keys
            .backup_contents_page(&retained.receipt, retained.pages, &mut budget())
            .is_err()
    );
    let mut foreign = retained.receipt.clone();
    foreign.authority_id = Uuid::max();
    assert!(
        f.keys
            .backup_contents_page(&foreign, 0, &mut budget())
            .is_err()
    );
    legacy_registry(&f.keys, false);
    let unissued = f.keys.engine.head_sequence().expect("before unissued");
    assert!(
        f.native
            .retain_backup_contents(&f.first.context, &old, &mut budget())
            .is_err(),
        "backfill cannot invent issuance"
    );
    let partial = rows
        .into_iter()
        .take(PAGE_ROWS)
        .map(Ok)
        .chain(std::iter::once(Err(crate::exhausted(
            "stop after staged issuance and page",
        ))));
    assert!(
        f.keys
            .accept_backup_contents(
                &old,
                &previous.registration.logical_digest,
                partial,
                true,
                &mut budget()
            )
            .is_err()
    );
    assert_eq!(
        f.keys.engine.head_sequence().expect("no partial issuance"),
        unissued
    );
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("registry")
            .revision,
        0
    );
    f.keys.verify().expect("no orphan registration/pages");
    assert_eq!(
        archive(&f).bytes,
        old.bytes,
        "normal issuance remains exact"
    );
}

#[test]
fn archive_contents_loss_or_rehashed_page_cannot_mint_replacement_evidence() {
    for fault in [
        "page",
        "event",
        "index",
        "all_contents",
        "issuance",
        "legacy_issuance",
        "changed_version",
    ] {
        let f = fixture();
        let old = archive(&f);
        let inventory = inventory(&f, &old);
        if fault == "legacy_issuance" {
            legacy_registry(&f.keys, true);
        }
        let mut tx = f.keys.engine.begin_write().expect("tx");
        let key = match fault {
            "page" | "changed_version" => page_key(inventory.receipt.sequence, inventory.pages - 1),
            "event" => event_key(inventory.receipt.sequence),
            "index" => index_key(&old.digest),
            "issuance" | "legacy_issuance" => super::super::index_key(&old.digest),
            "all_contents" => Vec::new(),
            _ => unreachable!(),
        };
        if fault == "changed_version" {
            let bytes = tx.get(&f.keys.rows, &key).expect("get").expect("page");
            let mut page: CopyPage = f.keys.open_backup_record(&key, &bytes).expect("page");
            page.copies[0].version.value_digest = "ab".repeat(32);
            page.digest = page.commitment(inventory.pages - 1).expect("rehashed page");
            tx.put(
                &f.keys.rows,
                key.clone(),
                f.keys
                    .seal_backup_record(&key, &page)
                    .expect("seal altered page"),
            )
            .expect("put");
        } else if fault == "all_contents" {
            for row in tx
                .scan_prefix(&f.keys.rows, b"backup/contents/")
                .expect("contents")
            {
                tx.delete(&f.keys.rows, row.key).expect("loss");
            }
        } else {
            tx.delete(&f.keys.rows, key).expect("loss");
        }
        tx.commit(Durability::Sync).expect("damage fixture");
        let before = f.keys.engine.head_sequence().expect("head");
        assert!(f.keys.verify().is_err(), "{fault}");
        assert!(
            f.keys
                .backup_contents_page(&inventory.receipt, inventory.pages - 1, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .retain_backup_contents(&f.first.context, &old, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .create_backup(CreateBackupRequest {
                    context: f.first.context.clone()
                })
                .is_err(),
            "{fault}"
        );
        assert_eq!(
            f.keys.engine.head_sequence().expect("no new acceptance"),
            before,
            "{fault}"
        );
    }
}
