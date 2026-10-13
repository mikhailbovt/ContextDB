use std::{path::Path, sync::Arc, time::Duration};

use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{CapturePort, ReadOriginalRequest};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use contextdb_storage_fjall::FjallStorage;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::*;
use crate::encryption::{CustodyMasterKey, NativeKeyUseCatalogPage};

const DATABASE: &str = "existing-encrypted";

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master")
}

fn authorities(root: &Path) -> (Arc<NativeSuppressionLedger>, Arc<NativeCustodyKeys>) {
    let ledger = NativeSuppressionLedger::create_with_authority(
        root.join("ledger"),
        DATABASE,
        Uuid::from_u128(41),
    )
    .expect("ledger");
    let keys = NativeCustodyKeys::create_with_authority(
        root.join("keys"),
        DATABASE,
        Uuid::from_u128(42),
        master(),
    )
    .expect("keys");
    (ledger, keys)
}

fn catalog(keys: &NativeCustodyKeys) -> NativeKeyUseCatalogPage {
    keys.native_use_catalog_page(
        None,
        64,
        &mut QueryBudget::new(
            1_000_000,
            128 * 1024 * 1024,
            Duration::from_secs(30),
            QueryCancellation::default(),
        ),
    )
    .expect("use catalog")
}

fn reopen(
    path: &Path,
    ledger: &Arc<NativeSuppressionLedger>,
    keys: &Arc<NativeCustodyKeys>,
) -> ServiceResult<NativeService> {
    NativeService::open_encrypted_existing(path, DATABASE, [7; 32], ledger.clone(), keys.clone())
}

#[test]
fn existing_encrypted_cold_reopen_preserves_capture_and_authority_history() {
    let root = tempfile::tempdir().expect("root");
    let (ledger, keys) = authorities(root.path());
    let path = root.path().join("native");
    assert!(!path.exists());
    let service =
        NativeService::open_encrypted(&path, DATABASE, [7; 32], ledger.clone(), keys.clone())
            .expect("explicit create-capable open");
    let input = crate::capture::tests::request(1, "retained original across cold reopen");
    service.append_event(input.clone()).expect("capture");
    let archive_digest = service
        .verify_native(true)
        .expect("before verify")
        .archive_digest;
    let history = catalog(&keys);
    let native_sequence = service
        .engine
        .snapshot_before_recovery()
        .expect("snapshot")
        .sequence();
    drop(service);
    drop(ledger);
    drop(keys);
    let ledger =
        NativeSuppressionLedger::open(root.path().join("ledger"), DATABASE, Uuid::from_u128(41))
            .expect("cold ledger");
    let keys = NativeCustodyKeys::open(
        root.path().join("keys"),
        DATABASE,
        Uuid::from_u128(42),
        master(),
    )
    .expect("cold keys");
    assert_eq!(ledger.format_version(), 3);
    assert_eq!(keys.format_version(), 4);
    let service = reopen(&path, &ledger, &keys).expect("existing-only cold reopen");
    assert_eq!(
        service
            .verify_native(true)
            .expect("after verify")
            .archive_digest,
        archive_digest
    );
    assert_eq!(
        service
            .engine
            .snapshot_before_recovery()
            .expect("snapshot")
            .sequence(),
        native_sequence
    );
    assert_eq!(catalog(&keys), history);
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: input.context,
                event_id: input.event.event_id,
                after_receipt: None
            })
            .expect("read original")
            .event,
        input.event
    );
}

#[test]
fn existing_encrypted_refuses_missing_empty_and_partial_physical_stores_without_registration() {
    let root = tempfile::tempdir().expect("root");
    let (ledger, keys) = authorities(root.path());
    let history = catalog(&keys);
    let missing = root.path().join("missing");
    assert!(reopen(&missing, &ledger, &keys).is_err());
    assert!(!missing.exists());
    let empty = root.path().join("empty");
    std::fs::create_dir(&empty).expect("empty dir");
    assert!(reopen(&empty, &ledger, &keys).is_err());
    assert_eq!(
        std::fs::read_dir(&empty).expect("empty contents").count(),
        0
    );
    let partial = root.path().join("partial");
    let engine = FjallStorage::open(&partial).expect("partial physical store");
    let names = engine.physical_keyspace_names();
    drop(engine);
    assert!(reopen(&partial, &ledger, &keys).is_err());
    let engine = FjallStorage::try_open_existing(&partial)
        .expect("partial inspect")
        .expect("closed");
    assert_eq!(engine.physical_keyspace_names(), names);
    assert_eq!(
        engine
            .begin_read(SnapshotSelector::Latest)
            .expect("partial snapshot")
            .sequence(),
        0
    );
    assert_eq!(catalog(&keys), history);
    drop(engine);
    let protocol_only = root.path().join("protocol-only");
    let storage = NativeStorage::open(&protocol_only, Some(keys.clone()))
        .expect("interrupted application initialization");
    let snapshot = storage
        .snapshot_before_recovery()
        .expect("protocol snapshot");
    assert_eq!(snapshot.sequence(), 1);
    drop(snapshot);
    let names = storage.physical_keyspace_names();
    let history = catalog(&keys);
    drop(storage);
    assert!(reopen(&protocol_only, &ledger, &keys).is_err());
    let engine = FjallStorage::try_open_existing(&protocol_only)
        .expect("protocol inspect")
        .expect("closed");
    assert_eq!(engine.physical_keyspace_names(), names);
    assert_eq!(
        engine
            .begin_read(SnapshotSelector::Latest)
            .expect("protocol snapshot")
            .sequence(),
        1
    );
    assert_eq!(catalog(&keys), history);
}

#[test]
fn existing_encrypted_refuses_missing_control_manifest_and_protocol_without_repair() {
    let root = tempfile::tempdir().expect("root");
    let (ledger, keys) = authorities(root.path());
    let path = root.path().join("native");
    let service =
        NativeService::open_encrypted(&path, DATABASE, [7; 32], ledger.clone(), keys.clone())
            .expect("provision");
    let history = catalog(&keys);
    drop(service);
    for control in ["version", "lock"] {
        let retained = root.path().join(format!("retained-{control}"));
        std::fs::rename(path.join(control), &retained).expect("hold fixture control");
        assert!(reopen(&path, &ledger, &keys).is_err());
        assert!(!path.join(control).exists());
        assert_eq!(catalog(&keys), history);
        std::fs::rename(retained, path.join(control)).expect("restore fixture control");
    }
    let service = reopen(&path, &ledger, &keys).expect("controls restored");
    let mut tx = service
        .engine
        .begin_write()
        .expect("delete fixture manifest");
    tx.delete(&service.keyspaces.meta, crate::META_MANIFEST_KEY.to_vec())
        .expect("delete manifest");
    tx.commit(Durability::Sync)
        .expect("commit missing manifest");
    let history = catalog(&keys);
    drop(service);
    assert!(reopen(&path, &ledger, &keys).is_err());
    assert_eq!(catalog(&keys), history);
    let engine = FjallStorage::try_open_existing(&path)
        .expect("inspect manifest")
        .expect("closed");
    let snapshot = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let meta = Keyspace::new("contextdb_native_meta").expect("meta");
    assert!(
        snapshot
            .get(&meta, crate::META_MANIFEST_KEY)
            .expect("missing manifest")
            .is_none()
    );
    drop(snapshot);
    let mut tx = engine.begin_write().expect("delete fixture marker");
    tx.delete(
        &Keyspace::new(crate::encryption::keys::uses::LOCAL_SPACE).expect("local"),
        crate::encryption::keys::uses::LOCAL_HEAD.to_vec(),
    )
    .expect("delete local marker");
    tx.commit(Durability::Sync)
        .expect("missing protocol commit");
    drop(engine);
    assert!(reopen(&path, &ledger, &keys).is_err());
    assert_eq!(catalog(&keys), history);
}

#[test]
fn pinned_authority_creation_rejects_nil_and_existing_paths_before_effects() {
    let root = tempfile::tempdir().expect("root");
    let nil_ledger = root.path().join("nil-ledger");
    let nil_keys = root.path().join("nil-keys");
    assert!(
        NativeSuppressionLedger::create_with_authority(&nil_ledger, DATABASE, Uuid::nil()).is_err()
    );
    assert!(
        NativeCustodyKeys::create_with_authority(&nil_keys, DATABASE, Uuid::nil(), master())
            .is_err()
    );
    assert!(!nil_ledger.exists());
    assert!(!nil_keys.exists());
    let (ledger, keys) = authorities(root.path());
    assert_eq!(ledger.authority_id(), Uuid::from_u128(41));
    assert_eq!(keys.authority_id(), Uuid::from_u128(42));
    let history = catalog(&keys);
    assert!(
        NativeSuppressionLedger::create_with_authority(
            root.path().join("ledger"),
            DATABASE,
            Uuid::from_u128(99)
        )
        .is_err()
    );
    assert!(
        NativeCustodyKeys::create_with_authority(
            root.path().join("keys"),
            DATABASE,
            Uuid::from_u128(99),
            master()
        )
        .is_err()
    );
    assert_eq!(catalog(&keys), history);
    let random_ledger =
        NativeSuppressionLedger::create(root.path().join("random-ledger"), DATABASE)
            .expect("old create ledger");
    let random_keys =
        NativeCustodyKeys::create(root.path().join("random-keys"), DATABASE, master())
            .expect("old create keys");
    assert!(!random_ledger.authority_id().is_nil());
    assert!(!random_keys.authority_id().is_nil());
    assert_eq!(random_ledger.format_version(), 3);
    assert_eq!(random_keys.format_version(), 4);
}

#[test]
fn existing_authority_open_refuses_missing_empty_and_control_loss_without_seeding() {
    let root = tempfile::tempdir().expect("root");
    let ledger_id = Uuid::from_u128(41);
    let keys_id = Uuid::from_u128(42);
    for present in [false, true] {
        let suffix = if present { "empty" } else { "missing" };
        let ledger_path = root.path().join(format!("{suffix}-ledger"));
        let keys_path = root.path().join(format!("{suffix}-keys"));
        if present {
            std::fs::create_dir(&ledger_path).expect("empty ledger");
            std::fs::create_dir(&keys_path).expect("empty keys");
        }
        assert!(NativeSuppressionLedger::open(&ledger_path, DATABASE, ledger_id).is_err());
        assert!(NativeCustodyKeys::open(&keys_path, DATABASE, keys_id, master()).is_err());
        if present {
            assert_eq!(
                std::fs::read_dir(&ledger_path)
                    .expect("ledger contents")
                    .count(),
                0
            );
            assert_eq!(
                std::fs::read_dir(&keys_path)
                    .expect("keys contents")
                    .count(),
                0
            );
        } else {
            assert!(!ledger_path.exists());
            assert!(!keys_path.exists());
        }
    }
    let (ledger, keys) = authorities(root.path());
    let history = catalog(&keys);
    drop(ledger);
    drop(keys);
    for authority in ["ledger", "keys"] {
        let path = root.path().join(authority);
        for control in ["version", "lock"] {
            let retained = root.path().join(format!("{authority}-{control}"));
            std::fs::rename(path.join(control), &retained).expect("hold authority control");
            if authority == "ledger" {
                assert!(NativeSuppressionLedger::open(&path, DATABASE, ledger_id).is_err());
            } else {
                assert!(NativeCustodyKeys::open(&path, DATABASE, keys_id, master()).is_err());
            }
            assert!(!path.join(control).exists());
            std::fs::rename(retained, path.join(control)).expect("restore authority control");
        }
    }
    let ledger = NativeSuppressionLedger::open(root.path().join("ledger"), DATABASE, ledger_id)
        .expect("retained ledger");
    let keys = NativeCustodyKeys::open(root.path().join("keys"), DATABASE, keys_id, master())
        .expect("retained keys");
    assert_eq!(ledger.authority_id(), ledger_id);
    assert_eq!(catalog(&keys), history);
}
