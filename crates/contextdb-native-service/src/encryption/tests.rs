use std::{path::Path, process::Command, sync::Arc, time::Duration};

use contextdb_core::{EventPayload, OriginalSourceSpan};
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{
    CapturePort, CognitiveMemoryService, CreateBackupRequest, PayloadPort, ReadOriginalRequest,
    RestoreBackupRequest, StagePayloadRequest,
};
use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};

use super::*;
use crate::{NATIVE_ENCRYPTED_BACKUP_FORMAT, NativeService, NativeSuppressionLedger};

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([79; 32])).expect("fixture custody key")
}

pub(crate) fn authority(database: &str) -> (tempfile::TempDir, Arc<NativeCustodyKeys>) {
    let directory = tempfile::tempdir().expect("key authority directory");
    let keys = NativeCustodyKeys::create(directory.path().join("keys"), database, master())
        .expect("key authority");
    (directory, keys)
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn assert_absent(path: &Path, plaintext: &[u8]) {
    for entry in std::fs::read_dir(path).expect("fixture directory") {
        let path = entry.expect("fixture entry").path();
        if path.is_dir() {
            assert_absent(&path, plaintext);
        } else {
            let bytes = std::fs::read(&path).expect("physical fixture bytes");
            assert!(
                !bytes.windows(plaintext.len()).any(|part| part == plaintext),
                "plaintext found in {}",
                path.display()
            );
        }
    }
}

#[test]
fn capture_indexes_large_payload_backup_and_rotated_restore_keep_content_encrypted() {
    let root = tempfile::tempdir().expect("root");
    let (key_directory, keys) = authority("encrypted-db");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("encrypted-db");
    let source = NativeService::open_encrypted(
        root.path().join("source"),
        "encrypted-db",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted source");
    let text = "encryption_sentinel_original_4817 do not persist this phrase in plaintext";
    let input = crate::capture::tests::request(1, text);
    source.append_event(input.clone()).expect("original");
    let mut staged = crate::capture::tests::request(2, "placeholder");
    let payload_marker = b"encryption_sentinel_staged_across_chunk_boundary_9826";
    let mut payload = vec![b'x'; 256 * 1024 + 97];
    payload[256 * 1024 - 9..256 * 1024 - 9 + payload_marker.len()].copy_from_slice(payload_marker);
    let receipt = source
        .stage_payload(StagePayloadRequest {
            context: staged.context.clone(),
            idempotency_key: "staged-ciphertext".into(),
            block_id: contextdb_core::ContentBlockId::new(),
            bytes: payload.clone(),
        })
        .expect("stage large payload");
    staged.event.payload = EventPayload::Staged {
        reference: receipt.reference,
        media_type: "application/octet-stream".into(),
    };
    source
        .append_event(staged.clone())
        .expect("staged original");
    while !source
        .project_originals(&input.context, false, 64, &mut budget())
        .expect("encrypted index")
        .caught_up
    {}
    let archive = source
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("ciphertext backup");
    assert_eq!(archive.format, NATIVE_ENCRYPTED_BACKUP_FORMAT);
    for secret in [text.as_bytes(), payload_marker.as_slice()] {
        assert!(
            !archive
                .bytes
                .windows(secret.len())
                .any(|part| part == secret)
        );
    }
    let target_path = root.path().join("target");
    let target = NativeService::open_encrypted(
        &target_path,
        "encrypted-db",
        [9; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted target");
    target
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: archive.format,
            bytes: archive.bytes,
            digest: archive.digest,
        })
        .expect("restore with external keys and rotated token key");
    assert_eq!(
        target
            .read_original(ReadOriginalRequest {
                context: input.context.clone(),
                event_id: input.event.event_id,
                after_receipt: None
            })
            .expect("restored original")
            .event,
        input.event
    );
    let start = 256 * 1024 - 9;
    let span = OriginalSourceSpan {
        event_id: staged.event.event_id,
        payload_digest: contextdb_core::ContentDigest::from_bytes(
            *blake3::hash(&payload).as_bytes(),
        ),
        start: start as u64,
        end: (start + payload_marker.len()) as u64,
        span_digest: contextdb_core::ContentDigest::from_bytes(
            *blake3::hash(payload_marker).as_bytes(),
        ),
    };
    assert_eq!(
        target
            .read_original_span(&staged.context, &span)
            .expect("cross-chunk decrypted original"),
        payload_marker
    );
    let digest = target
        .verify_native(true)
        .expect("restored logical closure")
        .archive_digest;
    drop(target);
    let target =
        NativeService::open_encrypted(&target_path, "encrypted-db", [10; 32], ledger, keys.clone())
            .expect("encrypted reopen");
    assert_eq!(
        target
            .verify_native(true)
            .expect("reopened closure")
            .archive_digest,
        digest
    );
    drop(target);
    drop(source);
    let id = keys.authority_id();
    drop(keys);
    for secret in [text.as_bytes(), payload_marker.as_slice()] {
        assert_absent(root.path(), secret);
        assert_absent(key_directory.path(), secret);
    }
    assert!(
        NativeCustodyKeys::open(
            key_directory.path().join("keys"),
            "encrypted-db",
            id,
            CustodyMasterKey::from_zeroizing(Zeroizing::new([80; 32])).expect("wrong fixture key")
        )
        .is_err()
    );
    let reopened = NativeCustodyKeys::open(
        key_directory.path().join("keys"),
        "encrypted-db",
        id,
        master(),
    )
    .expect("right retained master key");
    assert_eq!(reopened.authority_id(), id);
}

#[test]
fn ciphertext_relocation_and_forbidden_corruption_do_not_expose_source_bytes() {
    let root = tempfile::tempdir().expect("root");
    let (_key_directory, keys) = authority("cipher-policy");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("cipher-policy");
    let service = NativeService::open_encrypted(
        root.path().join("native"),
        "cipher-policy",
        [7; 32],
        ledger,
        keys,
    )
    .expect("native");
    let first = crate::capture::tests::request(1, "private encrypted payload");
    let second = crate::capture::tests::request(2, "independent encrypted payload");
    service.append_event(first.clone()).expect("first");
    service.append_event(second.clone()).expect("second");
    let first_key = crate::digest_bytes(first.event.event_id.to_string().as_bytes()).into_bytes();
    let second_key = crate::digest_bytes(second.event.event_id.to_string().as_bytes()).into_bytes();
    let snapshot = service
        .engine
        .physical()
        .begin_read(SnapshotSelector::Latest)
        .expect("physical view");
    let first_cipher = snapshot
        .get(&service.keyspaces.observations_content, &first_key)
        .expect("first ciphertext")
        .expect("first row");
    let second_cipher = snapshot
        .get(&service.keyspaces.observations_content, &second_key)
        .expect("second ciphertext")
        .expect("second row");
    let mut tx = service
        .engine
        .physical()
        .begin_write()
        .expect("relocation fixture");
    tx.put(
        &service.keyspaces.observations_content,
        second_key.clone(),
        first_cipher,
    )
    .expect("relocate ciphertext");
    tx.commit(Durability::Sync).expect("inject");
    assert!(
        service
            .read_original(ReadOriginalRequest {
                context: second.context.clone(),
                event_id: second.event.event_id,
                after_receipt: None
            })
            .is_err(),
        "a valid ciphertext cannot move to another original address"
    );
    let mut tx = service
        .engine
        .physical()
        .begin_write()
        .expect("restore fixture row");
    tx.put(
        &service.keyspaces.observations_content,
        second_key,
        second_cipher,
    )
    .expect("restore ciphertext");
    tx.commit(Durability::Sync).expect("restore physical row");
    service
        .revoke_original(
            &first.context,
            first.event.event_id,
            "deny-before-corruption",
            &mut budget(),
        )
        .expect("deny");
    while !service
        .maintain_custody(&first.context, 64, &mut budget())
        .expect("propagate before injecting corruption")
        .caught_up
    {}
    let mut tx = service
        .engine
        .physical()
        .begin_write()
        .expect("forbidden corruption");
    tx.put(
        &service.keyspaces.observations_content,
        first_key,
        b"not-an-authenticated-envelope".to_vec(),
    )
    .expect("corrupt forbidden body");
    tx.commit(Durability::Sync).expect("inject");
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: first.context.clone(),
                event_id: first.event.event_id,
                after_receipt: None
            })
            .expect_err("policy must precede body decryption")
            .code,
        contextdb_service::ErrorCode::PermissionDenied
    );
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: second.context.clone(),
                event_id: second.event.event_id,
                after_receipt: None
            })
            .expect("unrelated source")
            .event,
        second.event
    );
}

#[test]
fn concurrent_key_allocation_has_one_winner_and_the_loser_retries_before_native_publication() {
    let root = tempfile::tempdir().expect("root");
    let (_key_directory, keys) = authority("key-race");
    let left = NativeStorage::open(&root.path().join("left"), Some(keys.clone())).expect("left");
    let right = NativeStorage::open(&root.path().join("right"), Some(keys)).expect("right");
    let space = Keyspace::new("fixture").expect("space");
    let mut first = left.begin_write().expect("first attempt");
    let mut second = right.begin_write().expect("competing attempt");
    first
        .put(&space, b"same".to_vec(), b"first bytes".to_vec())
        .expect("prepare first");
    second
        .put(&space, b"same".to_vec(), b"second bytes".to_vec())
        .expect("prepare second");
    first.commit(Durability::Sync).expect("winning key batch");
    assert!(second.commit(Durability::Sync).is_err());
    assert_eq!(
        right
            .head_sequence()
            .expect("unpublished losing native store"),
        0
    );
    let mut retry = right.begin_write().expect("retry");
    retry
        .put(&space, b"same".to_vec(), b"second bytes".to_vec())
        .expect("use retained winning key");
    retry
        .commit(Durability::Sync)
        .expect("retry native publication");
    assert_eq!(
        right
            .begin_read(SnapshotSelector::Latest)
            .expect("view")
            .get(&space, b"same")
            .expect("decrypt"),
        Some(b"second bytes".to_vec())
    );
}

#[test]
fn selected_key_read_does_not_scan_the_growing_inventory() {
    let root = tempfile::tempdir().expect("root");
    let (_directory, keys) = authority("bounded-keys");
    let store = NativeStorage::open(root.path(), Some(keys)).expect("store");
    let space = Keyspace::new("fixture").expect("keyspace");
    let mut start = 0_u64;
    for end in [1, 128, 4_096] {
        let mut tx = store.begin_write().expect("inventory growth");
        for index in start..end {
            tx.put(&space, index.to_be_bytes().to_vec(), b"value".to_vec())
                .expect("new independent key");
        }
        tx.commit(Durability::Sync)
            .expect("one key publication batch");
        start = end;
        keys::KEY_LOOKUPS.with(|count| count.set(0));
        keys::CATALOG_VERIFICATIONS.with(|count| count.set(0));
        assert_eq!(
            store
                .begin_read(SnapshotSelector::Latest)
                .expect("view")
                .get(&space, &0_u64.to_be_bytes())
                .expect("selected read"),
            Some(b"value".to_vec())
        );
        assert_eq!(keys::KEY_LOOKUPS.with(std::cell::Cell::get), 1);
        assert_eq!(keys::CATALOG_VERIFICATIONS.with(std::cell::Cell::get), 0);
    }
}

#[test]
fn encrypted_restore_requires_the_same_authority_and_never_downgrades_to_plaintext() {
    let root = tempfile::tempdir().expect("root");
    let (_directory, keys) = authority("binding-db");
    let (_other_directory, other) = authority("binding-db");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("binding-db");
    let source_path = root.path().join("source");
    let source = NativeService::open_encrypted(
        &source_path,
        "binding-db",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("source");
    let input = crate::capture::tests::request(1, "bound encrypted original");
    let archive = source
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("empty encrypted backup");
    let target = NativeService::open_encrypted(
        root.path().join("target"),
        "binding-db",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("matching target");
    let request = RestoreBackupRequest {
        context: input.context.clone(),
        format: archive.format,
        bytes: archive.bytes,
        digest: archive.digest,
    };
    target
        .restore_backup(request.clone())
        .expect("empty encrypted closure restores");
    let wrong = NativeService::open_encrypted(
        root.path().join("wrong"),
        "binding-db",
        [8; 32],
        ledger.clone(),
        other,
    )
    .expect("different authority target");
    let plain_path = root.path().join("plain");
    let plain =
        NativeService::open_with_suppression(&plain_path, "binding-db", [8; 32], ledger.clone())
            .expect("plaintext target");
    for rejected in [&wrong, &plain] {
        let before = rejected.engine.head_sequence().expect("physical head");
        assert_eq!(
            rejected
                .restore_backup(request.clone())
                .expect_err("wrong or absent key authority")
                .code,
            contextdb_service::ErrorCode::IntegrityFailure
        );
        assert_eq!(
            rejected.engine.head_sequence().expect("unchanged head"),
            before
        );
    }
    let plain_backup = plain
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("plaintext archive");
    let before = target.engine.head_sequence().expect("target head");
    assert!(
        target
            .restore_backup(RestoreBackupRequest {
                context: input.context,
                format: plain_backup.format,
                bytes: plain_backup.bytes,
                digest: plain_backup.digest,
            })
            .is_err()
    );
    assert_eq!(
        target.engine.head_sequence().expect("unchanged target"),
        before
    );
    drop(source);
    drop(plain);
    assert!(
        NativeService::open_with_suppression(&source_path, "binding-db", [9; 32], ledger.clone(),)
            .is_err()
    );
    assert!(
        NativeService::open_encrypted(&plain_path, "binding-db", [9; 32], ledger, keys.clone(),)
            .is_err()
    );
    let missing = root.path().join("missing");
    assert!(
        NativeCustodyKeys::open(&missing, "binding-db", keys.authority_id(), master()).is_err()
    );
    assert!(
        !missing.exists(),
        "missing custody must never create an empty authority"
    );
}

#[test]
fn key_publication_crash_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_KEY_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let key_id = std::env::var("CONTEXTDB_KEY_CRASH_ID")
        .expect("key ID")
        .parse()
        .expect("UUID");
    let ledger_id = std::env::var("CONTEXTDB_KEY_CRASH_LEDGER")
        .expect("ledger ID")
        .parse()
        .expect("UUID");
    let keys =
        NativeCustodyKeys::open(root.join("keys"), "key-crash", key_id, master()).expect("keys");
    let ledger =
        NativeSuppressionLedger::open(root.join("ledger"), "key-crash", ledger_id).expect("ledger");
    let service =
        NativeService::open_encrypted(root.join("native"), "key-crash", [7; 32], ledger, keys)
            .expect("native");
    storage::BEFORE_NATIVE_COMMIT
        .with(|hook| *hook.borrow_mut() = Some(Box::new(|| std::process::exit(74))));
    service
        .append_event(crate::capture::tests::request(
            1,
            "recoverable_ciphertext_source",
        ))
        .expect("crash before publication");
    panic!("crash hook did not execute");
}

#[test]
fn crash_after_key_sync_preserves_retry_without_publishing_a_partial_original() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "key-crash", master()).expect("keys");
    let ledger =
        NativeSuppressionLedger::create(root.path().join("ledger"), "key-crash").expect("ledger");
    let key_id = keys.authority_id();
    let ledger_id = ledger.authority_id();
    let service = NativeService::open_encrypted(
        root.path().join("native"),
        "key-crash",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    drop(service);
    drop(ledger);
    drop(keys);
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "encryption::tests::key_publication_crash_child",
            "--nocapture",
        ])
        .env("CONTEXTDB_KEY_CRASH_ROOT", root.path())
        .env("CONTEXTDB_KEY_CRASH_ID", key_id.to_string())
        .env("CONTEXTDB_KEY_CRASH_LEDGER", ledger_id.to_string())
        .status()
        .expect("child");
    assert_eq!(status.code(), Some(74));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "key-crash", key_id, master())
        .expect("retained key batch");
    let ledger = NativeSuppressionLedger::open(root.path().join("ledger"), "key-crash", ledger_id)
        .expect("retained ledger");
    let service = NativeService::open_encrypted(
        root.path().join("native"),
        "key-crash",
        [8; 32],
        ledger,
        keys,
    )
    .expect("native recovery");
    assert_eq!(
        service
            .verify_native(true)
            .expect("no partial capture")
            .commit_seq,
        0
    );
    let input = crate::capture::tests::request(1, "recoverable_ciphertext_source");
    service
        .append_event(input.clone())
        .expect("retry using durable keys");
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: input.context.clone(),
                event_id: input.event.event_id,
                after_receipt: None
            })
            .expect("recovered original")
            .event,
        input.event
    );
    service
        .verify_native(true)
        .expect("recovered encrypted closure");
}
