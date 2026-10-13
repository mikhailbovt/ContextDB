use contextdb_service::{
    CapturePort, CognitiveMemoryService, CreateBackupRequest, ErrorCode, RestoreBackupRequest,
};

use super::*;

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([79; 32])).expect("fixture master")
}

#[test]
fn issued_registry_is_idempotent_paged_and_reopens_but_corruption_or_total_loss_fails() {
    let root = tempfile::tempdir().expect("root");
    let (directory, keys) = crate::encryption::tests::authority("registered");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("registered");
    let service = crate::NativeService::open_encrypted(
        root.path(),
        "registered",
        [7; 32],
        ledger,
        keys.clone(),
    )
    .expect("native");
    let input = crate::capture::tests::request(1, "backup_registry_secret_not_a_receipt_body");
    service.append_event(input.clone()).expect("capture");
    let request = CreateBackupRequest {
        context: input.context.clone(),
    };
    let first = service
        .create_backup(request.clone())
        .expect("first archive");
    let registered = keys
        .backup_registration(&first.digest)
        .expect("lookup")
        .expect("registered");
    assert_eq!(registered.native_commit, first.commit_seq);
    assert_eq!(registered.encoded_bytes, first.bytes.len() as u64);
    let head = keys.engine.head_sequence().expect("key head");
    assert_eq!(
        service
            .create_backup(request.clone())
            .expect("same archive retry")
            .bytes,
        first.bytes
    );
    assert_eq!(
        keys.engine
            .head_sequence()
            .expect("no duplicate registration"),
        head
    );
    let initial = keys
        .backup_catalog_page(0, None, 1)
        .expect("initial registry");
    assert_eq!(
        (initial.revision, initial.entries.len(), initial.next_after),
        (1, 1, None)
    );
    service
        .append_event(crate::capture::tests::request(
            2,
            "second independent original",
        ))
        .expect("capture two");
    let second = service.create_backup(request).expect("second archive");
    assert_ne!(first.digest, second.digest);
    assert_eq!(
        keys.backup_catalog_page(1, Some(initial.revision), 1)
            .expect_err("concurrent issuance invalidates the old enumeration")
            .code,
        ErrorCode::IndexTooStale
    );
    let page = keys.backup_catalog_page(0, None, 1).expect("first page");
    assert_eq!(page.next_after, Some(1));
    service
        .append_event(crate::capture::tests::request(
            3,
            "unrelated catalog key growth",
        ))
        .expect("capture three");
    let last = keys
        .backup_catalog_page(1, Some(page.revision), 1)
        .expect("unrelated keys do not invalidate registry pages");
    assert_eq!(
        (last.revision, last.entries.len(), last.next_after),
        (2, 1, None)
    );
    assert_eq!(
        last.entries[0].previous_archive_digest,
        Some(first.digest.clone())
    );
    assert!(keys.backup_catalog_page(0, None, 0).is_err());
    assert!(keys.backup_registration("invalid").is_err());
    let target_directory = tempfile::tempdir().expect("restore target");
    let target = crate::NativeService::open_encrypted(
        target_directory.path(),
        "registered",
        [8; 32],
        service.suppression.as_ref().expect("ledger").clone(),
        keys.clone(),
    )
    .expect("restore owner");
    target
        .restore_backup(RestoreBackupRequest {
            context: input.context,
            format: first.format,
            bytes: first.bytes,
            digest: first.digest.clone(),
        })
        .expect("older native backup installs without replacing the issued registry");
    assert_eq!(
        keys.backup_catalog_page(0, None, 256)
            .expect("current independent registry")
            .entries
            .len(),
        2
    );
    drop(target);
    let authority = keys.authority_id();
    drop(service);
    drop(keys);
    let keys = NativeCustodyKeys::open(
        directory.path().join("keys"),
        "registered",
        authority,
        master(),
    )
    .expect("retained registry");
    assert_eq!(
        keys.backup_catalog_page(0, None, 256)
            .expect("reopened registry")
            .entries
            .len(),
        2
    );
    let key = issued_key(1);
    let snapshot = keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("physical snapshot");
    let original = snapshot
        .get(&keys.rows, &key)
        .expect("ciphertext")
        .expect("entry");
    let mut corrupted = original.clone();
    *corrupted.last_mut().expect("tag") ^= 1;
    let mut tx = keys.engine.begin_write().expect("tamper fixture");
    tx.put(&keys.rows, key.clone(), corrupted)
        .expect("corrupt proof");
    tx.commit(Durability::Sync).expect("inject");
    assert!(keys.backup_registration(&first.digest).is_err());
    assert!(keys.verify().is_err());
    let mut tx = keys.engine.begin_write().expect("restore fixture");
    tx.put(&keys.rows, key, original).expect("restore proof");
    tx.commit(Durability::Sync).expect("restore");
    let mut tx = keys
        .engine
        .begin_write()
        .expect("lose entire registry fixture");
    for row in tx
        .scan_prefix(&keys.rows, b"backup/")
        .expect("registry rows")
    {
        tx.delete(&keys.rows, row.key).expect("remove fixture row");
    }
    tx.commit(Durability::Sync)
        .expect("inject total registry loss");
    drop(snapshot);
    drop(keys);
    assert!(
        NativeCustodyKeys::open(
            directory.path().join("keys"),
            "registered",
            authority,
            master()
        )
        .is_err(),
        "a registry-capable authority must never replace a missing registry with an empty one"
    );
}

#[test]
fn legacy_key_authority_remains_readable_but_cannot_issue_unregistered_archives() {
    let root = tempfile::tempdir().expect("root");
    let created =
        NativeCustodyKeys::create_version(&root.path().join("keys"), "legacy", master(), 2)
            .expect("version 2 fixture before explicit downgrade to the version 1 wire format");
    let mut fixture = Arc::try_unwrap(created).expect("sole authority handle");
    fixture.identity.version = 1;
    let id = fixture.authority_id();
    let mut tx = fixture
        .engine
        .begin_write()
        .expect("legacy authority fixture");
    tx.put(
        &fixture.rows,
        b"identity".to_vec(),
        encode(&fixture.identity).expect("identity"),
    )
    .expect("v1 identity");
    tx.put(
        &fixture.rows,
        b"proof".to_vec(),
        seal(
            &fixture.master.0,
            &encode(&fixture.identity).expect("AAD"),
            b"contextdb/native-custody-authority/v1",
        )
        .expect("v1 proof"),
    )
    .expect("proof");
    tx.delete(&fixture.rows, HEAD.to_vec())
        .expect("v1 had no registry");
    tx.commit(Durability::Sync).expect("legacy fixture");
    drop(fixture);
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "legacy", id, master())
        .expect("existing v1 authority opens");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("legacy");
    let service = crate::NativeService::open_encrypted(
        root.path().join("native"),
        "legacy",
        [7; 32],
        ledger,
        keys.clone(),
    )
    .expect("legacy values supported");
    let input = crate::capture::tests::request(1, "old authority can still retain an original");
    service.append_event(input.clone()).expect("legacy capture");
    service
        .verify_native(true)
        .expect("legacy ciphertext closure");
    let before = keys.engine.head_sequence().expect("head");
    assert_eq!(
        service
            .create_backup(CreateBackupRequest {
                context: input.context
            })
            .expect_err("explicit registry migration required")
            .code,
        ErrorCode::FormatIncompatible
    );
    assert_eq!(
        keys.engine
            .head_sequence()
            .expect("no registry substitution"),
        before
    );
}

#[test]
fn backup_registration_crash_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_BACKUP_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let id = std::env::var("CONTEXTDB_BACKUP_CRASH_KEY")
        .expect("key ID")
        .parse()
        .expect("UUID");
    let ledger_id = std::env::var("CONTEXTDB_BACKUP_CRASH_LEDGER")
        .expect("ledger ID")
        .parse()
        .expect("UUID");
    let keys =
        NativeCustodyKeys::open(root.join("keys"), "backup-crash", id, master()).expect("keys");
    let ledger =
        crate::NativeSuppressionLedger::open(root.join("ledger"), "backup-crash", ledger_id)
            .expect("ledger");
    let service = crate::NativeService::open_encrypted(
        root.join("native"),
        "backup-crash",
        [8; 32],
        ledger,
        keys,
    )
    .expect("native");
    crate::backup::AFTER_REGISTRATION
        .with(|hook| *hook.borrow_mut() = Some(Box::new(|| std::process::exit(75))));
    service
        .create_backup(CreateBackupRequest {
            context: crate::capture::tests::request(1, "unused").context,
        })
        .expect("process exits before archive response");
    panic!("crash hook did not run");
}

#[test]
fn crash_before_backup_response_retains_the_potential_copy_and_retry_is_idempotent() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "backup-crash", master())
        .expect("keys");
    let ledger = crate::NativeSuppressionLedger::create(root.path().join("ledger"), "backup-crash")
        .expect("ledger");
    let key_id = keys.authority_id();
    let ledger_id = ledger.authority_id();
    let service = crate::NativeService::open_encrypted(
        root.path().join("native"),
        "backup-crash",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let input =
        crate::capture::tests::request(1, "archive may have escaped before the response was lost");
    service.append_event(input.clone()).expect("capture");
    drop(service);
    drop(keys);
    drop(ledger);
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "encryption::keys::backups::tests::backup_registration_crash_child",
            "--nocapture",
        ])
        .env("CONTEXTDB_BACKUP_CRASH_ROOT", root.path())
        .env("CONTEXTDB_BACKUP_CRASH_KEY", key_id.to_string())
        .env("CONTEXTDB_BACKUP_CRASH_LEDGER", ledger_id.to_string())
        .status()
        .expect("child process");
    assert_eq!(status.code(), Some(75));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "backup-crash", key_id, master())
        .expect("durable registry");
    let page = keys
        .backup_catalog_page(0, None, 1)
        .expect("potential copy");
    assert_eq!((page.revision, page.entries.len()), (1, 1));
    let membership = keys
        .backup_contents(
            &page.entries[0].archive_digest,
            &mut crate::raw_index::copies::tests::budget(),
        )
        .expect("contents lookup after abrupt exit")
        .expect("all copy pages were accepted before the lost response");
    let ledger =
        crate::NativeSuppressionLedger::open(root.path().join("ledger"), "backup-crash", ledger_id)
            .expect("ledger");
    let service = crate::NativeService::open_encrypted(
        root.path().join("native"),
        "backup-crash",
        [9; 32],
        ledger,
        keys.clone(),
    )
    .expect("native recovery");
    let archive = service
        .create_backup(CreateBackupRequest {
            context: input.context,
        })
        .expect("lost-response retry");
    assert_eq!(archive.digest, page.entries[0].archive_digest);
    assert_eq!(
        keys.backup_contents(
            &archive.digest,
            &mut crate::raw_index::copies::tests::budget()
        )
        .expect("contents retry"),
        Some(membership)
    );
    assert_eq!(
        keys.backup_catalog_page(0, None, 1)
            .expect("one registration")
            .revision,
        1
    );
}
