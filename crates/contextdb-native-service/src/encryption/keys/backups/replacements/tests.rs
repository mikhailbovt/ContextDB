use super::*;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{NativeRemovalBackup, NativeService, NativeSuppressionLedger};
use contextdb_service::{AuthenticatedRequestContext, CognitiveMemoryService, CreateBackupRequest};

fn prepared() -> (Fixture, BackupResponse) {
    let f = fixture();
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("old");
    f.native
        .prepare_original_removal_sources(
            &f.input.context,
            &f.removal,
            &f.removal.roots,
            &mut budget(),
        )
        .expect("prepare");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(
            &f.input.context,
            &f.removal,
            &f.removal.roots,
            &mut budget(),
        )
        .expect("prune");
    (f, old)
}

fn replace(f: &Fixture, old: &BackupResponse) -> ServiceResult<NativeRemovalBackup> {
    f.native
        .create_removal_backup(&f.input.context, &f.removal, old, &mut budget())
}

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master")
}

#[test]
fn archive_replacement_publication_rolls_back_and_retries_one_complete_sync() {
    let (f, old) = prepared();
    let before = f.keys.engine.head_sequence().expect("head");
    BEFORE_REPLACEMENT_SYNC.with(|hook| {
        hook.replace(Some(Box::new(|| {
            Err(crate::exhausted("injected publication failure"))
        })))
    });
    assert_eq!(
        replace(&f, &old).expect_err("interrupted staging").code,
        contextdb_service::ErrorCode::ResourceExhausted
    );
    assert_eq!(
        f.keys.engine.head_sequence().expect("no partial Sync"),
        before
    );
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("catalog")
            .revision,
        1
    );
    f.keys.verify().expect("no orphan target or proof");
    let result = replace(&f, &old).expect("retry");
    assert_eq!(f.keys.engine.head_sequence().expect("one Sync"), before + 1);
    assert_eq!(replace(&f, &old).expect("same acceptance"), result);
    assert_eq!(
        f.keys.engine.head_sequence().expect("no retry Sync"),
        before + 1
    );
    f.keys.verify().expect("complete acceptance");
}

#[test]
fn archive_replacement_backfills_only_verified_old_bytes_and_fences_provenance_growth() {
    let (f, old) = prepared();
    contents::tests::legacy_registry(&f.keys, true);
    assert!(
        f.keys
            .backup_contents(&old.digest, &mut budget())
            .expect("unknown")
            .is_none()
    );
    let before = f.keys.engine.head_sequence().expect("head");
    let result = replace(&f, &old).expect("verified backfill and replacement");
    assert_eq!(
        f.keys
            .engine
            .head_sequence()
            .expect("source backfill then atomic target"),
        before + 2
    );
    assert_eq!(
        f.keys
            .backup_contents(&old.digest, &mut budget())
            .expect("old contents"),
        Some(result.replacement.source.clone())
    );
    let all = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("complete reverse closure");
    assert_eq!(all.archives.len(), 2);
    assert_eq!(
        all.frontier.replacements,
        Some(result.replacement.receipt.clone())
    );
    let (f, old) = prepared();
    let preissued = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("ordinary cleaned archive");
    let before = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("before");
    let result = replace(&f, &old).expect("add provenance for previously issued target");
    assert_eq!(result.backup, preissued);
    let after = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("after");
    assert_eq!(before.archives, after.archives);
    assert_eq!(before.frontier.contents, after.frontier.contents);
    assert_eq!(
        before.frontier.issued_sequence,
        after.frontier.issued_sequence
    );
    assert_ne!(before.frontier.replacements, after.frontier.replacements);
    assert_eq!(
        f.keys
            .require_backup_frontier(&before.frontier, &mut budget())
            .expect_err("provenance fence")
            .code,
        contextdb_service::ErrorCode::IndexTooStale
    );
}

#[test]
fn archive_replacement_missing_or_rehashed_provenance_cannot_mint_another_receipt() {
    for fault in [
        "event",
        "index",
        "all",
        "orphan",
        "rolled_back_head",
        "target_contents",
        "rehashed_target",
        "rehashed_counts",
    ] {
        let (f, old) = prepared();
        let result = replace(&f, &old).expect("accepted");
        let mut tx = f.keys.engine.begin_write().expect("tx");
        let key = event_key(result.replacement.receipt.sequence);
        let mut event: ReplacementEvent = f
            .keys
            .open_backup_record(
                &key,
                &tx.get(&f.keys.rows, &key).expect("read").expect("event"),
            )
            .expect("event");
        match fault {
            "event" => tx.delete(&f.keys.rows, key).expect("loss"),
            "index" => tx.delete(&f.keys.rows, event.index_key()).expect("loss"),
            "all" => {
                for row in tx
                    .scan_prefix(&f.keys.rows, b"backup/replacement/")
                    .expect("rows")
                {
                    tx.delete(&f.keys.rows, row.key).expect("loss");
                }
            }
            "orphan" => tx
                .put(&f.keys.rows, b"backup/replacement/orphan".to_vec(), vec![1])
                .expect("orphan"),
            "rolled_back_head" => {
                let mut head = f.keys.backup_head(&tx).expect("head");
                head.replacements = None;
                tx.put(
                    &f.keys.rows,
                    HEAD.to_vec(),
                    f.keys.seal_backup_record(HEAD, &head).expect("seal"),
                )
                .expect("rollback");
            }
            "target_contents" => {
                let key = format!(
                    "backup/contents/page/{:020}/{:08}",
                    result.replacement.target.receipt.sequence, 0
                )
                .into_bytes();
                tx.delete(&f.keys.rows, key).expect("loss");
            }
            "rehashed_target" | "rehashed_counts" => {
                if fault == "rehashed_target" {
                    event.value.target = event.value.source.clone();
                } else {
                    event.value.pruning = NativeBackupPruningCounts::default();
                }
                event.value.receipt.digest = event.commitment().expect("new digest");
                tx.put(
                    &f.keys.rows,
                    key.clone(),
                    f.keys.seal_backup_record(&key, &event).expect("seal"),
                )
                .expect("changed event");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fixture damage");
        let before = f.keys.engine.head_sequence().expect("head");
        assert!(f.keys.verify().is_err(), "{fault}");
        assert!(
            f.keys
                .backup_replacement(&result.replacement.receipt, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.keys
                .selected_backup_keys(&BTreeMap::new(), &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(replace(&f, &old).is_err(), "{fault}");
        assert_eq!(
            f.keys
                .engine
                .head_sequence()
                .expect("no replacement acceptance"),
            before,
            "{fault}"
        );
        let id = f.keys.authority_id();
        drop((f.native, f.keys, f.ledger));
        assert!(
            NativeCustodyKeys::open(
                f.root.path().join("keys"),
                "primary-decisions",
                id,
                master()
            )
            .is_err(),
            "cold reopen {fault}"
        );
    }
}

#[derive(Serialize, Deserialize)]
struct CrashInput {
    keys: Uuid,
    ledger: Uuid,
    context: AuthenticatedRequestContext,
    request: NativeRemovalRequestReceipt,
    original: BackupResponse,
}

#[test]
fn archive_replacement_crash_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_REPLACEMENT_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let input: CrashInput =
        serde_json::from_slice(&std::fs::read(root.join("input.json")).expect("input"))
            .expect("input");
    let keys =
        NativeCustodyKeys::open(root.join("keys"), "primary-decisions", input.keys, master())
            .expect("keys");
    let ledger =
        NativeSuppressionLedger::open(root.join("ledger"), "primary-decisions", input.ledger)
            .expect("ledger");
    let native = NativeService::open_encrypted(
        root.join("native"),
        "primary-decisions",
        [9; 32],
        ledger,
        keys,
    )
    .expect("native");
    if std::env::var("CONTEXTDB_REPLACEMENT_CRASH_STAGE").expect("stage") == "before" {
        BEFORE_REPLACEMENT_SYNC
            .with(|hook| hook.replace(Some(Box::new(|| std::process::exit(76)))));
    } else {
        crate::backup::AFTER_REGISTRATION
            .with(|hook| hook.replace(Some(Box::new(|| std::process::exit(77)))));
    }
    native
        .create_removal_backup(
            &input.context,
            &input.request,
            &input.original,
            &mut budget(),
        )
        .expect("replacement");
    panic!("crash hook did not run");
}

#[test]
fn archive_replacement_actual_crash_before_and_after_sync_recovers_exact_acceptance() {
    for stage in ["before", "after"] {
        let (f, old) = prepared();
        let input = CrashInput {
            keys: f.keys.authority_id(),
            ledger: f.ledger.authority_id(),
            context: f.input.context,
            request: f.removal,
            original: old,
        };
        std::fs::write(
            f.root.path().join("input.json"),
            serde_json::to_vec(&input).expect("serialize input"),
        )
        .expect("write fixture");
        drop((f.native, f.keys, f.ledger));
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "encryption::keys::backups::replacements::tests::archive_replacement_crash_child",
                "--nocapture",
            ])
            .env("CONTEXTDB_REPLACEMENT_CRASH_ROOT", f.root.path())
            .env("CONTEXTDB_REPLACEMENT_CRASH_STAGE", stage)
            .status()
            .expect("child");
        assert_eq!(status.code(), Some(if stage == "before" { 76 } else { 77 }));
        let keys = NativeCustodyKeys::open(
            f.root.path().join("keys"),
            "primary-decisions",
            input.keys,
            master(),
        )
        .expect("recovered keys");
        let ledger = NativeSuppressionLedger::open(
            f.root.path().join("ledger"),
            "primary-decisions",
            input.ledger,
        )
        .expect("recovered ledger");
        let native = NativeService::open_encrypted(
            f.root.path().join("native"),
            "primary-decisions",
            [8; 32],
            ledger,
            keys.clone(),
        )
        .expect("recovered native");
        assert_eq!(
            keys.backup_catalog_page(0, None, 256)
                .expect("catalog")
                .revision,
            if stage == "before" { 1 } else { 2 }
        );
        let before = keys.engine.head_sequence().expect("before retry");
        let result = native
            .create_removal_backup(
                &input.context,
                &input.request,
                &input.original,
                &mut budget(),
            )
            .expect("retry after crash");
        assert_eq!(
            keys.engine
                .head_sequence()
                .expect("new acceptance only before Sync"),
            before + u64::from(stage == "before")
        );
        assert_eq!(result.replacement.receipt.sequence, 1);
        assert_eq!(
            keys.backup_replacement(&result.replacement.receipt, &mut budget())
                .expect("retained"),
            result.replacement
        );
        keys.verify().expect("complete closure after recovery");
    }
}
