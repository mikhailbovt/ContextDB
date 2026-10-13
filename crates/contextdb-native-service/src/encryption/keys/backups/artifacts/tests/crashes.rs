use super::*;
use crate::NativeRemovalRequestReceipt;
use contextdb_service::AuthenticatedRequestContext;

#[derive(Serialize, Deserialize)]
struct CrashInput {
    keys: Uuid,
    ledger: Uuid,
    context: AuthenticatedRequestContext,
    request: NativeRemovalRequestReceipt,
    replacement: NativeRemovalBackup,
}

#[test]
fn archive_artifact_crash_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_ARTIFACT_CRASH_ROOT") else {
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
    if std::env::var("CONTEXTDB_ARTIFACT_CRASH_STAGE").expect("stage") == "before" {
        BEFORE_ARTIFACT_SYNC.with(|hook| hook.replace(Some(Box::new(|| std::process::exit(78)))));
    } else {
        AFTER_ARTIFACT_SYNC.with(|hook| hook.replace(Some(Box::new(|| std::process::exit(79)))));
    }
    native
        .retain_removal_backup(
            &input.context,
            &input.request,
            &input.replacement,
            1,
            1,
            &mut budget(),
        )
        .expect("retention");
    panic!("crash hook did not run");
}

#[test]
fn archive_artifact_actual_crash_recovers_the_last_durable_prefix() {
    for stage in ["before", "after"] {
        let (f, _, replacement) = prepared(true);
        let first = retain(&f, &replacement, 0, 1).expect("previous durable portion");
        let input = CrashInput {
            keys: f.keys.authority_id(),
            ledger: f.ledger.authority_id(),
            context: f.input.context,
            request: f.removal,
            replacement,
        };
        std::fs::write(
            f.root.path().join("input.json"),
            serde_json::to_vec(&input).expect("encode input"),
        )
        .expect("write input");
        drop((f.native, f.keys, f.ledger));
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "encryption::keys::backups::artifacts::tests::crashes::archive_artifact_crash_child",
                "--nocapture",
            ])
            .env("CONTEXTDB_ARTIFACT_CRASH_ROOT", f.root.path())
            .env("CONTEXTDB_ARTIFACT_CRASH_STAGE", stage)
            .status().expect("child");
        assert_eq!(status.code(), Some(if stage == "before" { 78 } else { 79 }));
        let keys = NativeCustodyKeys::open(
            f.root.path().join("keys"),
            "primary-decisions",
            input.keys,
            master(),
        )
        .expect("recovered custody");
        let ledger = NativeSuppressionLedger::open(
            f.root.path().join("ledger"),
            "primary-decisions",
            input.ledger,
        )
        .expect("ledger");
        let native = NativeService::open_encrypted(
            f.root.path().join("native"),
            "primary-decisions",
            [8; 32],
            ledger,
            keys.clone(),
        )
        .expect("native");
        let recovered = keys
            .backup_artifact(&input.replacement.backup.digest, &mut budget())
            .expect("recovered")
            .expect("prefix");
        assert_eq!(
            recovered.stored_pages,
            if stage == "before" { 1 } else { 2 }
        );
        if stage == "before" {
            assert_eq!(recovered, first);
        }
        let before = keys.engine.head_sequence().expect("before retry");
        let mut progress = native
            .retain_removal_backup(
                &input.context,
                &input.request,
                &input.replacement,
                1,
                1,
                &mut budget(),
            )
            .expect("retry uncertain portion");
        assert_eq!(
            keys.engine
                .head_sequence()
                .expect("new Sync only when needed"),
            before + u64::from(stage == "before")
        );
        if stage == "after" {
            assert_eq!(progress, recovered);
        }
        while !progress.complete {
            progress = native
                .retain_removal_backup(
                    &input.context,
                    &input.request,
                    &input.replacement,
                    progress.stored_pages,
                    16,
                    &mut budget(),
                )
                .expect("finish remaining bytes");
        }
        assert_eq!(
            native
                .read_retained_removal_backup(
                    &input.context,
                    &input.request,
                    &input.replacement.replacement.receipt,
                    &progress.receipt,
                    &mut budget(),
                )
                .expect("complete byte recovery"),
            input.replacement.backup
        );
        keys.verify().expect("complete closure");
    }
}
