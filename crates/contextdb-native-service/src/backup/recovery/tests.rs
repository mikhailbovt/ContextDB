use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{
    CustodyMasterKey, NativeBackupCleanupStage, NativeCustodyKeys, NativeSuppressionLedger,
};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use std::sync::Arc;
use zeroize::Zeroizing;

fn archive(f: &Fixture) -> BackupResponse {
    f.native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("issued archive")
}

fn original(f: &Fixture, backup: &BackupResponse) -> NativeBackupRegistration {
    f.keys
        .backup_registration(&backup.digest)
        .expect("catalog")
        .expect("registration")
}

fn recovery(f: &Fixture) -> NativeBackupRecoveryInventory {
    f.native
        .read_removal_backup_recovery(&f.input.context, &f.removal, &mut budget())
        .expect("recovery inventory")
}

fn reopen(f: Fixture) -> Fixture {
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("cold custody");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("cold ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            f.root.path().join("native"),
            "primary-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("cold native"),
    );
    Fixture {
        root: f.root,
        native,
        keys,
        ledger,
        input: f.input,
        removal: f.removal,
        witness: f.witness,
    }
}

#[test]
fn archive_recovery_retains_originals_across_partial_retry_cold_reopen_and_old_restore() {
    let f = fixture();
    for sequence in 3..=4 {
        f.native
            .append_event(request(sequence, &"independent".repeat(18_000)))
            .expect("large independent capture");
    }
    let backup = archive(&f);
    let issued = original(&f, &backup);
    assert!(matches!(
        recovery(&f).archives[0].state,
        NativeBackupRecoveryState::AwaitingArtifact { .. }
    ));
    let before = f.native.engine.head_sequence().expect("native head");
    let partial = f
        .native
        .retain_issued_backup(&f.input.context, &backup, 0, 1, &mut budget())
        .expect("first original page");
    assert!(!partial.complete);
    assert_eq!(
        f.native
            .retain_issued_backup(&f.input.context, &backup, 0, 1, &mut budget())
            .expect("exact retry"),
        partial
    );
    assert_eq!(
        f.native
            .retain_issued_backup(&f.input.context, &backup, 0, 2, &mut budget())
            .expect_err("changed retry bound")
            .code,
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(
        f.native
            .read_removal_backup_input(&f.input.context, &f.removal, &issued, &mut budget())
            .expect_err("partial is not available")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert_eq!(
        f.native.engine.head_sequence().expect("native unchanged"),
        before
    );
    let f = reopen(f);
    let complete = f
        .native
        .retain_issued_backup(
            &f.input.context,
            &backup,
            partial.stored_pages,
            16,
            &mut budget(),
        )
        .expect("continue original bytes");
    assert!(complete.complete);
    let recovered = f
        .native
        .read_removal_backup_input(&f.input.context, &f.removal, &issued, &mut budget())
        .expect("automatic original recovery");
    assert_eq!(recovered.backup, backup);
    assert!(recovered.replacements.is_empty());
    assert_eq!(recovered.artifact, complete.receipt);
    let target = NativeService::open_encrypted(
        f.root.path().join("restore"),
        "primary-decisions",
        [9; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("isolated target");
    target
        .restore_backup(RestoreBackupRequest {
            context: f.input.context.clone(),
            format: backup.format.clone(),
            bytes: backup.bytes.clone(),
            digest: backup.digest.clone(),
        })
        .expect("actual old restore");
    assert_eq!(
        target
            .read_removal_backup_input(&f.input.context, &f.removal, &issued, &mut budget())
            .expect("retained outside native restore"),
        recovered
    );
    target.verify_native(true).expect("full native replay");
}

#[test]
fn archive_recovery_selects_partial_cleanup_input_and_finishes_its_remaining_sources() {
    let f = fixture();
    let second = request(2, "").event.event_id;
    let removal = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([f.input.event.event_id, second]),
            "both originals",
            &mut budget(),
        )
        .expect("both selected");
    let backup = archive(&f);
    let issued = original(&f, &backup);
    f.native
        .prepare_original_removal_sources(&f.input.context, &removal, &removal.roots, &mut budget())
        .expect("prepare");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(
            &f.input.context,
            &removal,
            &BTreeSet::from([f.input.event.event_id]),
            &mut budget(),
        )
        .expect("partial source cleanup");
    let partial = f
        .native
        .create_removal_backup(&f.input.context, &removal, &backup, &mut budget())
        .expect("partial replacement");
    f.native
        .retain_removal_backup(&f.input.context, &removal, &partial, 0, 16, &mut budget())
        .expect("complete bytes, incomplete cleanup");
    let recovered = f
        .native
        .read_removal_backup_input(&f.input.context, &removal, &issued, &mut budget())
        .expect("auto-select available partial replacement");
    assert_eq!(recovered.backup, partial.backup);
    assert_eq!(recovered.replacements, vec![partial.replacement.receipt]);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    assert!(
        snapshot
            .get(
                &f.native.keyspaces.observations_content,
                digest_bytes(second.to_string().as_bytes()).as_bytes()
            )
            .expect("remaining source")
            .is_some()
    );
    drop(snapshot);
    let mut ready = None;
    for _ in 0..32 {
        let progress = f
            .native
            .advance_removal_backup(&f.input.context, &removal, &recovered.backup, &mut budget())
            .expect("finish recovered input");
        if progress.stage == NativeBackupCleanupStage::Available {
            ready = Some(progress);
            break;
        }
    }
    let ready = ready.expect("terminal cleanup");
    assert_eq!(
        ready
            .replacement
            .expect("remaining source proof")
            .pruning
            .sources,
        1
    );
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("clean view");
    assert!(
        snapshot
            .get(
                &f.native.keyspaces.observations_content,
                digest_bytes(second.to_string().as_bytes()).as_bytes()
            )
            .expect("source removed")
            .is_none()
    );
    f.native
        .verify_native(true)
        .expect("complete cleaned replay");
}

#[test]
fn archive_recovery_rejects_bad_authority_bytes_issuance_and_stale_frontiers() {
    let f = fixture();
    let backup = archive(&f);
    let issued = original(&f, &backup);
    let before = recovery(&f);
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .retain_issued_backup(&denied, &backup, 0, 16, &mut budget())
            .expect_err("Admin before archive bytes")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        f.native
            .read_removal_backup_recovery(&denied, &f.removal, &mut budget())
            .expect_err("Admin before catalog")
            .code,
        ErrorCode::Unauthorized
    );
    let mut wrong = f.removal.clone();
    wrong.digest = "ab".repeat(32);
    assert!(
        f.native
            .read_removal_backup_recovery(&f.input.context, &wrong, &mut budget())
            .is_err()
    );
    let mut foreign = f.input.context.clone();
    foreign.request.workspace_id = "different-workspace".into();
    assert!(
        f.native
            .read_removal_backup_recovery(&foreign, &f.removal, &mut budget())
            .is_err()
    );
    let mut invalid = backup.clone();
    invalid.bytes[0] ^= 1;
    assert!(
        f.native
            .retain_issued_backup(&f.input.context, &invalid, 0, 16, &mut budget())
            .is_err()
    );
    let mut altered = issued.clone();
    altered.native_commit += 1;
    assert!(
        f.native
            .read_removal_backup_input(&f.input.context, &f.removal, &altered, &mut budget())
            .is_err()
    );
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .read_removal_backup_recovery(&f.input.context, &f.removal, &mut empty)
            .expect_err("bounded")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(recovery(&f), before, "rejected calls do not change custody");

    f.native
        .append_event(request(3, "independent later original"))
        .expect("new native head");
    let (decoded, unissued) = f.native.build_native_backup().expect("unissued bytes");
    assert_eq!(
        f.native
            .retain_issued_backup(&f.input.context, &unissued, 0, 16, &mut budget())
            .expect_err("not an issuance API")
            .code,
        ErrorCode::EvidenceRequired
    );
    f.keys
        .register_backup(
            &unissued.digest,
            unissued.commit_seq,
            &decoded.deep_digest,
            unissued.bytes.len() as u64,
        )
        .expect("legacy issuance without membership");
    assert!(matches!(
        recovery(&f).archives[1].state,
        NativeBackupRecoveryState::UnknownContents
    ));
    assert!(
        f.native
            .retain_issued_backup(&f.input.context, &unissued, 0, 16, &mut budget())
            .is_err()
    );
    f.native
        .retain_backup_contents(&f.input.context, &unissued, &mut budget())
        .expect("explicit verified backfill");
    f.native
        .retain_issued_backup(&f.input.context, &unissued, 0, 16, &mut budget())
        .expect("known issued bytes");
    let native = f.native.clone();
    let context = f.input.context.clone();
    BEFORE_RECOVERY_FENCE.with(|hook| {
        hook.replace(Some(Box::new(move || {
            native
                .append_event(request(4, "concurrent archive"))
                .expect("capture");
            native
                .create_backup(CreateBackupRequest { context })
                .expect("new issuance");
        })))
    });
    assert_eq!(
        f.native
            .read_removal_backup_recovery(&f.input.context, &f.removal, &mut budget())
            .expect_err("frontier changed")
            .code,
        ErrorCode::IndexTooStale
    );
}
