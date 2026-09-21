use super::*;
use crate::{
    NativeBackupContentsReceipt, NativeBackupReplacementReceipt, NativeRemovalKeySelection,
};
use contextdb_core::ContentBlockId;
use contextdb_service::{PayloadPort, StagePayloadRequest};

fn refuse_originals(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    removal: &NativeRemovalRequestReceipt,
) {
    let witness = native
        .retain_original_key_removal(context, removal, &mut budget())
        .expect("retained keys");
    let ids = witness
        .dispositions
        .values()
        .flatten()
        .map(|value| value.allocation.key_id)
        .collect();
    native
        .retire_removal_keys(
            context,
            removal,
            &NativeRemovalKeySelection::Originals,
            &ids,
            &mut budget(),
        )
        .expect("current refusal");
}

#[test]
fn archive_successor_cleanup_resumes_after_original_and_intermediate_keys_are_refused() {
    let f = fixture();
    let context = &f.input.context;
    let independent = request(3, "preserve through every authorized replacement");
    f.native
        .append_event(independent.clone())
        .expect("independent original");
    let old = archive(&f.native, context);
    let (_, first) = complete(&f.native, context, &f.removal, &old);
    let middle = retained(&f.native, context, &f.removal, &first);
    let first_proof = first.replacement.expect("first edge");
    let original = first_proof.source.receipt.clone();
    let path = vec![first_proof.receipt.clone()];
    refuse_originals(&f.native, context, &f.removal);
    assert!(
        f.native
            .verify_encrypted_archive(&old, &mut budget())
            .is_err()
    );
    let second = f
        .native
        .request_original_removal(
            context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "second removal",
            &mut budget(),
        )
        .expect("second request");
    let automatic = f
        .native
        .read_removal_backup_input(
            context,
            &second,
            &first_proof.source.registration,
            &mut budget(),
        )
        .expect("automatically resolve separately authorized successor");
    assert_eq!(automatic.backup, middle);
    assert_eq!(automatic.replacements, path);
    assert_eq!(
        f.native
            .read_removal_backup_successor(context, &second, &original, &path, &mut budget())
            .expect("readable successor"),
        middle
    );

    let mut native = f.native;
    let mut stages = Vec::new();
    let ready = loop {
        assert!(stages.len() < 32);
        let progress = native
            .advance_removal_backup_from_replacement(
                context,
                &second,
                &original,
                &path,
                &mut budget(),
            )
            .expect("continue from preserved successor");
        stages.push(progress.stage);
        drop(native);
        native = Arc::new(
            NativeService::open_encrypted(
                f.root.path().join("native"),
                "primary-decisions",
                [7; 32],
                f.ledger.clone(),
                f.keys.clone(),
            )
            .expect("cold worker restart"),
        );
        if progress.stage == NativeBackupCleanupStage::Available {
            break progress;
        }
        assert_ne!(progress.stage, NativeBackupCleanupStage::Unchanged);
    };
    assert_eq!(
        native
            .advance_removal_backup_from_replacement(
                context,
                &second,
                &original,
                &path,
                &mut budget()
            )
            .expect("exact retry"),
        ready
    );
    let second_proof = ready.replacement.as_ref().expect("second edge");
    assert_eq!(second_proof.source, first_proof.target);
    assert_eq!(second_proof.request, second);
    let clean = retained(&native, context, &second, &ready);
    refuse_originals(&native, context, &second);
    assert!(
        native
            .verify_encrypted_archive(&middle, &mut budget())
            .is_err()
    );
    assert!(
        native
            .read_removal_backup_successor(context, &second, &original, &path, &mut budget())
            .is_err(),
        "unreadable terminal is not usable preservation"
    );
    let full_path = vec![first_proof.receipt.clone(), second_proof.receipt.clone()];
    let automatic = native
        .read_removal_backup_input(
            context,
            &second,
            &first_proof.source.registration,
            &mut budget(),
        )
        .expect("automatically bypass both refused ancestors");
    assert_eq!(automatic.backup, clean);
    assert_eq!(automatic.replacements, full_path);
    assert_eq!(
        native
            .read_removal_backup_successor(context, &second, &original, &full_path, &mut budget())
            .expect("two separately authorized edges"),
        clean
    );
    for broken in [
        vec![second_proof.receipt.clone()],
        vec![second_proof.receipt.clone(), first_proof.receipt.clone()],
    ] {
        assert!(
            native
                .read_removal_backup_successor(context, &second, &original, &broken, &mut budget())
                .is_err(),
            "no skipped or reversed edges"
        );
    }
    let restored = open(&native, &f.root.path().join("clean"));
    restore(&restored, context, &clean);
    restored
        .verify_native(true)
        .expect("complete current-key replay");
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("clean view");
    assert!(
        snapshot
            .get(
                &restored.keyspaces.observations_content,
                digest_bytes(independent.event.event_id.to_string().as_bytes()).as_bytes()
            )
            .expect("independent retained")
            .is_some()
    );
}

#[test]
fn archive_successor_checks_authority_path_budget_and_owner_before_cleanup() {
    let f = fixture();
    let context = &f.input.context;
    let old = archive(&f.native, context);
    let fork = open(&f.native, &f.root.path().join("fork"));
    restore(&fork, context, &old);
    fork.append_event(request(3, "divergent branch"))
        .expect("different history");
    let (_, ready) = complete(&f.native, context, &f.removal, &old);
    let proof = ready.replacement.expect("proof");
    let original = &proof.source.receipt;
    let path = vec![proof.receipt.clone()];
    let head = f.native.engine.head_sequence().expect("head");
    let mut forged = proof.receipt.clone();
    forged.digest = "ab".repeat(32);
    for broken in [
        vec![],
        vec![forged],
        vec![proof.receipt.clone(); 2],
        vec![proof.receipt.clone(); 257],
    ] {
        assert!(
            f.native
                .advance_removal_backup_from_replacement(
                    context,
                    &f.removal,
                    original,
                    &broken,
                    &mut budget()
                )
                .is_err()
        );
    }
    let mut wrong = original.clone();
    wrong.digest = "ab".repeat(32);
    assert!(
        f.native
            .advance_removal_backup_from_replacement(
                context,
                &f.removal,
                &wrong,
                &path,
                &mut budget()
            )
            .is_err()
    );
    let mut denied = context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .read_removal_backup_successor(&denied, &f.removal, original, &[], &mut budget())
            .expect_err("authority before path inspection")
            .code,
        ErrorCode::Unauthorized
    );
    let mut cross_scope = context.clone();
    cross_scope.request.workspace_id = "different-workspace".into();
    assert!(
        f.native
            .read_removal_backup_successor(&cross_scope, &f.removal, original, &path, &mut budget())
            .is_err()
    );
    let mut forged_request = f.removal.clone();
    forged_request.digest = "ab".repeat(32);
    assert!(
        f.native
            .read_removal_backup_successor(context, &forged_request, original, &path, &mut budget())
            .is_err()
    );
    let mut empty_budget =
        QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        f.native
            .advance_removal_backup_from_replacement(
                context,
                &f.removal,
                original,
                &path,
                &mut empty_budget
            )
            .is_err()
    );
    assert_eq!(
        f.native.engine.head_sequence().expect("no native mutation"),
        head
    );
    let fork_head = fork.engine.head_sequence().expect("fork head");
    assert!(
        fork.advance_removal_backup_from_replacement(
            context,
            &f.removal,
            original,
            &path,
            &mut budget()
        )
        .is_err(),
        "a later divergent owner cannot continue this path"
    );
    assert_eq!(
        fork.engine.head_sequence().expect("fork unchanged"),
        fork_head
    );
}

#[test]
fn archive_successor_requires_complete_retained_bytes() {
    let f = fixture();
    let context = &f.input.context;
    // Unpublished staged bytes are still part of the exact archive and must be
    // retained. Publishing a staged original is closed while removal is pending.
    f.native
        .stage_payload(StagePayloadRequest {
            context: context.clone(),
            idempotency_key: "independent-large-payload".into(),
            block_id: ContentBlockId::new(),
            bytes: vec![43; 300 * 1024],
        })
        .expect("large independent payload");
    let old = archive(&f.native, context);
    f.native
        .prepare_original_removal_sources(context, &f.removal, &f.removal.roots, &mut budget())
        .expect("prepare");
    f.native
        .maintain_custody(context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(context, &f.removal, &f.removal.roots, &mut budget())
        .expect("prune");
    let replacement = f
        .native
        .create_removal_backup(context, &f.removal, &old, &mut budget())
        .expect("replacement issuance");
    let original: &NativeBackupContentsReceipt = &replacement.replacement.source.receipt;
    let path: &[NativeBackupReplacementReceipt] =
        std::slice::from_ref(&replacement.replacement.receipt);
    assert_eq!(
        f.native
            .read_removal_backup_successor(context, &f.removal, original, path, &mut budget())
            .expect_err("issuance is not retained bytes")
            .code,
        ErrorCode::EvidenceRequired
    );
    let partial = f
        .native
        .retain_removal_backup(context, &f.removal, &replacement, 0, 1, &mut budget())
        .expect("one actual page");
    assert!(!partial.complete);
    assert_eq!(
        f.native
            .read_removal_backup_successor(context, &f.removal, original, path, &mut budget())
            .expect_err("partial bytes")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert!(
        f.native
            .retain_removal_backup(
                context,
                &f.removal,
                &replacement,
                partial.stored_pages,
                16,
                &mut budget()
            )
            .expect("remaining bytes")
            .complete
    );
    assert_eq!(
        f.native
            .read_removal_backup_successor(context, &f.removal, original, path, &mut budget())
            .expect("complete successor"),
        replacement.backup
    );
}
