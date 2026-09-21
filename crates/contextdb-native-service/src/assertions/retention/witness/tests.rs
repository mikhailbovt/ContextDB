use super::super::tests::{mixed, prepare as prepare_sources, remove, row};
use super::*;
use crate::assertions::tests::{capture, key};
use crate::{NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_recall::QueryCancellation;
use contextdb_service::{
    BackupResponse, CaptureRequest, CognitiveMemoryService, CreateBackupRequest,
    RestoreBackupRequest,
};
use std::sync::Arc;

pub(crate) fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        512 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        Default::default(),
    )
}

pub(crate) struct Fixture {
    pub root: tempfile::TempDir,
    pub ledger_directory: tempfile::TempDir,
    _keys_directory: tempfile::TempDir,
    pub native: Arc<NativeService>,
    pub ledger: Arc<NativeSuppressionLedger>,
    keys: Arc<NativeCustodyKeys>,
    pub first: CaptureRequest,
    scope: ScopeId,
    pub accepted: AssertionReceipt,
    pub removal: NativeRemovalRequestReceipt,
    pub witness: NativeAssertionRemovalWitnessReceipt,
    independent: ClaimId,
    empty: BackupResponse,
    old: BackupResponse,
}

pub(crate) fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("root");
    let (ledger_directory, ledger) = crate::suppression::tests::authority("assertion-witness");
    let (keys_directory, keys) = crate::encryption::tests::authority("assertion-witness");
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            "assertion-witness",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native"),
    );
    let first = capture(1, "raw-private-assertion-source");
    let empty = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("empty archive");
    let (request, _, independent) = mixed(&native, &first, &capture(2, "independent source"));
    let scope = key(&first).scope;
    let accepted = native
        .publish_assertions(request, &mut budget())
        .expect("mixed batch");
    let old = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("old full archive");
    let removal = remove(&native, &first, "assertion witness");
    let witness = native
        .prepare_assertion_removal(
            &first.context,
            &removal,
            scope,
            accepted.workspace_commit,
            &mut budget(),
        )
        .expect("independent witness");
    Fixture {
        root,
        ledger_directory,
        _keys_directory: keys_directory,
        native,
        ledger,
        keys,
        first,
        scope,
        accepted,
        removal,
        witness,
        independent,
        empty,
        old,
    }
}

pub(crate) fn retry(f: &Fixture) -> ServiceResult<NativeAssertionRemovalWitnessReceipt> {
    f.native.prepare_assertion_removal(
        &f.first.context,
        &f.removal,
        f.scope,
        f.accepted.workspace_commit,
        &mut budget(),
    )
}

#[test]
fn assertion_witness_inventory_retains_mixed_copy_boundaries_through_cleanup_and_old_restore() {
    let f = fixture();
    let independent = row(&f.native, &claim_key(f.independent)).expect("independent bytes");
    let before = f
        .native
        .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
        .expect("initial key families");
    assert_eq!(before.mutations.keys().copied().collect::<Vec<_>>(), [1]);
    assert_eq!(before.batches[&NativeAssertionBatchKind::Original].len(), 1);
    assert!(before.batches[&NativeAssertionBatchKind::Retained].is_empty());
    assert_eq!(before.mutations[&1].len(), 3);
    assert!(before.native_use.is_some());
    assert!(before.mutations[&1].values().all(|keys| keys.len() == 1));
    let independent_address =
        crate::encryption::address(&f.native.keyspaces.continuous, &claim_key(f.independent));
    assert!(
        before
            .mutations
            .values()
            .flat_map(|copies| copies.values())
            .flatten()
            .all(|key| key.address_digest != independent_address)
    );
    assert!(
        !before
            .native_use
            .as_ref()
            .expect("tracked use")
            .addresses
            .contains_key(&independent_address)
    );
    assert_eq!(retry(&f).expect("retry before pruning"), f.witness);
    prepare_sources(&f.native, &f.first, &f.removal);
    f.native
        .prune_source_assertions(
            &f.first.context,
            &f.removal,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("prune selected mutation");
    assert_eq!(
        retry(&f).expect("same witness from pruned controls"),
        f.witness
    );
    f.native
        .prune_original_sources(
            &f.first.context,
            &f.removal,
            &BTreeSet::from([f.first.event.event_id]),
            &mut budget(),
        )
        .expect("primary cleanup");
    let after = f
        .native
        .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
        .expect("historical and cleaned keys");
    assert_eq!(
        after.batches[&NativeAssertionBatchKind::Original],
        before.batches[&NativeAssertionBatchKind::Original]
    );
    assert_eq!(after.batches[&NativeAssertionBatchKind::Retained].len(), 1);
    assert_eq!(
        after.mutations[&1][&NativeAssertionCopyKind::Body],
        before.mutations[&1][&NativeAssertionCopyKind::Body]
    );
    for kind in [
        NativeAssertionCopyKind::SlotLabel,
        NativeAssertionCopyKind::ClaimLabel,
    ] {
        assert_eq!(after.mutations[&1][&kind].len(), 2);
        assert_eq!(
            after.mutations[&1][&kind][0],
            before.mutations[&1][&kind][0]
        );
        assert_ne!(
            after.mutations[&1][&kind][0].key_id,
            after.mutations[&1][&kind][1].key_id
        );
        let family = &after.mutations[&1][&kind];
        let history = &after
            .native_use
            .as_ref()
            .expect("cleaned and historical use")
            .addresses[&family[0].address_digest];
        assert_eq!(history.transitions.len(), 2);
        assert_eq!(
            history.transitions[0]
                .after
                .as_ref()
                .expect("old label")
                .key_id,
            family[0].key_id
        );
        assert_eq!(history.transitions[1].before, history.transitions[0].after);
        assert_eq!(
            history
                .acknowledged
                .values()
                .next()
                .expect("cleaned label")
                .key_id,
            family[1].key_id
        );
    }
    assert_eq!(
        row(&f.native, &claim_key(f.independent)),
        Some(independent.clone())
    );
    let clean = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.first.context.clone(),
        })
        .expect("clean archive");
    drop(f.native);
    let reopened = NativeService::open_encrypted(
        f.root.path().join("native"),
        "assertion-witness",
        [8; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual native reopen");
    let keys = reopened
        .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
        .expect("reopened inventory");
    assert_eq!(keys.batches, after.batches);
    assert_eq!(keys.mutations, after.mutations);
    for (name, archive) in [("empty", f.empty), ("old", f.old), ("clean", clean)] {
        let restored = NativeService::open_encrypted(
            f.root.path().join(name),
            "assertion-witness",
            [9; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: f.first.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore encrypted archive");
        let keys = restored
            .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
            .expect("keys independent of restored batch presence");
        assert_eq!(keys.batches, after.batches);
        assert_eq!(keys.mutations, after.mutations);
        if name != "empty" {
            assert_eq!(
                row(&restored, &claim_key(f.independent)),
                Some(independent.clone())
            );
            assert_eq!(
                restored
                    .prepare_assertion_removal(
                        &f.first.context,
                        &f.removal,
                        f.scope,
                        f.accepted.workspace_commit,
                        &mut budget()
                    )
                    .expect("original witness after restore"),
                f.witness
            );
        }
        restored
            .verify_native(true)
            .expect("exact archived semantic closure");
    }
}

#[test]
fn assertion_witness_rejects_policy_forgery_budget_and_cas_and_recovers_lost_ack() {
    let f = fixture();
    for restriction in [
        "admin",
        "scope",
        "purpose",
        "workspace",
        "audience",
        "clearance",
    ] {
        let mut denied = f.first.context.clone();
        match restriction {
            "admin" => {
                denied.capability_grants.remove(&Capability::Admin);
            }
            "scope" => denied.request.scopes.clear(),
            "purpose" => denied.request.purpose = "outside".into(),
            "workspace" => denied.request.workspace_id = "outside".into(),
            "audience" => {
                denied.request.subject_id = "outsider".into();
                denied.request.audiences.clear();
            }
            "clearance" => denied.request.clearance = contextdb_service::Sensitivity::Public,
            _ => unreachable!(),
        }
        let code = if restriction == "admin" {
            ErrorCode::Unauthorized
        } else {
            ErrorCode::PermissionDenied
        };
        assert_eq!(
            f.native
                .read_assertion_key_inventory(&denied, &f.witness, &mut budget())
                .expect_err("policy before key inventory")
                .code,
            code,
            "{restriction}"
        );
        assert_eq!(
            f.native
                .prepare_assertion_removal(
                    &denied,
                    &f.removal,
                    f.scope,
                    f.accepted.workspace_commit,
                    &mut budget()
                )
                .expect_err("policy before retention")
                .code,
            code,
            "{restriction}"
        );
    }
    let mut forged = f.witness.clone();
    forged.assertion_commit += 1;
    assert!(
        f.native
            .read_assertion_key_inventory(&f.first.context, &forged, &mut budget())
            .is_err()
    );
    let mut limited =
        QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        f.native
            .read_assertion_key_inventory(&f.first.context, &f.witness, &mut limited)
            .is_err()
    );
    let uncertain = remove(&f.native, &f.first, "uncertain witness acknowledgement");
    let service = f.native.clone();
    BEFORE_PUBLICATION.with(|hook| {
        hook.replace(Some(Box::new(move || {
            service
                .append_event(capture(3, "concurrent capture"))
                .expect("concurrent write");
        })))
    });
    assert_eq!(
        f.native
            .prepare_assertion_removal(
                &f.first.context,
                &uncertain,
                f.scope,
                f.accepted.workspace_commit,
                &mut budget()
            )
            .expect_err("workspace CAS")
            .code,
        ErrorCode::IndexTooStale
    );
    let cancellation = QueryCancellation::default();
    let cancel = cancellation.clone();
    AFTER_AUTHORITY_SYNC.with(|hook| hook.replace(Some(Box::new(move || cancel.cancel()))));
    let mut interrupted = QueryBudget::new(
        1_000_000,
        512 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancellation,
    );
    assert!(
        f.native
            .prepare_assertion_removal(
                &f.first.context,
                &uncertain,
                f.scope,
                f.accepted.workspace_commit,
                &mut interrupted
            )
            .is_err()
    );
    let accepted = f
        .native
        .prepare_assertion_removal(
            &f.first.context,
            &uncertain,
            f.scope,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("recover new witness acknowledgement");
    assert!(accepted.witness_sequence > f.witness.witness_sequence);
    assert_eq!(
        f.native
            .prepare_assertion_removal(
                &f.first.context,
                &uncertain,
                f.scope,
                f.accepted.workspace_commit,
                &mut budget()
            )
            .expect("exact recovered retry"),
        accepted
    );
    f.native.verify_native(true).expect("no body erased");
}
