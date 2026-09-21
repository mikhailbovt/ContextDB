use super::*;
use crate::assertions::retention::tests::{mixed, prepare, remove};
use crate::assertions::retention::witness::tests::budget;
use crate::assertions::tests::{capture, key};
use crate::{
    CustodyMasterKey, NativeBackupPreservation, NativeCustodyKeys, NativeSuppressionLedger,
};
use contextdb_service::{
    BackupResponse, CapturePort, CaptureRequest, CognitiveMemoryService, CreateBackupRequest,
    RestoreBackupRequest,
};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) struct Fixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) native: Arc<NativeService>,
    pub(crate) ledger: Arc<NativeSuppressionLedger>,
    pub(crate) keys: Arc<NativeCustodyKeys>,
    pub(crate) first: CaptureRequest,
    pub(crate) second: CaptureRequest,
    pub(crate) accepted: AssertionReceipt,
    pub(crate) removal: NativeRemovalRequestReceipt,
    pub(crate) witness: NativeAssertionRemovalWitnessReceipt,
    pub(crate) empty: BackupResponse,
    pub(crate) old: BackupResponse,
}

pub(crate) fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([97; 32])).expect("fixture master")
}

fn archive(native: &NativeService, input: &CaptureRequest) -> BackupResponse {
    native
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("archive")
}

pub(crate) fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "assertion-archives", master())
        .expect("keys");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "assertion-archives")
        .expect("ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            "assertion-archives",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native"),
    );
    let first = capture(1, "raw-private-archive-source");
    let second = capture(2, "independent archive source");
    let empty = archive(&native, &first);
    let (request, _, _) = mixed(&native, &first, &second);
    let accepted = native
        .publish_assertions(request, &mut budget())
        .expect("mixed assertions");
    let old = archive(&native, &first);
    let removal = remove(&native, &first, "first removal");
    let witness = native
        .prepare_assertion_removal(
            &first.context,
            &removal,
            key(&first).scope,
            accepted.workspace_commit,
            &mut budget(),
        )
        .expect("ownership");
    Fixture {
        root,
        native,
        ledger,
        keys,
        first,
        second,
        accepted,
        removal,
        witness,
        empty,
        old,
    }
}

fn report(f: &Fixture) -> ServiceResult<NativeAssertionBackupInventory> {
    f.native.read_assertion_backup_inventory(
        &f.first.context,
        &f.removal,
        &f.witness,
        &mut budget(),
    )
}

pub(crate) fn prune(f: &Fixture) {
    prepare(&f.native, &f.first, &f.removal);
    f.native
        .prune_source_assertions(
            &f.first.context,
            &f.removal,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("prune selected mutation");
}

fn dispositions<'a>(
    report: &'a NativeAssertionBackupInventory,
    digest: &str,
) -> Vec<&'a NativeAssertionValueDisposition> {
    let archive = report
        .backups
        .archives
        .iter()
        .find(|archive| archive.registration.archive_digest == digest)
        .expect("issued archive");
    assert!(archive.contents.is_some());
    let values = report
        .key_inventory
        .value_ownership
        .as_ref()
        .expect("compositions");
    archive
        .copies
        .iter()
        .map(|copy| {
            &values.addresses[&copy.address_digest]
                .iter()
                .find(|value| value.version == copy.version)
                .expect("exact archived version")
                .disposition
        })
        .collect()
}

#[test]
fn assertion_archive_inventory_preserves_mixed_copies_after_both_authority_reopen_and_restore() {
    let f = fixture();
    let unknown = report(&f).expect("before classification");
    assert!(dispositions(&unknown, &f.empty.digest).is_empty());
    let copies = dispositions(&unknown, &f.old.digest);
    assert_eq!(
        unknown.preservation[&1],
        NativeBackupPreservation::NotRequired
    );
    assert_eq!(
        unknown.preservation[&2],
        NativeBackupPreservation::UnclassifiedValues
    );
    assert_eq!(
        copies.len(),
        4,
        "original batch and three selected mutation copies"
    );
    assert!(
        copies
            .iter()
            .all(|value| **value == NativeAssertionValueDisposition::Unclassified)
    );
    prune(&f);
    let clean = f
        .native
        .create_removal_backup(&f.first.context, &f.removal, &f.old, &mut budget())
        .expect("verified replacement");
    let pending = report(&f).expect("replacement is not availability");
    assert!(matches!(
        pending.preservation[&2],
        NativeBackupPreservation::AwaitingArtifact { .. }
    ));
    let native = f.native.clone();
    let context = f.first.context.clone();
    let removal = f.removal.clone();
    let target = clean.clone();
    BEFORE_ARCHIVE_FENCE.with(|hook| {
        hook.replace(Some(Box::new(move || {
            assert!(
                native
                    .retain_removal_backup(&context, &removal, &target, 0, 16, &mut budget())
                    .expect("retained bytes")
                    .complete
            );
        })))
    });
    assert_eq!(
        report(&f).expect_err("artifact frontier advanced").code,
        ErrorCode::IndexTooStale
    );
    let before = f.native.verify_native(true).expect("native before report");
    let classified = report(&f).expect("archive compositions");
    assert!(
        matches!(&classified.preservation[&2], NativeBackupPreservation::Preserved { path, .. }
        if path.replacements == [clean.replacement.receipt.clone()])
    );
    assert_eq!(
        classified.preservation[&3],
        NativeBackupPreservation::NotRequired
    );
    assert_eq!(
        f.native
            .verify_native(true)
            .expect("read only")
            .archive_digest,
        before.archive_digest
    );
    let selected = dispositions(&classified, &f.old.digest);
    assert!(selected.iter().all(|value| matches!(
        value,
        NativeAssertionValueDisposition::RequiresRemoval { .. }
    )));
    assert!(selected.iter().any(|value| matches!(value,
        NativeAssertionValueDisposition::RequiresRemoval { selected_mutations, independent_mutations }
            if selected_mutations == &BTreeSet::from([1]) && independent_mutations == &BTreeSet::from([0, 2, 3]))));
    let kept = dispositions(&classified, &clean.backup.digest);
    assert!(kept.iter().any(|value| matches!(value,
        NativeAssertionValueDisposition::PreserveIndependent { mutations } if mutations == &BTreeSet::from([0, 2, 3]))));
    assert!(
        kept.iter()
            .any(|value| **value == NativeAssertionValueDisposition::PreserveControl)
    );
    assert!(kept.iter().all(|value| matches!(
        value,
        NativeAssertionValueDisposition::PreserveIndependent { .. }
            | NativeAssertionValueDisposition::PreserveControl
    )));
    let artifact = classified
        .backups
        .archives
        .iter()
        .find(|archive| archive.registration.archive_digest == clean.backup.digest)
        .expect("replacement member")
        .artifact
        .as_ref()
        .expect("actual bytes");
    assert!(artifact.complete);
    let serialized = String::from_utf8(encode(&classified).expect("json")).expect("text");
    for text in [
        "raw-private-archive-source",
        "semanticremovalsentinel",
        "independent-semantic-value",
        "removed-envelope-sentinel",
    ] {
        assert!(!serialized.contains(text));
    }
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "assertion-archives",
        key_id,
        master(),
    )
    .expect("cold keys");
    let ledger = NativeSuppressionLedger::open(
        f.root.path().join("ledger"),
        "assertion-archives",
        ledger_id,
    )
    .expect("cold ledger");
    for (name, archive) in [("old", f.old), ("clean", clean.backup)] {
        let native = NativeService::open_encrypted(
            f.root.path().join(name),
            "assertion-archives",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("new instance");
        native
            .restore_backup(RestoreBackupRequest {
                context: f.first.context.clone(),
                bytes: archive.bytes,
                format: archive.format,
                digest: archive.digest,
            })
            .expect("actual restore");
        native.verify_native(true).expect("full replay");
        let restored = native
            .read_assertion_backup_inventory(
                &f.first.context,
                &f.removal,
                &f.witness,
                &mut budget(),
            )
            .expect("historical archive obligations");
        assert_eq!(restored.backups, classified.backups);
        assert_eq!(restored.preservation, classified.preservation);
        assert_eq!(
            restored.key_inventory.value_ownership,
            classified.key_inventory.value_ownership
        );
    }
}

#[test]
fn assertion_archive_inventory_classifies_shared_versions_relative_to_each_request() {
    let f = fixture();
    prune(&f);
    let middle = archive(&f.native, &f.first);
    let first = report(&f).expect("first request");
    let removal = remove(&f.native, &f.second, "second removal");
    let witness = f
        .native
        .prepare_assertion_removal(
            &f.second.context,
            &removal,
            f.witness.scope,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("second ownership");
    let second = f
        .native
        .read_assertion_backup_inventory(&f.second.context, &removal, &witness, &mut budget())
        .expect("second request");
    assert!(dispositions(&first, &middle.digest).iter().any(|value| matches!(value,
        NativeAssertionValueDisposition::PreserveIndependent { mutations } if mutations == &BTreeSet::from([0, 2, 3]))));
    assert!(dispositions(&second, &middle.digest).iter().any(|value| matches!(value,
        NativeAssertionValueDisposition::RequiresRemoval { selected_mutations, independent_mutations }
            if selected_mutations == &BTreeSet::from([3]) && independent_mutations == &BTreeSet::from([0, 2]))));
    prepare(&f.native, &f.second, &removal);
    f.native
        .prune_source_assertions(
            &f.second.context,
            &removal,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("second cleanup");
    let clean = archive(&f.native, &f.first);
    let final_report = f
        .native
        .read_assertion_backup_inventory(&f.second.context, &removal, &witness, &mut budget())
        .expect("final compositions");
    assert!(dispositions(&final_report, &clean.digest).iter().any(|value| matches!(value,
        NativeAssertionValueDisposition::PreserveIndependent { mutations } if mutations == &BTreeSet::from([0, 2]))));
    assert!(
        f.native
            .read_assertion_backup_inventory(&f.first.context, &f.removal, &witness, &mut budget())
            .is_err(),
        "another request's witness is not interchangeable"
    );
}

#[test]
fn assertion_archive_inventory_requires_authority_budget_and_all_current_frontiers() {
    for race in ["issuance", "native", "classification"] {
        let f = fixture();
        prepare(&f.native, &f.first, &f.removal);
        let mut denied = f.first.context.clone();
        denied.capability_grants.remove(&Capability::Admin);
        assert_eq!(
            f.native
                .read_assertion_backup_inventory(&denied, &f.removal, &f.witness, &mut budget())
                .expect_err("admin first")
                .code,
            ErrorCode::Unauthorized
        );
        denied = f.first.context.clone();
        denied.request.scopes.clear();
        assert!(
            f.native
                .read_assertion_backup_inventory(&denied, &f.removal, &f.witness, &mut budget())
                .is_err()
        );
        denied = f.first.context.clone();
        denied.request.workspace_id = "foreign-workspace".into();
        assert!(
            f.native
                .read_assertion_backup_inventory(&denied, &f.removal, &f.witness, &mut budget())
                .is_err()
        );
        let mut wrong = f.removal.clone();
        wrong.digest = "ab".repeat(32);
        assert!(
            f.native
                .read_assertion_backup_inventory(
                    &f.first.context,
                    &wrong,
                    &f.witness,
                    &mut budget()
                )
                .is_err()
        );
        let mut empty =
            QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
        assert_eq!(
            f.native
                .read_assertion_backup_inventory(
                    &f.first.context,
                    &f.removal,
                    &f.witness,
                    &mut empty
                )
                .expect_err("bounded")
                .code,
            ErrorCode::BudgetExhausted
        );
        let native = f.native.clone();
        let first = f.first.clone();
        let second = f.second.clone();
        BEFORE_ARCHIVE_FENCE.with(|hook| {
            hook.replace(Some(Box::new(move || match race {
                "issuance" => {
                    archive(&native, &first);
                }
                "native" => {
                    native
                        .append_event(capture(3, "independent race"))
                        .expect("native use/allocation change");
                }
                "classification" => {
                    remove(&native, &second, "advance independent removal head");
                }
                _ => unreachable!(),
            })))
        });
        assert_eq!(
            report(&f).expect_err("fresh frontiers").code,
            ErrorCode::IndexTooStale,
            "{race}"
        );
        report(&f).expect("retry after growth");
    }
}

#[test]
fn archived_assertion_versions_do_not_invent_native_use_evidence() {
    let f = fixture();
    prune(&f);
    let current = report(&f).expect("verified actual archive copies");
    let (mut selection, owner, selected) = f
        .native
        .assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
        .expect("selection");
    // Exercise the classifier with an explicit observation gap, without mutating
    // custody or pretending that deleting accepted history is a valid migration.
    for address in selection
        .native_use
        .as_mut()
        .expect("tracked selection")
        .addresses
        .values_mut()
    {
        address.transitions.clear();
        address.acknowledged.clear();
    }
    let classifications = f
        .native
        .assertion_value_inventory(
            &owner,
            &selected,
            &selection,
            Some(&current.backups),
            &mut budget(),
        )
        .expect("archived observations remain classifiable")
        .expect("values");
    let copies = &current
        .backups
        .archives
        .iter()
        .find(|archive| archive.registration.archive_digest == f.old.digest)
        .expect("full archive")
        .copies;
    for copy in copies {
        let value = classifications.addresses[&copy.address_digest]
            .iter()
            .find(|value| value.version == copy.version)
            .expect("exact archived ciphertext");
        assert!(matches!(
            value.disposition,
            NativeAssertionValueDisposition::RequiresRemoval { .. }
        ));
    }
    assert!(
        selection
            .native_use
            .as_ref()
            .expect("still no native evidence")
            .addresses
            .values()
            .all(|address| address.transitions.is_empty() && address.acknowledged.is_empty())
    );

    // Classifier inputs with unrecognized commitments remain unknown; a second
    // value claim for the same ciphertext is an integrity error, never a fallback.
    let mut observations = current.backups.clone();
    let archive = observations
        .archives
        .iter_mut()
        .find(|archive| archive.registration.archive_digest == f.old.digest)
        .expect("archive observations");
    let mut unknown = archive.copies[0].clone();
    unknown.version.ciphertext_digest = "ef".repeat(32);
    unknown.version.value_digest = "ab".repeat(32);
    archive.copies.push(unknown.clone());
    let classifications = f
        .native
        .assertion_value_inventory(
            &owner,
            &selected,
            &selection,
            Some(&observations),
            &mut budget(),
        )
        .expect("unknown version")
        .expect("values");
    assert_eq!(
        classifications.addresses[&unknown.address_digest]
            .iter()
            .find(|value| value.version == unknown.version)
            .expect("explicit unknown")
            .disposition,
        NativeAssertionValueDisposition::Unclassified
    );
    let archive = observations
        .archives
        .iter_mut()
        .find(|archive| archive.registration.archive_digest == f.old.digest)
        .expect("archive observations");
    let mut conflicting = archive.copies[0].clone();
    conflicting.version.value_digest = "cd".repeat(32);
    archive.copies.push(conflicting);
    assert!(
        f.native
            .assertion_value_inventory(
                &owner,
                &selected,
                &selection,
                Some(&observations),
                &mut budget(),
            )
            .is_err()
    );
}
