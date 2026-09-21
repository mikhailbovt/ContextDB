use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{NativeRemovalBackupInventory, NativeRemovalKeySelection, NativeRemovalRequestReceipt};
use contextdb_service::{BackupResponse, CapturePort, CognitiveMemoryService, CreateBackupRequest};
use std::collections::BTreeSet;

fn archive(f: &Fixture) -> BackupResponse {
    f.native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive")
}

fn report(f: &Fixture, removal: &NativeRemovalRequestReceipt) -> NativeRemovalBackupInventory {
    f.native
        .read_removal_backup_inventory(
            &f.input.context,
            removal,
            &NativeRemovalKeySelection::Originals,
            &mut budget(),
        )
        .expect("preservation inventory")
}

fn prepare(f: &Fixture, removal: &NativeRemovalRequestReceipt) {
    f.native
        .prepare_original_removal_sources(&f.input.context, removal, &removal.roots, &mut budget())
        .expect("prepare roots");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
}

#[test]
fn archive_preservation_follows_partial_replacements_and_requires_complete_bytes() {
    let f = fixture();
    // Two ordinary inline originals force a real multi-page target artifact.
    for sequence in 3..=4 {
        f.native
            .append_event(request(sequence, &"i".repeat(200 * 1024)))
            .expect("independent");
    }
    let second = request(2, "independent-original-witness-sentinel")
        .event
        .event_id;
    let removal = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([f.input.event.event_id, second]),
            "two roots",
            &mut budget(),
        )
        .expect("retained request");
    let old = archive(&f);
    prepare(&f, &removal);
    f.native
        .prune_original_sources(
            &f.input.context,
            &removal,
            &BTreeSet::from([f.input.event.event_id]),
            &mut budget(),
        )
        .expect("first root");
    let middle = f
        .native
        .create_removal_backup(&f.input.context, &removal, &old, &mut budget())
        .expect("partial replacement");
    f.native
        .prune_original_sources(
            &f.input.context,
            &removal,
            &BTreeSet::from([second]),
            &mut budget(),
        )
        .expect("second root");
    let newer = archive(&f);
    let incomplete = report(&f, &removal);
    assert_eq!(
        incomplete.preservation[&1],
        NativeBackupPreservation::ReplacementRequired
    );
    assert_eq!(
        incomplete.preservation[&2],
        NativeBackupPreservation::ReplacementRequired
    );
    assert_eq!(
        incomplete.preservation[&3],
        NativeBackupPreservation::NotRequired
    );
    let clean = f
        .native
        .create_removal_backup(&f.input.context, &removal, &middle.backup, &mut budget())
        .expect("second preservation edge");
    assert_eq!(
        clean.backup, newer,
        "proof may reference already issued bytes"
    );
    let pending = report(&f, &removal);
    let chain = vec![
        middle.replacement.receipt.clone(),
        clean.replacement.receipt.clone(),
    ];
    assert!(
        matches!(&pending.preservation[&1], NativeBackupPreservation::AwaitingArtifact { path }
        if path.target_sequence == 3 && path.replacements == chain)
    );
    assert!(
        matches!(&pending.preservation[&2], NativeBackupPreservation::AwaitingArtifact { path }
        if path.target_sequence == 3 && path.replacements == [clean.replacement.receipt.clone()])
    );
    let prefix = f
        .native
        .retain_removal_backup(&f.input.context, &removal, &clean, 0, 1, &mut budget())
        .expect("one actual page");
    assert!(!prefix.complete);
    assert_eq!(report(&f, &removal).preservation, pending.preservation);
    let available = f
        .native
        .retain_removal_backup(
            &f.input.context,
            &removal,
            &clean,
            prefix.stored_pages,
            16,
            &mut budget(),
        )
        .expect("remaining bytes");
    assert!(available.complete);
    let preserved = report(&f, &removal);
    assert!(
        matches!(&preserved.preservation[&1], NativeBackupPreservation::Preserved { path, artifact }
        if path.target_sequence == 3 && path.replacements == chain && *artifact == available.receipt)
    );
    assert!(
        matches!(&preserved.preservation[&2], NativeBackupPreservation::Preserved { path, .. }
        if path.target_sequence == 3 && path.replacements == [clean.replacement.receipt.clone()])
    );

    // Identical roots are not authority to splice another request's proof chain.
    let another = f
        .native
        .request_original_removal(
            &f.input.context,
            &removal.roots,
            "separate request",
            &mut budget(),
        )
        .expect("another retained request");
    assert_eq!(
        report(&f, &another).preservation[&1],
        NativeBackupPreservation::ReplacementRequired
    );

    // A narrower composition can make the middle archive clean. Its missing bytes
    // must not hide the longer path to an actually available target. Use the same
    // verified copies/proofs and vary only this internal classifier's selected data.
    let crate::NativeRemovalKeyInventory::Originals(primary) = &preserved.key_inventory else {
        panic!("primary inventory");
    };
    let independent_address = &primary.sources[&second][0].address_digest;
    let narrower = inventory(
        &preserved.backups,
        &[middle.replacement, clean.replacement],
        |copy| {
            Ok(if &copy.address_digest == independent_address {
                CopyDisposition::Retain
            } else {
                CopyDisposition::Remove
            })
        },
        &mut budget(),
    )
    .expect("available path through a clean intermediate");
    assert_eq!(narrower[&2], NativeBackupPreservation::NotRequired);
    assert!(
        matches!(&narrower[&1], NativeBackupPreservation::Preserved { path, .. }
        if path.target_sequence == 3 && path.replacements == chain)
    );
}

#[test]
fn archive_preservation_keeps_legacy_unknown_and_orders_ancestry_before_issuance() {
    let f = fixture();
    // Build valid bytes without issuing them. The legacy registration below is
    // real retained metadata without membership, not damaged accepted history.
    let (source, old) = f.native.build_native_backup().expect("old snapshot bytes");
    prepare(&f, &f.removal);
    f.native
        .prune_original_sources(
            &f.input.context,
            &f.removal,
            &f.removal.roots,
            &mut budget(),
        )
        .expect("prune");
    let clean = archive(&f);
    f.keys
        .register_backup(
            &old.digest,
            old.commit_seq,
            &source.deep_digest,
            old.bytes.len() as u64,
        )
        .expect("legacy-shaped registration issued after newer native snapshot");
    let unknown = report(&f, &f.removal);
    assert_eq!(
        unknown.preservation[&1],
        NativeBackupPreservation::NotRequired
    );
    assert_eq!(
        unknown.preservation[&2],
        NativeBackupPreservation::UnknownContents
    );
    assert!(unknown.backups.archives[1].copies.is_empty());
    f.native
        .retain_backup_contents(&f.input.context, &old, &mut budget())
        .expect("verified backfill");
    assert_eq!(
        report(&f, &f.removal).preservation[&2],
        NativeBackupPreservation::ReplacementRequired
    );
    let replacement = f
        .native
        .create_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
        .expect("older native source, later issuance");
    assert_eq!(replacement.backup, clean);
    assert!(
        replacement.replacement.source.registration.sequence
            > replacement.replacement.target.registration.sequence
    );
    let available = f
        .native
        .retain_removal_backup(
            &f.input.context,
            &f.removal,
            &replacement,
            0,
            16,
            &mut budget(),
        )
        .expect("available target");
    assert!(available.complete);
    assert!(
        matches!(&report(&f, &f.removal).preservation[&2], NativeBackupPreservation::Preserved { path, artifact }
        if path.target_sequence == 1 && path.replacements == [replacement.replacement.receipt] && *artifact == available.receipt)
    );
}
