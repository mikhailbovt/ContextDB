//! Actual small-page encrypted reclamation, including absent mutable siblings.

use super::*;
use crate::raw_index::copies::NativeRawCopyKind;
use crate::raw_index::dense::graph::segments::types::{SegMember, directory_head_key};
use contextdb_storage::Entry;

fn segment_rows(native: &NativeService, workspace: &str) -> Vec<Entry> {
    let prefix = graph_prefix(workspace, 1);
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("segment inventory snapshot")
        .scan_prefix(&native.keyspaces.continuous, &prefix)
        .expect("actual bounded fixture rows")
        .into_iter()
        .filter(|row| {
            row.key
                .strip_prefix(prefix.as_slice())
                .is_some_and(|relative| {
                    relative == b"segments/head" || relative.starts_with(b"segment/")
                })
        })
        .collect()
}

#[test]
fn encrypted_segment_copies_survive_sibling_gc_and_finished_head_retirement() {
    let f = fixture();
    let mut third =
        crate::capture::tests::request(3, "first actual independently captured delta original");
    third.event.source_version = Some("actual-gc-segment-version-three".into());
    let third_id = third.event.event_id;
    f.native
        .append_event(third)
        .expect("first actual delta capture");
    let first = f
        .native
        .seal_original_span_segment(&f.context, &seal_request(&f, project(&f)), &mut budget())
        .expect("accepted first segment");
    let mut fourth =
        crate::capture::tests::request(4, "second actual independently captured delta original");
    fourth.event.source_version = Some("actual-gc-segment-version-four".into());
    let fourth_id = fourth.event.event_id;
    f.native
        .append_event(fourth)
        .expect("second actual delta capture");
    let second = f
        .native
        .seal_original_span_segment(&f.context, &seal_request(&f, project(&f)), &mut budget())
        .expect("accepted second segment");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let old = generation(&f.native, &f.context);
    let head_key = directory_head_key(&workspace, 1).expect("canonical head key");
    let saved = segment_rows(&f.native, &workspace);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("pre-GC snapshot");
    let old_rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            generation_prefix(&workspace, 1).as_bytes(),
        )
        .expect("exact old fixture generation");
    let mut expected_addresses: BTreeSet<_> = old_rows
        .iter()
        .map(|row| crate::encryption::address(&f.native.keyspaces.continuous, &row.key))
        .collect();
    expected_addresses.insert(crate::encryption::address(
        &f.native.keyspaces.continuous,
        &generation_key(&workspace, 1),
    ));
    let mut segment_owners = BTreeMap::new();
    let mut members = 0;
    let mut shared = 0;
    for row in &saved {
        let owner = f
            .native
            .verify_dense_segment_copy(&snapshot, &old, &row.key, &row.value, &mut budget())
            .expect("actual segment copy attribution before GC");
        if std::str::from_utf8(&row.key)
            .expect("canonical key")
            .contains("/member/")
        {
            let member: SegMember = decode(&row.value, "actual segment member").expect("member");
            assert_eq!(owner, Some(member.source.event_id));
            let version = match member.source.event_id {
                id if id == third_id => "actual-gc-segment-version-three",
                id if id == fourth_id => "actual-gc-segment-version-four",
                _ => panic!("unexpected owner in actual two-source segment fixture"),
            };
            assert_eq!(member.source.source_version.as_deref(), Some(version));
            members += 1;
        } else {
            assert!(
                owner.is_none(),
                "node, cohort, receipt and head remain shared"
            );
            shared += 1;
        }
        segment_owners.insert(
            crate::encryption::address(&f.native.keyspaces.continuous, &row.key),
            owner,
        );
    }
    assert_eq!((members, shared), (2, 7));
    assert_eq!(
        f.native
            .accepted_segment_for_ordinal(&snapshot, &workspace, 1, 1, &mut budget())
            .expect("retained first acceptance before GC"),
        first
    );
    assert_eq!(
        f.native
            .accepted_segment_for_ordinal(&snapshot, &workspace, 1, 2, &mut budget())
            .expect("retained second acceptance before GC"),
        second
    );
    drop(snapshot);

    let mut rebuild = budget();
    let raw = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut rebuild)
        .expect("new accepted raw generation");
    assert!(raw.caught_up);
    assert_eq!(raw.generation, 2);
    let dense = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut rebuild)
        .expect("new exact source generation");
    assert!(dense.caught_up);
    f.native
        .publish_original_span_graph(&f.context, &mut rebuild)
        .expect("new active immutable base protects its v1 rows");

    let mut observed = BTreeSet::new();
    let mut previous = None;
    let mut removed = 0;
    let mut checked_without_cohort = false;
    let mut checked_without_head = false;
    let mut finished = false;
    // One-row pages force a member to remain after its cohort is removed. The
    // finite written fixture gives an explicit bound, not an open-ended retry.
    for _ in 0..=old_rows.len() {
        let progress = f
            .native
            .reclaim_raw_generations(&f.context, 1, &mut budget())
            .expect("actual witnessed one-row reclamation");
        assert_eq!(progress.generation, Some(1));
        assert!(progress.removed_rows <= 1);
        let receipt = progress
            .copies
            .as_ref()
            .expect("suppression witness on every actual page");
        let witness = f
            .native
            .read_raw_copy_witness(&f.context, receipt, &mut budget())
            .expect("independently retained actual observations");
        assert_eq!(witness.previous, previous);
        assert_eq!(witness.removed_before, removed);
        removed += witness.row_count();
        previous = Some(receipt.clone());
        let segment_page = witness
            .rows
            .iter()
            .any(|row| segment_owners.contains_key(&row.address_digest));
        for row in &witness.rows {
            assert!(
                row.version.is_some(),
                "actual encrypted ciphertext is observed"
            );
            assert!(
                observed.insert(row.address_digest.clone()),
                "GC never repeats a copy row"
            );
            if let Some(owner) = segment_owners.get(&row.address_digest) {
                assert_eq!(row.source, *owner);
                assert_eq!(
                    row.kind,
                    if owner.is_some() {
                        NativeRawCopyKind::Document
                    } else {
                        NativeRawCopyKind::SharedMetadata
                    }
                );
                if let Some(owner) = owner {
                    assert!(
                        witness.sources.contains_key(owner),
                        "member has actual capture control"
                    );
                }
            }
        }
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("remaining-row snapshot");
        let state = f
            .native
            .current_segment_heads(&snapshot, &f.context.request.workspace_id, &mut budget())
            .expect("current certified heads survive each GC frame");
        let heads = state
            .segment_heads
            .as_ref()
            .expect("activation remains Some, including after final GC");
        assert_eq!(
            heads.contains_key(&1),
            !progress.finished,
            "only finished GC removes old head entry"
        );
        let remaining = segment_rows(&f.native, &workspace);
        // Authenticate all remaining segment rows whenever a segment sibling is
        // actually deleted; unrelated lexical GC pages need no repeated proof.
        for row in remaining.iter().filter(|_| segment_page) {
            assert_eq!(f.native.verify_dense_segment_copy(
                &snapshot, &old, &row.key, &row.value, &mut budget(),
            ).expect("remaining immutable copy needs no mutable siblings"),
                segment_owners[&crate::encryption::address(&f.native.keyspaces.continuous, &row.key)]);
            if !checked_without_cohort
                && std::str::from_utf8(&row.key)
                    .expect("canonical key")
                    .contains("/member/")
            {
                let member: SegMember = decode(&row.value, "remaining member").expect("member");
                let cohort = segment_cohort_key(
                    &workspace,
                    1,
                    member.segment_ordinal,
                    &member.policy_domain,
                )
                .expect("canonical deleted cohort address");
                if snapshot
                    .get(&f.native.keyspaces.continuous, &cohort)
                    .expect("cohort point")
                    .is_none()
                {
                    assert!(!progress.finished);
                    f.native
                        .verify_native(true)
                        .expect("deep unfinished GC with missing cohort");
                    checked_without_cohort = true;
                }
            }
        }
        if !checked_without_head
            && !progress.finished
            && snapshot
                .get(&f.native.keyspaces.continuous, &head_key)
                .expect("head point")
                .is_none()
        {
            f.native
                .verify_native(true)
                .expect("deep unfinished GC after directory row is deleted");
            checked_without_head = true;
        }
        if progress.finished {
            assert!(remaining.is_empty());
            assert!(heads.is_empty());
            assert!(
                snapshot
                    .get(
                        &f.native.keyspaces.continuous,
                        &generation_key(&workspace, 1)
                    )
                    .expect("old manifest point")
                    .is_none()
            );
            finished = true;
            break;
        }
    }
    assert!(finished && checked_without_cohort && checked_without_head);
    assert_eq!(
        observed, expected_addresses,
        "every actual old row and final manifest was witnessed"
    );
    f.native
        .verify_native(true)
        .expect("completed GC retains accepted segment and copy closure");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("completed snapshot");
    for (ordinal, expected) in [(1, &first), (2, &second)] {
        assert_eq!(
            &f.native
                .accepted_segment_for_ordinal(&snapshot, &workspace, 1, ordinal, &mut budget())
                .expect("immutable acceptance survives full generation GC"),
            expected
        );
    }
    // Saved authentic copies remain attributable even when every live generation
    // row is gone. This does not claim that any ciphertext was physically erased.
    for row in &saved {
        assert_eq!(
            f.native
                .verify_dense_segment_copy(&snapshot, &old, &row.key, &row.value, &mut budget())
                .expect("saved immutable copy after all live siblings are gone"),
            segment_owners[&crate::encryption::address(&f.native.keyspaces.continuous, &row.key)]
        );
    }
    drop(snapshot);
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        "span-ann-segment-fixture",
        [31; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold encrypted owner after full GC");
    cold.verify_native(true)
        .expect("cold accepted copy and retired-directory closure");
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold final snapshot");
    let state = cold
        .current_segment_heads(&snapshot, &f.context.request.workspace_id, &mut budget())
        .expect("cold certified activated empty heads");
    assert!(
        state
            .segment_heads
            .as_ref()
            .expect("Some empty after old generation finished")
            .is_empty()
    );
    for (ordinal, expected) in [(1, &first), (2, &second)] {
        assert_eq!(
            &cold
                .accepted_segment_for_ordinal(&snapshot, &workspace, 1, ordinal, &mut budget())
                .expect("cold retained immutable acceptance"),
            expected
        );
    }
    for row in &saved {
        assert_eq!(
            cold.verify_dense_segment_copy(&snapshot, &old, &row.key, &row.value, &mut budget())
                .expect("cold saved copy attribution without live generation"),
            segment_owners[&crate::encryption::address(&cold.keyspaces.continuous, &row.key)]
        );
    }
}
