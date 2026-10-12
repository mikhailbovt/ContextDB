//! Encrypted publication, exact cold retries and paged retirement; no recall score.

use super::super::prefix_v2::inputs::tests::{
    DATABASE, Fixture, TOKEN_KEY, budget, fixture, read_generation,
};
use super::super::prefix_v2::types::DensePrefixBaseRequestV2;
use super::*;
use contextdb_service::{CapturePort, ErrorCode};

fn initial(f: &Fixture) -> (PrefixSegmentSealRequestV2, PrefixSegmentPublicationV2) {
    f.native
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: f.target.generation,
                target: f.target.clone(),
            },
            &mut budget(),
        )
        .expect("genuine partial base with pre-recorded third capture");
    assert!(
        f.native
            .original_span_prefix_segment_head(&f.context, 1, &mut budget())
            .expect("authenticated first None")
            .is_none()
    );
    let target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("accepted third source projection");
    let request = PrefixSegmentSealRequestV2 {
        generation: 1,
        previous: None,
        target,
    };
    let publication = f
        .native
        .seal_original_span_prefix_segment(&f.context, &request, &mut budget())
        .expect("actual whole interval publication");
    assert_eq!(publication.delta.manifest.interval.work_items, 1);
    assert_eq!(publication.delta.manifest.before.sources, 2);
    assert_eq!(publication.delta.manifest.after.sources, 3);
    assert_eq!(publication.delta.manifest.raw.projected_sources, 3);
    assert!(
        publication.delta.manifest.end.global_commit
            < publication.delta.manifest.before_dense.global_commit,
        "third original really predates the before-dense publication"
    );
    (request, publication)
}

#[test]
fn encrypted_prefix_two_intervals_preserve_archive_and_cold_exact_old_retry() {
    let f = fixture();
    let (first_request, first) = initial(&f);
    let first_ref = f
        .native
        .original_span_prefix_segment_head(&f.context, 1, &mut budget())
        .expect("current first head")
        .expect("head");
    let mut capture =
        crate::capture::tests::request(80, "fourth actual original: an independent weather note");
    capture.context = f.context.clone();
    capture.event.source_version = Some("prefix-segment-v2-fourth-actual-version".into());
    f.native
        .append_event(capture)
        .expect("actual subsequent capture");
    let raw = f
        .native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("real raw advance");
    assert!(raw.caught_up && raw.projected_sources == 4);
    let dense = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("real dense advance");
    let second_request = PrefixSegmentSealRequestV2 {
        generation: 1,
        previous: Some(first_ref.clone()),
        target: dense,
    };
    let second = f
        .native
        .seal_original_span_prefix_segment(&f.context, &second_request, &mut budget())
        .expect("second independent interval");
    assert_eq!(second.directory.head.count, 2);
    assert_eq!(second.delta.manifest.before, first.delta.manifest.after);
    assert_eq!(second.delta.manifest.start, first.delta.manifest.end);
    assert_eq!(second.delta.manifest.raw.projected_sources, 4);
    assert_eq!(second.delta.manifest.interval.work_items, 1);
    let latest = f
        .native
        .original_span_prefix_segment_head(&f.context, 1, &mut budget())
        .expect("latest")
        .expect("head");
    assert_ne!(latest, first_ref);
    assert_eq!(
        f.native
            .seal_original_span_prefix_segment(&f.context, &first_request, &mut budget())
            .expect("historical exact retry"),
        first
    );
    assert_eq!(
        f.native
            .original_span_prefix_segment_head(&f.context, 1, &mut budget())
            .expect("unchanged latest"),
        Some(latest.clone())
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("complete real interval reconstruction")
            .valid
    );
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        DATABASE,
        TOKEN_KEY,
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual encrypted cold open");
    assert_eq!(
        cold.seal_original_span_prefix_segment(&f.context, &first_request, &mut budget())
            .expect("cold immutable exact retry"),
        first
    );
    assert_eq!(
        cold.seal_original_span_prefix_segment(&f.context, &second_request, &mut budget())
            .expect("cold latest exact retry"),
        second
    );
    assert_eq!(
        cold.original_span_prefix_segment_head(&f.context, 1, &mut budget())
            .expect("cold current head"),
        Some(latest)
    );
    assert!(cold.verify_native(true).expect("cold whole history").valid);
}

#[test]
fn encrypted_one_row_gc_keeps_current_root_until_finished_and_retained_copies_afterward() {
    let f = fixture();
    let (request, publication) = initial(&f);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let old = read_generation(&f.native, &f.context, &mut budget());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before GC");
    let all = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            generation_prefix(&workspace, 1).as_bytes(),
        )
        .expect("actual old generation rows");
    let saved: Vec<_> = all
        .iter()
        .filter(|row| {
            let key = String::from_utf8_lossy(&row.key);
            key.contains("/dense/prefix-segment-v2/")
                || key.ends_with("/dense/prefix-segments-v2/head")
        })
        .cloned()
        .collect();
    assert!(!saved.is_empty());
    let mut owners = BTreeMap::new();
    for row in &saved {
        let owner = f
            .native
            .verify_dense_prefix_segment_copy(&snapshot, &old, &row.key, &row.value, &mut budget())
            .expect("actual source/shared copy");
        assert_eq!(
            owner.is_some(),
            String::from_utf8_lossy(&row.key).contains("/member/")
        );
        let mut noncanonical = row.value.clone();
        noncanonical.push(b' ');
        assert_eq!(
            f.native
                .verify_dense_prefix_segment_copy(
                    &snapshot,
                    &old,
                    &row.key,
                    &noncanonical,
                    &mut budget()
                )
                .expect_err("canonical bytes required")
                .code,
            ErrorCode::IntegrityFailure
        );
        owners.insert(row.key.clone(), owner);
    }
    drop(snapshot);
    let new = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut budget())
        .expect("real replacement raw generation");
    assert!(new.caught_up && new.generation == 2);
    let mut finished = false;
    let mut shared_gone_member_remains = false;
    for _ in 0..=all.len() {
        let progress = f
            .native
            .reclaim_raw_generations(&f.context, 1, &mut budget())
            .expect("one-row witnessed GC");
        assert!(progress.removed_rows <= 1 && progress.copies.is_some());
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("GC progress");
        let world = f
            .native
            .current_prefix_segment_heads(&snapshot, &f.context.request.workspace_id, &mut budget())
            .expect("current roots after each GC page");
        assert_eq!(
            world
                .prefix_segment_heads
                .as_ref()
                .expect("Some persists")
                .contains_key(&1),
            !progress.finished
        );
        let mut member_remains = false;
        let mut cohort_remains = false;
        for row in &saved {
            if snapshot
                .get(&f.native.keyspaces.continuous, &row.key)
                .expect("live point row")
                .is_some()
            {
                f.native
                    .verify_dense_prefix_segment_copy(
                        &snapshot,
                        &old,
                        &row.key,
                        &row.value,
                        &mut budget(),
                    )
                    .expect("copy proof independent of missing sibling");
                member_remains |= String::from_utf8_lossy(&row.key).contains("/member/");
                cohort_remains |= String::from_utf8_lossy(&row.key).contains("/cohort/");
            }
        }
        shared_gone_member_remains |= member_remains && !cohort_remains;
        drop(snapshot);
        assert!(f.native.verify_native(true).expect("deep partial GC").valid);
        if progress.finished {
            finished = true;
            break;
        }
    }
    assert!(finished && shared_gone_member_remains);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fully reclaimed");
    for row in &saved {
        assert!(
            snapshot
                .get(&f.native.keyspaces.continuous, &row.key)
                .expect("removed point row")
                .is_none()
        );
        assert_eq!(
            f.native
                .verify_dense_prefix_segment_copy(
                    &snapshot,
                    &old,
                    &row.key,
                    &row.value,
                    &mut budget()
                )
                .expect("independent retained copy acceptance"),
            owners[&row.key]
        );
    }
    drop(snapshot);
    assert_eq!(
        f.native
            .seal_original_span_prefix_segment(&f.context, &request, &mut budget())
            .expect("old exact retry after full GC"),
        publication
    );
    assert_eq!(
        read_generation(&f.native, &f.context, &mut budget()).number,
        2
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("all retained declarations after GC")
            .valid
    );
}

#[test]
fn retained_prefix_declaration_blocks_legacy_activation_after_joint_field_and_locator_loss() {
    let f = fixture();
    f.native
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: 1,
                target: f.target.clone(),
            },
            &mut budget(),
        )
        .expect("actual accepted prefix base");
    let target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("real full dense catchup");
    assert!(target.caught_up && target.sources == 3);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let key = generation_key(&workspace, 1);
    let locator_key = prefix_v2::types::retained_locator_key(&workspace, 1).expect("retained key");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before isolated fault");
    let saved_generation = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("generation read")
        .expect("generation");
    let saved_locator = snapshot
        .get(&f.native.keyspaces.idempotency, &locator_key)
        .expect("locator read")
        .expect("locator");
    let head = f
        .native
        .global_head(&snapshot)
        .expect("native logical head");
    let mut forged: Generation = decode(&saved_generation, "actual generation").expect("decode");
    forged.dense_prefix_base = None;
    forged.dense_prefix_segments = None;
    drop(snapshot);
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("isolated fixture corruption");
    tx.put(
        &f.native.keyspaces.continuous,
        key.clone(),
        encode(&forged).expect("fault bytes"),
    )
    .expect("strip only fields");
    tx.delete(&f.native.keyspaces.idempotency, locator_key.clone())
        .expect("strip only locator");
    require_sync(
        tx.commit(Durability::Sync)
            .expect("fixture fault Sync")
            .durability,
    )
    .expect("Sync");
    assert_eq!(
        f.native
            .publish_original_span_graph(&f.context, &mut budget())
            .expect_err("accepted declaration forbids another family")
            .code,
        ErrorCode::IntegrityFailure
    );
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after refusal");
    assert_eq!(
        f.native
            .global_head(&snapshot)
            .expect("unchanged native head"),
        head
    );
    assert!(
        snapshot
            .scan_prefix(&f.native.keyspaces.continuous, &graph_prefix(&workspace, 1))
            .expect("no legacy graph rows")
            .is_empty()
    );
    drop(snapshot);
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("exact fixture restoration");
    tx.put(&f.native.keyspaces.continuous, key, saved_generation)
        .expect("restore actual bytes");
    tx.put(&f.native.keyspaces.idempotency, locator_key, saved_locator)
        .expect("restore actual locator");
    require_sync(
        tx.commit(Durability::Sync)
            .expect("restore Sync")
            .durability,
    )
    .expect("Sync");
    assert!(
        f.native
            .verify_native(true)
            .expect("exact original valid history restored")
            .valid
    );
}
