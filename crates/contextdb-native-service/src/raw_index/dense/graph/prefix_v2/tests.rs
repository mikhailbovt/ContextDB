//! Real encrypted maintenance/cold/copy/GC; artificial vectors prove no recall quality.

use super::inputs::tests::{DATABASE, Fixture, TOKEN_KEY, budget, fixture, read_generation};
use super::*;
use contextdb_recall::QueryCancellation;
use contextdb_service::ErrorCode;
use contextdb_storage::Entry;
use std::time::Duration;

fn request(f: &Fixture) -> DensePrefixBaseRequestV2 {
    DensePrefixBaseRequestV2 {
        generation: f.target.generation,
        target: f.target.clone(),
    }
}

fn rows(native: &NativeService, workspace: &str, generation: u64) -> Vec<Entry> {
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual row snapshot")
        .scan_prefix(
            &native.keyspaces.continuous,
            &prefix_key(workspace, generation).expect("prefix"),
        )
        .expect("finite fixture prefix rows")
}

#[test]
fn encrypted_partial_base_preserves_real_archive_and_cold_retry_after_dense_progress() {
    let f = fixture();
    let request = request(&f);
    let before = read_generation(&f.native, &f.context, &mut budget());
    let receipt = f
        .native
        .publish_original_span_prefix_base(&f.context, &request, &mut budget())
        .expect("actual accepted partial-prefix publication");
    let after = read_generation(&f.native, &f.context, &mut budget());
    assert_eq!(
        (after.through, after.projected_sources, &after.dense),
        (before.through, before.projected_sources, &before.dense)
    );
    assert_eq!(receipt.manifest.raw.through, before.through);
    assert_eq!(receipt.manifest.raw.projected_sources, 3);
    assert_eq!(receipt.manifest.prefix.sources, 2);
    assert_eq!(receipt.manifest.prefix.spans, 1);
    assert_eq!(receipt.manifest.interval.work_items, 2);
    assert!(receipt.manifest.raw.through > receipt.manifest.prefix.through);
    assert!(after.dense_graph.is_none() && after.dense_segments.is_none());
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("owner snapshot");
    let world = f
        .native
        .current_prefix_bases(&snapshot, &f.context.request.workspace_id, &mut budget())
        .expect("current signed roots");
    assert_eq!(
        world.prefix_bases.as_ref().and_then(|roots| roots.get(&1)),
        after.dense_prefix_base.as_ref()
    );
    assert_eq!(
        f.native
            .accepted_prefix_base(&snapshot, &workspace, 1, &mut budget())
            .expect("retained owner acceptance"),
        receipt
    );
    drop(snapshot);
    assert!(
        f.native
            .verify_native(true)
            .expect("full deep accepted prefix")
            .valid
    );
    let advanced = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("genuine later dense progress");
    assert!(advanced.caught_up && advanced.sources == 3);
    assert_eq!(
        f.native
            .publish_original_span_prefix_base(&f.context, &request, &mut budget())
            .expect("historical exact retry without reinstall"),
        receipt
    );
    assert_eq!(
        read_generation(&f.native, &f.context, &mut budget())
            .dense
            .as_ref()
            .expect("dense")
            .sources,
        3
    );
    assert_eq!(
        f.native
            .publish_original_span_graph(&f.context, &mut budget())
            .expect_err("exclusive base family in both directions")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("historical prefix reconstruction after progress")
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
    .expect("real encrypted cold open");
    assert_eq!(
        cold.publish_original_span_prefix_base(&f.context, &request, &mut budget())
            .expect("cold exact accepted retry"),
        receipt
    );
    assert!(
        cold.verify_native(true)
            .expect("cold full deep reconstruction")
            .valid
    );
}

#[test]
fn changed_target_and_parent_refusals_do_not_activate_or_write_a_prefix() {
    let f = fixture();
    let mut changed = request(&f);
    changed.target.commitment = digest(b"caller change is not native authority");
    assert_eq!(
        f.native
            .publish_original_span_prefix_base(&f.context, &changed, &mut budget())
            .expect_err("changed actual accepted target")
            .code,
        ErrorCode::IndexTooStale
    );
    let request = request(&f);
    for (bytes, duration, cancel) in [
        (0, Duration::from_secs(1), false),
        (4096, Duration::ZERO, false),
        (4096, Duration::from_secs(1), true),
    ] {
        let cancellation = QueryCancellation::default();
        if cancel {
            cancellation.cancel();
        }
        let mut parent = QueryBudget::new(100_000, bytes, duration, cancellation);
        assert_eq!(
            f.native
                .publish_original_span_prefix_base(&f.context, &request, &mut parent)
                .expect_err("same parent refusal before activation")
                .code,
            ErrorCode::BudgetExhausted
        );
    }
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    assert!(rows(&f.native, &workspace, 1).is_empty());
    assert!(
        read_generation(&f.native, &f.context, &mut budget())
            .dense_prefix_base
            .is_none()
    );
    let target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("complete actual source prefix");
    f.native
        .publish_original_span_graph(&f.context, &mut budget())
        .expect("actual v1 family");
    assert_eq!(
        f.native
            .publish_original_span_prefix_base(
                &f.context,
                &DensePrefixBaseRequestV2 {
                    generation: target.generation,
                    target
                },
                &mut budget()
            )
            .expect_err("prefix cannot reinterpret existing v1 family")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(rows(&f.native, &workspace, 1).is_empty());
    assert!(
        f.native
            .verify_native(true)
            .expect("unchanged valid legacy family")
            .valid
    );
}

#[test]
fn encrypted_prefix_copies_survive_shared_sibling_gc_and_completed_root_retirement() {
    let f = fixture();
    let request = request(&f);
    let receipt = f
        .native
        .publish_original_span_prefix_base(&f.context, &request, &mut budget())
        .expect("actual prefix acceptance");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let old = read_generation(&f.native, &f.context, &mut budget());
    let saved = rows(&f.native, &workspace, 1);
    assert_eq!(saved.len(), 4, "one member, one shared cohort/node/receipt");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before GC");
    let old_rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            generation_prefix(&workspace, 1).as_bytes(),
        )
        .expect("finite genuine old generation");
    let mut owners = BTreeMap::new();
    for row in &saved {
        let owner = f
            .native
            .verify_dense_prefix_base_copy(&snapshot, &old, &row.key, &row.value, &mut budget())
            .expect("actual source/shared copy attribution");
        if String::from_utf8_lossy(&row.key).contains("/member/") {
            assert_eq!(owner, Some(f.sources[0]));
            let member: PrefixMemberV2 =
                decode(&row.value, "actual prefix member").expect("member");
            assert_eq!(
                member.source.source_version.as_deref(),
                Some("prefix-v2-actual-source-1")
            );
            let mut changed = member;
            changed.source.source_version =
                Some("copied owner must keep its actual version".into());
            assert_eq!(
                f.native
                    .verify_dense_prefix_base_copy(
                        &snapshot,
                        &old,
                        &row.key,
                        &encode(&changed).expect("version fault"),
                        &mut budget()
                    )
                    .expect_err("source version cannot reuse a legitimate row token")
                    .code,
                ErrorCode::IntegrityFailure
            );
            let mut noncanonical = row.value.clone();
            noncanonical.push(b' ');
            assert_eq!(
                f.native
                    .verify_dense_prefix_base_copy(
                        &snapshot,
                        &old,
                        &row.key,
                        &noncanonical,
                        &mut budget()
                    )
                    .expect_err("exact accepted row encoding required")
                    .code,
                ErrorCode::IntegrityFailure
            );
        } else {
            assert!(owner.is_none());
        }
        owners.insert(row.key.clone(), owner);
    }
    drop(snapshot);
    let new = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut budget())
        .expect("real next generation");
    assert!(new.caught_up && new.generation == 2);
    let mut finished = false;
    let mut saw_member_without_cohort = false;
    for _ in 0..=old_rows.len() {
        let progress = f
            .native
            .reclaim_raw_generations(&f.context, 1, &mut budget())
            .expect("actual one-row witnessed reclamation");
        assert_eq!(progress.generation, Some(1));
        assert!(progress.removed_rows <= 1 && progress.copies.is_some());
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("remaining rows");
        let world = f
            .native
            .current_prefix_bases(&snapshot, &f.context.request.workspace_id, &mut budget())
            .expect("current owner root after every page");
        let roots = world
            .prefix_bases
            .as_ref()
            .expect("Some persists after final GC");
        assert_eq!(roots.contains_key(&1), !progress.finished);
        for row in rows(&f.native, &workspace, 1) {
            assert_eq!(
                f.native
                    .verify_dense_prefix_base_copy(
                        &snapshot,
                        &old,
                        &row.key,
                        &row.value,
                        &mut budget()
                    )
                    .expect("remaining copy does not need live sibling rows"),
                owners[&row.key]
            );
            if String::from_utf8_lossy(&row.key).contains("/member/") {
                let member: PrefixMemberV2 =
                    decode(&row.value, "remaining member").expect("member");
                if snapshot
                    .get(
                        &f.native.keyspaces.continuous,
                        &cohort_key(&workspace, 1, &member.policy_domain).expect("cohort key"),
                    )
                    .expect("cohort point")
                    .is_none()
                {
                    saw_member_without_cohort = true;
                }
            }
        }
        if progress.finished {
            assert!(roots.is_empty());
            finished = true;
            break;
        }
    }
    assert!(finished && saw_member_without_cohort);
    assert!(rows(&f.native, &workspace, 1).is_empty());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fully reclaimed");
    assert_eq!(
        f.native
            .accepted_prefix_base(&snapshot, &workspace, 1, &mut budget())
            .expect("retained after full GC"),
        receipt
    );
    for row in saved {
        assert_eq!(
            f.native
                .verify_dense_prefix_base_copy(&snapshot, &old, &row.key, &row.value, &mut budget())
                .expect("independent immutable copies after entire live generation GC"),
            owners[&row.key]
        );
    }
    drop(snapshot);
    assert_eq!(
        f.native
            .publish_original_span_prefix_base(&f.context, &request, &mut budget())
            .expect("retired historical exact retry returns no live rows"),
        receipt
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("deep complete GC and retained acceptance")
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
    .expect("cold complete GC");
    assert_eq!(
        cold.publish_original_span_prefix_base(&f.context, &request, &mut budget())
            .expect("cold retired exact retry"),
        receipt
    );
    assert!(
        cold.verify_native(true)
            .expect("cold retained roots/GC/locator")
            .valid
    );
}

#[test]
fn accepted_prefix_requires_retained_locator_and_format_after_lost_response() {
    let f = fixture();
    let request = request(&f);
    f.native
        .publish_original_span_prefix_base(&f.context, &request, &mut budget())
        .expect("accepted native publication");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault source snapshot");
    let locator_key = retained_locator_key(&workspace, 1).expect("locator address");
    let locator = snapshot
        .get(&f.native.keyspaces.idempotency, &locator_key)
        .expect("locator")
        .expect("accepted locator");
    let original = snapshot
        .get(&f.native.keyspaces.meta, crate::META_MANIFEST_KEY)
        .expect("format")
        .expect("format row");
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("locator fault");
    tx.delete(&f.native.keyspaces.idempotency, locator_key.clone())
        .expect("remove locator only");
    tx.commit(Durability::Sync).expect("fixture deletion");
    let refused = f
        .native
        .publish_original_span_prefix_base(&f.context, &request, &mut budget());
    let mut tx = f.native.engine.begin_write().expect("restore locator");
    tx.put(&f.native.keyspaces.idempotency, locator_key, locator)
        .expect("exact locator bytes");
    tx.commit(Durability::Sync).expect("exact restore");
    assert_eq!(
        refused
            .expect_err("lost-response retry still needs retained authority")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut manifest: crate::Manifest = decode(&original, "actual prefix format").expect("format");
    assert!(manifest.features.remove(types::FEATURE));
    manifest.checksum = crate::manifest_checksum(&manifest).expect("ordinary checksum");
    crate::validate_manifest(&manifest, DATABASE).expect("ordinary declaration remains valid");
    let mut tx = f.native.engine.begin_write().expect("feature fault");
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("format encoding"),
    )
    .expect("only feature changed");
    tx.commit(Durability::Sync).expect("fixture feature strip");
    let refused = f.native.verify_native(true);
    let mut tx = f.native.engine.begin_write().expect("restore exact format");
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        original,
    )
    .expect("exact previous bytes");
    tx.commit(Durability::Sync).expect("fixture restore");
    assert_eq!(
        refused
            .expect_err("retained publication requires prefix feature")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("restored actual prefix publication")
            .valid
    );
}
