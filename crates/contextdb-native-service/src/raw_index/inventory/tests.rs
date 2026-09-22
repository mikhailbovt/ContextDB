use super::*;
use crate::raw_index::copies::tests::{Fixture, budget, fixture};
use contextdb_service::{
    CapturePort, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};

pub(crate) fn request(f: &Fixture) -> NativeRemovalRequestReceipt {
    f.native
        .request_original_removal(
            &f.first.context,
            &BTreeSet::from([f.first.event.event_id]),
            "live-index-inventory",
            &mut budget(),
        )
        .expect("removal request")
}

pub(crate) fn gather(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
) -> Vec<NativeRawIndexInventoryPage> {
    let mut pages = Vec::new();
    let mut cursor = None;
    for _ in 0..256 {
        let page = native
            .inventory_raw_removal_copies(context, request, cursor.as_deref(), 3, &mut budget())
            .expect("inventory page");
        assert!(page.witness.row_count() <= 3);
        assert_eq!(
            page.witness.previous.as_ref(),
            pages
                .last()
                .map(|page: &NativeRawIndexInventoryPage| &page.receipt)
        );
        cursor = page.continuation.clone();
        pages.push(page);
        if cursor.is_none() {
            assert!(pages.last().expect("terminal").witness.finished);
            return pages;
        }
    }
    panic!("fixture inventory did not finish");
}

#[test]
fn present_raw_inventory_preserves_snapshot_copies_and_retry_across_reopen_pruning_and_restore() {
    let f = fixture();
    let context = f.first.context.clone();
    let mut child = crate::capture::tests::request(3, "liveinventorydescendantsecret");
    child.event.kind = EventKind::MessageEdited;
    child.event.supersedes_event_id = Some(f.first.event.event_id);
    f.native.append_event(child.clone()).expect("descendant");
    f.native
        .project_originals(&context, false, 64, &mut budget())
        .expect("active generation catch-up");
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("before inventory archive");
    let removal = request(&f);
    let before = f.native.engine.head_sequence().expect("native head");
    let start = f
        .native
        .inventory_raw_removal_copies(&context, &removal, None, 3, &mut budget())
        .expect("start");
    let retry = f
        .native
        .inventory_raw_removal_copies(&context, &removal, None, 3, &mut budget())
        .expect("exact retry");
    assert_eq!(retry.receipt, start.receipt);
    assert_eq!(retry.witness, start.witness);
    drop(f.native);
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "raw-copies",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual reopen");
    let resumed = native
        .inventory_raw_removal_copies(
            &context,
            &removal,
            start.continuation.as_deref(),
            3,
            &mut budget(),
        )
        .expect("resume persisted page");
    let pages = gather(&native, &context, &removal);
    assert_eq!(pages[1].receipt, resumed.receipt);
    assert_eq!(
        native.engine.head_sequence().expect("unchanged native"),
        before
    );
    let anchor = &pages[0].witness.snapshot;
    assert_eq!(anchor.generations.len(), 2);
    assert_eq!(
        anchor.generations[0].role,
        NativeRawGenerationRole::Retained
    );
    assert_eq!(anchor.generations[1].role, NativeRawGenerationRole::Active);
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let mut expected = BTreeMap::new();
    for generation in &anchor.generations {
        let mut rows = snapshot
            .scan_prefix(
                &native.keyspaces.continuous,
                generation_prefix(&workspace, generation.number).as_bytes(),
            )
            .expect("generation rows");
        let key = generation_key(&workspace, generation.number);
        rows.push(contextdb_storage::Entry {
            value: snapshot
                .get(&native.keyspaces.continuous, &key)
                .expect("manifest")
                .expect("manifest present"),
            key,
        });
        for row in rows {
            expected.insert(
                crate::encryption::address(&native.keyspaces.continuous, &row.key),
                (
                    digest_bytes(&row.value),
                    digest_bytes(
                        &snapshot
                            .inner
                            .get(&native.keyspaces.continuous, &row.key)
                            .expect("physical")
                            .expect("ciphertext"),
                    ),
                ),
            );
        }
    }
    let mut observed = BTreeMap::new();
    for page in &pages {
        assert_eq!(&page.witness.snapshot, anchor);
        assert_eq!(
            native
                .read_raw_index_inventory_witness(&context, &page.receipt, &mut budget())
                .expect("readback"),
            page.witness
        );
        for row in &page.witness.rows {
            assert!(
                observed
                    .insert(
                        row.address_digest.clone(),
                        (
                            row.value_digest.clone(),
                            row.version
                                .as_ref()
                                .expect("encrypted")
                                .ciphertext_digest
                                .clone()
                        )
                    )
                    .is_none()
            );
        }
        let encoded = String::from_utf8(encode(page).expect("page JSON")).expect("UTF8");
        for secret in [
            "rawcopysentinelprivate",
            "rawcopysentinelindependent",
            "liveinventorydescendantsecret",
        ] {
            assert!(!encoded.contains(secret));
        }
    }
    assert_eq!(observed, expected);
    let terminal = pages.last().expect("terminal").receipt.clone();
    let keys = native
        .read_raw_index_key_inventory(&context, &removal, &terminal, &mut budget())
        .expect("live source key families");
    assert_eq!(keys.inspected_pages as usize, pages.len());
    assert_eq!(
        keys.sources.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([f.first.event.event_id, child.event.event_id])
    );
    for families in keys.sources.values() {
        assert!(!families.is_empty());
        for (address, family) in families {
            assert!(!family.observed_versions.is_empty());
            for version in &family.observed_versions {
                assert!(
                    family
                        .allocations
                        .iter()
                        .any(|key| key.address_digest == *address && key.key_id == version.key_id)
                );
            }
        }
    }
    assert!(
        native
            .read_raw_index_key_inventory(&context, &removal, &pages[0].receipt, &mut budget())
            .is_err(),
        "partial page chain cannot become full key coverage"
    );
    drop(snapshot);
    let decisions = native
        .retain_raw_index_key_removal(&context, &removal, &terminal, &mut budget())
        .expect("retain complete inspection decisions");
    assert!(!decisions.dispositions.is_empty());
    assert_eq!(
        native
            .retain_raw_index_key_removal(&context, &removal, &terminal, &mut budget())
            .expect("exact retry"),
        decisions
    );
    assert_eq!(native.engine.head_sequence().expect("head"), before);
    native
        .verify_native(true)
        .expect("independent inventory preserves native closure");
    let owners = BTreeSet::from([f.first.event.event_id, child.event.event_id]);
    native
        .prepare_original_removal_sources(&context, &removal, &owners, &mut budget())
        .expect("prepare");
    native
        .maintain_custody(&context, 64, &mut budget())
        .expect("custody");
    native
        .project_originals(&context, true, 64, &mut budget())
        .expect("clean generation");
    for _ in 0..2 {
        while !native
            .reclaim_raw_generations(&context, 64, &mut budget())
            .expect("reclaim old generation")
            .finished
        {}
    }
    native
        .prune_original_sources(&context, &removal, &owners, &mut budget())
        .expect("prune originals");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("independent snapshot");
    assert_eq!(
        native
            .load_captured_original(&snapshot, f.independent.event.event_id)
            .expect("independent original")
            .event,
        f.independent.event
    );
    drop(snapshot);
    for page in &pages {
        assert_eq!(
            native
                .read_raw_index_inventory_witness(&context, &page.receipt, &mut budget())
                .expect("after pruning"),
            page.witness
        );
    }
    assert_eq!(
        native
            .read_raw_index_key_inventory(&context, &removal, &terminal, &mut budget())
            .expect("keys after pruning")
            .sources,
        keys.sources
    );
    assert_eq!(
        native
            .read_raw_index_key_removal(
                &context,
                &removal,
                &terminal,
                &decisions.receipt,
                &mut budget()
            )
            .expect("exact inspection decisions after pruning"),
        decisions
    );
    for (name, archive) in [("empty", f.empty), ("old", old)] {
        let target = NativeService::open_encrypted(
            f.root.path().join(name),
            "raw-copies",
            [9; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("restore target");
        target
            .restore_backup(RestoreBackupRequest {
                context: context.clone(),
                bytes: archive.bytes,
                format: archive.format,
                digest: archive.digest,
            })
            .expect("older encrypted restore");
        for page in &pages {
            assert_eq!(
                target
                    .read_raw_index_inventory_witness(&context, &page.receipt, &mut budget())
                    .expect("retained observations"),
                page.witness
            );
        }
        assert_eq!(
            target
                .read_raw_index_key_inventory(&context, &removal, &terminal, &mut budget())
                .expect("historical live keys after restore")
                .sources,
            keys.sources
        );
        assert_eq!(
            target
                .read_raw_index_key_removal(
                    &context,
                    &removal,
                    &terminal,
                    &decisions.receipt,
                    &mut budget()
                )
                .expect("exact inspection decisions after encrypted restore"),
            decisions
        );
        let inspected = gather(&target, &context, &removal);
        if name == "empty" {
            assert_eq!(inspected.len(), 1);
            assert!(inspected[0].witness.rows.is_empty());
            assert_eq!(inspected[0].witness.snapshot.native_commit, 0);
        }
        target
            .verify_native(true)
            .expect("restored native and retained authority");
    }
}

#[test]
fn present_raw_inventory_cursors_enforce_authority_and_native_snapshot_fences() {
    use std::{sync::Arc, time::Duration};
    let f = fixture();
    let context = f.first.context.clone();
    let removal = request(&f);
    let first = f
        .native
        .inventory_raw_removal_copies(&context, &removal, None, 1, &mut budget())
        .expect("start");
    let cursor = first.continuation.clone().expect("cursor");
    let mut changed = context.clone();
    changed.actor_id = "another-admin".into();
    assert!(
        f.native
            .inventory_raw_removal_copies(&changed, &removal, Some(&cursor), 1, &mut budget())
            .is_err()
    );
    changed = context.clone();
    changed.request.workspace_id = "another-workspace".into();
    assert!(
        f.native
            .inventory_raw_removal_copies(&changed, &removal, Some(&cursor), 1, &mut budget())
            .is_err()
    );
    changed = context.clone();
    changed.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .inventory_raw_removal_copies(&changed, &removal, None, 1, &mut budget())
            .expect_err("admin")
            .code,
        ErrorCode::Unauthorized
    );
    assert!(
        f.native
            .inventory_raw_removal_copies(
                &context,
                &removal,
                Some(&(cursor.clone() + "00")),
                1,
                &mut budget()
            )
            .is_err()
    );
    for max_rows in [0, 1025] {
        assert!(
            f.native
                .inventory_raw_removal_copies(&context, &removal, None, max_rows, &mut budget())
                .is_err()
        );
    }
    let mut tiny = QueryBudget::new(1, 1, Duration::from_secs(5), Default::default());
    assert_eq!(
        f.native
            .inventory_raw_removal_copies(&context, &removal, None, 1, &mut tiny)
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    let foreign = fixture();
    let foreign_request = request(&foreign);
    assert!(
        foreign
            .native
            .inventory_raw_removal_copies(
                &foreign.first.context,
                &foreign_request,
                Some(&cursor),
                1,
                &mut budget()
            )
            .is_err()
    );
    let second = f
        .native
        .request_original_removal(
            &context,
            &BTreeSet::from([f.independent.event.event_id]),
            "independent-removal",
            &mut budget(),
        )
        .expect("another request");
    assert!(
        f.native
            .inventory_raw_removal_copies(&context, &second, Some(&cursor), 1, &mut budget())
            .is_err()
    );
    f.native
        .inventory_raw_removal_copies(&context, &removal, Some(&cursor), 1, &mut budget())
        .expect("unrelated retained history does not change the native snapshot");
    drop(f.native);
    let native = Arc::new(
        NativeService::open_encrypted(
            f.root.path().join("native"),
            "raw-copies",
            [8; 32],
            f.ledger,
            f.keys,
        )
        .expect("rotated token key"),
    );
    assert!(
        native
            .inventory_raw_removal_copies(&context, &removal, Some(&cursor), 1, &mut budget())
            .is_err()
    );
    let fresh = native
        .inventory_raw_removal_copies(&context, &removal, None, 1, &mut budget())
        .expect("fresh cursor after rotation");
    assert_eq!(fresh.receipt, first.receipt);
    native
        .append_event(crate::capture::tests::request(3, "later unrelated capture"))
        .expect("native change");
    assert_eq!(
        native
            .inventory_raw_removal_copies(
                &context,
                &removal,
                fresh.continuation.as_deref(),
                1,
                &mut budget()
            )
            .expect_err("stale native")
            .code,
        ErrorCode::IndexTooStale
    );
    let writer = native.clone();
    let winning = crate::capture::tests::request(4, "capture while inspection runs");
    let accepted = winning.clone();
    page::BEFORE_RETAIN.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            writer.append_event(accepted).expect("winning capture");
        }))
    });
    assert_eq!(
        native
            .inventory_raw_removal_copies(&context, &removal, None, 1, &mut budget())
            .expect_err("native CAS")
            .code,
        ErrorCode::IndexTooStale
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        native
            .load_captured_original(&snapshot, winning.event.event_id)
            .expect("winning original")
            .event,
        winning.event
    );
    native
        .inventory_raw_removal_copies(&context, &removal, None, 1, &mut budget())
        .expect("restart from new native state");
}

#[test]
fn present_raw_inventory_keeps_builds_reclaimed_prefixes_unknown_rows_and_orphan_failures_explicit()
{
    let f = fixture();
    let context = f.first.context.clone();
    let building = f
        .native
        .project_originals(&context, true, 1, &mut budget())
        .expect("partial third generation");
    assert!(!building.caught_up);
    let reclaimed = f
        .native
        .reclaim_raw_generations(&context, 2, &mut budget())
        .expect("partial first GC");
    assert!(!reclaimed.finished);
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let key = format!("{}opaque-address-secret", generation_prefix(&workspace, 1)).into_bytes();
    let unknown_address = crate::encryption::address(&f.native.keyspaces.continuous, &key);
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("opaque unreachable row");
    tx.put(
        &f.native.keyspaces.continuous,
        key,
        b"opaque-value-secret".to_vec(),
    )
    .expect("opaque row");
    tx.commit(Durability::Sync).expect("opaque fixture");
    let removal = request(&f);
    let pages = gather(&f.native, &context, &removal);
    let anchor = &pages[0].witness.snapshot;
    assert_eq!(
        anchor.generations[0].role,
        NativeRawGenerationRole::Reclaiming
    );
    assert_eq!(anchor.generations[0].removed_before, 2);
    assert_eq!(anchor.generations[0].reclamation, reclaimed.copies);
    assert_eq!(anchor.generations[1].role, NativeRawGenerationRole::Active);
    assert_eq!(
        anchor.generations[2].role,
        NativeRawGenerationRole::Building
    );
    let unknown = pages
        .iter()
        .flat_map(|page| &page.witness.rows)
        .find(|row| row.address_digest == unknown_address)
        .expect("unresolved row");
    assert_eq!(unknown.kind, NativeRawCopyKind::Unknown);
    assert_eq!(unknown.source, None);
    let serialized = String::from_utf8(encode(&pages).expect("JSON")).expect("UTF8");
    assert!(
        !serialized.contains("opaque-address-secret")
            && !serialized.contains("opaque-value-secret")
    );
    let keys = f
        .native
        .read_raw_index_key_inventory(
            &context,
            &removal,
            &pages.last().expect("terminal").receipt,
            &mut budget(),
        )
        .expect("selected families and unresolved receipt chain");
    assert!(
        keys.sources
            .values()
            .all(|families| !families.contains_key(&unknown_address))
    );
    f.native
        .verify_native(true)
        .expect("unreachable opaque row is not admitted to reads");
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("missing index control fault");
    tx.delete(&f.native.keyspaces.continuous, state_key(&workspace))
        .expect("lose state");
    for generation in &anchor.generations {
        tx.delete(
            &f.native.keyspaces.continuous,
            generation_key(&workspace, generation.number),
        )
        .expect("lose manifest");
    }
    tx.commit(Durability::Sync).expect("fault");
    assert_eq!(
        f.native
            .inventory_raw_removal_copies(&context, &removal, None, 3, &mut budget())
            .expect_err("orphan rows are not absence")
            .code,
        ErrorCode::IntegrityFailure
    );
}
