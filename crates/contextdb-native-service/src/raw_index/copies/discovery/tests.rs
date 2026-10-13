use super::*;
use crate::raw_index::copies::tests::{budget, fixture, reclaim};
use contextdb_service::{
    CapturePort, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};
use std::time::Duration;

fn request(f: &super::super::tests::Fixture, key: &str) -> NativeRemovalRequestReceipt {
    f.native
        .request_original_removal(
            &f.first.context,
            &BTreeSet::from([f.first.event.event_id]),
            key,
            &mut budget(),
        )
        .expect("removal request")
}

fn gather(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
    max_events: u32,
) -> Vec<NativeRawRemovalCopy> {
    let mut continuation = None;
    let mut previous = 0;
    let mut copies = Vec::new();
    for _ in 0..256 {
        let page = native
            .read_raw_removal_copies(
                context,
                request,
                continuation.as_deref(),
                max_events,
                &mut budget(),
            )
            .expect("bounded page");
        assert!(page.examined_events <= max_events);
        assert!(page.scanned_through > previous || page.continuation.is_none());
        previous = page.scanned_through;
        copies.extend(page.copies);
        continuation = page.continuation;
        if continuation.is_none() {
            assert_eq!(previous, page.observation_sequence);
            return copies;
        }
    }
    panic!("fixture discovery failed to reach its frontier");
}

#[test]
fn raw_copy_discovery_selects_descendants_and_keeps_key_families_after_pruning_and_restore() {
    let f = fixture();
    let context = f.first.context.clone();
    let mut child = crate::capture::tests::request(3, "rawcopydescendantsecret");
    child.event.kind = EventKind::MessageEdited;
    child.event.supersedes_event_id = Some(f.first.event.event_id);
    child.event.parent_event_ids.insert(f.first.event.event_id);
    f.native.append_event(child.clone()).expect("descendant");
    f.native
        .project_originals(&context, false, 64, &mut budget())
        .expect("advance second generation");
    f.native
        .project_originals(&context, true, 64, &mut budget())
        .expect("third generation");
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("archive before witnesses");
    for _ in 0..2 {
        while !reclaim(&f, 3).finished {}
    }
    let removal = request(&f, "remove-after-index-gc");
    let copies = gather(&f.native, &context, &removal, 1);
    let owners: BTreeSet<_> = copies
        .iter()
        .flat_map(|copy| copy.rows.iter().filter_map(|row| row.source))
        .collect();
    assert_eq!(
        owners,
        BTreeSet::from([f.first.event.event_id, child.event.event_id])
    );
    assert!(copies.iter().any(|copy| {
        copy.rows
            .iter()
            .any(|row| row.kind == NativeRawCopyKind::SharedMetadata && row.source.is_none())
    }));
    assert!(
        !String::from_utf8(encode(&copies).expect("copy JSON"))
            .expect("UTF8")
            .contains("rawcopydescendantsecret")
    );
    let inventory = f
        .native
        .read_reclaimed_raw_key_inventory(&context, &removal, &mut budget())
        .expect("historical raw keys");
    assert_eq!(
        inventory.sources.keys().copied().collect::<BTreeSet<_>>(),
        owners
    );
    for addresses in inventory.sources.values() {
        assert!(!addresses.is_empty());
        for (address, family) in addresses {
            assert!(!family.allocations.is_empty());
            assert!(!family.observed_versions.is_empty());
            for observed in &family.observed_versions {
                assert!(
                    family
                        .allocations
                        .iter()
                        .any(|key| key.address_digest == *address && key.key_id == observed.key_id)
                );
            }
        }
    }
    let frontier = inventory.observation_frontier();
    let decisions = f
        .native
        .retain_reclaimed_raw_key_removal(&context, &removal, &frontier, &mut budget())
        .expect("retain decisions before pruning");
    assert!(!decisions.dispositions.is_empty());
    let first_page = f
        .native
        .read_raw_removal_copies(&context, &removal, None, 1, &mut budget())
        .expect("cursor start");
    assert!(
        first_page.copies.is_empty(),
        "an unrelated registration page is not completion"
    );
    let cursor = first_page.continuation.expect("cursor");
    let expected_next = f
        .native
        .read_raw_removal_copies(&context, &removal, Some(&cursor), 1, &mut budget())
        .expect("second page");
    drop(f.native);
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "raw-copies",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual reopen");
    assert_eq!(
        native
            .read_raw_removal_copies(&context, &removal, Some(&cursor), 1, &mut budget())
            .expect("cursor survives reopen"),
        expected_next
    );
    native
        .prepare_original_removal_sources(&context, &removal, &owners, &mut budget())
        .expect("prepare roots and descendants");
    native
        .maintain_custody(&context, 64, &mut budget())
        .expect("custody");
    native
        .project_originals(&context, true, 64, &mut budget())
        .expect("clean generation");
    while !native
        .reclaim_raw_generations(&context, 64, &mut budget())
        .expect("reclaim third generation")
        .finished
    {}
    native
        .prune_original_sources(&context, &removal, &owners, &mut budget())
        .expect("prune original bodies");
    let complete = native
        .read_reclaimed_raw_key_inventory(&context, &removal, &mut budget())
        .expect("key families after pruning");
    assert_eq!(
        native
            .read_reclaimed_raw_key_removal(
                &context,
                &removal,
                &frontier,
                &decisions.receipt,
                &mut budget()
            )
            .expect("exact decisions after later observations and pruning"),
        decisions
    );
    for (owner, addresses) in &inventory.sources {
        for (address, family) in addresses {
            assert_eq!(&complete.sources[owner][address], family);
        }
    }
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
    native.verify_native(true).expect("native closure");
    let final_start = native
        .read_raw_removal_copies(&context, &removal, None, 1, &mut budget())
        .expect("fresh cursor");
    let final_cursor = final_start.continuation.expect("final cursor");
    let final_next = native
        .read_raw_removal_copies(&context, &removal, Some(&final_cursor), 1, &mut budget())
        .expect("next");
    for (name, archive) in [("empty", f.empty), ("old", old)] {
        let target = NativeService::open_encrypted(
            f.root.path().join(name),
            "raw-copies",
            [7; 32],
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
            .expect("encrypted restore");
        assert_eq!(
            target
                .read_raw_removal_copies(&context, &removal, Some(&final_cursor), 1, &mut budget())
                .expect("cursor on older native"),
            final_next
        );
        let restored = target
            .read_reclaimed_raw_key_inventory(&context, &removal, &mut budget())
            .expect("all retained historical keys");
        assert_eq!(restored.sources, complete.sources);
        assert_eq!(restored.witnesses, complete.witnesses);
        assert_eq!(restored.observation_digest, complete.observation_digest);
        assert_eq!(
            target
                .read_reclaimed_raw_key_removal(
                    &context,
                    &removal,
                    &frontier,
                    &decisions.receipt,
                    &mut budget()
                )
                .expect("exact decisions after encrypted restore"),
            decisions
        );
    }
}

#[test]
fn raw_copy_discovery_cursors_bind_request_authority_policy_token_and_frontier() {
    let f = fixture();
    let removal = request(&f, "remove");
    let first = f
        .native
        .read_raw_removal_copies(&f.first.context, &removal, None, 1, &mut budget())
        .expect("start");
    let token = first.continuation.expect("cursor");
    let mut forged = token.clone();
    forged.push('0');
    assert!(
        f.native
            .read_raw_removal_copies(&f.first.context, &removal, Some(&forged), 1, &mut budget())
            .is_err()
    );
    let mut changed = f.first.context.clone();
    changed.actor_id = "another-admin".into();
    assert!(
        f.native
            .read_raw_removal_copies(&changed, &removal, Some(&token), 1, &mut budget())
            .is_err()
    );
    changed = f.first.context.clone();
    changed.request.workspace_id = "another-workspace".into();
    assert!(
        f.native
            .read_raw_removal_copies(&changed, &removal, Some(&token), 1, &mut budget())
            .is_err()
    );
    changed = f.first.context.clone();
    changed.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .read_raw_removal_copies(&changed, &removal, Some(&token), 1, &mut budget())
            .expect_err("admin")
            .code,
        ErrorCode::Unauthorized
    );
    let mut tiny = QueryBudget::new(1, 1, Duration::from_secs(5), Default::default());
    assert_eq!(
        f.native
            .read_raw_removal_copies(&f.first.context, &removal, None, 1, &mut tiny)
            .expect_err("budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    let other = fixture();
    let other_removal = request(&other, "remove");
    assert!(
        other
            .native
            .read_raw_removal_copies(
                &other.first.context,
                &other_removal,
                Some(&token),
                1,
                &mut budget()
            )
            .is_err()
    );
    let second = f
        .native
        .request_original_removal(
            &f.first.context,
            &BTreeSet::from([f.independent.event.event_id]),
            "independent-request",
            &mut budget(),
        )
        .expect("different request");
    assert!(
        f.native
            .read_raw_removal_copies(&f.first.context, &second, Some(&token), 1, &mut budget())
            .is_err()
    );
    assert_eq!(
        f.native
            .read_raw_removal_copies(&f.first.context, &removal, Some(&token), 1, &mut budget())
            .expect_err("frontier growth")
            .code,
        ErrorCode::IndexTooStale
    );
    let fresh = f
        .native
        .read_raw_removal_copies(&f.first.context, &removal, None, 1, &mut budget())
        .expect("fresh")
        .continuation
        .expect("fresh token");
    drop(f.native);
    let rotated = NativeService::open_encrypted(
        f.root.path().join("native"),
        "raw-copies",
        [8; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("rotated token key");
    assert!(
        rotated
            .read_raw_removal_copies(&f.first.context, &removal, Some(&fresh), 1, &mut budget())
            .is_err()
    );
    assert!(
        gather(&rotated, &f.first.context, &removal, 64).is_empty(),
        "no GC observations is not a claim about active copies"
    );
}

#[test]
fn raw_copy_discovery_preserves_unknown_rows_and_untracked_legacy_prefixes() {
    let mut f = fixture();
    f.native.suppression = None;
    assert!(reclaim(&f, 1).copies.is_none());
    f.native.suppression = Some(f.ledger.clone());
    let workspace = digest_bytes(f.first.context.request.workspace_id.as_bytes());
    let mut tx = f.native.engine.begin_write().expect("legacy opaque row");
    let opaque = format!("{}opaque-legacy-address", generation_prefix(&workspace, 1)).into_bytes();
    tx.put(
        &f.native.keyspaces.continuous,
        opaque.clone(),
        b"unknown-legacy-secret".to_vec(),
    )
    .expect("opaque row");
    tx.commit(Durability::Sync).expect("legacy fixture");
    let removal = request(&f, "remove");
    assert!(reclaim(&f, 1024).finished);
    let copies = gather(&f.native, &f.first.context, &removal, 64);
    assert!(copies.iter().any(|copy| copy.untracked_prefix));
    assert!(
        copies
            .iter()
            .flat_map(|copy| &copy.rows)
            .any(|row| row.kind == NativeRawCopyKind::Unknown
                && row.address_digest
                    == crate::encryption::address(&f.native.keyspaces.continuous, &opaque))
    );
    let serialized = String::from_utf8(encode(&copies).expect("JSON")).expect("UTF8");
    assert!(!serialized.contains("unknown-legacy-secret"));
    assert!(!serialized.contains("opaque-legacy-address"));
    let keys = f
        .native
        .read_reclaimed_raw_key_inventory(&f.first.context, &removal, &mut budget())
        .expect("known source keys");
    assert!(
        !keys.witnesses.is_empty(),
        "unresolved observations remain recoverable"
    );
    assert!(
        keys.sources
            .values()
            .all(|rows| !rows.contains_key(&crate::encryption::address(
                &f.native.keyspaces.continuous,
                &opaque
            )))
    );
}
