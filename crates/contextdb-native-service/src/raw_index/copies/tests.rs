use super::*;
use contextdb_service::{
    CapturePort, CaptureRequest, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};
use contextdb_storage::Entry;
use std::{sync::Arc, time::Duration};

pub(crate) fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

pub(crate) struct Fixture {
    pub native: NativeService,
    pub ledger: Arc<crate::NativeSuppressionLedger>,
    pub keys: Arc<crate::NativeCustodyKeys>,
    pub first: CaptureRequest,
    pub independent: CaptureRequest,
    pub empty: contextdb_service::BackupResponse,
    pub root: tempfile::TempDir,
    pub ledger_directory: tempfile::TempDir,
    pub keys_directory: tempfile::TempDir,
}

pub(crate) fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("native directory");
    let (ledger_directory, ledger) = crate::suppression::tests::authority("raw-copies");
    let (keys_directory, keys) = crate::encryption::tests::authority("raw-copies");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "raw-copies",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let first = crate::capture::tests::request(1, "rawcopysentinelprivate shared original");
    let independent =
        crate::capture::tests::request(2, "rawcopysentinelindependent shared original");
    let empty = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("empty archive");
    native.append_event(first.clone()).expect("capture");
    native
        .append_event(independent.clone())
        .expect("independent capture");
    native
        .project_originals(&first.context, false, 64, &mut budget())
        .expect("first generation");
    native
        .project_originals(&first.context, true, 64, &mut budget())
        .expect("second generation");
    Fixture {
        native,
        ledger,
        keys,
        first,
        independent,
        empty,
        root,
        ledger_directory,
        keys_directory,
    }
}

pub(crate) fn reclaim(f: &Fixture, max_rows: u32) -> RawReclaimProgress {
    f.native
        .reclaim_raw_generations(&f.first.context, max_rows, &mut budget())
        .expect("reclamation")
}

fn all_rows(native: &NativeService) -> Vec<Entry> {
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .scan_prefix(&native.keyspaces.continuous, b"raw/")
        .expect("raw rows")
}

#[test]
fn raw_copy_witnesses_preserve_exact_ciphertexts_through_pruning_reopen_and_old_archives() {
    let f = fixture();
    let context = f.first.context.clone();
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let mut expected = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            generation_prefix(&workspace, 1).as_bytes(),
        )
        .expect("generation rows");
    let key = generation_key(&workspace, 1);
    expected.push(Entry {
        value: snapshot
            .get(&f.native.keyspaces.continuous, &key)
            .expect("manifest")
            .expect("present"),
        key,
    });
    let expected_addresses: BTreeSet<_> = expected
        .iter()
        .map(|row| crate::encryption::address(&f.native.keyspaces.continuous, &row.key))
        .collect();
    let expected_ciphertexts: BTreeMap<_, _> = expected
        .iter()
        .map(|row| {
            (
                crate::encryption::address(&f.native.keyspaces.continuous, &row.key),
                digest_bytes(
                    &snapshot
                        .inner
                        .get(&f.native.keyspaces.continuous, &row.key)
                        .expect("physical")
                        .expect("ciphertext"),
                ),
            )
        })
        .collect();
    drop(snapshot);
    let full = f
        .native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("full archive");
    let first = reclaim(&f, 1);
    assert!(!first.finished);
    let partial = f
        .native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("partial archive");
    let mut receipts = vec![first.copies.expect("first copy receipt")];
    loop {
        let page = reclaim(&f, 3);
        receipts.push(page.copies.expect("copy receipt"));
        if page.finished {
            break;
        }
    }
    let mut observed = BTreeMap::new();
    let mut previous = None;
    let mut removed = 0;
    let mut documents = BTreeSet::new();
    let mut shared = 0;
    for receipt in &receipts {
        let witness = f
            .native
            .read_raw_copy_witness(&context, receipt, &mut budget())
            .expect("independent witness");
        assert_eq!(witness.previous, previous);
        assert_eq!(witness.removed_before, removed);
        removed += witness.row_count();
        previous = Some(receipt.clone());
        let text = String::from_utf8(encode(&witness).expect("JSON")).expect("UTF8");
        assert!(!text.contains("rawcopysentinelprivate"));
        assert!(!text.contains("rawcopysentinelindependent"));
        for row in witness.rows {
            let version = row.version.as_ref().expect("encrypted observation");
            assert_eq!(version.authority_id, f.keys.authority_id());
            assert_eq!(
                version.ciphertext_digest,
                expected_ciphertexts[&row.address_digest]
            );
            if row.kind == NativeRawCopyKind::Document {
                documents.insert(row.source.expect("source"));
            }
            if row.kind == NativeRawCopyKind::SharedMetadata {
                assert!(row.source.is_none());
                shared += 1;
            }
            assert!(
                observed.insert(row.address_digest.clone(), row).is_none(),
                "pages do not repeat rows"
            );
        }
    }
    assert_eq!(
        observed.keys().cloned().collect::<BTreeSet<_>>(),
        expected_addresses
    );
    assert_eq!(
        documents,
        BTreeSet::from([f.first.event.event_id, f.independent.event.event_id])
    );
    assert!(shared >= 2, "policy and scope rows remain shared");
    let mut cursor = None;
    let mut matched = BTreeSet::new();
    loop {
        let page = f
            .keys
            .key_catalog_page(cursor.as_deref(), 256, &mut budget())
            .expect("key catalog");
        for key in page.entries {
            if observed
                .get(&key.address_digest)
                .is_some_and(|row| row.version.as_ref().expect("version").key_id == key.key_id)
            {
                matched.insert(key.address_digest);
            }
        }
        cursor = page.continuation;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        matched, expected_addresses,
        "all observed ciphertext keys were allocated"
    );
    let request = f
        .native
        .request_original_removal(
            &context,
            &BTreeSet::from([f.first.event.event_id]),
            "forget",
            &mut budget(),
        )
        .expect("request after old GC");
    f.native
        .prepare_original_removal_sources(
            &context,
            &request,
            &BTreeSet::from([f.first.event.event_id]),
            &mut budget(),
        )
        .expect("prepare");
    f.native
        .maintain_custody(&context, 64, &mut budget())
        .expect("custody");
    f.native
        .project_originals(&context, true, 64, &mut budget())
        .expect("clean generation");
    while !reclaim(&f, 64).finished {}
    f.native
        .prune_original_sources(
            &context,
            &request,
            &BTreeSet::from([f.first.event.event_id]),
            &mut budget(),
        )
        .expect("prune source");
    f.native.verify_native(true).expect("pruned native closure");
    let last = receipts.last().expect("last");
    let retained = f
        .native
        .read_raw_copy_witness(&context, last, &mut budget())
        .expect("witness after pruning");
    let ledger_id = f.ledger.authority_id();
    let ledger_path = f.ledger.path.clone();
    let keys_id = f.keys.authority_id();
    let keys_path = f.keys.path.clone();
    drop(f.native);
    drop(f.ledger);
    drop(f.keys);
    let ledger = crate::NativeSuppressionLedger::open(ledger_path, "raw-copies", ledger_id)
        .expect("reopen independent authority");
    let keys = crate::NativeCustodyKeys::open(
        keys_path,
        "raw-copies",
        keys_id,
        crate::CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([79; 32])).expect("master"),
    )
    .expect("reopen key authority");
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "raw-copies",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen native");
    assert_eq!(
        native
            .read_raw_copy_witness(&context, last, &mut budget())
            .expect("read after reopen"),
        retained
    );
    drop(native);
    for (name, archive) in [("empty", f.empty), ("full", full), ("partial", partial)] {
        let target = NativeService::open_encrypted(
            f.root.path().join(name),
            "raw-copies",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restore target");
        target
            .restore_backup(RestoreBackupRequest {
                context: context.clone(),
                bytes: archive.bytes,
                digest: archive.digest,
                format: archive.format,
            })
            .expect("restore actual encrypted archive");
        assert_eq!(
            target
                .read_raw_copy_witness(&context, last, &mut budget())
                .expect("old restore retains current witness"),
            retained
        );
        target.verify_native(true).expect("restored native closure");
        if name == "partial" {
            assert!(
                target
                    .reclaim_raw_generations(&context, 64, &mut budget())
                    .expect("continue archived page")
                    .finished
            );
            target.verify_native(true).expect("restored page chain");
        }
    }
    drop((ledger, keys, f.root, f.ledger_directory, f.keys_directory));
}

#[test]
fn raw_copy_authority_budget_and_forged_routes_cannot_delete_or_disclose() {
    let f = fixture();
    let rows = all_rows(&f.native);
    let mut tiny = QueryBudget::new(1, 1, Duration::from_secs(5), Default::default());
    assert!(
        f.native
            .reclaim_raw_generations(&f.first.context, 1024, &mut tiny)
            .is_err()
    );
    assert_eq!(all_rows(&f.native), rows);
    let receipt = reclaim(&f, 1).copies.expect("receipt");
    let mut denied = f.first.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .read_raw_copy_witness(&denied, &receipt, &mut budget())
            .expect_err("admin required")
            .code,
        ErrorCode::Unauthorized
    );
    denied = f.first.context.clone();
    denied.request.workspace_id = "another-workspace".into();
    assert!(
        f.native
            .read_raw_copy_witness(&denied, &receipt, &mut budget())
            .is_err()
    );
    let mut forged = receipt.clone();
    forged.digest = "00".repeat(32);
    assert!(
        f.native
            .read_raw_copy_witness(&f.first.context, &forged, &mut budget())
            .is_err()
    );
    let before = all_rows(&f.native);
    let route = before
        .iter()
        .find(|row| {
            std::str::from_utf8(&row.key)
                .expect("key")
                .contains("/00000000000000000001/route/")
                && decode::<ObservationId>(&row.value, "route")
                    .is_ok_and(|id| id == f.first.event.event_id)
        })
        .expect("first source route");
    let mut tx = f.native.engine.begin_write().expect("fault");
    tx.put(
        &f.native.keyspaces.continuous,
        route.key.clone(),
        encode(&f.independent.event.event_id).expect("forged owner"),
    )
    .expect("put");
    tx.commit(Durability::Sync).expect("fault commit");
    let corrupted = all_rows(&f.native);
    assert_eq!(
        f.native
            .reclaim_raw_generations(&f.first.context, 1024, &mut budget())
            .expect_err("route ownership differs")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(all_rows(&f.native), corrupted);
}

#[test]
fn raw_copy_legacy_prefix_is_explicit_and_concurrent_native_changes_prevent_acceptance() {
    let mut f = fixture();
    f.native.suppression = None; // Execute the original untracked GC wire profile.
    let legacy = reclaim(&f, 1);
    assert!(legacy.copies.is_none());
    f.native.suppression = Some(f.ledger.clone());
    let tracked = reclaim(&f, 1);
    let witness = f
        .native
        .read_raw_copy_witness(
            &f.first.context,
            tracked.copies.as_ref().expect("tracked"),
            &mut budget(),
        )
        .expect("witness");
    assert_eq!(witness.removed_before, 1);
    assert!(
        witness.previous.is_none(),
        "missing legacy prefix is never invented"
    );
    f.native
        .verify_native(true)
        .expect("mixed legacy and tracked reclamation");
    let native = Arc::new(f.native);
    let other = native.clone();
    gc::BEFORE_COPY_PUBLICATION.with(|hook| {
        hook.replace(Some(Box::new(move || {
            other
                .append_event(crate::capture::tests::request(3, "concurrent capture"))
                .expect("concurrent commit");
        })))
    });
    let before = all_rows(&native);
    assert_eq!(
        native
            .reclaim_raw_generations(&f.first.context, 1, &mut budget())
            .expect_err("snapshot changed")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        all_rows(&native),
        before,
        "CAS failure cannot delete index rows"
    );
    native
        .verify_native(true)
        .expect("recover after concurrency");
}
