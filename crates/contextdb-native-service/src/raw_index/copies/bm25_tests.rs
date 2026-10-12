//! Accepted text, exact statistics, retained publication and observed copy closure.

use super::tests::budget;
use super::*;
use contextdb_service::{
    CapturePort, CaptureRequest, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};
use std::sync::Arc;

struct Fixture {
    native: NativeService,
    ledger: Arc<crate::NativeSuppressionLedger>,
    keys: Arc<crate::NativeCustodyKeys>,
    first: CaptureRequest,
    independent: CaptureRequest,
    root: tempfile::TempDir,
    _ledger_directory: tempfile::TempDir,
    _keys_directory: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("native directory");
    let (ledger_directory, ledger) = crate::suppression::tests::authority("raw-bm25-copies");
    let (keys_directory, keys) = crate::encryption::tests::authority("raw-bm25-copies");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "raw-bm25-copies",
        [11; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native");
    let first = crate::capture::tests::request(1, "privatebm25sentinel privatebm25sentinel shared");
    let independent = crate::capture::tests::request(2, "independentbm25sentinel shared shared");
    native
        .append_event(first.clone())
        .expect("first accepted original");
    native
        .append_event(independent.clone())
        .expect("independent accepted original");
    native
        .project_originals_bm25(&first.context, false, 64, &mut budget())
        .expect("explicit BM25 generation");
    Fixture {
        native,
        ledger,
        keys,
        first,
        independent,
        root,
        _ledger_directory: ledger_directory,
        _keys_directory: keys_directory,
    }
}

fn replace(native: &NativeService, key: &[u8], bytes: Option<&[u8]>) {
    let mut tx = native.engine.begin_write().expect("fault transaction");
    if let Some(bytes) = bytes {
        tx.put(&native.keyspaces.continuous, key.to_vec(), bytes.to_vec())
            .expect("replace row");
    } else {
        tx.delete(&native.keyspaces.continuous, key.to_vec())
            .expect("remove row");
    }
    tx.commit(Durability::Sync).expect("fault commit");
}

fn check_raw(native: &NativeService) -> ServiceResult<()> {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("verification snapshot");
    native.verify_raw_index_records(&snapshot)
}

#[test]
fn bm25_reconstructs_literal_tf_df_and_refuses_joint_profile_or_prefix_retargeting() {
    let f = fixture();
    let workspace = digest_bytes(f.first.context.request.workspace_id.as_bytes());
    let key = bm25::document_key(&workspace, 1, f.first.event.event_id);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("statistics snapshot");
    let bytes = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("document read")
        .expect("statistical document");
    let document: bm25::Bm25Document = decode(&bytes, "test statistics").expect("statistics");
    assert_eq!(document.token_count, 3);
    assert_eq!(document.term_frequencies["privatebm25sentinel"], 2);
    assert_eq!(document.term_frequencies["shared"], 1);
    assert!(document.omission.is_none());
    let corpus_key = bm25::corpus_key(&workspace, 1, &document.policy_domain);
    let corpus: bm25::DomainStatistics = f
        .native
        .raw_value(&snapshot, &corpus_key)
        .expect("corpus read")
        .expect("shared corpus");
    assert_eq!(
        (
            corpus.documents,
            corpus.total_tokens,
            corpus.omitted_documents
        ),
        (2, 6, 0)
    );
    let df_key = bm25::df_key(&workspace, 1, &document.policy_domain, "shared");
    let df_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &df_key)
        .expect("DF read")
        .expect("shared DF");
    let df: bm25::TermStatistics = decode(&df_bytes, "test DF").expect("DF");
    assert_eq!((df.term.as_str(), df.document_frequency), ("shared", 2));
    let generation_key = generation_key(&workspace, 1);
    let generation_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &generation_key)
        .expect("manifest read")
        .expect("generation manifest");
    let generation: Generation = decode(&generation_bytes, "test generation").expect("generation");
    let publication = snapshot
        .scan_prefix(&f.native.keyspaces.events, b"")
        .expect("native publications")
        .into_iter()
        .map(|row| {
            decode::<crate::StoredEvent>(&row.value, "test publication").expect("publication")
        })
        .find(|event| event.operation == bm25::OPERATION)
        .expect("distinct accepted BM25 publication");
    let receipt_key = publication.request_digest.as_bytes().to_vec();
    let receipt_bytes = snapshot
        .get(&f.native.keyspaces.idempotency, &receipt_key)
        .expect("retained receipt read")
        .expect("accepted projection receipt");
    let bm25_prefix = format!("{}bm25/", generation_prefix(&workspace, 1));
    let statistics_rows = snapshot
        .scan_prefix(&f.native.keyspaces.continuous, bm25_prefix.as_bytes())
        .expect("statistical rows");
    drop(snapshot);
    f.native
        .verify_native(true)
        .expect("actual accepted statistics and native closure");

    // Preserve the TF sum while changing which term occurred: shape checks alone
    // cannot establish the statistics of this accepted literal original.
    let mut changed = document;
    changed
        .term_frequencies
        .insert("privatebm25sentinel".into(), 1);
    changed.term_frequencies.insert("shared".into(), 2);
    replace(
        &f.native,
        &key,
        Some(&encode(&changed).expect("changed TF")),
    );
    assert!(
        check_raw(&f.native).is_err(),
        "forged shape-valid TF is not an accepted original"
    );
    replace(&f.native, &key, Some(&bytes));
    let mut changed = df;
    changed.document_frequency = 1;
    replace(
        &f.native,
        &df_key,
        Some(&encode(&changed).expect("changed DF")),
    );
    assert!(
        check_raw(&f.native).is_err(),
        "shape-valid DF is reconstructed across both sources"
    );
    replace(&f.native, &df_key, Some(&df_bytes));
    replace(&f.native, &df_key, None);
    assert!(
        check_raw(&f.native).is_err(),
        "a required sparse DF row cannot disappear"
    );
    replace(&f.native, &df_key, Some(&df_bytes));

    let mut changed = generation.clone();
    changed.bm25 = None;
    replace(
        &f.native,
        &generation_key,
        Some(&encode(&changed).expect("stripped profile")),
    );
    for row in &statistics_rows {
        replace(&f.native, &row.key, None);
    }
    let error = check_raw(&f.native)
        .expect_err("profile and every statistical row cannot jointly become legacy");
    assert!(error.message.contains("accepted projection prefix"));
    for row in &statistics_rows {
        replace(&f.native, &row.key, Some(&row.value));
    }
    replace(&f.native, &generation_key, Some(&generation_bytes));
    let mut changed = generation.clone();
    changed.through += 1;
    replace(
        &f.native,
        &generation_key,
        Some(&encode(&changed).expect("future prefix")),
    );
    let error = check_raw(&f.native)
        .expect_err("unchanged outbox rows do not authorize an unpublished prefix");
    assert!(error.message.contains("accepted projection prefix"));
    replace(&f.native, &generation_key, Some(&generation_bytes));
    let mut changed = generation;
    changed.bm25.as_mut().expect("profile").k1_millis = 900;
    replace(
        &f.native,
        &generation_key,
        Some(&encode(&changed).expect("different method")),
    );
    assert!(
        check_raw(&f.native).is_err(),
        "a fixed publication cannot be retyped as a different method"
    );
    replace(&f.native, &generation_key, Some(&generation_bytes));
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("receipt fault transaction");
    tx.delete(&f.native.keyspaces.idempotency, receipt_key.clone())
        .expect("remove accepted receipt");
    tx.commit(Durability::Sync).expect("fault commit");
    assert!(
        check_raw(&f.native)
            .expect_err("accepted declaration cannot lose its digest-bound receipt")
            .message
            .contains("projection receipt is absent")
    );
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("receipt restore transaction");
    tx.put(&f.native.keyspaces.idempotency, receipt_key, receipt_bytes)
        .expect("restore accepted receipt");
    tx.commit(Durability::Sync).expect("restore commit");
    check_raw(&f.native).expect("restored statistics");
}

#[test]
fn bm25_gc_inventory_keeps_documents_owned_aggregates_shared_and_declaration_after_reopen() {
    let f = fixture();
    let context = f.first.context.clone();
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("copy snapshot");
    let mut expected = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            generation_prefix(&workspace, 1).as_bytes(),
        )
        .expect("all generation rows");
    let first_address = crate::encryption::address(
        &f.native.keyspaces.continuous,
        &bm25::document_key(&workspace, 1, f.first.event.event_id),
    );
    let independent_address = crate::encryption::address(
        &f.native.keyspaces.continuous,
        &bm25::document_key(&workspace, 1, f.independent.event.event_id),
    );
    let shared: BTreeSet<_> = expected
        .iter()
        .filter(|row| {
            row.key
                .starts_with(format!("{}bm25/corpus/", generation_prefix(&workspace, 1)).as_bytes())
                || row
                    .key
                    .starts_with(format!("{}bm25/df/", generation_prefix(&workspace, 1)).as_bytes())
        })
        .map(|row| crate::encryption::address(&f.native.keyspaces.continuous, &row.key))
        .collect();
    assert_eq!(
        shared.len(),
        4,
        "one domain corpus and three distinct term DFs"
    );
    let manifest_key = generation_key(&workspace, 1);
    expected.push(contextdb_storage::Entry {
        value: snapshot
            .get(&f.native.keyspaces.continuous, &manifest_key)
            .expect("generation read")
            .expect("generation manifest"),
        key: manifest_key,
    });
    let expected_addresses: BTreeSet<_> = expected
        .iter()
        .map(|row| crate::encryption::address(&f.native.keyspaces.continuous, &row.key))
        .collect();
    let expected_versions: BTreeMap<_, _> = expected
        .iter()
        .map(|row| {
            let ciphertext = snapshot
                .inner
                .get(&f.native.keyspaces.continuous, &row.key)
                .expect("physical read")
                .expect("encrypted copy");
            (
                crate::encryption::address(&f.native.keyspaces.continuous, &row.key),
                (digest_bytes(&ciphertext), digest_bytes(&row.value)),
            )
        })
        .collect();
    drop(snapshot);
    let archive = f
        .native
        .create_backup(CreateBackupRequest {
            context: context.clone(),
        })
        .expect("encrypted BM25 archive");
    f.native
        .project_originals(&context, true, 64, &mut budget())
        .expect("separate legacy generation retires BM25");
    let mut observations = BTreeMap::new();
    let mut receipts = Vec::new();
    loop {
        let progress = f
            .native
            .reclaim_raw_generations(&context, 3, &mut budget())
            .expect("bounded GC page");
        assert_eq!(progress.generation, Some(1));
        let receipt = progress.copies.expect("independent observation");
        let witness = f
            .native
            .read_raw_copy_witness(&context, &receipt, &mut budget())
            .expect("copy witness");
        let encoded = String::from_utf8(encode(&witness).expect("witness JSON")).expect("UTF8");
        assert!(!encoded.contains("privatebm25sentinel"));
        for row in witness.rows {
            let version = row
                .version
                .as_ref()
                .expect("authenticated encrypted custody");
            assert_eq!(version.authority_id, f.keys.authority_id());
            assert_eq!(
                (&version.ciphertext_digest, &row.value_digest),
                (
                    &expected_versions[&row.address_digest].0,
                    &expected_versions[&row.address_digest].1
                )
            );
            if row.address_digest == first_address {
                assert_eq!(
                    (row.kind, row.source),
                    (NativeRawCopyKind::Document, Some(f.first.event.event_id))
                );
            }
            if row.address_digest == independent_address {
                assert_eq!(
                    (row.kind, row.source),
                    (
                        NativeRawCopyKind::Document,
                        Some(f.independent.event.event_id)
                    )
                );
            }
            if shared.contains(&row.address_digest) {
                assert_eq!(
                    (row.kind, row.source),
                    (NativeRawCopyKind::SharedMetadata, None)
                );
            }
            assert!(
                observations
                    .insert(row.address_digest.clone(), row)
                    .is_none()
            );
        }
        receipts.push(receipt);
        if progress.finished {
            break;
        }
    }
    assert_eq!(
        observations.keys().cloned().collect::<BTreeSet<_>>(),
        expected_addresses
    );
    f.native
        .verify_native(true)
        .expect("fully reclaimed statistical generation");
    let removal = f
        .native
        .request_original_removal(
            &context,
            &BTreeSet::from([f.first.event.event_id]),
            "bm25-key-inventory",
            &mut budget(),
        )
        .expect("source removal request");
    let inventory = f
        .native
        .read_reclaimed_raw_key_inventory(&context, &removal, &mut budget())
        .expect("source-owned key families");
    assert!(inventory.sources[&f.first.event.event_id].contains_key(&first_address));
    assert!(!inventory.sources[&f.first.event.event_id].contains_key(&independent_address));
    assert!(
        shared
            .iter()
            .all(|address| !inventory.sources[&f.first.event.event_id].contains_key(address))
    );
    assert!(
        !inventory.witnesses.is_empty(),
        "shared obligations remain in the retained page chain"
    );

    let native_path = f.root.path().join("native");
    drop(f.native);
    let cold = NativeService::open_encrypted(
        native_path,
        "raw-bm25-copies",
        [12; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold native after GC");
    cold.verify_native(true)
        .expect("retained projection receipts survive cold reopen");
    assert_eq!(
        cold.read_raw_copy_witness(&context, receipts.last().expect("last"), &mut budget())
            .expect("cold retained witness")
            .rows
            .last()
            .expect("manifest")
            .kind,
        NativeRawCopyKind::Manifest
    );
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("retained declaration snapshot");
    let mut manifest = cold.raw_manifest(&snapshot).expect("native manifest");
    assert!(manifest.features.remove(bm25::FEATURE));
    manifest.checksum = crate::manifest_checksum(&manifest).expect("checksum");
    drop(snapshot);
    let mut tx = cold
        .engine
        .begin_write()
        .expect("feature fault transaction");
    tx.put(
        &cold.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("stripped feature"),
    )
    .expect("strip feature");
    tx.commit(Durability::Sync).expect("fault commit");
    assert!(
        check_raw(&cold)
            .expect_err(
                "accepted BM25 history requires its feature even without remaining BM25 rows"
            )
            .message
            .contains("format feature")
    );
    drop(cold);
    let restored = NativeService::open_encrypted(
        f.root.path().join("restored"),
        "raw-bm25-copies",
        [13; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("fresh restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context,
            bytes: archive.bytes,
            digest: archive.digest,
            format: archive.format,
        })
        .expect("actual encrypted BM25 backup restore");
    restored
        .verify_native(true)
        .expect("restored source, profile and shared aggregates");
}
