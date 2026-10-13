//! Fault only the format declaration; accepted captures and their owner tags stay intact.

use crate::router_trace::hybrid::HYBRID_FEATURE;
use crate::router_trace::hybrid::segments::SEGMENTED_HYBRID_FEATURE;
use crate::{META_MANIFEST_KEY, Manifest, NativeService, decode, encode, manifest_checksum};
use contextdb_service::{AuthenticatedRequestContext, ErrorCode};
use contextdb_storage::{
    Durability, ReadSnapshot, ScanPageRequest, StorageEngine, WriteTransaction,
};

pub(super) fn assert_feature_retention(
    native: &NativeService,
    _context: &AuthenticatedRequestContext,
) {
    let snapshot = native
        .engine
        .begin_read(contextdb_storage::SnapshotSelector::Latest)
        .expect("current encrypted feature fixture");
    let page = snapshot
        .scan_prefix_page(
            &native.keyspaces.meta,
            ScanPageRequest {
                prefix: META_MANIFEST_KEY,
                start_after: None,
                max_entries: 1,
                max_bytes: crate::MAX_JSON_BYTES + META_MANIFEST_KEY.len() + 256,
            },
        )
        .expect("bounded actual manifest row");
    let original = page
        .entries
        .into_iter()
        .next()
        .filter(|row| row.key == META_MANIFEST_KEY)
        .expect("exact native manifest key")
        .value;
    assert!(original.len() <= crate::MAX_JSON_BYTES);
    let mut manifest: Manifest =
        decode(&original, "actual segmented feature manifest").expect("valid native manifest");
    assert!(manifest.features.contains(HYBRID_FEATURE));
    assert!(
        manifest
            .features
            .contains(crate::raw_index::dense::graph::segments::types::FEATURE)
    );
    assert!(manifest.features.remove(SEGMENTED_HYBRID_FEATURE));
    manifest.checksum = manifest_checksum(&manifest).expect("ordinary metadata checksum");
    crate::validate_manifest(&manifest, &native.database_id)
        .expect("ordinary format remains valid with only the new marker stripped");
    drop(snapshot);

    let stripped = encode(&manifest).expect("bounded modified manifest");
    replace_manifest(native, stripped);
    let refused = native.verify_native(true);
    // Always restore the exact saved bytes before asserting the fault outcome.
    replace_manifest(native, original);
    assert!(
        native
            .verify_native(true)
            .expect("restored actual archive")
            .valid
    );

    let error = refused.expect_err("accepted segmented recovery requires its format marker");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert!(
        error
            .message
            .contains("capture recovery segmented hybrid feature"),
        "accepted recovery marker must reject the stripped declaration: {error:?}"
    );
}

fn replace_manifest(native: &NativeService, bytes: Vec<u8>) {
    assert!(bytes.len() <= crate::MAX_JSON_BYTES);
    let mut tx = native
        .engine
        .begin_write()
        .expect("explicit metadata fault transaction");
    tx.put(&native.keyspaces.meta, META_MANIFEST_KEY.to_vec(), bytes)
        .expect("replace only the bounded format row");
    tx.commit(Durability::Sync)
        .expect("durable fixture metadata replacement");
}
