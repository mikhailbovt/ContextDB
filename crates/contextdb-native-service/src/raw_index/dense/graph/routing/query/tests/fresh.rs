//! A genuine old-generation tag cannot authorize a different fresh plan.
use super::*;

#[test]
fn genuine_old_generation_document_is_rejected_by_complete_fresh_commitment() {
    let f = fixture();
    let source = capture(
        &f,
        90,
        "Fresh sapphire orbital source with two actual generations",
    );
    let old_target = project(&f, &f.encoder);
    assert!(old_target.caught_up);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let old_key = document_key(&workspace, 1, source);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old accepted document");
    let old_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &old_key)
        .expect("old point read")
        .expect("actual old tagged plan");
    let old: DenseDocument = decode(&old_bytes, "old genuine source plan").expect("old typed doc");
    drop(snapshot);
    let raw = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut budget())
        .expect("genuine second raw generation");
    assert_eq!(raw.generation, 2);
    assert!(raw.caught_up);
    let target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 3, &mut budget())
        .expect("genuine second-generation partial dense receipt");
    assert_eq!(target.sources, 3);
    assert!(!target.caught_up);
    f.native
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: 2,
                target,
            },
            &mut budget(),
        )
        .expect("actual second-generation prefix");
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 2, &mut budget())
        .expect("actual base-only coverage");
    f.native
        .publish_original_span_directory_router(&f.context, &request, &mut budget())
        .expect("actual second-generation router");
    let encoder = Directions(&f.encoder);
    let latest = f
        .native
        .project_original_spans(&f.context, &encoder, 64, &mut budget())
        .expect("same full profile, actual changed controlled vector");
    assert!(latest.caught_up);
    assert_eq!(latest.sources, 4);
    let key = document_key(&workspace, 2, source);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual new accepted document");
    let current_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("current point")
        .expect("new tagged plan");
    let current: DenseDocument =
        decode(&current_bytes, "new genuine source plan").expect("new typed doc");
    assert_eq!(current.source, old.source);
    assert_eq!(current.profile_digest, old.profile_digest);
    assert_ne!(current.spans[0].vector_digest, old.spans[0].vector_digest);
    // Both genuine owner tags validate; the old MAC format contains no generation.
    f.native
        .check_dense_document_token(&old)
        .expect("legitimate retained old tag");
    f.native
        .check_dense_document_token(&current)
        .expect("legitimate current tag");
    let position = f.native.global_head(&snapshot).expect("accepted position");
    drop(snapshot);
    let query = encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut query_budget())
        .expect("actual controlled query observation");
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("old signed document replay fault");
    tx.put(&f.native.keyspaces.continuous, key.clone(), old_bytes)
        .expect("copy EXACT genuine old bytes, no new tag");
    tx.commit(Durability::Sync).expect("fault Sync");
    let refused = search(&f, &query, limits())
        .expect_err("complete accepted fresh commitment precedes every fresh vector");
    assert_eq!(refused.code, ErrorCode::IntegrityFailure);
    assert!(
        refused.message.contains("complete fresh doc commitment"),
        "the full current commitment must reject a valid old tag: {refused:?}"
    );
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("restore actual new bytes");
    tx.put(&f.native.keyspaces.continuous, key, current_bytes)
        .expect("exact current restore");
    tx.commit(Durability::Sync).expect("restore Sync");
    let restored = search(&f, &query, limits()).expect("genuine latest plan restored");
    assert_eq!(restored.tail_vector_reads, 1);
    assert!(restored.admitted_sources.contains_key(&source));
    assert_counts(&restored);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("no serving publication");
    assert_eq!(
        f.native.global_head(&snapshot).expect("owner position"),
        position
    );
    drop(snapshot);
    assert!(
        f.native
            .verify_native(true)
            .expect("exact old/current generations deep verification")
            .valid
    );
}
