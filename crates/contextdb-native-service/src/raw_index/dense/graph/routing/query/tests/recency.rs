//! Authentic older rows still need a current accepted dense-head binding.
use super::*;
use contextdb_service::{CognitiveMemoryService, TokenizedText, VerifyRequest};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct CountedQuery<'a> {
    encoder: &'a Encoder,
    measurements: AtomicUsize,
    forwards: AtomicUsize,
}
impl<'a> CountedQuery<'a> {
    fn new(encoder: &'a Encoder) -> Self {
        Self {
            encoder,
            measurements: AtomicUsize::new(0),
            forwards: AtomicUsize::new(0),
        }
    }
}
impl TextEmbeddingAdapter for CountedQuery<'_> {
    fn profile(&self) -> &TextEmbeddingProfile {
        self.encoder.profile()
    }
    fn measure_tokens(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<TokenizedText> {
        self.measurements.fetch_add(1, Ordering::SeqCst);
        let profile = self.profile();
        parent
            .charge(
                text.len() as u64 + 1,
                (text.len() + profile.query_instruction.len() + 32) as u64 * 4 + 8192,
            )
            .map_err(budget_error)?;
        let input = profile.input_text(kind, text)?;
        Ok(TokenizedText {
            profile_digest: profile.digest()?,
            kind,
            text_digest: ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes()),
            input_digest: ContentDigest::from_bytes(*blake3::hash(input.as_bytes()).as_bytes()),
            tokens_digest: ContentDigest::from_bytes(
                *blake3::hash(b"prefix-v2 fixture exact tokens").as_bytes(),
            ),
            token_count: 7,
        })
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        self.forwards.fetch_add(1, Ordering::SeqCst);
        self.encoder.embed(kind, text, parent)
    }
}

fn admitted_callbacks(
    f: &Fixture,
    encoder: &CountedQuery<'_>,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    // This is the same native admission boundary used before the owned query
    // tokenizer. The controlled callbacks expose an erroneous successful gate.
    f.native
        .admit_owned_routed_query_embedding_profile(&f.context, encoder.profile(), parent)?;
    let measured = encoder.measure_tokens(EmbeddingTextKind::Query, QUERY, parent)?;
    measured.validate(encoder.profile(), EmbeddingTextKind::Query, QUERY, parent)?;
    let embedded = encoder.embed(EmbeddingTextKind::Query, QUERY, parent)?;
    embedded.validate(encoder.profile(), EmbeddingTextKind::Query, QUERY, parent)
}

#[test]
fn unchanged_certificate_allows_foreign_head_but_rejects_actual_vector_and_old_row_faults() {
    let f = fixture();
    base(&f);
    router(&f);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let generation_key = generation_key(&workspace, 1);
    let receipt_key = dense::receipt_key(&workspace, 1);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("old genuine rows");
    let old_generation = snapshot
        .get(&f.native.keyspaces.continuous, &generation_key)
        .expect("old generation read")
        .expect("actual old generation");
    let old_receipt = snapshot
        .get(&f.native.keyspaces.continuous, &receipt_key)
        .expect("old receipt read")
        .expect("actual old Dense receipt");
    drop(snapshot);
    capture(&f, 501, "A genuinely newer sapphire orbital original");
    project(&f, &f.encoder);
    let (_, view) = f
        .native
        .admit_owned_routed_query_embedding_profile(
            &f.context,
            f.encoder.profile(),
            &mut query_budget(),
        )
        .expect("full genuine current admission");
    for _ in 0..2 {
        f.native
            .check_routed_query_view(&f.context, &view, &mut query_budget())
            .expect("unchanged current certificate");
    }
    let embedded = f
        .encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut query_budget())
        .expect("actual controlled query receipt");

    let mut foreign = crate::capture::tests::request(502, "A separate workspace original");
    foreign.context = f.context.clone();
    foreign.event.workspace_id = contextdb_core::WorkspaceId::new();
    foreign.context.request.workspace_id = foreign.event.workspace_id.to_string();
    f.native
        .append_event(foreign)
        .expect("actual foreign-workspace global advance");
    f.native
        .check_routed_query_view(&f.context, &view, &mut query_budget())
        .expect("foreign global scalar is not this workspace's successor");

    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("genuine current controls");
    let generation = snapshot
        .get(&f.native.keyspaces.continuous, &generation_key)
        .expect("current generation read")
        .expect("actual current generation");
    let receipt = snapshot
        .get(&f.native.keyspaces.continuous, &receipt_key)
        .expect("current receipt read")
        .expect("actual current receipt");
    let vectors = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            format!("{}dense/vector/", generation_prefix(&workspace, 1)).as_bytes(),
        )
        .expect("actual source-vector rows");
    assert!(!vectors.is_empty());
    drop(snapshot);

    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("actual vector corruption fault");
    for row in &vectors {
        tx.put(
            &f.native.keyspaces.continuous,
            row.key.clone(),
            b"invalid vector sentinel".to_vec(),
        )
        .expect("damage actual source vector");
    }
    tx.commit(Durability::Sync).expect("vector fault Sync");
    let unchanged = f
        .native
        .check_routed_query_view(&f.context, &view, &mut query_budget());
    let vector_outcome = f.native.search_original_spans_routed_in_view(
        &f.context,
        QUERY,
        &embedded,
        limits(),
        &view,
        &mut query_budget(),
    );
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("restore actual vectors");
    for row in &vectors {
        tx.put(
            &f.native.keyspaces.continuous,
            row.key.clone(),
            row.value.clone(),
        )
        .expect("EXACT source vector restore");
    }
    tx.commit(Durability::Sync).expect("vector restore Sync");
    unchanged.expect("metadata certificate grants no vector exemption");
    assert_eq!(
        vector_outcome
            .expect_err("actual vector authentication still executes")
            .code,
        ErrorCode::IntegrityFailure
    );

    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("genuine older row replay during cached query");
    tx.put(
        &f.native.keyspaces.continuous,
        generation_key.clone(),
        old_generation,
    )
    .expect("EXACT older generation");
    tx.put(
        &f.native.keyspaces.continuous,
        receipt_key.clone(),
        old_receipt,
    )
    .expect("EXACT older receipt");
    for row in &vectors {
        tx.put(
            &f.native.keyspaces.continuous,
            row.key.clone(),
            b"invalid vector sentinel".to_vec(),
        )
        .expect("vector-read sentinel");
    }
    tx.commit(Durability::Sync).expect("replay fault Sync");
    let replay_outcome = f.native.search_original_spans_routed_in_view(
        &f.context,
        QUERY,
        &embedded,
        limits(),
        &view,
        &mut query_budget(),
    );
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("restore authentic current archive");
    tx.put(&f.native.keyspaces.continuous, generation_key, generation)
        .expect("current generation restore");
    tx.put(&f.native.keyspaces.continuous, receipt_key, receipt)
        .expect("current receipt restore");
    for row in vectors {
        tx.put(&f.native.keyspaces.continuous, row.key, row.value)
            .expect("actual vector restore");
    }
    tx.commit(Durability::Sync).expect("exact restore Sync");
    assert_eq!(
        replay_outcome
            .expect_err("old genuine controls fail BEFORE vector sentinel")
            .code,
        ErrorCode::IndexTooStale
    );
    let mut zero = QueryBudget::new(
        0,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    );
    assert_eq!(
        f.native
            .check_routed_query_view(&f.context, &view, &mut zero)
            .expect_err("certificate never bypasses parent admission")
            .code,
        ErrorCode::BudgetExhausted
    );
    f.native
        .verify(VerifyRequest {
            context: f.context.request.clone(),
            deep: true,
        })
        .expect("exact genuine rows restored before deep verification");
}

#[test]
fn reused_opaque_view_refuses_changed_principal_and_new_dense_before_vector_reads() {
    let f = fixture();
    base(&f);
    router(&f);
    let (_, view) = f
        .native
        .admit_owned_routed_query_embedding_profile(
            &f.context,
            f.encoder.profile(),
            &mut query_budget(),
        )
        .expect("genuine owner-minted current view");
    let embedded = f
        .encoder
        .embed(EmbeddingTextKind::Query, QUERY, &mut query_budget())
        .expect("exact controlled query observation");
    let mut foreign = f.context.clone();
    foreign.request.subject_id = contextdb_core::MemorySubjectId::new().to_string();
    foreign.request.audiences = BTreeSet::from([foreign.request.subject_id.clone()]);
    assert_eq!(
        f.native
            .search_original_spans_routed_in_view(
                &foreign,
                QUERY,
                &embedded,
                limits(),
                &view,
                &mut query_budget(),
            )
            .expect_err("opaque admission is bound to its exact principal")
            .code,
        ErrorCode::IndexTooStale
    );

    capture(&f, 4, "A genuinely newer sapphire orbital observation");
    let advanced = project(&f, &f.encoder);
    assert!(advanced.global_commit > view.current_dense_ref().global_commit);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current source vectors");
    let generation = read_generation(&f.native, &f.context, &mut query_budget());
    assert_eq!(
        generation.dense_prefix_base,
        view.generation().dense_prefix_base
    );
    assert_eq!(
        generation.dense_directory_router,
        view.generation().dense_directory_router
    );
    let vectors = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            format!(
                "{}dense/vector/",
                generation_prefix(view.workspace(), generation.number)
            )
            .as_bytes(),
        )
        .expect("actual original vector rows");
    assert!(!vectors.is_empty());
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("vector-read sentinel");
    for row in &vectors {
        tx.put(
            &f.native.keyspaces.continuous,
            row.key.clone(),
            b"invalid vector sentinel".to_vec(),
        )
        .expect("damage only actual vector values");
    }
    tx.commit(Durability::Sync)
        .expect("sentinel synchronization");
    let outcome = f.native.search_original_spans_routed_in_view(
        &f.context,
        QUERY,
        &embedded,
        limits(),
        &view,
        &mut query_budget(),
    );
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("restore genuine vector bytes");
    for row in vectors {
        tx.put(&f.native.keyspaces.continuous, row.key, row.value)
            .expect("exact original vector restore");
    }
    tx.commit(Durability::Sync)
        .expect("restore synchronization");
    assert_eq!(outcome.expect_err("new Dense with unchanged graph roots closes reused admission before any damaged vector read").code,
        ErrorCode::IndexTooStale);
    f.native
        .verify(VerifyRequest {
            context: f.context.request.clone(),
            deep: true,
        })
        .expect("restored authentic archive remains consistent");
}

#[test]
fn coherent_older_generation_and_dense_receipt_refuse_before_query_callbacks() {
    let f = fixture();
    base(&f);
    router(&f);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let generation_key = generation_key(&workspace, 1);
    let receipt_key = dense::receipt_key(&workspace, 1);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("authentic older accepted view");
    let old_generation_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &generation_key)
        .expect("old generation point")
        .expect("accepted generation");
    let old_receipt_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &receipt_key)
        .expect("old receipt point")
        .expect("accepted dense receipt");
    let old_generation: Generation =
        decode(&old_generation_bytes, "authentic old generation").expect("typed old generation");
    let old_receipt: DenseProjectionReceipt =
        decode(&old_receipt_bytes, "authentic old dense receipt").expect("typed old receipt");
    let old_world = f
        .native
        .current_directory_router_heads(
            &snapshot,
            &f.context.request.workspace_id,
            &mut query_budget(),
        )
        .expect("actual certified old maps");
    drop(snapshot);
    capture(&f, 500, "A genuinely newer sapphire orbital original");
    let new_receipt = project(&f, &f.encoder);
    assert_eq!(new_receipt.generation, old_receipt.generation);
    assert!(
        new_receipt.global_commit > old_receipt.global_commit
            && new_receipt.through > old_receipt.through
    );
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("genuine newer accepted view");
    let new_generation_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &generation_key)
        .expect("new generation point")
        .expect("current accepted generation");
    let new_receipt_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &receipt_key)
        .expect("new receipt point")
        .expect("current accepted receipt");
    let new_generation: Generation = decode(&new_generation_bytes, "authentic current generation")
        .expect("typed current generation");
    let new_world = f
        .native
        .current_directory_router_heads(
            &snapshot,
            &f.context.request.workspace_id,
            &mut query_budget(),
        )
        .expect("genuine current certified maps");
    let position = f
        .native
        .global_head(&snapshot)
        .expect("actual latest native position");
    assert_eq!(
        old_generation.dense_prefix_base,
        new_generation.dense_prefix_base
    );
    assert_eq!(
        old_generation.dense_directory_router,
        new_generation.dense_directory_router
    );
    assert_eq!(old_world.segment_heads, new_world.segment_heads);
    assert_eq!(old_world.prefix_bases, new_world.prefix_bases);
    assert_eq!(
        old_world.prefix_segment_heads,
        new_world.prefix_segment_heads
    );
    assert_eq!(old_world.directory_routers, new_world.directory_routers);
    assert!(new_world.watermarks.journal > old_world.watermarks.journal);
    drop(snapshot);
    let good = CountedQuery::new(&f.encoder);
    admitted_callbacks(&f, &good, &mut query_budget())
        .expect("genuine latest accepted dense state admits callbacks");
    assert_eq!(good.measurements.load(Ordering::SeqCst), 1);
    assert_eq!(good.forwards.load(Ordering::SeqCst), 1);
    let blocked = CountedQuery::new(&f.encoder);
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("coherent old-row replay fault");
    tx.put(
        &f.native.keyspaces.continuous,
        generation_key.clone(),
        old_generation_bytes,
    )
    .expect("EXACT genuine older generation bytes");
    tx.put(
        &f.native.keyspaces.continuous,
        receipt_key.clone(),
        old_receipt_bytes,
    )
    .expect("EXACT genuine older dense receipt bytes");
    tx.commit(Durability::Sync).expect("two-row replay Sync");
    // No source, BM25 statistics, event, idempotency, world or map row is altered.
    let outcome = admitted_callbacks(&f, &blocked, &mut query_budget());
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("restore genuine current rows");
    tx.put(
        &f.native.keyspaces.continuous,
        generation_key,
        new_generation_bytes,
    )
    .expect("EXACT new generation restore");
    tx.put(
        &f.native.keyspaces.continuous,
        receipt_key,
        new_receipt_bytes,
    )
    .expect("EXACT new receipt restore");
    tx.commit(Durability::Sync).expect("current restore Sync");
    // Restore first, including when the old implementation incorrectly succeeds.
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("restored current native view");
    assert_eq!(
        f.native
            .global_head(&snapshot)
            .expect("unchanged native journal"),
        position
    );
    let restored_world = f
        .native
        .current_directory_router_heads(
            &snapshot,
            &f.context.request.workspace_id,
            &mut query_budget(),
        )
        .expect("unchanged certified current owner");
    assert_eq!(restored_world, new_world);
    drop(snapshot);
    assert!(
        f.native
            .verify_native(true)
            .expect("exact current bytes restore deep verification")
            .valid
    );
    let error = outcome
        .expect_err("coherent older authenticated rows do not prove current accepted dense state");
    assert!(matches!(
        error.code,
        ErrorCode::IntegrityFailure | ErrorCode::IndexTooStale
    ));
    assert_eq!(
        blocked.measurements.load(Ordering::SeqCst),
        0,
        "refusal precedes tokenization"
    );
    assert_eq!(
        blocked.forwards.load(Ordering::SeqCst),
        0,
        "refusal precedes query inference"
    );
}

#[test]
fn genuine_newer_raw_acceptance_rejects_older_generation_before_query_callbacks() {
    let f = fixture();
    base(&f);
    router(&f);
    let current_dense = project(&f, &f.encoder);
    assert!(current_dense.caught_up);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let key = generation_key(&workspace, 1);
    let dense_key = dense::receipt_key(&workspace, 1);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual old caught-up raw/dense generation");
    let old_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("old generation point")
        .expect("authentic accepted generation");
    let receipt_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &dense_key)
        .expect("unchanged dense point")
        .expect("actual current dense receipt");
    let old: Generation =
        decode(&old_bytes, "old actual caught-up generation").expect("typed old generation");
    let old_world = f
        .native
        .current_directory_router_heads(
            &snapshot,
            &f.context.request.workspace_id,
            &mut query_budget(),
        )
        .expect("old certified roots");
    drop(snapshot);
    capture(
        &f,
        501,
        "A newer accepted raw original awaiting its dense projection",
    );
    let progress = f
        .native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("genuine RAW-only owner publication");
    assert!(progress.caught_up && progress.generation == 1 && progress.through > old.through);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("genuine new raw acceptance");
    let new_bytes = snapshot
        .get(&f.native.keyspaces.continuous, &key)
        .expect("new raw generation point")
        .expect("actual new generation");
    let new: Generation =
        decode(&new_bytes, "new actual raw generation").expect("typed new generation");
    assert_eq!(
        old.dense, new.dense,
        "dense state was never advanced or replayed"
    );
    assert_eq!(
        snapshot
            .get(&f.native.keyspaces.continuous, &dense_key)
            .expect("unchanged current receipt"),
        Some(receipt_bytes.clone())
    );
    let world = f
        .native
        .current_directory_router_heads(
            &snapshot,
            &f.context.request.workspace_id,
            &mut query_budget(),
        )
        .expect("new certified owner roots");
    assert_eq!(old_world.segment_heads, world.segment_heads);
    assert_eq!(old_world.prefix_bases, world.prefix_bases);
    assert_eq!(old_world.prefix_segment_heads, world.prefix_segment_heads);
    assert_eq!(old_world.directory_routers, world.directory_routers);
    let position = f
        .native
        .global_head(&snapshot)
        .expect("actual newer raw position");
    drop(snapshot);
    let good = CountedQuery::new(&f.encoder);
    admitted_callbacks(&f, &good, &mut query_budget())
        .expect("genuine current raw envelope admits query despite honest dense lag");
    assert_eq!(good.measurements.load(Ordering::SeqCst), 1);
    assert_eq!(good.forwards.load(Ordering::SeqCst), 1);
    let blocked = CountedQuery::new(&f.encoder);
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("old raw envelope replay fault");
    tx.put(&f.native.keyspaces.continuous, key.clone(), old_bytes)
        .expect("EXACT genuine old generation, no new MAC");
    tx.commit(Durability::Sync).expect("one-row replay Sync");
    let outcome = admitted_callbacks(&f, &blocked, &mut query_budget());
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("restore genuine new generation");
    tx.put(&f.native.keyspaces.continuous, key, new_bytes)
        .expect("EXACT new generation restore");
    tx.commit(Durability::Sync).expect("restore Sync");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("restored current state");
    assert_eq!(
        f.native
            .global_head(&snapshot)
            .expect("journal unchanged by observations"),
        position
    );
    assert_eq!(
        snapshot
            .get(&f.native.keyspaces.continuous, &dense_key)
            .expect("dense receipt untouched"),
        Some(receipt_bytes)
    );
    assert_eq!(
        f.native
            .current_directory_router_heads(
                &snapshot,
                &f.context.request.workspace_id,
                &mut query_budget()
            )
            .expect("certified roots unchanged"),
        world
    );
    drop(snapshot);
    assert!(
        f.native
            .verify_native(true)
            .expect("exact new raw bytes restore deep verification")
            .valid
    );
    let error =
        outcome.expect_err("older raw generation cannot become current merely by reporting RawLag");
    assert!(matches!(
        error.code,
        ErrorCode::IntegrityFailure | ErrorCode::IndexTooStale
    ));
    assert_eq!(blocked.measurements.load(Ordering::SeqCst), 0);
    assert_eq!(blocked.forwards.load(Ordering::SeqCst), 0);
}
