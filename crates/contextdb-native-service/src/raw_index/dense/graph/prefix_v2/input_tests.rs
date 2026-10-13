//! Real accepted input contracts; constant vectors establish no encoder quality.

use super::*;
use crate::raw_index::{IndexState, generation_key, state_key};
use contextdb_recall::QueryCancellation;
use contextdb_service::{
    Capability, CapturePort, EmbeddedText, EmbeddingTextKind, ErrorCode, TextEmbeddingAdapter,
    TextEmbeddingProfile,
};
use contextdb_storage::{
    Durability, Entry, Keyspace, ScanPage, ScanPageRequest, StorageSequence, WriteTransaction,
};
use std::{cell::Cell, sync::Arc, time::Duration};

#[path = "input_boundary_tests.rs"]
mod boundaries;

pub(in crate::raw_index::dense::graph) const DATABASE: &str = "prefix-v2-input-fixture";
pub(in crate::raw_index::dense::graph) const TOKEN_KEY: [u8; 32] = [31; 32];

#[derive(Debug)]
pub(in crate::raw_index::dense::graph) struct Encoder(
    pub(in crate::raw_index::dense::graph) TextEmbeddingProfile,
);
impl TextEmbeddingAdapter for Encoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.0
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        parent
            .charge(
                1,
                self.0.dimensions as u64 * 4 + text.len() as u64 * 4 + 8192,
            )
            .map_err(budget_error)?;
        let mut values = vec![0_f32; self.0.dimensions as usize];
        values[0] = 1.;
        let mut hasher = blake3::Hasher::new();
        for value in &values {
            hasher.update(&value.to_le_bytes());
        }
        Ok(EmbeddedText {
            profile_digest: self.0.digest()?,
            kind,
            text_digest: super::super::super::digest(text.as_bytes()),
            input_digest: super::super::super::digest(self.0.input_text(kind, text)?.as_bytes()),
            tokens_digest: super::super::super::digest(b"prefix-v2 fixture exact tokens"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hasher.finalize().as_bytes()),
        })
    }
}

pub(in crate::raw_index::dense::graph) struct Fixture {
    pub(in crate::raw_index::dense::graph) native: NativeService,
    pub(in crate::raw_index::dense::graph) context: AuthenticatedRequestContext,
    pub(in crate::raw_index::dense::graph) root: tempfile::TempDir,
    pub(in crate::raw_index::dense::graph) ledger: Arc<crate::NativeSuppressionLedger>,
    pub(in crate::raw_index::dense::graph) keys: Arc<crate::NativeCustodyKeys>,
    pub(in crate::raw_index::dense::graph) _ledger: tempfile::TempDir,
    pub(in crate::raw_index::dense::graph) _keys: tempfile::TempDir,
    pub(in crate::raw_index::dense::graph) encoder: Encoder,
    pub(in crate::raw_index::dense::graph) target: crate::raw_index::dense::DenseProjectionReceipt,
    pub(in crate::raw_index::dense::graph) sources: [ObservationId; 3],
}

pub(in crate::raw_index::dense::graph) fn budget() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
        1024 * 1024 * 1024,
        Duration::from_secs(60),
        QueryCancellation::default(),
    )
}

pub(in crate::raw_index::dense::graph) fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("prefix-v2 native directory");
    let (ld, ledger) = crate::suppression::tests::authority(DATABASE);
    let (kd, keys) = crate::encryption::tests::authority(DATABASE);
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        DATABASE,
        TOKEN_KEY,
        ledger.clone(),
        keys.clone(),
    )
    .expect("real encrypted owner");
    let mut first = crate::capture::tests::request(1, "immutable nonempty prefix original");
    first
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    let context = first.context.clone();
    let mut sources = Vec::new();
    for (sequence, text) in [
        (1, "immutable nonempty prefix original".to_owned()),
        (2, "x".repeat(64 * 1024 + 1)),
        (
            3,
            "genuine raw archive original outside the dense prefix".to_owned(),
        ),
    ] {
        let mut request = crate::capture::tests::request(sequence, &text);
        request.context = context.clone();
        request.event.source_version = Some(format!("prefix-v2-actual-source-{sequence}"));
        sources.push(request.event.event_id);
        native
            .append_event(request)
            .expect("actual immutable archive capture");
    }
    let progress = native
        .project_originals_bm25(&context, false, 64, &mut budget())
        .expect("complete full raw/BM25 archive");
    assert!(progress.caught_up && progress.projected_sources == 3);
    let encoder = Encoder(TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(
        super::super::super::digest(b"prefix-v2 structural fixture backend"),
    ));
    let target = native
        .project_original_spans(&context, &encoder, 2, &mut budget())
        .expect("genuine current partial dense receipt");
    assert!(!target.caught_up && target.sources == 2 && target.spans == 1);
    assert_eq!(target.omitted_sources, 1);
    assert_eq!(target.raw_sources, 3);
    Fixture {
        native,
        context,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        encoder,
        target,
        sources: sources.try_into().expect("three actual original IDs"),
    }
}

fn generation_at<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    workspace: &str,
    parent: &mut QueryBudget,
) -> ServiceResult<Generation> {
    let state: IndexState = native
        .graph_read(
            snapshot,
            &native.keyspaces.continuous,
            &state_key(workspace),
            parent,
        )?
        .ok_or_else(stale_index)?;
    native
        .graph_read(
            snapshot,
            &native.keyspaces.continuous,
            &generation_key(workspace, state.active.ok_or_else(stale_index)?),
            parent,
        )?
        .ok_or_else(stale_index)
}

pub(in crate::raw_index::dense::graph) fn read_generation(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    parent: &mut QueryBudget,
) -> Generation {
    let workspace = digest_bytes(context.request.workspace_id.as_bytes());
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current real snapshot");
    generation_at(native, &snapshot, &workspace, parent).expect("actual full raw generation")
}

fn built(f: &Fixture, parent: &mut QueryBudget) -> ServiceResult<PrefixBuildInput> {
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    let generation = generation_at(&f.native, &snapshot, &workspace, parent)?;
    let target = f.native.verify_current_prefix_dense_target(
        &snapshot,
        &workspace,
        &generation,
        &f.target,
        parent,
    )?;
    f.native.prefix_build_input(
        &snapshot,
        Some(&f.context),
        &workspace,
        &generation,
        &target,
        parent,
    )
}

#[test]
fn actual_partial_prefix_keeps_raw_totals_and_commits_omission_without_payload_reexecution() {
    let f = fixture();
    let before = read_generation(&f.native, &f.context, &mut budget());
    let actual = built(&f, &mut budget()).expect("complete genuine partial-prefix input");
    assert_eq!(
        actual.interval.work_items, 2,
        "explicit omission is real accepted work"
    );
    assert_eq!(actual.documents.len(), 2);
    assert_eq!(actual.inputs.len(), 1);
    assert_eq!(actual.inputs[0].vector.source.event_id, f.sources[0]);
    assert_eq!(
        actual.inputs[0].vector.source.source_version.as_deref(),
        Some("prefix-v2-actual-source-1")
    );
    assert_eq!(actual.documents[1].source.event_id, f.sources[1]);
    assert_eq!(
        actual.documents[1].omission,
        Some(crate::raw_index::dense::DenseOmission::TooLarge)
    );
    assert!(actual.documents[1].spans.is_empty());
    assert!(
        actual
            .documents
            .iter()
            .all(|doc| doc.source.event_id != f.sources[2])
    );
    assert!(before.through > f.target.through && before.projected_sources > f.target.sources);
    assert_eq!(
        read_generation(&f.native, &f.context, &mut budget()),
        before,
        "proof construction does not rewrite actual raw/dense counters"
    );
    let repeat = built(&f, &mut budget()).expect("repeat native accepted input");
    assert_eq!(repeat.interval, actual.interval);
    assert_eq!(repeat.documents, actual.documents);
    assert_eq!(repeat.inputs[0].vector, actual.inputs[0].vector);
    assert_eq!(repeat.inputs[0].values, actual.inputs[0].values);
}

struct Watched<'a, S> {
    inner: &'a S,
    protected: Vec<Vec<u8>>,
    protected_reads: Cell<usize>,
}
impl<S: ReadSnapshot> Watched<'_, S> {
    fn observe(&self, key: &[u8]) {
        if self.protected.iter().any(|prefix| key.starts_with(prefix)) {
            self.protected_reads.set(self.protected_reads.get() + 1);
        }
    }
}
impl<S: ReadSnapshot> ReadSnapshot for Watched<'_, S> {
    fn sequence(&self) -> StorageSequence {
        self.inner.sequence()
    }
    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.observe(key);
        self.inner.get(keyspace, key)
    }
    fn scan_prefix(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Vec<Entry>> {
        panic!("prefix-v2 input may not perform a whole-prefix corpus scan")
    }
    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> contextdb_storage::Result<ScanPage> {
        self.observe(request.prefix);
        self.inner.scan_prefix_page(keyspace, request)
    }
}

#[test]
fn currently_denied_source_refuses_before_document_raw_or_vector_point_read() {
    let f = fixture();
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual snapshot");
    let generation = generation_at(&f.native, &snapshot, &workspace, &mut budget())
        .expect("actual raw generation");
    let target = f
        .native
        .verify_current_prefix_dense_target(
            &snapshot,
            &workspace,
            &generation,
            &f.target,
            &mut budget(),
        )
        .expect("genuine target factory");
    let base = crate::raw_index::generation_prefix(&workspace, generation.number);
    let watched = Watched {
        inner: &snapshot,
        protected: ["doc/", "dense/document/", "dense/vector/"]
            .into_iter()
            .map(|suffix| format!("{base}{suffix}").into_bytes())
            .collect(),
        protected_reads: Cell::new(0),
    };
    let mut denied = f.context.clone();
    denied.request.scopes.clear();
    let error = f
        .native
        .prefix_build_input(
            &watched,
            Some(&denied),
            &workspace,
            &generation,
            &target,
            &mut budget(),
        )
        .err()
        .expect("current source admission refusal");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        watched.protected_reads.get(),
        0,
        "no denied source material was read"
    );
}

#[test]
fn missing_authoritative_outbox_work_refuses_without_accepting_a_shorter_prefix() {
    let f = fixture();
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let (generation, target) = {
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("actual target snapshot");
        let generation = generation_at(&f.native, &snapshot, &workspace, &mut budget())
            .expect("actual generation");
        let target = f
            .native
            .verify_current_prefix_dense_target(
                &snapshot,
                &workspace,
                &generation,
                &f.target,
                &mut budget(),
            )
            .expect("native authoritative accepted-work census");
        (generation, target)
    };
    assert_eq!(target.work().len(), 2);
    let missing = target
        .work()
        .last()
        .expect("actual omitted-source accepted work");
    assert_eq!(missing.event_id, f.sources[1]);
    let mut transaction = f
        .native
        .engine
        .begin_write()
        .expect("controlled retained-row fault");
    transaction
        .delete(
            &f.native.keyspaces.continuous,
            crate::capture::work_key(&workspace, missing.workspace_commit),
        )
        .expect("remove only the accepted outbox row");
    transaction
        .commit(Durability::Sync)
        .expect("actual missing-row fault");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("faulted current snapshot");
    let error = f
        .native
        .prefix_build_input(
            &snapshot,
            Some(&f.context),
            &workspace,
            &generation,
            &target,
            &mut budget(),
        )
        .err()
        .expect("no partial input result");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert!(
        error.message.contains("accepted outbox work"),
        "exact authoritative point join refused"
    );
}

#[test]
fn streaming_interval_preserves_typed_byte_cancel_and_deadline_limits_before_hashing() {
    for (bytes, duration, cancelled, expected) in [
        (1, Duration::from_secs(1), false, QueryLimit::Bytes),
        (100, Duration::from_secs(1), true, QueryLimit::Cancelled),
        (100, Duration::ZERO, false, QueryLimit::Deadline),
    ] {
        let cancellation = QueryCancellation::default();
        let mut parent = QueryBudget::new(100, bytes, duration, cancellation.clone());
        if cancelled {
            cancellation.cancel();
        }
        let mut hasher = blake3::Hasher::new();
        let before = *hasher.finalize().as_bytes();
        let mut writer = BudgetHashWriter {
            hasher: &mut hasher,
            parent: &mut parent,
            limit: None,
        };
        writer
            .write_all(b"unchanged until admitted")
            .expect_err("same parent refusal");
        assert_eq!(writer.limit, Some(expected));
        assert_eq!(*hasher.finalize().as_bytes(), before);
    }
    let mut value = IntervalHash {
        hasher: blake3::Hasher::new(),
        work_items: 0,
    };
    let mut parent = QueryBudget::new(100, 0, Duration::from_secs(1), QueryCancellation::default());
    let error = value
        .part(&"failed metadata", &mut parent)
        .expect_err("typed stream failure");
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    assert!(error.message.contains("byte budget"));
}
