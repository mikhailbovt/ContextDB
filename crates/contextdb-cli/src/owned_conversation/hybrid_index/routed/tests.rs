//! Real encrypted stage/receipt recovery with controlled vectors, not recall quality.

use super::*;
use contextdb_core::{
    ContentDigest, EVENT_ENVELOPE_VERSION, EventCoverage, EventEnvelope, EventKind, EventPayload,
    EventRole, ObservationId, ScopeId, SourceId, StreamId, TimestampMicros, WorkspaceId,
};
use contextdb_native_service::{
    CustodyMasterKey, DenseGraphQueryLimits, DenseRoutedQueryLimits, NativeCustodyKeys,
    NativeSuppressionLedger,
};
use contextdb_service::{
    AuthenticationEvidence, Capability, CapturePort, CaptureRequest, CognitiveMemoryService,
    EmbeddedText, EmbeddingTextKind, RequestContext, Sensitivity, ServiceResult, VerifyRequest,
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn budget() -> QueryBudget {
    crate::owned_conversation::routed_maintenance_budget()
}

#[derive(Debug)]
struct Encoder {
    profile: TextEmbeddingProfile,
    sources: AtomicUsize,
}
impl Encoder {
    fn new() -> Self {
        Self {
            profile: TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
                b"CLI controlled source adapter",
            )),
            sources: AtomicUsize::new(0),
        }
    }
}
impl TextEmbeddingAdapter for Encoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.profile
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        parent.charge(1024, 16384).map_err(budget_error)?;
        if kind == EmbeddingTextKind::Source {
            self.sources.fetch_add(1, Ordering::SeqCst);
        }
        let mut values = vec![0.0_f32; self.profile.dimensions as usize];
        values[0] = 1.0;
        let mut hash = blake3::Hasher::new();
        for value in &values {
            hash.update(&value.to_le_bytes());
        }
        Ok(EmbeddedText {
            profile_digest: self.profile.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(self.profile.input_text(kind, text)?.as_bytes()),
            tokens_digest: digest(b"controlled tokens; no real tokenizer/model"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
        })
    }
}

struct Fixture {
    root: tempfile::TempDir,
    _authorities: tempfile::TempDir,
    ledger: Arc<NativeSuppressionLedger>,
    keys: Arc<NativeCustodyKeys>,
    owner: NativeService,
    context: AuthenticatedRequestContext,
    workspace: WorkspaceId,
    scope: ScopeId,
    producer: StreamId,
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("encrypted CLI owner");
    let authorities = tempfile::tempdir().expect("retained source authorities");
    let ledger =
        NativeSuppressionLedger::create(authorities.path().join("ledger"), "routed-stage-fixture")
            .expect("ledger");
    let keys = NativeCustodyKeys::create(
        authorities.path().join("keys"),
        "routed-stage-fixture",
        CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([9; 32])).expect("custody key"),
    )
    .expect("keys");
    let owner = NativeService::open_encrypted(
        root.path(),
        "routed-stage-fixture",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("actual native owner");
    let workspace = WorkspaceId::new();
    let scope = ScopeId::new();
    let context = AuthenticatedRequestContext {
        request: RequestContext {
            request_id: "routed-stage-request".into(),
            workspace_id: workspace.to_string(),
            subject_id: "stage-subject".into(),
            audiences: BTreeSet::from(["stage-subject".into()]),
            scopes: BTreeSet::from([scope.to_string()]),
            purpose: "conversation".into(),
            clearance: Sensitivity::Private,
        },
        actor_id: "stage-host".into(),
        agent_id: "stage-agent".into(),
        session_id: None,
        capability_grants: BTreeSet::from([
            Capability::Observe,
            Capability::Recall,
            Capability::Admin,
            Capability::Runtime,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ]),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "stage-channel".into(),
            peer_identity: "stage-host".into(),
            binding_digest: "63".repeat(32),
        },
    };
    Fixture {
        root,
        _authorities: authorities,
        ledger,
        keys,
        owner,
        context,
        workspace,
        scope,
        producer: StreamId::new(),
    }
}
fn capture(f: &Fixture, sequence: u64) {
    let text = format!("Actual independent captured original {sequence}; retain exact source.");
    f.owner
        .append_event(CaptureRequest {
            context: f.context.clone(),
            idempotency_key: format!("routed-stage/input/{sequence}"),
            event: EventEnvelope {
                version: EVENT_ENVELOPE_VERSION,
                event_id: ObservationId::new(),
                workspace_id: f.workspace,
                scope_ids: BTreeSet::from([f.scope]),
                producer_id: f.producer,
                producer_sequence: sequence,
                kind: EventKind::MessageCreated,
                recorded_at: TimestampMicros(1_000_000 + sequence as i64),
                observed_at: None,
                source_id: SourceId::new(),
                source_version: None,
                adapter_id: "controlled-cli-capture".into(),
                role: EventRole::User,
                session_id: None,
                run_id: None,
                task_id: None,
                parent_event_ids: BTreeSet::new(),
                supersedes_event_id: None,
                payload: EventPayload::InlineUtf8 {
                    digest: digest(text.as_bytes()),
                    text,
                },
                coverage: EventCoverage::CompleteObservation,
                upstream_truncated: false,
                gap_reason: None,
                response_stream: None,
                provenance: None,
            },
        })
        .expect("actual accepted original");
}
fn stage(f: &Fixture, encoder: Option<&dyn TextEmbeddingAdapter>, selected: Stage) -> Progress {
    advance(
        &f.owner,
        &f.context,
        encoder,
        Mode::Continue,
        selected,
        &mut budget(),
        |_| Ok(()),
    )
    .expect("explicit actual stage")
}

#[test]
fn small_routed_operator_stages_share_the_actual_cli_parent_allowance() {
    let f = fixture();
    let encoder = Encoder::new();
    for sequence in 1..=8 {
        capture(&f, sequence);
    }
    for (selected, mode, use_encoder) in [
        (Stage::Raw, Mode::Bootstrap, false),
        (Stage::Base, Mode::Continue, true),
        (Stage::Router, Mode::Continue, false),
    ] {
        let mut parent = crate::owned_conversation::routed_maintenance_budget();
        let outcome = advance(
            &f.owner,
            &f.context,
            use_encoder.then_some(&encoder as &dyn TextEmbeddingAdapter),
            mode,
            selected,
            &mut parent,
            |_| Ok(()),
        );
        eprintln!(
            "routed_stage_production_cost stage={selected:?} work={} bytes={} error={:?}",
            crate::owned_conversation::ROUTED_MAINTENANCE_MAX_WORK
                .saturating_sub(parent.remaining_work()),
            crate::owned_conversation::ROUTED_MAINTENANCE_MAX_BYTES
                .saturating_sub(parent.remaining_bytes()),
            outcome.as_ref().err().map(|error| error.0.code),
        );
        outcome.expect("small genuine maintenance under the actual CLI allowance");
    }
    capture(&f, 9);
    let mut parent = crate::owned_conversation::routed_maintenance_budget();
    f.owner
        .project_originals_bm25(&f.context, false, 64, &mut parent)
        .expect("actual new raw prefix within the operation parent");
    let result = advance(
        &f.owner,
        &f.context,
        Some(&encoder),
        Mode::Continue,
        Stage::Seal,
        &mut parent,
        |_| Ok(()),
    )
    .expect("one genuine source plus seal shares the actual parent");
    assert!(result.seal.is_some());
    assert_eq!(encoder.sources.load(Ordering::SeqCst), 9);
}

#[test]
fn raw_backlog_partial_base_pending_seal_explicit_router_and_cold_continuation() {
    let mut f = fixture();
    let encoder = Encoder::new();
    for sequence in 1..=140 {
        capture(&f, sequence);
    }
    let raw = advance(
        &f.owner,
        &f.context,
        None,
        Mode::Bootstrap,
        Stage::Raw,
        &mut budget(),
        |_| Ok(()),
    )
    .expect("encoder-free raw bootstrap");
    assert_eq!(raw.raw_batches, 3);
    assert_eq!(
        raw.raw
            .as_ref()
            .expect("actual raw receipt")
            .projected_sources,
        140
    );
    assert!(
        raw.raw.as_ref().expect("raw").caught_up && raw.before.is_none() && raw.after.is_none()
    );
    assert_eq!(encoder.sources.load(Ordering::SeqCst), 0);
    let base = stage(&f, Some(&encoder), Stage::Base);
    assert!(base.base.is_some());
    assert_eq!(base.dense_batches, 1);
    let base_status = base.after.expect("accepted partial base observation");
    let dense = base_status.dense.expect("real partial dense receipt");
    assert_eq!(dense.sources, 64);
    assert_eq!(dense.raw_sources, 140);
    assert!(!dense.caught_up);
    assert_eq!(encoder.sources.load(Ordering::SeqCst), 64);
    let existing = stage(&f, None, Stage::Base);
    assert!(existing.base.is_some() && existing.dense_batches == 0);
    assert_eq!(encoder.sources.load(Ordering::SeqCst), 64);

    // Simulate a lost source-projection response before the operator sealed it.
    let pending = f
        .owner
        .project_original_spans(&f.context, &encoder, 4, &mut budget())
        .expect("genuine pending projection");
    assert_eq!(pending.sources, 68);
    let calls = encoder.sources.load(Ordering::SeqCst);
    let mut saved = None;
    let sealed = advance(
        &f.owner,
        &f.context,
        None,
        Mode::Continue,
        Stage::Seal,
        &mut budget(),
        |request| {
            saved = Some(request.clone());
            Ok(())
        },
    )
    .expect("pending exact target recovery WITHOUT encoder");
    assert_eq!(sealed.dense_batches, 0);
    assert!(sealed.seal.is_some());
    assert_eq!(
        encoder.sources.load(Ordering::SeqCst),
        calls,
        "pending seal cannot extend the projection"
    );
    let request: PrefixSegmentSealRequestV2 =
        serde_json::from_value(saved.expect("request emitted before acceptance"))
            .expect("exact typed native request");
    assert_eq!(request.target, pending);
    assert_eq!(
        f.owner
            .seal_original_span_prefix_segment(&f.context, &request, &mut budget())
            .expect("known exact retry"),
        sealed.seal.expect("accepted interval")
    );
    let second = stage(&f, Some(&encoder), Stage::Seal);
    assert_eq!(second.dense_batches, 1);
    assert!(second.seal.is_some());
    let built = stage(&f, None, Stage::Router);
    assert!(built.router.is_some());
    assert!(
        built
            .after
            .as_ref()
            .expect("current router observation")
            .router_matches_directory
    );

    let query_text = "Find the independent captured original";
    let query = encoder
        .embed(EmbeddingTextKind::Query, query_text, &mut budget())
        .expect("controlled query data");
    let fine = stage(&f, Some(&encoder), Stage::Seal);
    assert!(fine.seal.is_some());
    assert!(
        !fine
            .after
            .expect("real fine advancement")
            .router_matches_directory
    );
    let limits = DenseRoutedQueryLimits {
        graph: DenseGraphQueryLimits {
            limit: 2,
            max_node_reads: 64,
            max_vector_reads: 256,
            max_discovered: 256,
            ef_search: 16,
        },
        max_fine_paths: 2,
        coarse_node_reads: 16,
        coarse_vector_reads: 16,
        coarse_discovered: 16,
        coarse_ef_search: 8,
        max_tail_work: 128,
        max_tail_vectors: 256,
    };
    let error = f
        .owner
        .search_original_spans_routed(&f.context, query_text, &query, limits, &mut budget())
        .expect_err("fine append cannot silently serve an old router");
    assert_eq!(error.code, ErrorCode::IndexTooStale);
    stage(&f, None, Stage::Router);
    let current = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("genuine current target");
    let calls = encoder.sources.load(Ordering::SeqCst);
    drop(f.owner);
    f.owner = NativeService::open_encrypted_existing(
        f.root.path(),
        "routed-stage-fixture",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold encrypted owner");
    assert_eq!(
        f.owner
            .original_span_routed_maintenance_target(&f.context, &mut budget())
            .expect("cold exact accepted metadata"),
        current
    );
    assert_eq!(encoder.sources.load(Ordering::SeqCst), calls);
    assert!(
        f.owner
            .verify(VerifyRequest {
                context: f.context.request.clone(),
                deep: true
            })
            .expect("actual cold deep verification")
            .valid
    );
}

#[test]
fn bootstrap_outside_raw_and_failed_request_observer_never_publish() {
    let f = fixture();
    let encoder = Encoder::new();
    capture(&f, 1);
    assert!(
        advance(
            &f.owner,
            &f.context,
            None,
            Mode::Bootstrap,
            Stage::Base,
            &mut budget(),
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(encoder.sources.load(Ordering::SeqCst), 0);
    advance(
        &f.owner,
        &f.context,
        None,
        Mode::Bootstrap,
        Stage::Raw,
        &mut budget(),
        |_| Ok(()),
    )
    .expect("raw");
    let mut saved = None;
    let failed = advance(
        &f.owner,
        &f.context,
        Some(&encoder),
        Mode::Continue,
        Stage::Base,
        &mut budget(),
        |request| {
            saved = Some(request.clone());
            Err(invalid("operator could not persist the exact request"))
        },
    );
    assert!(failed.is_err());
    let observed = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("earlier dense frame remains durable");
    assert!(observed.base.is_none());
    assert_eq!(
        observed.dense.expect("actual accepted source work").sources,
        1
    );
    let request: DensePrefixBaseRequestV2 =
        serde_json::from_value(saved.expect("exact publication target")).expect("typed request");
    f.owner
        .publish_original_span_prefix_base(&f.context, &request, &mut budget())
        .expect("operator persisted request can be retried exactly");
    assert_eq!(encoder.sources.load(Ordering::SeqCst), 1);
}
