//! Encrypted owner progression with controlled vectors; no model-quality claim.

use super::*;
use contextdb_core::{
    ContentDigest, EVENT_ENVELOPE_VERSION, EventCoverage, EventEnvelope, EventKind, EventPayload,
    EventRole, ObservationId, ScopeId, SourceId, StreamId, TimestampMicros, WorkspaceId,
};
use contextdb_native_service::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_service::{
    AuthenticationEvidence, Capability, CapturePort, CaptureRequest, CognitiveMemoryService,
    EmbeddedText, EmbeddingTextKind, RequestContext, Sensitivity, TextEmbeddingProfile,
    VerifyRequest,
};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

mod routed;

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}

#[derive(Debug)]
struct ControlledEncoder {
    profile: TextEmbeddingProfile,
    calls: AtomicUsize,
}
impl ControlledEncoder {
    fn new(artifacts: &[u8]) -> Self {
        Self {
            profile: TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(artifacts)),
            calls: AtomicUsize::new(0),
        }
    }
}
impl TextEmbeddingAdapter for ControlledEncoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.profile
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        parent.charge(1024, 8192).map_err(|_| {
            ServiceError::new(
                ErrorCode::BudgetExhausted,
                "controlled encoder parent exhausted",
                false,
            )
        })?;
        self.calls.fetch_add(1, Ordering::SeqCst);
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
            tokens_digest: digest(b"controlled fixture tokens; no tokenizer or neural model"),
            token_count: 7,
            values,
            vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
        })
    }
}

struct Fixture {
    root: tempfile::TempDir,
    _authority_root: tempfile::TempDir,
    owner: Arc<NativeService>,
    ledger: Arc<NativeSuppressionLedger>,
    keys: Arc<NativeCustodyKeys>,
    context: AuthenticatedRequestContext,
    workspace: WorkspaceId,
    scope: ScopeId,
    producer: StreamId,
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("encrypted owner");
    let authority_root = tempfile::tempdir().expect("retained authorities");
    let ledger =
        NativeSuppressionLedger::create(authority_root.path().join("ledger"), "hybrid-host-hook")
            .expect("ledger");
    let keys = NativeCustodyKeys::create(
        authority_root.path().join("keys"),
        "hybrid-host-hook",
        CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([9; 32])).expect("master"),
    )
    .expect("keys");
    let owner = Arc::new(
        NativeService::open_encrypted(
            root.path(),
            "hybrid-host-hook",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("actual native owner"),
    );
    let workspace = WorkspaceId::new();
    let scope = ScopeId::new();
    let context = AuthenticatedRequestContext {
        request: RequestContext {
            request_id: "hybrid-hook-fixture".into(),
            workspace_id: workspace.to_string(),
            subject_id: "hook-subject".into(),
            audiences: BTreeSet::from(["hook-subject".into()]),
            scopes: BTreeSet::from([scope.to_string()]),
            purpose: "conversation".into(),
            clearance: Sensitivity::Private,
        },
        actor_id: "hook-host".into(),
        agent_id: "hook-agent".into(),
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
            channel_id: "hook-channel".into(),
            peer_identity: "hook-host".into(),
            binding_digest: "63".repeat(32),
        },
    };
    Fixture {
        root,
        _authority_root: authority_root,
        owner,
        ledger,
        keys,
        context,
        workspace,
        scope,
        producer: StreamId::new(),
    }
}
fn capture(f: &Fixture, owner: &NativeService, sequence: u64) {
    let text = format!("Independent captured input {sequence}; preserve original.");
    owner
        .append_event(CaptureRequest {
            context: f.context.clone(),
            idempotency_key: format!("hook/input/{sequence}"),
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
                adapter_id: "controlled-hook-capture".into(),
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
        .expect("actual accepted capture");
}

fn verify(f: &Fixture) {
    f.owner
        .verify(VerifyRequest {
            context: f.context.request.clone(),
            deep: true,
        })
        .expect("actual native accepted projection verification");
}

#[test]
fn hybrid_hook_advances_more_than_one_batch_and_continues_after_cold_capture() {
    let mut f = fixture();
    for sequence in 1..=65 {
        capture(&f, &f.owner, sequence);
    }
    let encoder = Arc::new(ControlledEncoder::new(b"controlled-hook-profile"));
    let hook = NativePreparation::with_hybrid(f.owner.clone(), encoder.clone());
    hook.before_prepare(&f.context, &mut budget())
        .expect("two actual native batches share a parent");
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        65,
        "one complete short source vector per accepted original"
    );
    let receipt = f
        .owner
        .project_original_spans(&f.context, encoder.as_ref(), 64, &mut budget())
        .expect("accepted dense receipt");
    assert!(receipt.caught_up);
    assert_eq!(receipt.embedded_sources, 65);
    assert_eq!(receipt.spans, 65);
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        65,
        "receipt inspection must not repeat forwards"
    );
    verify(&f);
    drop(hook);
    drop(f.owner);
    f.owner = Arc::new(
        NativeService::open_encrypted_existing(
            f.root.path(),
            "hybrid-host-hook",
            [7; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("cold encrypted owner"),
    );
    capture(&f, &f.owner, 66);
    let hook = NativePreparation::with_hybrid(f.owner.clone(), encoder.clone());
    hook.before_prepare(&f.context, &mut budget())
        .expect("new capture advances retained dense tail without rebuilding");
    let receipt = f
        .owner
        .project_original_spans(&f.context, encoder.as_ref(), 64, &mut budget())
        .expect("cold accepted receipt");
    assert!(receipt.caught_up);
    assert_eq!(receipt.embedded_sources, 66);
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        66,
        "cold next step forwards only the new original"
    );
    let changed = Arc::new(ControlledEncoder::new(b"different-runtime-artifacts"));
    let wrong = NativePreparation::with_hybrid(f.owner.clone(), changed.clone());
    assert_eq!(
        wrong
            .before_prepare(&f.context, &mut budget())
            .expect_err("profile mismatch must propagate")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(changed.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        hook.before_prepare(
            &f.context,
            &mut QueryBudget::new(0, 0, Duration::from_secs(10), Default::default())
        )
        .expect_err("no fresh parent allowance")
        .code,
        ErrorCode::BudgetExhausted
    );
    verify(&f);
}

#[test]
fn legacy_hook_keeps_legacy_generation_and_hybrid_never_rebuilds_it_implicitly() {
    let f = fixture();
    capture(&f, &f.owner, 1);
    NativePreparation::new(f.owner.clone())
        .before_prepare(&f.context, &mut budget())
        .expect("unchanged legacy raw path");
    let encoder = Arc::new(ControlledEncoder::new(b"controlled-hook-profile"));
    let hook = NativePreparation::with_hybrid(f.owner.clone(), encoder.clone());
    assert_eq!(
        hook.before_prepare(&f.context, &mut budget())
            .expect_err("legacy profile requires explicit operator rebuild")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        0,
        "no source forward before exact profile admission"
    );
    assert_eq!(
        f.owner
            .project_originals_bm25(&f.context, false, 64, &mut budget())
            .expect_err("hook did not reinterpret old generation")
            .code,
        ErrorCode::IndexTooStale
    );
    verify(&f);
}
