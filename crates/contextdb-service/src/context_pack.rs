//! First-class policy-first recall to ContextPack composition.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::{
    BlockId, BlockRepresentation, CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM,
    CONTEXT_PACK_CANONICAL_ENCODING, CandidateUsePolicy, CompileRequest, CompressionLevel,
    ContentTaint, ContextBudgetUsage, ContextBudgets, ContextCompiler, ContextContinuationToken,
    ContextError, ContextPack, DisclosureRule, EvidenceHandle, EvidenceSelector,
    InMemoryContextProvider, InstructionCapability, InterpretationRule, ModelProfile,
    PackBlockKind, PackCandidate, PackEvidence, PackFacetRequirement, PackPurpose, PackStatus,
    ProviderCandidate, ProviderEvidence as ContextProviderEvidence, RecallContextBinding,
    ReferenceTokenizer, RendererKind, SourceClass, SourceHandle, StructuredFormat, SupportState,
};
use contextdb_core::{
    AcceptanceState, ActorId, AgentId, ClaimId, CommitSeq, ConflictState, ContextPackId,
    ConversationMode, CueBundle, EpistemicBasis, EpistemicRole, EpistemicState, EvidencePolicy,
    FacetRequirement, LifecycleState, MemoryRef, MemorySubjectId, ModelProfileId, NonEmptyVec,
    PolicyDecision, PolicyId, QueryContent, RecallBudgets, RecallIntent,
    RecallRequest as CoreRecallRequest, ScopeId, ScopeInheritance, ScopeKind, ScopeRef, SessionId,
    TemporalConstraint, TemporalContext, TimestampMicros,
};
use contextdb_recall::{
    AccessConsent, AccessRule, BudgetUsage, DeterministicRecallRequest, DeterministicRecallResult,
    MemoryUseDecision, ProviderRequest, ProviderSnapshot, RecallContinuationToken,
    RecallDocumentKind, RecallEngine, RecallError, RecallLimits, RecallMode, RecallPrincipal,
    RecallProvider, RecallSensitivity, RecallStatus, ReferenceProvider, StopReason, SuppliedVector,
};
use contextdb_reference::ContextDb;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AuthenticatedRequestContext, Capability, ErrorCode, Sensitivity, ServiceError, ServiceResult,
};

const PIPELINE_CURSOR_VERSION: u16 = 1;
const MAX_COMPILE_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_COMPILE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_BYTES: usize = 32 * 1024;
const MAX_REQUIRED_FACETS: usize = 32;
const MAX_VECTOR_DIMENSIONS: usize = 4_096;
const MAX_CONTEXT_TOKENS: u32 = 262_144;
const MAX_CONTEXT_BLOCKS: u32 = 4_096;
const MAX_CONTEXT_EVIDENCE: u32 = 4_096;
const MAX_SELECTION_EVALUATIONS: u32 = 100_000;
const MAX_RECALL_NODES: u32 = 100_000;

/// Exact bounded inputs for the deterministic RecallEngine to ContextCompiler
/// pipeline. The authenticated context remains outside this plan so transports
/// can authorize it before decoding or inspecting query content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileContextPlan {
    /// Caller-stable ContextPack identity; retries and continuations reuse it.
    pub pack_id: ContextPackId,
    /// Current textual cue passed to deterministic recall.
    pub query: String,
    /// Explicit recall-gate and disclosure mode.
    pub mode: RecallMode,
    /// Typed recall intent used for route and temporal semantics.
    pub intent: RecallIntent,
    /// ContextPack shape and authorization purpose.
    pub purpose: PackPurpose,
    /// Exact retained commit; missing selects one pinned current snapshot.
    pub at_commit: Option<u64>,
    /// Caller-supplied current Unix time used only for temporal filtering.
    pub now_micros: i64,
    /// Required facets shared by recall sufficiency and ContextPack compilation.
    pub required_facets: Vec<PackFacetRequirement>,
    /// Strict recall work and token limits.
    pub recall_limits: RecallLimits,
    /// Strict compiler, rendering, and serialization limits.
    pub context_budgets: ContextBudgets,
    /// Exact renderer/model capability profile.
    pub model_profile: ModelProfile,
    /// Whether policy may treat this as an explicit request to mention memory.
    pub explicit_memory_request: bool,
    /// Whether factual recall requires primary evidence.
    pub require_primary_evidence: bool,
    /// Whether authorized evidence excerpts may cross the service boundary.
    pub include_evidence_quotes: bool,
    /// Whether an explicit unsupported/derived marker may substitute for evidence.
    pub permit_derived_only: bool,
    /// Maximum acceptable lag for every projection used by the pipeline.
    pub max_projection_lag_commits: u64,
    /// Return explicit warnings instead of failing when the lag ceiling is exceeded.
    pub allow_stale: bool,
    /// Optional caller-supplied exact vector in a declared vector space.
    pub query_vector: Option<SuppliedVector>,
    /// Opaque authenticated pipeline continuation issued by this service.
    pub continuation: Option<String>,
}

/// Fully authenticated typed ContextPack compilation request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileContextRequest {
    /// Host-authenticated caller, agent, subject, scope, and capability context.
    pub context: AuthenticatedRequestContext,
    /// Bounded deterministic recall/compiler plan.
    pub plan: CompileContextPlan,
}

/// Model-ready rendering with trusted control kept separate from untrusted data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedContextPayload {
    /// Model profile that selected this rendering.
    pub profile_id: String,
    /// Renderer used without changing canonical pack semantics.
    pub renderer: RendererKind,
    /// Compiler-generated control that contains no recalled payload.
    pub trusted_control: String,
    /// Authorized memory data with zero instruction capability.
    pub untrusted_data: String,
    /// Tokens consumed by trusted control.
    pub control_tokens: u32,
    /// Tokens consumed by untrusted data.
    pub data_tokens: u32,
    /// Total rendered tokens.
    pub total_tokens: u32,
}

/// Privacy-safe composition trace. It exposes only the pinned binding,
/// authorized-result counts, bounded work usage, and projection freshness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPackTrace {
    /// Keyed opaque handle over this exact result summary.
    pub trace_id: String,
    /// Pinned provider snapshot shared by recall and compilation.
    pub snapshot: ProviderSnapshot,
    /// Keyed digest of every recall policy/filter input.
    pub filter_digest: String,
    /// Deterministic recall outcome.
    pub recall_status: RecallStatus,
    /// Why deterministic recall stopped.
    pub stop_reason: StopReason,
    /// Strict recall work actually consumed.
    pub recall_usage: BudgetUsage,
    /// Canonical ContextPack outcome.
    pub pack_status: PackStatus,
    /// Strict compiler/render/serialization usage.
    pub pack_usage: ContextBudgetUsage,
    /// Number of authorized blocks present in the returned pack.
    pub selected_blocks: u32,
    /// Number of independently authorized evidence blocks in the pack.
    pub evidence_blocks: u32,
    /// Worst projection lag relative to the pinned snapshot.
    pub max_projection_lag_commits: u64,
    /// True when at least one projection trails the pinned snapshot.
    pub stale: bool,
    /// Stable content-free projection warning codes.
    pub freshness_warnings: Vec<String>,
}

/// Canonical typed ContextPack response. Internal recall/compiler continuation
/// states are wrapped into one authenticated service token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileContextResponse {
    /// Minimal model-neutral ContextPack compiled from the authorized recall set.
    pub context_pack: ContextPack,
    /// Versioned public schema used to encode `canonical_bytes`.
    pub canonical_encoding: String,
    /// Exact canonical Protobuf bytes whose digest binds this ContextPack.
    pub canonical_bytes: Vec<u8>,
    /// Hash algorithm used for `canonical_digest`.
    pub canonical_digest_algorithm: String,
    /// BLAKE3 digest of canonical ContextPack Protobuf bytes.
    pub canonical_digest: String,
    /// Model-specific placement preserving trusted/untrusted channel separation.
    pub rendered: RenderedContextPayload,
    /// Opaque next pipeline page, when either recall or compilation has more work.
    pub continuation: Option<String>,
    /// Privacy-safe result and freshness trace.
    pub trace: ContextPackTrace,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineCursor {
    schema_version: u16,
    binding_digest: String,
    snapshot_commit: u64,
    active_recall: Option<RecallContinuationToken>,
    next_recall: Option<RecallContinuationToken>,
    context: Option<ContextContinuationToken>,
}

#[derive(Debug)]
struct PinnedProvider<'a, P: RecallProvider + ?Sized> {
    inner: &'a P,
    snapshot: ProviderSnapshot,
}

impl<P: RecallProvider + ?Sized> RecallProvider for PinnedProvider<'_, P> {
    fn snapshot(&self, at_commit: Option<u64>) -> contextdb_recall::Result<ProviderSnapshot> {
        if at_commit.is_some_and(|commit| commit != self.snapshot.commit_seq) {
            return Err(RecallError::InvalidContinuation);
        }
        Ok(self.snapshot.clone())
    }

    fn authorized_corpus(
        &self,
        request: &ProviderRequest,
    ) -> contextdb_recall::Result<contextdb_recall::AuthorizedCorpus> {
        if request.snapshot != self.snapshot {
            return Err(RecallError::Provider(
                "authorized corpus requested for a different pinned snapshot".to_owned(),
            ));
        }
        self.inner.authorized_corpus(request)
    }
}

pub(crate) fn compile_reference_context(
    database: &ContextDb,
    continuation_key: &[u8; 32],
    request: CompileContextRequest,
) -> ServiceResult<CompileContextResponse> {
    let provider = ReferenceProvider { database };
    compile_provider_context(&provider, continuation_key, request)
}

/// Runs the canonical policy-first RecallEngine to ContextCompiler pipeline
/// over an arbitrary provider without exposing provider content before the
/// authenticated service contract and freshness checks succeed.
///
/// The provider is asked for exactly one snapshot. Every subsequent corpus
/// request is constrained to that exact snapshot, and the returned ContextPack,
/// privacy-safe trace, and continuation all carry the same snapshot/filter
/// binding. Durable production compositions should delegate here instead of
/// reimplementing selection, materialization, or continuation semantics.
pub fn compile_provider_context<P: RecallProvider + ?Sized>(
    provider: &P,
    continuation_key: &[u8; 32],
    request: CompileContextRequest,
) -> ServiceResult<CompileContextResponse> {
    crate::authenticated::require_capability(&request.context, Capability::Recall)?;
    if request.plan.model_profile.external_processing {
        crate::authenticated::require_capability(&request.context, Capability::ModelProcessing)?;
    }
    if request.plan.include_evidence_quotes {
        crate::authenticated::require_capability(&request.context, Capability::RawEvidence)?;
    }
    validate_plan(&request)?;

    let binding_digest = pipeline_binding_digest(&request)?;
    let cursor = decode_cursor(continuation_key, &request, &binding_digest)?;
    let requested_commit = cursor
        .as_ref()
        .map(|value| value.snapshot_commit)
        .or(request.plan.at_commit);
    // Pin and evaluate freshness before any provider content is authorized or
    // materialized. The engine receives this exact immutable snapshot.
    let snapshot = provider
        .snapshot(requested_commit)
        .map_err(map_recall_error)?;
    let freshness = enforce_freshness(
        &snapshot,
        request.plan.max_projection_lag_commits,
        request.plan.allow_stale,
    )?;
    let provider = PinnedProvider {
        inner: provider,
        snapshot: snapshot.clone(),
    };

    let active_recall = cursor
        .as_ref()
        .and_then(|value| value.active_recall.clone());
    let deterministic = deterministic_request(&request, active_recall)?;
    let engine = RecallEngine::new(*continuation_key);
    let mut recalled = engine
        .recall(&provider, &deterministic)
        .map_err(map_recall_error)?;
    // A skipped memory gate intentionally avoids corpus access. The service
    // still binds the explicit no-memory ContextPack to the already pinned,
    // non-content snapshot so every response has one coherent identity.
    if recalled.snapshot.is_none() {
        recalled.snapshot = Some(snapshot.clone());
        recalled.trace.snapshot = Some(snapshot.clone());
    }
    if recalled.snapshot.as_ref() != Some(&snapshot)
        || recalled.trace.snapshot.as_ref() != Some(&snapshot)
    {
        return Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "recall returned a result for a different pinned snapshot",
            false,
        ));
    }

    let context_provider = context_provider(&request, &recalled, &snapshot)?;
    let binding = RecallContextBinding::identity(&recalled).map_err(map_context_error)?;
    let compile_request = compile_request(
        &request,
        &deterministic,
        &recalled,
        cursor.as_ref().and_then(|value| value.context.clone()),
    )?;
    let compiler = ContextCompiler::new(*continuation_key).map_err(map_context_error)?;
    let compiled = compiler
        .compile_recall(
            &compile_request,
            &recalled,
            &binding,
            &context_provider,
            &ReferenceTokenizer,
        )
        .map_err(map_context_error)?;

    let continuation = next_pipeline_cursor(
        continuation_key,
        &binding_digest,
        &snapshot,
        cursor.as_ref(),
        &recalled,
        compiled.pack.continuation.clone(),
    )?;
    let rendered = RenderedContextPayload {
        profile_id: compiled.rendered.profile_id,
        renderer: compiled.rendered.renderer,
        trusted_control: compiled.rendered.trusted_control,
        untrusted_data: compiled.rendered.untrusted_data,
        control_tokens: compiled.rendered.control_tokens,
        data_tokens: compiled.rendered.data_tokens,
        total_tokens: compiled.rendered.total_tokens,
    };
    let selected_blocks =
        u32::try_from(compiled.pack.compilation.selected_blocks.len()).unwrap_or(u32::MAX);
    let evidence_blocks = u32::try_from(compiled.pack.evidence.len()).unwrap_or(u32::MAX);
    let filter_digest = recalled.trace.filter_digest;
    let pack_status = compiled.pack.status;
    let pack_usage = compiled.pack.compilation.usage;
    let canonical_bytes = compiled.canonical_protobuf;
    let canonical_digest = compiled.canonical_digest;
    if blake3::hash(&canonical_bytes).to_hex().as_str() != canonical_digest {
        return Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "ContextPack canonical bytes differ from the compiler digest",
            false,
        ));
    }
    let trace_id = crate::continuation::trace_id(
        continuation_key,
        &(
            &snapshot,
            &filter_digest,
            recalled.status,
            recalled.stop_reason,
            recalled.usage,
            pack_status,
            pack_usage,
            selected_blocks,
            evidence_blocks,
            freshness.max_lag,
            &freshness.warnings,
            &canonical_digest,
        ),
    )?;
    let response = CompileContextResponse {
        context_pack: compiled.pack,
        canonical_encoding: CONTEXT_PACK_CANONICAL_ENCODING.to_owned(),
        canonical_bytes,
        canonical_digest_algorithm: CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM.to_owned(),
        canonical_digest,
        rendered,
        continuation,
        trace: ContextPackTrace {
            trace_id,
            snapshot,
            filter_digest,
            recall_status: recalled.status,
            stop_reason: recalled.stop_reason,
            recall_usage: recalled.usage,
            pack_status,
            pack_usage,
            selected_blocks,
            evidence_blocks,
            max_projection_lag_commits: freshness.max_lag,
            stale: freshness.max_lag > 0,
            freshness_warnings: freshness.warnings,
        },
    };
    let response_bytes = serde_json::to_vec(&response).map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "ContextPack response serialization failed",
            false,
        )
    })?;
    if response_bytes.len() > MAX_COMPILE_RESPONSE_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "ContextPack response exceeds the 8 MiB service limit",
            false,
        ));
    }
    Ok(response)
}

fn validate_plan(request: &CompileContextRequest) -> ServiceResult<()> {
    let bytes = serde_json::to_vec(request).map_err(|_| invalid_request())?;
    if bytes.len() > MAX_COMPILE_REQUEST_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "ContextPack request exceeds the 1 MiB service limit",
            false,
        ));
    }
    let plan = &request.plan;
    if plan.query.trim().is_empty()
        || plan.query.len() > MAX_QUERY_BYTES
        || plan.query.contains('\0')
    {
        return Err(invalid_request());
    }
    let expected_purpose = contextdb_recall::purpose_key(&plan.purpose.core_purpose());
    if request.context.request.purpose != expected_purpose {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "ContextPack purpose differs from the authenticated purpose",
            false,
        ));
    }
    if request.context.request.scopes.is_empty()
        || plan.required_facets.len() > MAX_REQUIRED_FACETS
        || plan.required_facets.iter().any(|facet| {
            facet.name.trim().is_empty()
                || facet.name.len() > 1_024
                || facet.minimum_confidence_micros > 1_000_000
        })
    {
        return Err(invalid_request());
    }
    plan.recall_limits.validate().map_err(map_recall_error)?;
    if let Some(vector) = &plan.query_vector {
        vector.validate().map_err(map_recall_error)?;
        if vector.values.len() > MAX_VECTOR_DIMENSIONS {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "query vector exceeds the service dimension limit",
                false,
            ));
        }
    }
    let budgets = plan.context_budgets;
    let profile = &plan.model_profile;
    let invalid_context_shape = budgets.hard_tokens == 0
        || budgets.soft_tokens == 0
        || budgets.soft_tokens > budgets.hard_tokens
        || budgets.max_blocks == 0
        || budgets.max_evidence_blocks == 0
        || budgets.max_raw_evidence_tokens == 0
        || budgets.max_history_tokens == 0
        || budgets.max_conflict_tokens == 0
        || budgets.max_serialized_bytes == 0
        || budgets.max_selection_evaluations == 0
        || profile.id.trim().is_empty()
        || profile.family.trim().is_empty()
        || profile.tokenizer_id.trim().is_empty()
        || profile.max_context_tokens == 0
        || profile.reserved_output_tokens >= profile.max_context_tokens
        || profile.max_schema_complexity == 0
        || (profile.preferred_structured_format == StructuredFormat::ToolResult
            && !profile.supports_tool_results)
        || !matches!(
            (profile.renderer, profile.preferred_structured_format),
            (RendererKind::Compact, StructuredFormat::CompactText)
                | (RendererKind::HostedStructured, StructuredFormat::ToolResult)
                | (
                    RendererKind::Chat | RendererKind::Coding,
                    StructuredFormat::Markdown
                )
                | (RendererKind::CanonicalJson, StructuredFormat::Json)
        )
        || budgets.hard_tokens
            > profile
                .max_context_tokens
                .saturating_sub(profile.reserved_output_tokens);
    if invalid_context_shape {
        return Err(invalid_request());
    }
    if plan.context_budgets.hard_tokens > MAX_CONTEXT_TOKENS
        || plan.context_budgets.max_blocks > MAX_CONTEXT_BLOCKS
        || plan.context_budgets.max_evidence_blocks > MAX_CONTEXT_EVIDENCE
        || usize::try_from(plan.context_budgets.max_serialized_bytes).unwrap_or(usize::MAX)
            > MAX_COMPILE_REQUEST_BYTES
        || plan.context_budgets.max_selection_evaluations > MAX_SELECTION_EVALUATIONS
        || plan.recall_limits.max_nodes_examined > MAX_RECALL_NODES
        || plan.recall_limits.max_seed_candidates > MAX_RECALL_NODES
        || plan.recall_limits.max_frontier_per_hop > MAX_RECALL_NODES
        || plan.recall_limits.max_evidence_units > MAX_CONTEXT_EVIDENCE
        || plan.recall_limits.max_context_tokens > MAX_CONTEXT_TOKENS
    {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "ContextPack plan exceeds the service work or serialization profile",
            false,
        ));
    }
    Ok(())
}

fn deterministic_request(
    request: &CompileContextRequest,
    continuation: Option<RecallContinuationToken>,
) -> ServiceResult<DeterministicRecallRequest> {
    let context = &request.context;
    let scope_refs = context
        .request
        .scopes
        .iter()
        .map(|scope| {
            Ok(ScopeRef {
                kind: ScopeKind::Other("service_scope".to_owned()),
                id: ScopeId::from_uuid(stable_uuid("scope", scope)).map_err(core_error)?,
                inheritance: ScopeInheritance::Exact,
            })
        })
        .collect::<ServiceResult<Vec<_>>>()?;
    let scopes =
        NonEmptyVec::try_from_vec(scope_refs, "compile_context.scopes").map_err(core_error)?;
    let subject = MemorySubjectId::from_uuid(stable_uuid("subject", &context.request.subject_id))
        .map_err(core_error)?;
    let actor = ActorId::from_uuid(stable_uuid("actor", &context.actor_id)).map_err(core_error)?;
    let agent = AgentId::from_uuid(stable_uuid("agent", &context.agent_id)).map_err(core_error)?;
    let session_id = context
        .session_id
        .as_ref()
        .map(|value| SessionId::from_uuid(stable_uuid("session", value)).map_err(core_error))
        .transpose()?;
    let purpose = request.plan.purpose.core_purpose();
    let required_facets = request
        .plan
        .required_facets
        .iter()
        .map(|facet| FacetRequirement {
            name: facet.name.clone(),
            required: true,
            minimum_confidence: micros_to_unit(facet.minimum_confidence_micros),
        })
        .collect();
    let target_model = request
        .plan
        .model_profile
        .external_processing
        .then(|| {
            ModelProfileId::from_uuid(stable_uuid("model_profile", &request.plan.model_profile.id))
                .map_err(core_error)
        })
        .transpose()?;
    let mut principal_scopes = context.request.scopes.clone();
    principal_scopes.extend(scopes.iter().map(|scope| scope.id.to_string()));
    Ok(DeterministicRecallRequest {
        request: CoreRecallRequest {
            agent_id: agent,
            actor_id: actor,
            session_id,
            cues: CueBundle {
                current_input: QueryContent::Text(request.plan.query.clone()),
                recent_observations: Vec::new(),
                participants: NonEmptyVec::new(subject),
                active_referents: Vec::new(),
                active_topics: Vec::new(),
                temporal_context: TemporalContext {
                    now: TimestampMicros(request.plan.now_micros),
                    referenced_valid_time: None,
                    known_at: request.plan.at_commit.map(CommitSeq::new),
                },
                location_context: None,
                conversation_mode: ConversationMode::QuestionAnswering,
                goal: None,
                interaction_signals: Vec::new(),
            },
            intent: request.plan.intent.clone(),
            scopes,
            temporal: request
                .plan
                .at_commit
                .map_or(TemporalConstraint::Current, |commit_seq| {
                    TemporalConstraint::KnownAt {
                        commit_seq: CommitSeq::new(commit_seq),
                    }
                }),
            required_facets,
            budgets: RecallBudgets {
                max_tokens: request.plan.recall_limits.max_context_tokens,
                max_latency_micros: request.plan.recall_limits.deadline_micros,
                max_candidates: request.plan.recall_limits.max_nodes_examined,
                max_graph_visits: request.plan.recall_limits.max_nodes_examined,
                max_evidence_items: request.plan.recall_limits.max_evidence_units,
            },
            evidence_policy: EvidencePolicy {
                require_primary_evidence: request.plan.require_primary_evidence,
                include_quotes: request.plan.include_evidence_quotes,
                permit_derived_only: request.plan.permit_derived_only,
            },
            memory_use_policy: PolicyId::from_uuid(stable_uuid(
                "memory_use_policy",
                &context.authorization_binding_digest()?,
            ))
            .map_err(core_error)?,
            purpose: purpose.clone(),
            target_model,
        },
        principal: RecallPrincipal {
            subject: context.request.subject_id.clone(),
            audiences: context.request.audiences.clone(),
            workspace: context.request.workspace_id.clone(),
            scopes: principal_scopes,
            purpose: contextdb_recall::purpose_key(&purpose),
            clearance: recall_sensitivity(context.request.clearance),
        },
        mode: request.plan.mode,
        limits: request.plan.recall_limits,
        query_vector: request.plan.query_vector.clone(),
        continuation,
    })
}

fn compile_request(
    request: &CompileContextRequest,
    deterministic: &DeterministicRecallRequest,
    recalled: &DeterministicRecallResult,
    continuation: Option<ContextContinuationToken>,
) -> ServiceResult<CompileRequest> {
    let snapshot = recalled.snapshot.clone().ok_or_else(|| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "recall result has no pinned snapshot",
            false,
        )
    })?;
    Ok(CompileRequest {
        pack_id: request.plan.pack_id,
        snapshot,
        principal: deterministic.principal.clone(),
        filter_digest: recalled.trace.filter_digest.clone(),
        purpose: request.plan.purpose,
        scopes: request.context.request.scopes.clone(),
        temporal_view: deterministic.request.temporal,
        required_facets: request.plan.required_facets.clone(),
        budgets: request.plan.context_budgets,
        model_profile: request.plan.model_profile.clone(),
        explicit_memory_request: request.plan.explicit_memory_request,
        require_primary_evidence: request.plan.require_primary_evidence,
        continuation,
    })
}

fn context_provider(
    request: &CompileContextRequest,
    recalled: &DeterministicRecallResult,
    snapshot: &ProviderSnapshot,
) -> ServiceResult<InMemoryContextProvider> {
    let included = recalled
        .items
        .iter()
        .filter(|item| item.use_decision.is_included())
        .collect::<Vec<_>>();
    let access = sealed_access(request);
    let mut candidates = Vec::with_capacity(included.len());
    let mut evidence = Vec::new();
    for (index, item) in included.into_iter().enumerate() {
        let content = item.content.as_ref().ok_or_else(|| {
            ServiceError::new(
                ErrorCode::IntegrityFailure,
                "included recall item is missing authorized content",
                false,
            )
        })?;
        let is_situation = index == 0;
        let kind = if is_situation {
            PackBlockKind::Situation
        } else {
            pack_kind(item.kind)
        };
        let claim_id = kind
            .is_factual()
            .then(|| {
                ClaimId::from_uuid(stable_uuid("claim", item.document_id.as_str()))
                    .map_err(core_error)
            })
            .transpose()?;
        let selected_evidence = recalled
            .evidence
            .iter()
            .filter(|entry| entry.document_id == item.document_id)
            .collect::<Vec<_>>();
        let evidence_handles = if claim_id.is_some() {
            selected_evidence
                .iter()
                .map(|entry| EvidenceHandle::new(&entry.evidence.id).map_err(map_context_error))
                .collect::<ServiceResult<BTreeSet<_>>>()?
        } else {
            BTreeSet::new()
        };
        if let Some(claim_id) = claim_id {
            for entry in selected_evidence {
                evidence.push(ContextProviderEvidence {
                    access: access.clone(),
                    external_model_use: PolicyDecision::Allow,
                    evidence: PackEvidence {
                        original_span: None,
                        id: EvidenceHandle::new(&entry.evidence.id).map_err(map_context_error)?,
                        source: SourceHandle::new(
                            entry
                                .evidence
                                .source_observation
                                .clone()
                                .unwrap_or_else(|| {
                                    format!("recall-evidence:{}", entry.evidence.id)
                                }),
                        )
                        .map_err(map_context_error)?,
                        selector: EvidenceSelector::Whole,
                        excerpt: entry.evidence.excerpt.clone(),
                        claim_ids: BTreeSet::from([claim_id]),
                        provenance_family: "recall:selected:v1".to_owned(),
                        primary: entry.evidence.primary,
                        trust_micros: unit_to_micros(entry.evidence.trust),
                        source_class: SourceClass::Imported,
                        taints: BTreeSet::from([ContentTaint::UserControlled]),
                        lineage: Vec::new(),
                    },
                });
            }
        }
        let supported = !kind.is_factual() || !evidence_handles.is_empty();
        let interpretation = match item.use_decision {
            MemoryUseDecision::IncludeOnlyAsConstraint => InterpretationRule::ConstraintData,
            MemoryUseDecision::IncludeOnlyAsStyleSignal => InterpretationRule::StyleSignal,
            MemoryUseDecision::IncludeAndMention | MemoryUseDecision::IncludeSilently
                if matches!(kind, PackBlockKind::Episode | PackBlockKind::SharedHistory) =>
            {
                InterpretationRule::HistoricalData
            }
            MemoryUseDecision::IncludeAndMention | MemoryUseDecision::IncludeSilently => {
                InterpretationRule::FactualData
            }
            MemoryUseDecision::WithholdDueToUncertainty
            | MemoryUseDecision::WithholdDueToPrivacy
            | MemoryUseDecision::WithholdAsIrrelevant => {
                return Err(ServiceError::new(
                    ErrorCode::IntegrityFailure,
                    "withheld recall item entered ContextPack materialization",
                    false,
                ));
            }
        };
        let claim_ids = claim_id.into_iter().collect::<BTreeSet<_>>();
        let memory_refs = claim_id
            .into_iter()
            .map(|id| MemoryRef::Claim { id })
            .collect();
        let unknown =
            (kind == PackBlockKind::Unknown).then(|| contextdb_context::UnknownDescriptor {
                question: content.clone(),
                reason: "recall preserved an unknown or conflicted result".to_owned(),
                blocking: true,
            });
        candidates.push(ProviderCandidate {
            access: access.clone(),
            use_policy: sealed_use_policy(item.use_decision),
            candidate: PackCandidate {
                id: BlockId::new(item.document_id.as_str()).map_err(map_context_error)?,
                kind,
                representations: vec![BlockRepresentation {
                    level: CompressionLevel::L0Orientation,
                    summary: content.clone(),
                    fields: BTreeMap::new(),
                    omitted_facets: BTreeSet::new(),
                }],
                exact_fragments: Vec::new(),
                memory_refs,
                claim_ids,
                evidence_handles,
                facets: item.covered_facets.clone(),
                scopes: request.context.request.scopes.clone(),
                valid_time: None,
                known_at_commit: snapshot.commit_seq,
                perspective: if kind.is_factual() {
                    Some(contextdb_core::Perspective {
                        knower: MemorySubjectId::from_uuid(stable_uuid(
                            "subject",
                            &request.context.request.subject_id,
                        ))
                        .map_err(core_error)?,
                        experiencer: None,
                        narrator: ActorId::from_uuid(stable_uuid(
                            "actor",
                            &request.context.actor_id,
                        ))
                        .map_err(core_error)?,
                        role: EpistemicRole::Asserter,
                    })
                } else {
                    None
                },
                epistemic: EpistemicState {
                    basis: if supported {
                        EpistemicBasis::Observation
                    } else {
                        EpistemicBasis::ActorAssertion
                    },
                    acceptance: AcceptanceState::Accepted,
                    conflict: ConflictState::None,
                    lifecycle: LifecycleState::Active,
                },
                confidence_micros: u32::try_from(item.score.final_micros.min(1_000_000))
                    .unwrap_or(1_000_000),
                trust: contextdb_context::ContentTrust::Mixed,
                instruction_capability: InstructionCapability::None,
                source_class: SourceClass::Imported,
                taints: BTreeSet::from([ContentTaint::UserControlled]),
                interpretation,
                support: if supported {
                    SupportState::Supported
                } else {
                    SupportState::Unsupported {
                        reason: "authorized recall item has no selected evidence".to_owned(),
                    }
                },
                conflict: None,
                unknown,
                utility_micros: item.score.final_micros.max(1),
                mandatory: is_situation
                    || item.use_decision == MemoryUseDecision::IncludeOnlyAsConstraint,
            },
        });
    }
    InMemoryContextProvider::new(snapshot.clone(), candidates, evidence).map_err(map_context_error)
}

fn sealed_access(request: &CompileContextRequest) -> AccessRule {
    AccessRule {
        workspace: request.context.request.workspace_id.clone(),
        scopes: request.context.request.scopes.clone(),
        owners: BTreeSet::from([request.context.request.subject_id.clone()]),
        audience_purpose_grants: BTreeMap::from([(
            request.context.request.subject_id.clone(),
            BTreeSet::from([request.context.request.purpose.clone()]),
        )]),
        sensitivity: recall_sensitivity(request.context.request.clearance),
        required_compartments: BTreeSet::new(),
        consent: AccessConsent::Granted,
        retrievable: true,
    }
}

const fn sealed_use_policy(decision: MemoryUseDecision) -> CandidateUsePolicy {
    CandidateUsePolicy {
        influence: PolicyDecision::Allow,
        mention: if matches!(decision, MemoryUseDecision::IncludeAndMention) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        },
        external_model_use: PolicyDecision::Allow,
        disclosure: if matches!(decision, MemoryUseDecision::IncludeAndMention) {
            DisclosureRule::MayMention
        } else {
            DisclosureRule::UseSilently
        },
    }
}

const fn pack_kind(kind: RecallDocumentKind) -> PackBlockKind {
    match kind {
        RecallDocumentKind::Entity => PackBlockKind::Participant,
        RecallDocumentKind::Claim
        | RecallDocumentKind::Observation
        | RecallDocumentKind::Reflection
        | RecallDocumentKind::Knowledge
        | RecallDocumentKind::Domain => PackBlockKind::Fact,
        RecallDocumentKind::Relationship => PackBlockKind::Relationship,
        RecallDocumentKind::SharedReference => PackBlockKind::SharedHistory,
        RecallDocumentKind::Episode => PackBlockKind::Episode,
        RecallDocumentKind::Preference => PackBlockKind::Preference,
        RecallDocumentKind::Boundary => PackBlockKind::Boundary,
        RecallDocumentKind::Goal => PackBlockKind::Goal,
        RecallDocumentKind::Commitment => PackBlockKind::OpenLoop,
        RecallDocumentKind::Procedure => PackBlockKind::Procedure,
        RecallDocumentKind::Decision => PackBlockKind::Decision,
        RecallDocumentKind::Conflict | RecallDocumentKind::Unknown => PackBlockKind::Unknown,
    }
}

fn pipeline_binding_digest(request: &CompileContextRequest) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        schema_version: u16,
        authorization: String,
        pack_id: ContextPackId,
        query: &'a str,
        mode: RecallMode,
        intent: &'a RecallIntent,
        purpose: PackPurpose,
        at_commit: Option<u64>,
        now_micros: i64,
        required_facets: &'a [PackFacetRequirement],
        recall_limits: RecallLimits,
        context_budgets: ContextBudgets,
        model_profile: &'a ModelProfile,
        explicit_memory_request: bool,
        require_primary_evidence: bool,
        include_evidence_quotes: bool,
        permit_derived_only: bool,
        max_projection_lag_commits: u64,
        allow_stale: bool,
        query_vector: &'a Option<SuppliedVector>,
    }
    crate::continuation::digest_value(&Binding {
        schema_version: PIPELINE_CURSOR_VERSION,
        authorization: request.context.authorization_binding_digest()?,
        pack_id: request.plan.pack_id,
        query: &request.plan.query,
        mode: request.plan.mode,
        intent: &request.plan.intent,
        purpose: request.plan.purpose,
        at_commit: request.plan.at_commit,
        now_micros: request.plan.now_micros,
        required_facets: &request.plan.required_facets,
        recall_limits: request.plan.recall_limits,
        context_budgets: request.plan.context_budgets,
        model_profile: &request.plan.model_profile,
        explicit_memory_request: request.plan.explicit_memory_request,
        require_primary_evidence: request.plan.require_primary_evidence,
        include_evidence_quotes: request.plan.include_evidence_quotes,
        permit_derived_only: request.plan.permit_derived_only,
        max_projection_lag_commits: request.plan.max_projection_lag_commits,
        allow_stale: request.plan.allow_stale,
        query_vector: &request.plan.query_vector,
    })
}

fn decode_cursor(
    key: &[u8; 32],
    request: &CompileContextRequest,
    binding_digest: &str,
) -> ServiceResult<Option<PipelineCursor>> {
    let Some(token) = request.plan.continuation.as_deref() else {
        return Ok(None);
    };
    let cursor: PipelineCursor = crate::continuation::decode_value(key, token)?;
    let invalid_shape = cursor.schema_version != PIPELINE_CURSOR_VERSION
        || cursor.binding_digest != binding_digest
        || (cursor.context.is_none() && cursor.active_recall.is_none())
        || (cursor.next_recall.is_some() && cursor.context.is_none())
        || cursor
            .active_recall
            .as_ref()
            .is_some_and(|value| value.snapshot.commit_seq != cursor.snapshot_commit)
        || cursor
            .next_recall
            .as_ref()
            .is_some_and(|value| value.snapshot.commit_seq != cursor.snapshot_commit);
    if invalid_shape {
        return Err(invalid_continuation());
    }
    Ok(Some(cursor))
}

fn next_pipeline_cursor(
    key: &[u8; 32],
    binding_digest: &str,
    snapshot: &ProviderSnapshot,
    prior: Option<&PipelineCursor>,
    recalled: &DeterministicRecallResult,
    next_context: Option<ContextContinuationToken>,
) -> ServiceResult<Option<String>> {
    let prior_active = prior.and_then(|value| value.active_recall.clone());
    let held_next = prior.and_then(|value| value.next_recall.clone());
    let next = if next_context.is_some() {
        Some(PipelineCursor {
            schema_version: PIPELINE_CURSOR_VERSION,
            binding_digest: binding_digest.to_owned(),
            snapshot_commit: snapshot.commit_seq,
            active_recall: prior_active,
            next_recall: held_next.or_else(|| recalled.continuation.clone()),
            context: next_context,
        })
    } else {
        held_next
            .or_else(|| recalled.continuation.clone())
            .map(|next_recall| PipelineCursor {
                schema_version: PIPELINE_CURSOR_VERSION,
                binding_digest: binding_digest.to_owned(),
                snapshot_commit: snapshot.commit_seq,
                active_recall: Some(next_recall),
                next_recall: None,
                context: None,
            })
    };
    next.as_ref()
        .map(|value| crate::continuation::encode_value(key, value))
        .transpose()
}

#[derive(Debug)]
struct ProjectionFreshness {
    max_lag: u64,
    warnings: Vec<String>,
}

fn projection_freshness(snapshot: &ProviderSnapshot) -> ProjectionFreshness {
    let mut max_lag = 0_u64;
    let mut warnings = Vec::new();
    let mut observe = |name: &str, watermark: u64| {
        let lag = snapshot.commit_seq.saturating_sub(watermark);
        max_lag = max_lag.max(lag);
        if lag > 0 {
            warnings.push(name.to_owned());
        }
    };
    observe("journal_projection_lag", snapshot.watermarks.journal);
    observe("semantic_projection_lag", snapshot.watermarks.semantic);
    observe("lexical_projection_lag", snapshot.watermarks.lexical);
    observe("graph_projection_lag", snapshot.watermarks.graph);
    for watermark in snapshot.watermarks.vector.values() {
        observe("vector_projection_lag", *watermark);
    }
    for watermark in snapshot.watermarks.hierarchy.values() {
        observe("hierarchy_projection_lag", *watermark);
    }
    warnings.sort();
    warnings.dedup();
    ProjectionFreshness { max_lag, warnings }
}

fn enforce_freshness(
    snapshot: &ProviderSnapshot,
    max_projection_lag_commits: u64,
    allow_stale: bool,
) -> ServiceResult<ProjectionFreshness> {
    let freshness = projection_freshness(snapshot);
    if freshness.max_lag > max_projection_lag_commits && !allow_stale {
        return Err(ServiceError::new(
            ErrorCode::IndexTooStale,
            "a required recall projection exceeds the requested freshness ceiling",
            true,
        ));
    }
    Ok(freshness)
}

fn recall_sensitivity(value: Sensitivity) -> RecallSensitivity {
    match value {
        Sensitivity::Public => RecallSensitivity::Public,
        Sensitivity::Internal => RecallSensitivity::Internal,
        Sensitivity::Private => RecallSensitivity::Confidential,
        Sensitivity::Restricted => RecallSensitivity::Restricted,
    }
}

fn stable_uuid(domain: &str, value: &str) -> Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-service-stable-id-v1");
    hasher.update(&[0]);
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "micros are deliberately converted to the core unit-interval API"
)]
fn micros_to_unit(value: u32) -> f32 {
    value.min(1_000_000) as f32 / 1_000_000.0
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "validated unit floats are deterministically quantized to integer micros"
)]
fn unit_to_micros(value: f32) -> u32 {
    (f64::from(value.clamp(0.0, 1.0)) * 1_000_000.0).round() as u32
}

fn map_recall_error(error: RecallError) -> ServiceError {
    match error {
        RecallError::InvalidRequest(_) => invalid_request(),
        RecallError::Provider(_) => ServiceError::new(
            ErrorCode::ProviderUnavailable,
            "deterministic recall provider failed",
            true,
        ),
        RecallError::InvalidContinuation => invalid_continuation(),
        RecallError::DeadlineExceeded => ServiceError::new(
            ErrorCode::BudgetExhausted,
            "deterministic recall deadline was exhausted",
            true,
        ),
        _ => ServiceError::new(
            ErrorCode::ProviderUnavailable,
            "deterministic recall failed",
            true,
        ),
    }
}

fn map_context_error(error: ContextError) -> ServiceError {
    match error {
        ContextError::InvalidRequest(_) => invalid_request(),
        ContextError::Provider(_) => ServiceError::new(
            ErrorCode::ProviderUnavailable,
            "ContextPack provider failed",
            true,
        ),
        ContextError::Authorization(_) => ServiceError::new(
            ErrorCode::PermissionDenied,
            "ContextPack authorization binding failed",
            false,
        ),
        ContextError::BudgetExceeded(_) => ServiceError::new(
            ErrorCode::BudgetExhausted,
            "ContextPack could not satisfy its hard budget",
            false,
        ),
        ContextError::InvalidContinuation(_) => invalid_continuation(),
        ContextError::Tokenizer(_) | ContextError::Serialization(_) => ServiceError::new(
            ErrorCode::IntegrityFailure,
            "ContextPack compilation integrity failed",
            false,
        ),
    }
}

fn core_error(_error: contextdb_core::ValidationError) -> ServiceError {
    invalid_request()
}

fn invalid_request() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidArgument,
        "ContextPack request violates the bounded typed contract",
        false,
    )
}

fn invalid_continuation() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidContinuation,
        "ContextPack continuation is invalid or bound to another plan",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthenticationEvidence, CognitiveMemoryService, PublishMemoryRequest, ReferenceService,
        RequestContext,
    };
    use contextdb_context::{
        CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM, CONTEXT_PACK_CANONICAL_ENCODING,
        CanonicalSerializer, InstructionHierarchy, PositionProfile, StructuredFormat,
    };
    use contextdb_recall::RecallWatermarks;

    fn authenticated(subject: &str, request_id: &str) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: RequestContext {
                request_id: request_id.to_owned(),
                workspace_id: "workspace:context-pack".to_owned(),
                subject_id: subject.to_owned(),
                audiences: BTreeSet::from([subject.to_owned()]),
                scopes: BTreeSet::from(["project:context-pack".to_owned()]),
                purpose: "conversation".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: format!("actor:{subject}"),
            agent_id: "agent:context-pack".to_owned(),
            session_id: Some("session:context-pack".to_owned()),
            capability_grants: BTreeSet::from([
                Capability::Observe,
                Capability::Correct,
                Capability::Recall,
            ]),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: "channel:context-pack".to_owned(),
                peer_identity: format!("actor:{subject}"),
                binding_digest: "41".repeat(32),
            },
        }
    }

    fn plan(query: &str) -> CompileContextPlan {
        CompileContextPlan {
            pack_id: ContextPackId::from_uuid(stable_uuid("pack", "test-pack"))
                .expect("stable pack ID"),
            query: query.to_owned(),
            mode: RecallMode::Required,
            intent: RecallIntent::CurrentTruth,
            purpose: PackPurpose::Conversation,
            at_commit: None,
            now_micros: 0,
            required_facets: Vec::new(),
            recall_limits: RecallLimits {
                max_nodes_examined: 128,
                max_seed_candidates: 128,
                max_graph_hops: 2,
                max_frontier_per_hop: 128,
                max_evidence_units: 32,
                max_context_tokens: 2_048,
                deadline_micros: 5_000_000,
            },
            context_budgets: ContextBudgets {
                hard_tokens: 2_048,
                soft_tokens: 1_024,
                max_blocks: 32,
                max_evidence_blocks: 32,
                max_raw_evidence_tokens: 1_024,
                max_history_tokens: 1_024,
                max_conflict_tokens: 1_024,
                max_serialized_bytes: 256 * 1024,
                max_selection_evaluations: 128,
            },
            model_profile: ModelProfile {
                id: "model:local-test".to_owned(),
                family: "reference".to_owned(),
                tokenizer_id: ReferenceTokenizer::ID.to_owned(),
                renderer: RendererKind::Compact,
                max_context_tokens: 4_096,
                reserved_output_tokens: 1_024,
                preferred_structured_format: StructuredFormat::CompactText,
                supports_tool_results: false,
                supports_native_citations: false,
                supports_prompt_caching: false,
                position_profile: PositionProfile::SmallModelExplicit,
                instruction_hierarchy: InstructionHierarchy::SinglePromptDelimited,
                max_schema_complexity: 32,
                external_processing: false,
            },
            explicit_memory_request: false,
            require_primary_evidence: false,
            include_evidence_quotes: false,
            permit_derived_only: true,
            max_projection_lag_commits: 0,
            allow_stale: false,
            query_vector: None,
            continuation: None,
        }
    }

    fn remember(service: &ReferenceService, subject: &str, id: &str, text: &str) {
        service
            .publish_memory(PublishMemoryRequest {
                context: authenticated(subject, &format!("request:remember:{id}")),
                idempotency_key: format!("idempotency:{subject}:{id}"),
                memory_id: id.to_owned(),
                value: serde_json::json!({"text": text}),
                search_text: text.to_owned(),
            })
            .expect("publish explicit memory");
    }

    #[test]
    fn freshness_is_deterministic_and_does_not_expose_vector_space_names() {
        let snapshot = ProviderSnapshot {
            database_id: "db:test".to_owned(),
            commit_seq: 9,
            watermarks: RecallWatermarks {
                journal: 9,
                semantic: 7,
                lexical: 8,
                vector: BTreeMap::from([("tenant-secret-space".to_owned(), 5)]),
                graph: 9,
                hierarchy: BTreeMap::from([("tenant-secret-view".to_owned(), 6)]),
            },
        };
        let freshness = projection_freshness(&snapshot);
        assert_eq!(freshness.max_lag, 4);
        assert_eq!(
            freshness.warnings,
            vec![
                "hierarchy_projection_lag",
                "lexical_projection_lag",
                "semantic_projection_lag",
                "vector_projection_lag",
            ]
        );
        let trace = serde_json::to_string(&freshness.warnings).expect("warnings");
        assert!(!trace.contains("tenant-secret"));
        assert_eq!(
            enforce_freshness(&snapshot, 3, false)
                .expect_err("lag ceiling")
                .code,
            ErrorCode::IndexTooStale
        );
        assert_eq!(
            enforce_freshness(&snapshot, 3, true)
                .expect("explicit stale warning")
                .max_lag,
            4
        );
    }

    #[test]
    fn reference_pipeline_returns_one_bound_minimal_pack_and_safe_trace() {
        let service =
            ReferenceService::new("context-pack-reference", [0x52; 32]).expect("reference service");
        remember(
            &service,
            "subject:alice",
            "memory:espresso",
            "The project codename is Espresso",
        );
        remember(
            &service,
            "subject:bob",
            "memory:forbidden",
            "FORBIDDEN-CANARY-DO-NOT-LEAK",
        );
        let response = service
            .compile_context(CompileContextRequest {
                context: authenticated("subject:alice", "request:compile"),
                plan: plan("remember the project codename Espresso"),
            })
            .expect("compile ContextPack");

        response.context_pack.validate().expect("valid ContextPack");
        assert_eq!(response.context_pack.snapshot, response.trace.snapshot);
        assert_eq!(
            response.context_pack.scope_manifest.filter_digest,
            response.trace.filter_digest
        );
        assert_eq!(
            response.context_pack.provenance.policy_filter_digest,
            response.trace.filter_digest
        );
        assert_eq!(response.context_pack.sections.situation.len(), 1);
        assert_eq!(
            CanonicalSerializer::digest(&response.context_pack).expect("canonical digest"),
            response.canonical_digest
        );
        assert_eq!(response.canonical_encoding, CONTEXT_PACK_CANONICAL_ENCODING);
        assert_eq!(
            response.canonical_digest_algorithm,
            CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM
        );
        assert_eq!(
            CanonicalSerializer::to_protobuf(&response.context_pack)
                .expect("canonical Protobuf bytes"),
            response.canonical_bytes
        );
        assert_eq!(
            blake3::hash(&response.canonical_bytes).to_hex().as_str(),
            response.canonical_digest
        );
        let encoded = serde_json::to_string(&response).expect("response JSON");
        assert!(encoded.contains("Espresso"));
        assert!(!encoded.contains("FORBIDDEN-CANARY-DO-NOT-LEAK"));
        let trace = serde_json::to_string(&response.trace).expect("trace JSON");
        assert!(!trace.contains("Espresso"));
        assert!(!trace.contains("FORBIDDEN"));
        assert!(encoded.len() <= MAX_COMPILE_RESPONSE_BYTES);
    }

    #[test]
    fn pipeline_continuation_is_snapshot_bound_and_rejects_tampering_and_plan_drift() {
        let service = ReferenceService::new("context-pack-continuation", [0x63; 32])
            .expect("reference service");
        for (index, suffix) in ["alpha", "beta", "gamma", "delta"].into_iter().enumerate() {
            remember(
                &service,
                "subject:alice",
                &format!("memory:{index}"),
                &format!(
                    "shared recall marker {suffix} {}",
                    "bounded-memory-content ".repeat(12)
                ),
            );
        }
        let mut first_request = CompileContextRequest {
            context: authenticated("subject:alice", "request:first-page"),
            plan: plan("shared recall marker"),
        };
        first_request.plan.required_facets = vec![PackFacetRequirement {
            name: "facet:deliberately-missing".to_owned(),
            minimum_confidence_micros: 1,
            require_evidence: false,
        }];
        first_request.plan.recall_limits.max_context_tokens = 90;
        let first = service
            .compile_context(first_request.clone())
            .expect("first pipeline page");
        let token = first.continuation.clone().expect("recall continuation");

        let mut next_request = first_request.clone();
        next_request.context.request.request_id = "request:second-page".to_owned();
        next_request.plan.continuation = Some(token.clone());
        let second = service
            .compile_context(next_request)
            .expect("fresh request ID may resume the same authority and plan");
        assert_eq!(first.trace.snapshot, second.trace.snapshot);
        assert_eq!(first.trace.filter_digest, second.trace.filter_digest);

        let mut drifted = first_request.clone();
        drifted.plan.query.push_str(" changed");
        drifted.plan.continuation = Some(token.clone());
        assert_eq!(
            service
                .compile_context(drifted)
                .expect_err("query drift")
                .code,
            ErrorCode::InvalidContinuation
        );

        let mut bytes = token.into_bytes();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        let mut tampered = first_request;
        tampered.plan.continuation = Some(String::from_utf8(bytes).expect("ASCII token"));
        assert_eq!(
            service
                .compile_context(tampered)
                .expect_err("tampered continuation")
                .code,
            ErrorCode::InvalidContinuation
        );
    }
}
