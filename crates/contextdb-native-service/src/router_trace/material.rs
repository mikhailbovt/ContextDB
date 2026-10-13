//! Bounded generic discovery through the existing native resolver and recall engine.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::{
    BlockId, BlockRepresentation, CompressionLevel, ContentTaint, ContentTrust, DisclosureRule,
    EvidenceDependencies, EvidenceHandle, InstructionCapability, InterpretationRule, PackBlockKind,
    PackCandidate, ProviderCandidate, ProviderEvidence, SourceClass, SupportState,
    UnknownDescriptor,
};
use contextdb_core::{
    AcceptanceState, ClaimId, ConflictSetId, ConflictState, EdgeId, EpistemicBasis, EpistemicState,
    EvidenceId, LifecycleState, MemoryRef, NodeId, PolicyDecision, QueryContent,
};
use contextdb_recall::{
    AuthorizedCorpus, BudgetUsage, DeterministicRecallRequest, MemoryUseDecision, ProviderRequest,
    ProviderSnapshot, QueryBudget, RecallEngine, RecallError, RecallProvider, RecallStatus,
    RecallTrace, StopReason,
};
use contextdb_service::{
    AuthenticatedRequestContext, ErrorCode, MemoryRecordKind, PrepareContextRequest, ServiceError,
    ServiceResult,
};
use contextdb_storage::ReadSnapshot;
use serde::{Deserialize, Serialize};

use super::controls::RouterTraceControls;
use crate::provider::{NativeRecallFrontier, NativeRecallProvider, NativeRecallRecord};
use crate::raw_index::budget_error;
use crate::{NativeService, canonical_digest, integrity, invalid};

pub(crate) struct GenericRouterFrontier {
    pub(crate) candidates: Vec<ProviderCandidate>,
    pub(crate) evidence: BTreeMap<EvidenceHandle, ProviderEvidence>,
    pub(crate) dependencies: BTreeMap<BlockId, EvidenceDependencies>,
    pub(crate) unit_origins: BTreeMap<BlockId, RouterTraceControls>,
    pub(crate) evidence_origins: BTreeMap<EvidenceHandle, RouterTraceControls>,
    pub(crate) inspected_origins: RouterTraceControls,
    pub(crate) discovery: GenericRecallObservation,
}

/// Protected observations of one actual generic query. Complete means this
/// bounded recall operation completed, not that semantic recall covers history.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenericRecallObservation {
    pub(crate) query_digest: String,
    pub(crate) snapshot: ProviderSnapshot,
    pub(crate) status: RecallStatus,
    pub(crate) stop_reason: StopReason,
    pub(crate) usage: BudgetUsage,
    pub(crate) trace: RecallTrace,
    pub(crate) inspected_records: u32,
}

/// The publication owner supplies the already bound deterministic query. The
/// provider remains lazy so a skipped memory gate does not inspect record data.
pub(crate) fn generic_frontier<S: ReadSnapshot>(
    service: &NativeService,
    snapshot: &S,
    request: &PrepareContextRequest,
    deterministic: &DeterministicRecallRequest,
    budget: &mut QueryBudget,
) -> ServiceResult<GenericRouterFrontier> {
    let query = request
        .memory_query
        .as_ref()
        .ok_or_else(|| invalid("generic preparation query is absent"))?;
    if deterministic.continuation.is_some()
        || deterministic.principal.workspace != request.context.request.workspace_id
        || deterministic.principal.subject != request.context.request.subject_id
        || deterministic.principal.audiences != request.context.request.audiences
        || deterministic.principal.scopes != request.context.request.scopes
        || deterministic.principal.purpose != request.context.request.purpose
        || deterministic.request.cues.current_input != QueryContent::Text(query.query.clone())
    {
        return Err(invalid("generic preparation query binding differs"));
    }
    deterministic
        .validate()
        .map_err(|_| invalid("generic preparation query is invalid"))?;
    let known = deterministic
        .request
        .cues
        .temporal_context
        .known_at
        .ok_or_else(|| invalid("generic preparation knowledge is not pinned"))?
        .get();
    budget.charge(1, 0).map_err(budget_error)?;
    let (_, world) =
        service.select_snapshot(snapshot, &request.context.request.workspace_id, Some(known))?;
    let binding = NativeRecallProvider::provider_snapshot(&world, &service.database_id);
    let mut operation = deterministic.clone();
    operation.limits.deadline_micros = operation
        .limits
        .deadline_micros
        .min(budget.remaining_timeout_micros().map_err(budget_error)?);
    let provider = TracedProvider {
        native: NativeRecallProvider::new(service, &request.context.request.workspace_id),
        snapshot,
        context: &request.context,
        binding: binding.clone(),
        budget: RefCell::new(&mut *budget),
        frontier: RefCell::new(None),
        failure: RefCell::new(None),
        max_graph_hops: operation.limits.max_graph_hops,
    };
    let result = RecallEngine::new(*service.token_key).recall(&provider, &operation);
    let failure = provider.failure.borrow_mut().take();
    let frontier = provider.frontier.borrow_mut().take();
    drop(provider);
    if let Some(error) = failure {
        return Err(error);
    }
    budget.check().map_err(budget_error)?;
    let mut recalled = result.map_err(recall_error)?;
    if recalled.snapshot.is_none() {
        recalled.snapshot = Some(binding.clone());
        recalled.trace.snapshot = Some(binding.clone());
    }
    if recalled.snapshot.as_ref() != Some(&binding)
        || recalled.trace.snapshot.as_ref() != Some(&binding)
    {
        return Err(integrity("generic recall changed its pinned native view"));
    }
    let mut inspected_origins = RouterTraceControls::default();
    let mut candidates = Vec::new();
    let mut unit_origins = BTreeMap::new();
    let inspected_records = frontier
        .as_ref()
        .map_or(0, |value| value.records.len() as u32);
    if let Some(frontier) = frontier {
        let mut record_origins = BTreeMap::new();
        for (id, record) in &frontier.records {
            let origin = record_controls(service, snapshot, record, budget)?;
            inspected_origins.union_checked(&origin)?;
            record_origins.insert(id, origin);
        }
        for item in &recalled.items {
            if !item.use_decision.is_included() {
                continue;
            }
            budget.charge(1, 0).map_err(budget_error)?;
            let record = frontier
                .records
                .get(&item.document_id)
                .ok_or_else(|| integrity("generic result lacks its exact native origin"))?;
            let source = frontier
                .corpus
                .documents()
                .iter()
                .find(|document| document.id == item.document_id)
                .ok_or_else(|| integrity("generic result left its authorized corpus"))?;
            if item.content.as_deref() != Some(source.text.as_str()) {
                return Err(integrity(
                    "generic result content differs from native material",
                ));
            }
            let candidate = materialize(
                record,
                item,
                source,
                &request.context.request.scopes,
                budget,
            )?;
            let id = candidate.candidate.id.clone();
            let origin = record_origins
                .get(&item.document_id)
                .ok_or_else(|| integrity("generic result lacks its inherited native origins"))?;
            if unit_origins.insert(id, origin.clone()).is_some() {
                return Err(integrity("generic material repeats a candidate identity"));
            }
            candidates.push(candidate);
        }
    } else if recalled.status != RecallStatus::Skipped {
        return Err(integrity(
            "generic recall did not retain its inspected frontier",
        ));
    }
    let discovery = GenericRecallObservation {
        query_digest: canonical_digest(query)?,
        snapshot: binding,
        status: recalled.status,
        stop_reason: recalled.stop_reason,
        usage: recalled.usage,
        trace: recalled.trace,
        inspected_records,
    };
    contextdb_context::router::canonical_bytes(&discovery, budget).map_err(material_error)?;
    Ok(GenericRouterFrontier {
        candidates,
        evidence: BTreeMap::new(),
        dependencies: BTreeMap::new(),
        unit_origins,
        evidence_origins: BTreeMap::new(),
        inspected_origins,
        discovery,
    })
}

struct TracedProvider<'a, S> {
    native: NativeRecallProvider<'a>,
    snapshot: &'a S,
    context: &'a AuthenticatedRequestContext,
    binding: ProviderSnapshot,
    budget: RefCell<&'a mut QueryBudget>,
    frontier: RefCell<Option<NativeRecallFrontier>>,
    failure: RefCell<Option<ServiceError>>,
    max_graph_hops: u8,
}

impl<S: ReadSnapshot> RecallProvider for TracedProvider<'_, S> {
    fn snapshot(&self, at_commit: Option<u64>) -> contextdb_recall::Result<ProviderSnapshot> {
        if at_commit != Some(self.binding.commit_seq) {
            return Err(RecallError::Provider(
                "generic knowledge binding differs".into(),
            ));
        }
        Ok(self.binding.clone())
    }

    fn authorized_corpus(
        &self,
        request: &ProviderRequest,
    ) -> contextdb_recall::Result<AuthorizedCorpus> {
        let prepare = || -> ServiceResult<AuthorizedCorpus> {
            if self.frontier.borrow().is_some() {
                return Err(integrity(
                    "generic recall requested another materialization",
                ));
            }
            let mut shared = self.budget.borrow_mut();
            let frontier = self.native.authorized_frontier(
                self.snapshot,
                self.context,
                request,
                &mut shared,
            )?;
            let count = frontier.corpus.documents().len() as u64;
            let edges = frontier.corpus.relations().len() as u64;
            // Reserve a conservative bounded route/graph allowance before the
            // engine's synchronous execution. It has no shared cancellation hook.
            let work = count
                .saturating_mul(16 + count * u64::from(self.max_graph_hops))
                .saturating_add(edges.saturating_mul(16));
            shared.charge(work, 0).map_err(budget_error)?;
            contextdb_context::router::canonical_bytes(
                &(frontier.corpus.documents(), frontier.corpus.relations()),
                &mut shared,
            )
            .map_err(material_error)?;
            let corpus = frontier.corpus.clone();
            self.frontier.replace(Some(frontier));
            Ok(corpus)
        };
        prepare().map_err(|error| {
            self.failure.replace(Some(error));
            RecallError::Provider("native generic materialization was refused".into())
        })
    }
}

fn materialize(
    native: &NativeRecallRecord,
    item: &contextdb_recall::RecallItem,
    source: &contextdb_recall::RecallDocument,
    requested_scopes: &BTreeSet<String>,
    budget: &mut QueryBudget,
) -> ServiceResult<ProviderCandidate> {
    let typed = typed_reference(native.policy.kind, &native.record.document.id);
    let claim = match &typed {
        Some(MemoryRef::Claim { id }) => Some(*id),
        _ => None,
    };
    // Native generic records have no typed epistemic perspective. Retain their
    // real references without inventing an actor or promoting a record to truth.
    let kind = if native.policy.kind == MemoryRecordKind::Node {
        PackBlockKind::Participant
    } else {
        PackBlockKind::Unknown
    };
    let mut fields = BTreeMap::from([
        (
            "native_kind".into(),
            canonical_text(&native.policy.kind, budget)?,
        ),
        (
            "native_record".into(),
            canonical_text(
                &(
                    &native.record.document.id,
                    native.record.revision,
                    native.record.transaction_from,
                    &native.origin.control.document_digest,
                ),
                budget,
            )?,
        ),
        (
            "native_value".into(),
            canonical_text(&native.record.document.value, budget)?,
        ),
        (
            "typed_reference".into(),
            if typed.is_some() {
                "verified"
            } else {
                "unavailable"
            }
            .into(),
        ),
    ]);
    fields.insert(
        "role".into(),
        "Retained native record data; current applicable state is resolved separately.".into(),
    );
    let id = BlockId::new(format!(
        "native:{}",
        canonical_digest(&(
            native.policy.kind,
            &native.policy.record_digest,
            native.policy.revision,
        ))?
    ))
    .map_err(material_error)?;
    let use_policy = match item.use_decision {
        MemoryUseDecision::IncludeAndMention => contextdb_context::CandidateUsePolicy {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            disclosure: DisclosureRule::MayMention,
        },
        MemoryUseDecision::IncludeSilently
        | MemoryUseDecision::IncludeOnlyAsConstraint
        | MemoryUseDecision::IncludeOnlyAsStyleSignal => contextdb_context::CandidateUsePolicy {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Deny,
            external_model_use: PolicyDecision::Allow,
            disclosure: DisclosureRule::UseSilently,
        },
        _ => return Err(integrity("withheld generic item reached materialization")),
    };
    let candidate = PackCandidate {
        id,
        kind,
        representations: vec![BlockRepresentation {
            level: CompressionLevel::L2Structured, summary: source.text.clone(), fields,
            omitted_facets: BTreeSet::new(),
        }],
        exact_fragments: Vec::new(),
        memory_refs: typed.into_iter().collect(),
        claim_ids: claim.into_iter().collect(),
        evidence_handles: BTreeSet::new(),
        facets: item.covered_facets.clone(),
        scopes: if native.policy.access.scopes.is_empty() { requested_scopes.clone() }
            else { native.policy.access.scopes.intersection(requested_scopes).cloned().collect() },
        valid_time: source.temporal.valid_time,
        // The owned assembly provider uses coordinate zero for its opaque view.
        // Exact native accepted times remain in the origin and native metadata.
        known_at_commit: 0,
        perspective: None,
        epistemic: EpistemicState {
            basis: EpistemicBasis::ActorAssertion,
            acceptance: AcceptanceState::Proposed,
            conflict: ConflictState::None,
            lifecycle: LifecycleState::Historical,
        },
        confidence_micros: 0,
        trust: ContentTrust::Mixed,
        instruction_capability: InstructionCapability::None,
        source_class: SourceClass::Imported,
        taints: BTreeSet::from([ContentTaint::UserControlled]),
        interpretation: if kind == PackBlockKind::Unknown { InterpretationRule::UnknownMarker }
            else { InterpretationRule::HistoricalData },
        support: if claim.is_some() { SupportState::Unsupported {
            reason: "Retained native record content does not establish primary world-state evidence.".into(),
        }} else { SupportState::Supported },
        conflict: None,
        unknown: (kind == PackBlockKind::Unknown).then(|| UnknownDescriptor {
            question: "What does this retained native record establish?".into(),
            reason: "No complete typed factual representation was supplied; retained data is attributed without current-truth promotion.".into(),
            blocking: false,
        }),
        utility_micros: item.score.final_micros.max(1),
        mandatory: item.use_decision == MemoryUseDecision::IncludeOnlyAsConstraint,
    };
    candidate.validate().map_err(material_error)?;
    Ok(ProviderCandidate {
        access: crate::provider::access_rule(&native.policy.access),
        use_policy,
        candidate,
    })
}

fn record_controls<S: ReadSnapshot>(
    service: &NativeService,
    snapshot: &S,
    record: &NativeRecallRecord,
    budget: &mut QueryBudget,
) -> ServiceResult<RouterTraceControls> {
    let mut controls = RouterTraceControls {
        version: 1,
        originals: record.origin.control.sources.keys().copied().collect(),
        records: vec![record.origin.clone()],
        states: Vec::new(),
    };
    // Seal inherited generic/state authorities as well as direct raw roots.
    // The final publication check must see changes to every original input.
    for id in record.origin.control.sources.keys() {
        budget.charge(1, 0).map_err(budget_error)?;
        if let Some(inherited) = service.stored_router_trace_controls(snapshot, *id)? {
            budget
                .charge(0, inherited.byte_length()? as u64)
                .map_err(budget_error)?;
            controls.union_checked(&inherited)?;
        }
    }
    controls.validate()?;
    Ok(controls)
}

fn typed_reference(kind: MemoryRecordKind, id: &str) -> Option<MemoryRef> {
    let id = uuid::Uuid::parse_str(id).ok()?;
    match kind {
        MemoryRecordKind::Node => NodeId::from_uuid(id).ok().map(|id| MemoryRef::Node { id }),
        MemoryRecordKind::Claim => ClaimId::from_uuid(id)
            .ok()
            .map(|id| MemoryRef::Claim { id }),
        MemoryRecordKind::Edge => EdgeId::from_uuid(id).ok().map(|id| MemoryRef::Edge { id }),
        MemoryRecordKind::Conflict => ConflictSetId::from_uuid(id)
            .ok()
            .map(|id| MemoryRef::ConflictSet { id }),
        MemoryRecordKind::Evidence => EvidenceId::from_uuid(id)
            .ok()
            .map(|id| MemoryRef::Evidence { id }),
        _ => None,
    }
}

fn canonical_text(value: &impl Serialize, budget: &mut QueryBudget) -> ServiceResult<String> {
    let bytes =
        contextdb_context::router::canonical_bytes(value, budget).map_err(material_error)?;
    String::from_utf8(bytes).map_err(|_| integrity("native material encoding is not UTF-8"))
}

fn material_error(error: contextdb_context::ContextError) -> ServiceError {
    match error {
        contextdb_context::ContextError::BudgetExceeded(_) => {
            crate::exhausted("generic material budget exceeded")
        }
        _ => integrity("generic material could not be represented safely"),
    }
}
fn recall_error(error: RecallError) -> ServiceError {
    match error {
        RecallError::DeadlineExceeded => crate::exhausted("generic recall deadline exceeded"),
        _ => ServiceError::new(
            ErrorCode::IntegrityFailure,
            "generic recall failed verification",
            false,
        ),
    }
}
