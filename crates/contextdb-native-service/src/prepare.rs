//! Bounded native state/raw discovery and complete outgoing-context preparation.

use contextdb_context::*;
use contextdb_core::{
    AcceptanceState, ContentDigest, EpistemicBasis, EpistemicState, EventRole, LifecycleState,
    OriginalSourceSpan, PolicyDecision, ResolvedState, ScopeId, StateKey, TemporalConstraint,
    TimestampMicros,
};
use contextdb_recall::{
    IndexedRecallProvider, ProviderSnapshot, QueryBudget, RecallPrincipal, RecallWatermarks,
};
use contextdb_service::{
    AssertionPort, AuthenticatedRequestContext, Capability, CapturePort, PrepareContextPort,
    PrepareContextRequest, PreparedContext, ResolveStateRequest, ServiceError, ServiceResult,
    StateView,
};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::raw_index::budget_error;
use super::{
    NativeService, canonical_digest, digest_bytes, invalid, require_capability, storage_error,
};

const PREPARE_DOMAIN: &[u8] = b"contextdb/prepared-context/v1";

mod raw;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrepareFence {
    pub principal: String,
    pub known_at: u64,
    pub scopes: BTreeMap<ScopeId, u64>,
    pub authorization_epoch: u64,
    pub valid_until: TimestampMicros,
}

#[derive(Debug)]
struct NativeAssemblyProvider<'a> {
    service: &'a NativeService,
    context: &'a AuthenticatedRequestContext,
    data: InMemoryContextProvider,
    dependencies: BTreeMap<BlockId, EvidenceDependencies>,
    binding: AssemblyBinding,
    fence: PrepareFence,
}

impl ContextProvider for NativeAssemblyProvider<'_> {
    fn snapshot(&self) -> Result<ProviderSnapshot> {
        self.data.snapshot()
    }
    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>> {
        self.data.candidate_labels()
    }
    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate> {
        self.data.materialize_candidate(id)
    }
    fn evidence_labels(&self, ids: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>> {
        self.data.evidence_labels(ids)
    }
    fn materialize_evidence(&self, id: &EvidenceHandle) -> Result<PackEvidence> {
        self.data.materialize_evidence(id)
    }
}

impl AssemblyProvider for NativeAssemblyProvider<'_> {
    fn binding(&self) -> Result<AssemblyBinding> {
        Ok(self.binding.clone())
    }
    fn dependencies(&self, id: &BlockId) -> Result<EvidenceDependencies> {
        Ok(self.dependencies.get(id).cloned().unwrap_or_default())
    }
    fn verify_original(
        &self,
        span: &OriginalSourceSpan,
        bytes: &[u8],
        budget: &mut QueryBudget,
    ) -> Result<()> {
        budget.charge(1, bytes.len() as u64).map_err(|limit| {
            ContextError::BudgetExceeded(format!("source verification: {limit:?}"))
        })?;
        if bytes.len() > 1024 * 1024 {
            return Err(ContextError::BudgetExceeded(
                "source span exceeds one MiB".into(),
            ));
        }
        let snapshot = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(context_error)?;
        let original = self
            .service
            .source_span(&snapshot, Some(self.context), span, false)
            .map_err(context_error)?;
        let receipt = self
            .service
            .load_captured_original(&snapshot, span.event_id)
            .map_err(context_error)?
            .receipt;
        if original != bytes || receipt.workspace_commit > self.fence.known_at {
            return Err(ContextError::Provider(
                "source bytes/version exceed the pinned knowledge view".into(),
            ));
        }
        Ok(())
    }
    fn validate_read_set(
        &self,
        read_set: &AssemblyReadSet,
        budget: &mut QueryBudget,
    ) -> Result<()> {
        if read_set.binding != self.binding || read_set.scopes != self.context.request.scopes {
            return Err(ContextError::Authorization(
                "outgoing read-set changed its principal/scope binding".into(),
            ));
        }
        self.service
            .check_prepare_fence(self.context, &self.fence, budget)
            .map_err(context_error)
    }
}

impl PrepareContextPort for NativeService {
    fn prepare_context(
        &self,
        request: PrepareContextRequest,
        tokenizer: &dyn TokenCounter,
        encoder: &dyn OutgoingEncoder,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedContext> {
        for capability in [
            Capability::Runtime,
            Capability::Recall,
            Capability::ReadMemory,
            Capability::ReadEvidence,
            Capability::RawEvidence,
        ] {
            require_capability(&request.context, capability)?;
        }
        if request.model_profile.external_processing {
            require_capability(&request.context, Capability::ModelProcessing)?;
        }
        if request.raw_queries.len() > 8
            || request.required_facets.len() > 32
            || request.context.request.scopes.is_empty()
            || request.context.request.scopes.len() > 32
            || request.memory_budget.max_blocks > 512
            || request.memory_budget.max_evidence_blocks > 2048
            || request.memory_budget.max_selection_evaluations > 4096
        {
            return Err(invalid(
                "prepare frontier exceeds the supported bounded profile",
            ));
        }
        let scopes: BTreeSet<ScopeId> = request
            .context
            .request
            .scopes
            .iter()
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| invalid("continuous scopes must be typed scope IDs"))
            })
            .collect::<ServiceResult<_>>()?;
        if contextdb_recall::purpose_key(&request.purpose.core_purpose())
            != request.context.request.purpose
        {
            return Err(invalid("prepare purpose differs from authenticated use"));
        }
        if let Some(receipt) = &request.after_receipt {
            self.resolve_capture_receipt(&request.context, receipt)?;
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (_, world) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.known_at,
        )?;
        let known = world.watermarks.journal;
        if request
            .after_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.workspace_commit > known)
        {
            return Err(invalid(
                "prepared knowledge is below the native capture receipt",
            ));
        }
        let workspace = digest_bytes(request.context.request.workspace_id.as_bytes());
        let now = wall_time()?;
        let valid_at = request.valid_at.unwrap_or(now);
        let mut fence = PrepareFence {
            principal: request.context.authorization_binding_digest()?,
            known_at: known,
            scopes: BTreeMap::new(),
            authorization_epoch: self.raw_authorization_epoch(&snapshot, &workspace)?,
            valid_until: TimestampMicros(
                now.0
                    .checked_add(30_000_000)
                    .ok_or_else(|| invalid("prepare clock overflow"))?,
            ),
        };
        let access = sealed_access(&request.context);
        let mut candidates = vec![ProviderCandidate {
            access: access.clone(),
            use_policy: ordinary_use(),
            candidate: diagnostic(
                "contextdb:situation",
                PackBlockKind::Situation,
                "Continue the interaction using attributed originals and the applicable state; unresolved state stays unknown.",
                &request.context.request.scopes,
                true,
            )?,
        }];
        let mut dependencies = BTreeMap::new();
        let mut evidence = BTreeMap::<EvidenceHandle, ProviderEvidence>::new();
        let mut pending_interpretation = false;
        for scope in scopes {
            let epoch = self.scope_epoch(&snapshot, &workspace, scope)?;
            fence.scopes.insert(scope, epoch);
            let (gaps, _) = self.assembly_scope_coverage(
                &snapshot,
                &request.context,
                &workspace,
                scope,
                known,
                epoch,
                budget,
            )?;
            if !gaps.is_empty() {
                pending_interpretation = true;
                candidates.push(ProviderCandidate { access: access.clone(), use_policy: ordinary_use(),
                    candidate: diagnostic(&format!("contextdb:pending:{scope}"), PackBlockKind::Unknown,
                        "Relevant original interpretation or capture is incomplete; applicable state and constraints are not established.",
                        &BTreeSet::from([scope.to_string()]), true)? });
            }
            for key in self.scoped_state_keys(&snapshot, &request.context, scope, known, budget)? {
                if candidates.len() >= 256 {
                    return Err(super::exhausted(
                        "mandatory state exceeds 256 bounded slots",
                    ));
                }
                let view = self.resolve_state(
                    ResolveStateRequest {
                        context: request.context.clone(),
                        key: key.clone(),
                        known_at: Some(known),
                        valid_at,
                        after_receipt: None,
                    },
                    budget,
                )?;
                if request.valid_at.is_none()
                    && let Some(until) = view.resolution.valid_until
                {
                    fence.valid_until = fence.valid_until.min(until);
                }
                for until in view
                    .assertions
                    .iter()
                    .flat_map(|assertion| &assertion.revision.envelope.consent.decisions)
                    .filter_map(|consent| consent.valid_time.end)
                    .filter(|until| *until > now)
                {
                    fence.valid_until = fence.valid_until.min(until);
                }
                self.add_state_candidate(
                    &snapshot,
                    &request,
                    key,
                    view,
                    &mut candidates,
                    &mut evidence,
                    &mut dependencies,
                    budget,
                )?;
            }
        }
        let mut discovery = Vec::new();
        let mut unrendered_sources = Vec::new();
        let mut raw_ids = BTreeSet::new();
        if !request.raw_queries.is_empty() {
            let provider = self.indexed_recall_provider(&request.context);
            let view = provider.open_view(Some(known), budget)?;
            for query in &request.raw_queries {
                let page = provider.candidates(&view, query, budget)?;
                discovery.push(page.completion);
                for hit in page.hits {
                    if !raw_ids.insert(hit.source.event_id) {
                        continue;
                    }
                    if raw_ids.len() > 256 || candidates.len() >= 512 {
                        return Err(super::exhausted(
                            "raw preparation frontier exceeds its limit",
                        ));
                    }
                    let spans = match self.prepare_raw_spans(
                        &snapshot,
                        &request.context,
                        &hit,
                        budget,
                    )? {
                        Ok(spans) => spans,
                        Err(reason) => {
                            let omission = contextdb_service::UnrenderedSource {
                                source: hit.source,
                                reason,
                            };
                            let mut candidate = diagnostic(
                                &format!("unrendered:{}", omission.source.event_id),
                                PackBlockKind::Unknown,
                                "This original was found but not rendered. Retrieve its bytes with a bounded range or media adapter before relying on its contents.",
                                &request.context.request.scopes,
                                true,
                            )?;
                            candidate.representations[0].fields.insert(
                                "original".into(),
                                serde_json::to_string(&omission)
                                    .map_err(|_| invalid("original omission encoding failed"))?,
                            );
                            candidates.push(ProviderCandidate {
                                access: access.clone(),
                                use_policy: ordinary_use(),
                                candidate,
                            });
                            unrendered_sources.push(omission);
                            continue;
                        }
                    };
                    let mut handles = BTreeSet::new();
                    for span in spans {
                        let handle = self.add_original_evidence(
                            &snapshot,
                            &request.context,
                            &span,
                            BTreeSet::new(),
                            &mut evidence,
                            budget,
                        )?;
                        handles.insert(handle);
                    }
                    if handles.is_empty() {
                        continue;
                    }
                    let mut candidate = diagnostic(
                        &format!("raw:{}", hit.source.event_id),
                        PackBlockKind::RawObservation,
                        "Original interaction, retained as historical source data; it does not establish current truth.",
                        &request.context.request.scopes,
                        false,
                    )?;
                    candidate.representations[0].fields.insert(
                        "source".into(),
                        serde_json::to_string(&hit.source)
                            .map_err(|_| invalid("raw source encoding failed"))?,
                    );
                    candidate.evidence_handles = handles.clone();
                    candidate.source_class = source_class(hit.source.role);
                    dependencies.insert(
                        candidate.id.clone(),
                        EvidenceDependencies {
                            supports: vec![handles],
                            ..Default::default()
                        },
                    );
                    candidates.push(ProviderCandidate {
                        access: access.clone(),
                        use_policy: ordinary_use(),
                        candidate,
                    });
                }
            }
        }
        self.check_prepare_fence(&request.context, &fence, budget)?;
        let token = self.seal_private_cursor(PREPARE_DOMAIN, &fence)?;
        let binding = AssemblyBinding {
            snapshot: token.clone(),
            authorization: token.clone(),
            state: token.clone(),
            valid_until: Some(fence.valid_until),
        };
        // The existing pack snapshot represents this one opaque view. Its zero
        // coordinate is local to this pack, not an exposed global activity count.
        let opaque_snapshot = ProviderSnapshot {
            database_id: token.clone(),
            commit_seq: 0,
            watermarks: RecallWatermarks {
                journal: 0,
                semantic: 0,
                lexical: 0,
                vector: BTreeMap::new(),
                graph: 0,
                hierarchy: BTreeMap::new(),
            },
        };
        let provider = NativeAssemblyProvider {
            service: self,
            context: &request.context,
            data: InMemoryContextProvider::new(
                opaque_snapshot.clone(),
                candidates,
                evidence.into_values().collect(),
            )
            .map_err(service_error)?,
            dependencies,
            binding,
            fence,
        };
        let principal = RecallPrincipal {
            subject: request.context.request.subject_id.clone(),
            audiences: request.context.request.audiences.clone(),
            workspace: request.context.request.workspace_id.clone(),
            scopes: request.context.request.scopes.clone(),
            purpose: request.context.request.purpose.clone(),
            clearance: access.sensitivity,
        };
        let context = CompileRequest {
            pack_id: request.pack_id,
            snapshot: opaque_snapshot,
            principal,
            filter_digest: token,
            purpose: request.purpose,
            scopes: request.context.request.scopes.clone(),
            temporal_view: if request.known_at.is_some() || request.valid_at.is_some() {
                TemporalConstraint::Bitemporal {
                    valid_during: contextdb_core::TimeRange::new(
                        valid_at,
                        Some(TimestampMicros(
                            valid_at
                                .0
                                .checked_add(1)
                                .ok_or_else(|| invalid("applicability time overflow"))?,
                        )),
                    )
                    .map_err(|_| invalid("applicability time is invalid"))?,
                    known_at: contextdb_core::CommitSeq::GENESIS,
                }
            } else {
                TemporalConstraint::Current
            },
            required_facets: request.required_facets,
            budgets: request.memory_budget,
            model_profile: request.model_profile,
            explicit_memory_request: request.explicit_memory_request,
            require_primary_evidence: true,
            continuation: None,
        };
        let compiled = ContextCompiler::new(*self.token_key)
            .map_err(service_error)?
            .compile_assembly(
                &CompileAssemblyRequest {
                    context,
                    base: request.base,
                    budget: request.outgoing_budget,
                },
                &provider,
                tokenizer,
                encoder,
                &R0Scorer,
                budget,
            )
            .map_err(service_error)?;
        Ok(PreparedContext {
            context_pack: compiled.context.pack,
            canonical_bytes: compiled.context.canonical_protobuf,
            messages: compiled.messages,
            outgoing: compiled.outgoing,
            assembly: compiled.manifest,
            discovery,
            pending_interpretation,
            unrendered_sources,
        })
    }
}

impl NativeService {
    pub(super) fn check_prepare_fence(
        &self,
        context: &AuthenticatedRequestContext,
        fence: &PrepareFence,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, 0).map_err(budget_error)?;
        if fence.principal != context.authorization_binding_digest()?
            || wall_time()? >= fence.valid_until
        {
            return Err(stale("prepared principal or temporal validity changed"));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        if fence.authorization_epoch != self.raw_authorization_epoch(&snapshot, &workspace)? {
            return Err(stale("source authorization changed during preparation"));
        }
        for (scope, epoch) in &fence.scopes {
            if self.scope_epoch(&snapshot, &workspace, *scope)? != *epoch {
                return Err(stale("scope changed during preparation"));
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "state adaptation preserves separate policy and source support"
    )]
    fn add_state_candidate<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        request: &PrepareContextRequest,
        key: StateKey,
        view: StateView,
        candidates: &mut Vec<ProviderCandidate>,
        evidence: &mut BTreeMap<EvidenceHandle, ProviderEvidence>,
        dependencies: &mut BTreeMap<BlockId, EvidenceDependencies>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let id = format!("state:{}", canonical_digest(&key)?);
        let scopes = BTreeSet::from([key.scope.to_string()]);
        let mut candidate = diagnostic(
            &id,
            PackBlockKind::Unknown,
            "Applicable state is unknown or incomplete.",
            &scopes,
            true,
        )?;
        let claims: BTreeSet<_> = match &view.resolution.state {
            ResolvedState::Known { answer } => answer.supporting_claims.clone(),
            ResolvedState::Conflict { alternatives } => {
                require_capability(&request.context, Capability::ReadConflict)?;
                alternatives
                    .iter()
                    .flat_map(|alternative| alternative.supporting_claims.iter().copied())
                    .collect()
            }
            ResolvedState::Unknown | ResolvedState::Incomplete => BTreeSet::new(),
        };
        let selected: Vec<_> = view
            .assertions
            .iter()
            .filter(|assertion| claims.contains(&assertion.claim.id))
            .collect();
        let usable = !selected.is_empty()
            && selected.iter().all(|assertion| {
                let policy = assertion.revision.envelope.use_policy;
                decision_allows(policy.influence_response, request.explicit_memory_request)
                    && (!request.model_profile.external_processing
                        || policy.external_model_use == PolicyDecision::Allow)
            });
        let mut use_policy = ordinary_use();
        if usable {
            candidate.kind = if matches!(view.resolution.state, ResolvedState::Conflict { .. }) {
                PackBlockKind::Conflict
            } else if selected
                .iter()
                .any(|assertion| assertion.stance == contextdb_core::AssertionStance::Decision)
            {
                PackBlockKind::Decision
            } else {
                PackBlockKind::Fact
            };
            candidate.unknown = None;
            candidate.claim_ids = claims.clone();
            candidate.perspective = Some(selected[0].revision.envelope.perspective.clone());
            candidate.interpretation = if candidate.kind == PackBlockKind::Conflict {
                InterpretationRule::ConflictAlternatives
            } else {
                InterpretationRule::FactualData
            };
            candidate.representations[0].summary =
                "Applicable state resolved under the explicit source authority policy.".into();
            candidate.representations[0].fields.insert(
                "resolution".into(),
                serde_json::to_string(&view.resolution.state)
                    .map_err(|_| invalid("state encoding failed"))?,
            );
            if candidate.kind == PackBlockKind::Conflict {
                let bytes = blake3::hash(id.as_bytes());
                let mut uuid_bytes = [0_u8; 16];
                uuid_bytes.copy_from_slice(&bytes.as_bytes()[..16]);
                candidate.conflict = Some(ConflictDescriptor {
                    set_id: contextdb_core::ConflictSetId::from_uuid(uuid::Uuid::from_bytes(
                        uuid_bytes,
                    ))
                    .map_err(|_| invalid("conflict identity failed"))?,
                    alternatives: claims,
                    resolution: ConflictResolution::Unresolved,
                    blocking: true,
                });
            }
            for assertion in selected {
                if !decision_allows(
                    assertion.revision.envelope.use_policy.mention_explicitly,
                    request.explicit_memory_request,
                ) {
                    use_policy.mention = PolicyDecision::Deny;
                    use_policy.disclosure = DisclosureRule::UseSilently;
                }
                for span in &assertion.original_evidence {
                    candidate
                        .evidence_handles
                        .insert(self.add_original_evidence(
                            snapshot,
                            &request.context,
                            span,
                            BTreeSet::from([assertion.claim.id]),
                            evidence,
                            budget,
                        )?);
                }
            }
            dependencies.insert(
                candidate.id.clone(),
                EvidenceDependencies {
                    supports: vec![candidate.evidence_handles.clone()],
                    ..Default::default()
                },
            );
        }
        candidate.representations[0].fields.insert(
            "key".into(),
            serde_json::to_string(&key).map_err(|_| invalid("state key encoding failed"))?,
        );
        candidate.facets.insert(id);
        candidate.representations[0].fields.insert(
            "time_mode".into(),
            if request.known_at.is_some() || request.valid_at.is_some() {
                "historical"
            } else {
                "current"
            }
            .into(),
        );
        candidates.push(ProviderCandidate {
            access: sealed_access(&request.context),
            use_policy,
            candidate,
        });
        Ok(())
    }

    fn add_original_evidence<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        span: &OriginalSourceSpan,
        claims: BTreeSet<contextdb_core::ClaimId>,
        evidence: &mut BTreeMap<EvidenceHandle, ProviderEvidence>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<EvidenceHandle> {
        let length = span
            .end
            .checked_sub(span.start)
            .filter(|length| *length > 0 && *length <= 1024 * 1024)
            .ok_or_else(|| invalid("exact text source requires a bounded nonempty span"))?;
        budget.charge(1, length).map_err(budget_error)?;
        let policy = self.authorized_capture_policy(snapshot, context, span.event_id)?;
        let bytes = self.source_span(snapshot, Some(context), span, true)?;
        let original = self.load_captured_original(snapshot, span.event_id)?;
        let handle = EvidenceHandle::new(format!("span:{}", canonical_digest(span)?))
            .map_err(service_error)?;
        if let Some(existing) = evidence.get_mut(&handle) {
            existing.evidence.claim_ids.extend(claims);
            return Ok(handle);
        }
        let excerpt = String::from_utf8(bytes).map_err(|_| ServiceError::new(contextdb_service::ErrorCode::Unsupported,
            "binary originals require a declared multimodal encoder; a handle is not an exact text quote", false))?;
        let value = PackEvidence {
            id: handle.clone(),
            source: SourceHandle::new(span.event_id.to_string()).map_err(service_error)?,
            selector: EvidenceSelector::TextBytes {
                start: span.start,
                end: span.end,
            },
            excerpt: Some(excerpt),
            claim_ids: claims,
            provenance_family: original.event.source_id.to_string(),
            primary: true,
            trust_micros: 1_000_000,
            source_class: source_class(original.event.role),
            taints: BTreeSet::from([ContentTaint::UntrustedInstructions]),
            lineage: Vec::new(),
            original_span: Some(span.clone()),
        };
        evidence.insert(
            handle.clone(),
            ProviderEvidence {
                access: super::provider::access_rule(&policy.access),
                external_model_use: PolicyDecision::Allow,
                evidence: value,
            },
        );
        Ok(handle)
    }
}

fn diagnostic(
    id: &str,
    kind: PackBlockKind,
    text: &str,
    scopes: &BTreeSet<String>,
    mandatory: bool,
) -> ServiceResult<PackCandidate> {
    Ok(PackCandidate {
        id: BlockId::new(id).map_err(service_error)?,
        kind,
        representations: vec![BlockRepresentation {
            level: CompressionLevel::L2Structured,
            summary: text.into(),
            fields: BTreeMap::new(),
            omitted_facets: BTreeSet::new(),
        }],
        exact_fragments: Vec::new(),
        memory_refs: Vec::new(),
        claim_ids: BTreeSet::new(),
        evidence_handles: BTreeSet::new(),
        facets: BTreeSet::new(),
        scopes: scopes.clone(),
        valid_time: None,
        known_at_commit: 0,
        perspective: None,
        epistemic: EpistemicState {
            basis: EpistemicBasis::DeterministicDerivation,
            acceptance: AcceptanceState::Accepted,
            conflict: contextdb_core::ConflictState::None,
            lifecycle: LifecycleState::Active,
        },
        confidence_micros: 1_000_000,
        trust: ContentTrust::TrustedSource,
        instruction_capability: InstructionCapability::None,
        source_class: SourceClass::DeterministicDerivation,
        taints: BTreeSet::new(),
        interpretation: if kind == PackBlockKind::Unknown {
            InterpretationRule::UnknownMarker
        } else if kind == PackBlockKind::RawObservation {
            InterpretationRule::HistoricalData
        } else {
            InterpretationRule::FactualData
        },
        support: SupportState::Supported,
        conflict: None,
        unknown: (kind == PackBlockKind::Unknown).then(|| UnknownDescriptor {
            question: "What is applicable here?".into(),
            reason: text.into(),
            blocking: true,
        }),
        utility_micros: 1_000_000,
        mandatory,
    })
}

fn ordinary_use() -> CandidateUsePolicy {
    CandidateUsePolicy {
        influence: PolicyDecision::Allow,
        mention: PolicyDecision::Allow,
        external_model_use: PolicyDecision::Allow,
        disclosure: DisclosureRule::MayMention,
    }
}
fn decision_allows(decision: PolicyDecision, explicit: bool) -> bool {
    decision == PolicyDecision::Allow || (explicit && decision == PolicyDecision::Conditional)
}
fn source_class(role: EventRole) -> SourceClass {
    match role {
        EventRole::User => SourceClass::UserStatement,
        EventRole::Assistant => SourceClass::ModelGenerated,
        EventRole::Tool => SourceClass::ToolOutput,
        EventRole::ExternalSource => SourceClass::ExternalDocument,
        EventRole::Import => SourceClass::Imported,
        EventRole::Host => SourceClass::DeterministicDerivation,
    }
}
fn sealed_access(context: &AuthenticatedRequestContext) -> contextdb_recall::AccessRule {
    let mut access =
        super::provider::access_rule(&super::trusted_structured_policy(&context.request));
    access.scopes = context.request.scopes.clone();
    access
}
fn wall_time() -> ServiceResult<TimestampMicros> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| stale("wall clock unavailable"))?
        .as_micros();
    Ok(TimestampMicros(
        i64::try_from(micros).map_err(|_| invalid("clock overflow"))?,
    ))
}
fn stale(message: &str) -> ServiceError {
    ServiceError::new(contextdb_service::ErrorCode::IndexTooStale, message, true)
}
fn context_error(error: impl std::fmt::Display) -> ContextError {
    ContextError::Provider(error.to_string())
}
fn service_error(error: ContextError) -> ServiceError {
    use contextdb_service::ErrorCode;
    let code = match error {
        ContextError::BudgetExceeded(_) => ErrorCode::ResourceExhausted,
        ContextError::Authorization(_) => ErrorCode::PermissionDenied,
        ContextError::Provider(_) => ErrorCode::IndexTooStale,
        ContextError::InvalidRequest(_) | ContextError::InvalidContinuation(_) => {
            ErrorCode::InvalidArgument
        }
        ContextError::Tokenizer(_) | ContextError::Serialization(_) => {
            ErrorCode::FormatIncompatible
        }
    };
    ServiceError::new(code, error.to_string(), code == ErrorCode::IndexTooStale)
}
