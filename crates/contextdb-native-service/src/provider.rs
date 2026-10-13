//! Exact policy-first recall adapter over the native revision store.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{CommitRange, CommitSeq, PolicyDecision, TimeRange, TimestampMicros};
use contextdb_recall::{
    AccessConsent, AccessRule, AuthorizedCorpus, DocumentId, DocumentPerspective,
    DocumentTemporalState, DocumentUseProfile, ProviderDocument, ProviderEvidence,
    ProviderRelation, ProviderRequest, ProviderSnapshot, QueryBudget, RecallConflictState,
    RecallDocument, RecallDocumentKind, RecallError, RecallEvidence, RecallProvider,
    RecallRelation, RecallRelationKind, RecallSensitivity, RecallWatermarks, Result,
    SuppliedVector,
};
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, Consent, ErrorCode, MemoryLifecycle, MemoryRecord,
    MemoryRecordKind, Sensitivity, ServiceError, ServiceResult,
};
use contextdb_storage::{ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine};
use serde_json::Value;

use super::router_trace::controls::TraceRecordControl;
use super::{
    MAX_AUTHORIZED_CANDIDATES, NativeService, SCAN_PAGE_BYTES, SCAN_PAGE_ENTRIES, SCHEMA_VERSION,
    StoredEvent, StoredPolicy, WorkspaceState, decode, event_digest, policy_route_key,
    policy_route_prefix, validate_stored_policy, visible_at,
};

/// The complete bounded corpus inspected by generic routing, with exact native
/// record origins. This is private preparation material, not a disclosure grant.
pub(crate) struct NativeRecallFrontier {
    pub(crate) corpus: AuthorizedCorpus,
    pub(crate) records: BTreeMap<DocumentId, NativeRecallRecord>,
}

pub(crate) struct NativeRecallRecord {
    pub(crate) policy: StoredPolicy,
    pub(crate) record: MemoryRecord,
    pub(crate) origin: TraceRecordControl,
}

// This complete-inspection cap is separate from the number of ranked hits.
// Refusal does not truncate an archive or claim exhaustive top-k coverage.
const MAX_TRACED_CORPUS: usize = 100;

enum FrontierError {
    Recall(RecallError),
    Service(ServiceError),
}

impl From<RecallError> for FrontierError {
    fn from(error: RecallError) -> Self {
        Self::Recall(error)
    }
}
impl From<ServiceError> for FrontierError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}
type FrontierResult<T> = std::result::Result<T, FrontierError>;

/// Exact-scan provider used by the canonical RecallEngine to ContextPack path.
///
/// The provider scans only the caller's workspace policy partition, evaluates
/// labels before loading content, and then materializes the bounded authorized
/// set at one retained workspace snapshot. Its projection watermarks are exact
/// because no asynchronously derived index is consulted on this path.
#[derive(Debug)]
pub(crate) struct NativeRecallProvider<'a> {
    service: &'a NativeService,
    workspace_id: &'a str,
}

impl<'a> NativeRecallProvider<'a> {
    pub(crate) const fn new(service: &'a NativeService, workspace_id: &'a str) -> Self {
        Self {
            service,
            workspace_id,
        }
    }

    pub(crate) fn provider_snapshot(state: &WorkspaceState, database_id: &str) -> ProviderSnapshot {
        let commit = state.watermarks.journal;
        ProviderSnapshot {
            database_id: database_id.to_owned(),
            commit_seq: commit,
            watermarks: RecallWatermarks {
                journal: commit,
                semantic: commit,
                lexical: commit,
                vector: BTreeMap::from([("native-exact-scan-v1".to_owned(), commit)]),
                graph: commit,
                hierarchy: BTreeMap::new(),
            },
        }
    }

    fn workspace_commit_for_global<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_digest: &str,
        global_commit: u64,
        budget: &mut Option<&mut QueryBudget>,
    ) -> FrontierResult<u64> {
        let bytes = frontier_bytes(
            snapshot,
            &self.service.keyspaces.events,
            &global_commit.to_be_bytes(),
            budget,
        )?
        .ok_or_else(|| provider_failure("transaction event is absent"))?;
        let event: StoredEvent =
            decode(&bytes, "native provider event").map_err(provider_service)?;
        let expected_digest = event_digest(&event).map_err(provider_service)?;
        if event.schema_version != SCHEMA_VERSION
            || event.global_commit != global_commit
            || event.workspace_digest != workspace_digest
            || event.workspace_commit == 0
            || event.event_digest != expected_digest
        {
            return Err(provider_failure("transaction event binding is invalid").into());
        }
        Ok(event.workspace_commit)
    }

    fn transaction_range<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_digest: &str,
        policy: &StoredPolicy,
        budget: &mut Option<&mut QueryBudget>,
    ) -> FrontierResult<CommitRange> {
        let start = self.workspace_commit_for_global(
            snapshot,
            workspace_digest,
            policy.transaction_from,
            budget,
        )?;
        let end = policy
            .transaction_to
            .map(|commit| {
                self.workspace_commit_for_global(snapshot, workspace_digest, commit, budget)
            })
            .transpose()?;
        CommitRange::new(CommitSeq::new(start), end.map(CommitSeq::new))
            .map_err(|_| provider_failure("transaction-time range is invalid").into())
    }

    fn provider_document<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_digest: &str,
        policy: &StoredPolicy,
        access: AccessRule,
        record: &MemoryRecord,
        budget: &mut Option<&mut QueryBudget>,
    ) -> FrontierResult<(ProviderDocument, Option<ProviderRelation>)> {
        let valid_time = bounded_time(
            record.document.valid_time.from,
            record.document.valid_time.to,
        )?;
        let transaction_time =
            self.transaction_range(snapshot, workspace_digest, policy, budget)?;
        let text = record
            .document
            .search_text
            .clone()
            .unwrap_or_else(|| compact_json(&record.document.value));
        let estimated_tokens =
            u32::try_from(text.chars().count().div_ceil(4).max(1)).unwrap_or(u32::MAX);
        let kind = document_kind(record.document.kind);
        let evidence = record
            .document
            .links
            .evidence
            .iter()
            .map(|id| ProviderEvidence {
                access: access.clone(),
                evidence: RecallEvidence {
                    id: id.clone(),
                    source_observation: None,
                    excerpt: None,
                    primary: true,
                    trust: 1.0,
                    estimated_tokens: 1,
                },
            })
            .collect();
        let conflict = record.document.links.conflict_set.as_ref().map_or(
            RecallConflictState::None,
            |set_id| RecallConflictState::Unresolved {
                set_id: set_id.clone(),
            },
        );
        let document = RecallDocument {
            id: DocumentId::new(record.document.id.clone())?,
            kind,
            canonical_name: record
                .document
                .attributes
                .get("canonical_name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| record.document.search_text.clone()),
            aliases: string_vec(record.document.attributes.get("aliases")),
            text,
            facets: string_set(record.document.attributes.get("facets")),
            subjects: record.document.links.subject.iter().cloned().collect(),
            participants: string_set(record.document.attributes.get("participants")),
            active_keys: record
                .document
                .links
                .source
                .iter()
                .chain(record.document.links.target.iter())
                .cloned()
                .collect(),
            temporal: DocumentTemporalState {
                valid_time,
                transaction_time,
            },
            perspective: DocumentPerspective {
                knower: None,
                narrator: None,
                role: "native_materialized".to_owned(),
            },
            conflict,
            evidence: Vec::new(),
            vector: record.document.vector.clone().map(|values| SuppliedVector {
                space: "native-exact-scan-v1".to_owned(),
                values,
            }),
            source_trust: 1.0,
            importance: 0.5,
            estimated_tokens,
            use_profile: DocumentUseProfile {
                influence: PolicyDecision::Allow,
                mention: PolicyDecision::Conditional,
                external_model_use: PolicyDecision::Conditional,
                shared_with_principal: true,
                personal_detail: false,
                constraint_only: false,
                style_only: false,
            },
        };
        let relation = relation(record, &access, valid_time)?;
        Ok((
            ProviderDocument {
                access,
                document,
                evidence,
            },
            relation,
        ))
    }
}

impl NativeRecallProvider<'_> {
    /// Complete exact native materialization for the opt-in trace profile. The
    /// same authorization loop serves legacy recall; this entry additionally
    /// requires current retained provenance and charges the enclosing budget.
    pub(crate) fn authorized_frontier<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        request: &ProviderRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecallFrontier> {
        self.authorized_inner(snapshot, Some(context), request, &mut Some(budget))
            .map_err(frontier_service)
    }

    fn authorized_inner<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        request: &ProviderRequest,
        budget: &mut Option<&mut QueryBudget>,
    ) -> FrontierResult<NativeRecallFrontier> {
        frontier_charge(budget, 1, 0)?;
        if request.snapshot.database_id != self.service.database_id
            || request.principal.workspace != self.workspace_id
        {
            return Err(provider_failure("snapshot or workspace binding differs").into());
        }
        self.service.require_suppression_current(
            snapshot,
            &super::digest_bytes(self.workspace_id.as_bytes()),
        )?;
        let (global_commit, state) = self.service.select_snapshot(
            snapshot,
            self.workspace_id,
            Some(request.snapshot.commit_seq),
        )?;
        let expected = Self::provider_snapshot(&state, &self.service.database_id);
        if expected != request.snapshot {
            return Err(provider_failure("provider snapshot binding differs").into());
        }
        let complete = budget.is_some();
        if complete && context.is_none() {
            return Err(provider_failure("complete frontier context is absent").into());
        }
        let route_prefix = policy_route_prefix(self.workspace_id);
        let mut continuation: Option<Vec<u8>> = None;
        let mut scanned = 0_usize;
        let mut selected = BTreeMap::<String, (StoredPolicy, AccessRule)>::new();
        loop {
            frontier_charge(budget, 1, 0)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.service.keyspaces.policy_route,
                    ScanPageRequest {
                        prefix: &route_prefix,
                        start_after: continuation.as_deref(),
                        max_entries: SCAN_PAGE_ENTRIES,
                        max_bytes: SCAN_PAGE_BYTES,
                    },
                )
                .map_err(provider_storage)?;
            scanned = scanned
                .checked_add(page.entries.len())
                .ok_or_else(|| provider_failure("policy scan counter is exhausted"))?;
            if scanned > 1_000_000 {
                return Err(provider_failure("policy scan exceeds the bounded profile").into());
            }
            for entry in page.entries {
                frontier_charge(budget, 1, (entry.key.len() + entry.value.len()) as u64)?;
                let policy: StoredPolicy =
                    decode(&entry.value, "native provider policy").map_err(provider_service)?;
                validate_stored_policy(&policy).map_err(provider_service)?;
                if entry.key
                    != policy_route_key(
                        &policy.access.workspace_id,
                        &policy.record_digest,
                        policy.revision,
                    )
                {
                    return Err(provider_failure("policy route binding is invalid").into());
                }
                // Quarantined proposals never reach content or routing.
                if policy.kind == MemoryRecordKind::Candidate
                    || !visible_at(&policy, global_commit)
                    || policy.lifecycle != MemoryLifecycle::Active
                {
                    continue;
                }
                let access = access_rule(&policy.access);
                if !request.principal.allows(&access) {
                    continue;
                }
                access.validate()?;
                if complete {
                    // Historical labels cannot restore a current permission.
                    // Inspect the current head label before historical content.
                    let bytes = frontier_bytes(
                        snapshot,
                        &self.service.keyspaces.policy_head,
                        policy.record_digest.as_bytes(),
                        budget,
                    )?
                    .ok_or_else(|| provider_failure("current record policy is absent"))?;
                    let current: StoredPolicy = decode(&bytes, "current native provider policy")
                        .map_err(provider_service)?;
                    validate_stored_policy(&current).map_err(provider_service)?;
                    if current.record_digest != policy.record_digest
                        || current.access.workspace_id != self.workspace_id
                        || current.kind != policy.kind
                    {
                        return Err(
                            provider_failure("current record policy binding differs").into()
                        );
                    }
                    if current.lifecycle != MemoryLifecycle::Active
                        || !request.principal.allows(&access_rule(&current.access))
                    {
                        continue;
                    }
                    let shared = budget
                        .as_deref_mut()
                        .ok_or_else(|| provider_failure("complete frontier budget is absent"))?;
                    let policies = match self.service.router_record_policies(
                        snapshot,
                        context.ok_or_else(|| {
                            provider_failure("complete frontier context is absent")
                        })?,
                        &current,
                        shared,
                    ) {
                        Ok(policies) => policies,
                        Err(error) if source_denied(&error) => continue,
                        Err(error) => return Err(error.into()),
                    };
                    if policies
                        .iter()
                        .any(|policy| !request.principal.allows(&access_rule(policy)))
                    {
                        continue;
                    }
                }
                let policies = if let Some(shared) = budget.as_deref_mut() {
                    self.service.router_record_policies(
                        snapshot,
                        context.ok_or_else(|| {
                            provider_failure("complete frontier context is absent")
                        })?,
                        &policy,
                        shared,
                    )
                } else {
                    self.service.record_source_policies(snapshot, &policy)
                };
                let policies = match policies {
                    Ok(policies) => policies,
                    Err(error) if source_denied(&error) => continue,
                    Err(error) => return Err(error.into()),
                };
                if policies
                    .iter()
                    .any(|policy| !request.principal.allows(&access_rule(policy)))
                {
                    continue;
                }
                if selected
                    .insert(policy.record_digest.clone(), (policy, access))
                    .is_some()
                {
                    return Err(provider_failure("visible policy revisions overlap").into());
                }
                let ceiling = if complete {
                    MAX_TRACED_CORPUS
                } else {
                    MAX_AUTHORIZED_CANDIDATES
                };
                if selected.len() > ceiling {
                    if complete {
                        return Err(ServiceError::new(
                            ErrorCode::BudgetExhausted,
                            "complete generic inspection frontier exceeds 100 records",
                            false,
                        )
                        .into());
                    }
                    return Err(
                        provider_failure("authorized corpus exceeds the bounded profile").into(),
                    );
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if continuation
                .as_ref()
                .is_some_and(|previous| &next <= previous)
            {
                return Err(provider_failure("policy scan cursor did not advance").into());
            }
            continuation = Some(next);
        }
        let mut documents = Vec::with_capacity(selected.len());
        let mut relations = Vec::new();
        let mut records = BTreeMap::new();
        for (_, (policy, access)) in selected {
            frontier_charge(budget, 1, 0)?;
            let origin = if let Some(shared) = budget.as_deref_mut() {
                Some(
                    self.service
                        .router_record_control(snapshot, &policy, shared)?,
                )
            } else {
                None
            };
            let record = if complete {
                let bytes = frontier_bytes(
                    snapshot,
                    &self.service.keyspaces.content_history,
                    &super::history_key(&policy.record_digest, policy.revision),
                    budget,
                )?
                .ok_or_else(|| provider_failure("authorized record content is absent"))?;
                self.service.decode_content(&bytes, &policy)?
            } else {
                self.service.load_content(snapshot, &policy)?
            };
            if super::digest_bytes(record.document.id.as_bytes()) != policy.record_digest {
                return Err(provider_failure("authorized record identity binding differs").into());
            }
            let (document, relation) = self.provider_document(
                snapshot,
                &state.workspace_digest,
                &policy,
                access,
                &record,
                budget,
            )?;
            if let Some(origin) = origin {
                if origin.kind != policy.kind
                    || origin.control.record_digest != policy.record_digest
                {
                    return Err(provider_failure("record origin kind or identity differs").into());
                }
                if records
                    .insert(
                        document.document.id.clone(),
                        NativeRecallRecord {
                            policy,
                            record,
                            origin,
                        },
                    )
                    .is_some()
                {
                    return Err(provider_failure("duplicate native record identity").into());
                }
            }
            documents.push(document);
            relations.extend(relation);
        }
        frontier_charge(budget, documents.len() as u64 + relations.len() as u64, 0)?;
        let corpus = AuthorizedCorpus::authorize(request, documents, relations)?;
        if complete && corpus.documents().len() != records.len() {
            return Err(provider_failure("complete corpus origin inventory differs").into());
        }
        Ok(NativeRecallFrontier { corpus, records })
    }
}

impl RecallProvider for NativeRecallProvider<'_> {
    fn snapshot(&self, at_commit: Option<u64>) -> Result<ProviderSnapshot> {
        let snapshot = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(provider_storage)?;
        let (_, state) = self
            .service
            .select_snapshot(&snapshot, self.workspace_id, at_commit)
            .map_err(provider_service)?;
        let result = Self::provider_snapshot(&state, &self.service.database_id);
        result.validate()?;
        Ok(result)
    }

    fn authorized_corpus(&self, request: &ProviderRequest) -> Result<AuthorizedCorpus> {
        let snapshot = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(provider_storage)?;
        self.authorized_inner(&snapshot, None, request, &mut None)
            .map(|frontier| frontier.corpus)
            .map_err(frontier_recall)
    }
}

fn relation(
    record: &MemoryRecord,
    access: &AccessRule,
    valid_time: Option<TimeRange>,
) -> Result<Option<ProviderRelation>> {
    if record.document.kind != MemoryRecordKind::Edge {
        return Ok(None);
    }
    let (Some(source), Some(target)) = (
        record.document.links.source.as_ref(),
        record.document.links.target.as_ref(),
    ) else {
        return Ok(None);
    };
    Ok(Some(ProviderRelation {
        access: access.clone(),
        relation: RecallRelation {
            id: record.document.id.clone(),
            source: DocumentId::new(source.clone())?,
            target: DocumentId::new(target.clone())?,
            kind: record
                .document
                .links
                .predicate
                .as_ref()
                .map_or(RecallRelationKind::RelatedTo, |predicate| {
                    RecallRelationKind::Domain(predicate.clone())
                }),
            weight: 1.0,
            valid_time,
            trust: 1.0,
        },
    }))
}

pub(super) fn access_rule(policy: &AccessPolicy) -> AccessRule {
    let mut grants = policy.audience_purpose_grants.clone();
    if grants.is_empty() {
        let purposes = if policy.purposes.is_empty() {
            BTreeSet::from(["*".to_owned()])
        } else {
            policy.purposes.clone()
        };
        for audience in policy.audience.iter().chain(&policy.owners) {
            grants.insert(audience.clone(), purposes.clone());
        }
        if !policy.owners.is_empty() {
            grants.insert("@owner".to_owned(), purposes);
        }
    }
    AccessRule {
        workspace: policy.workspace_id.clone(),
        scopes: policy.scopes.clone(),
        owners: policy.owners.clone(),
        audience_purpose_grants: grants,
        sensitivity: match policy.sensitivity {
            Sensitivity::Public => RecallSensitivity::Public,
            Sensitivity::Internal => RecallSensitivity::Internal,
            Sensitivity::Private => RecallSensitivity::Confidential,
            Sensitivity::Restricted => RecallSensitivity::Restricted,
        },
        required_compartments: BTreeSet::new(),
        consent: match policy.consent {
            Consent::Granted => AccessConsent::Granted,
            Consent::Unknown => AccessConsent::Unknown,
            Consent::Denied => AccessConsent::Denied,
        },
        retrievable: policy.retrievable,
    }
}

const fn document_kind(kind: MemoryRecordKind) -> RecallDocumentKind {
    match kind {
        MemoryRecordKind::Node => RecallDocumentKind::Entity,
        MemoryRecordKind::Claim => RecallDocumentKind::Claim,
        MemoryRecordKind::Edge => RecallDocumentKind::Relationship,
        MemoryRecordKind::Conflict => RecallDocumentKind::Conflict,
        MemoryRecordKind::Evidence => RecallDocumentKind::Observation,
        MemoryRecordKind::Candidate => RecallDocumentKind::Unknown,
        MemoryRecordKind::SemanticObject => RecallDocumentKind::Knowledge,
        MemoryRecordKind::RuntimeState => RecallDocumentKind::Episode,
        MemoryRecordKind::DomainExtension => RecallDocumentKind::Domain,
    }
}

fn bounded_time(from: Option<i128>, to: Option<i128>) -> Result<Option<TimeRange>> {
    let Some(start) = from else {
        if to.is_some() {
            return Err(provider_failure("valid-time end has no start"));
        }
        return Ok(None);
    };
    let start =
        i64::try_from(start).map_err(|_| provider_failure("valid-time start is invalid"))?;
    let end = to
        .map(i64::try_from)
        .transpose()
        .map_err(|_| provider_failure("valid-time end is invalid"))?;
    TimeRange::new(TimestampMicros(start), end.map(TimestampMicros))
        .map(Some)
        .map_err(|_| provider_failure("valid-time range is invalid"))
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    string_vec(value).into_iter().collect()
}

fn string_vec(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned())
}

fn provider_storage(_error: contextdb_storage::StorageError) -> RecallError {
    provider_failure("native storage read failed")
}

fn provider_service(_error: ServiceError) -> RecallError {
    provider_failure("native store integrity check failed")
}

fn provider_failure(message: &str) -> RecallError {
    RecallError::Provider(message.to_owned())
}

fn frontier_charge(
    budget: &mut Option<&mut QueryBudget>,
    work: u64,
    bytes: u64,
) -> FrontierResult<()> {
    if let Some(shared) = budget.as_deref_mut() {
        shared
            .charge(work, bytes)
            .map_err(super::raw_index::budget_error)?;
    }
    Ok(())
}

fn frontier_bytes<S: ReadSnapshot>(
    snapshot: &S,
    keyspace: &contextdb_storage::Keyspace,
    key: &[u8],
    budget: &mut Option<&mut QueryBudget>,
) -> FrontierResult<Option<Vec<u8>>> {
    frontier_charge(budget, 1, 0)?;
    let bytes = snapshot.get(keyspace, key).map_err(provider_storage)?;
    if let Some(bytes) = &bytes {
        frontier_charge(budget, 0, bytes.len() as u64)?;
        if budget.is_some() && bytes.len() > super::MAX_JSON_BYTES {
            return Err(super::exhausted("generic material exceeds the native row limit").into());
        }
    }
    Ok(bytes)
}

fn frontier_recall(error: FrontierError) -> RecallError {
    match error {
        FrontierError::Recall(error) => error,
        FrontierError::Service(error) => provider_service(error),
    }
}

fn frontier_service(error: FrontierError) -> ServiceError {
    match error {
        FrontierError::Service(error) => error,
        FrontierError::Recall(RecallError::DeadlineExceeded) => {
            super::exhausted("generic recall deadline exceeded")
        }
        FrontierError::Recall(_) => ServiceError::new(
            ErrorCode::IntegrityFailure,
            "native generic recall frontier failed verification",
            false,
        ),
    }
}

fn source_denied(error: &ServiceError) -> bool {
    error.code == ErrorCode::PermissionDenied || super::record_sources::source_unavailable(error)
}
