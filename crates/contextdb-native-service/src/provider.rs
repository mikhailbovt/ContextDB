//! Exact policy-first recall adapter over the native revision store.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{CommitRange, CommitSeq, PolicyDecision, TimeRange, TimestampMicros};
use contextdb_recall::{
    AccessConsent, AccessRule, AuthorizedCorpus, DocumentId, DocumentPerspective,
    DocumentTemporalState, DocumentUseProfile, ProviderDocument, ProviderEvidence,
    ProviderRelation, ProviderRequest, ProviderSnapshot, RecallConflictState, RecallDocument,
    RecallDocumentKind, RecallError, RecallEvidence, RecallProvider, RecallRelation,
    RecallRelationKind, RecallSensitivity, RecallWatermarks, Result, SuppliedVector,
};
use contextdb_service::{AccessPolicy, Consent, MemoryRecord, MemoryRecordKind, Sensitivity};
use contextdb_storage::{ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine};
use serde_json::Value;

use super::{
    MAX_AUTHORIZED_CANDIDATES, NativeService, SCAN_PAGE_BYTES, SCAN_PAGE_ENTRIES, SCHEMA_VERSION,
    StoredEvent, StoredPolicy, WorkspaceState, decode, event_digest, policy_route_key,
    policy_route_prefix, validate_stored_policy, visible_at,
};

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

    fn provider_snapshot(state: &WorkspaceState, database_id: &str) -> ProviderSnapshot {
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
    ) -> Result<u64> {
        let bytes = snapshot
            .get(&self.service.keyspaces.events, &global_commit.to_be_bytes())
            .map_err(provider_storage)?
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
            return Err(provider_failure("transaction event binding is invalid"));
        }
        Ok(event.workspace_commit)
    }

    fn transaction_range<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_digest: &str,
        policy: &StoredPolicy,
    ) -> Result<CommitRange> {
        let start =
            self.workspace_commit_for_global(snapshot, workspace_digest, policy.transaction_from)?;
        let end = policy
            .transaction_to
            .map(|commit| self.workspace_commit_for_global(snapshot, workspace_digest, commit))
            .transpose()?;
        CommitRange::new(CommitSeq::new(start), end.map(CommitSeq::new))
            .map_err(|_| provider_failure("transaction-time range is invalid"))
    }

    fn provider_document<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_digest: &str,
        policy: &StoredPolicy,
        access: AccessRule,
    ) -> Result<(ProviderDocument, Option<ProviderRelation>)> {
        let record = self
            .service
            .load_content(snapshot, policy)
            .map_err(provider_service)?;
        let valid_time = bounded_time(
            record.document.valid_time.from,
            record.document.valid_time.to,
        )?;
        let transaction_time = self.transaction_range(snapshot, workspace_digest, policy)?;
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
        let relation = relation(&record, &access, valid_time)?;
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
        if request.snapshot.database_id != self.service.database_id
            || request.principal.workspace != self.workspace_id
        {
            return Err(provider_failure("snapshot or workspace binding differs"));
        }
        let snapshot = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(provider_storage)?;
        let (global_commit, state) = self
            .service
            .select_snapshot(
                &snapshot,
                self.workspace_id,
                Some(request.snapshot.commit_seq),
            )
            .map_err(provider_service)?;
        let expected = Self::provider_snapshot(&state, &self.service.database_id);
        if expected != request.snapshot {
            return Err(provider_failure("provider snapshot binding differs"));
        }

        let route_prefix = policy_route_prefix(self.workspace_id);
        let mut continuation: Option<Vec<u8>> = None;
        let mut scanned = 0_usize;
        let mut selected = BTreeMap::<String, (StoredPolicy, AccessRule)>::new();
        loop {
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
                return Err(provider_failure("policy scan exceeds the bounded profile"));
            }
            for entry in page.entries {
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
                    return Err(provider_failure("policy route binding is invalid"));
                }
                // Quarantined proposals, including their candidate-only links,
                // cannot influence ordinary recall counts, budgets, graph
                // expansion, ContextPack selection, or diagnostics.
                if policy.kind == MemoryRecordKind::Candidate {
                    continue;
                }
                let access = access_rule(&policy.access);
                if visible_at(&policy, global_commit)
                    && policy.lifecycle == contextdb_service::MemoryLifecycle::Active
                    && request.principal.allows(&access)
                {
                    access.validate()?;
                    if selected
                        .insert(policy.record_digest.clone(), (policy, access))
                        .is_some()
                    {
                        return Err(provider_failure("visible policy revisions overlap"));
                    }
                    if selected.len() > MAX_AUTHORIZED_CANDIDATES {
                        return Err(provider_failure(
                            "authorized corpus exceeds the bounded profile",
                        ));
                    }
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if continuation
                .as_ref()
                .is_some_and(|previous| &next <= previous)
            {
                return Err(provider_failure("policy scan cursor did not advance"));
            }
            continuation = Some(next);
        }

        let mut documents = Vec::with_capacity(selected.len());
        let mut relations = Vec::new();
        for (_, (policy, access)) in selected {
            let (document, relation) =
                self.provider_document(&snapshot, &state.workspace_digest, &policy, access)?;
            documents.push(document);
            relations.extend(relation);
        }
        AuthorizedCorpus::authorize(request, documents, relations)
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

fn provider_service(_error: contextdb_service::ServiceError) -> RecallError {
    provider_failure("native store integrity check failed")
}

fn provider_failure(message: &str) -> RecallError {
    RecallError::Provider(message.to_owned())
}
