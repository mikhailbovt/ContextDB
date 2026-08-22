use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use contextdb_core::Validate;
use serde::Serialize;
use serde_json::Value;

use crate::canonical;
use crate::error::{ReferenceError, Result};
use crate::model::{
    AccessLabel, CommitReceipt, CommitSeq, ContentRef, DeletionTombstone, Direction, Failpoint,
    IdempotencyRecord, JournalEvent, JournalRecord, Lifecycle, LogicalExport, LogicalId,
    LogicalRecord, LogicalRecordMetadata, MaterializedObservation, MaterializedRecord, Mutation,
    ObservationInput, ObservationRecord, Principal, ReadTrace, RecordContent, RecordKind,
    SearchHit, SemanticTransaction, Snapshot, StoredRevision, Traced, Watermarks,
    WorkspaceEventCandidate, WorkspaceEventCandidateKind, WorkspaceEventPage,
};

const EXPORT_FORMAT: &str = "contextdb.logical.v1";
const MAX_WORKSPACE_CANDIDATES: usize = 100_000;
const MAX_WORKSPACE_JOURNAL_PAGE: usize = 4_096;

/// Deterministic, clone-on-write in-memory correctness oracle.
///
/// This engine intentionally favours obvious semantics over throughput. Every write is prepared in
/// a private state clone and becomes visible by one lock-protected pointer replacement.
#[derive(Debug, Clone)]
pub struct ContextDb {
    inner: Arc<RwLock<State>>,
}

#[derive(Debug, Clone)]
struct State {
    database_id: String,
    head: CommitSeq,
    watermarks: Watermarks,
    histories: BTreeMap<LogicalId, Vec<StoredRevision>>,
    observations: BTreeMap<LogicalId, ObservationRecord>,
    tombstones: BTreeMap<LogicalId, DeletionTombstone>,
    journal: Vec<JournalRecord>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
    contents: BTreeMap<String, Value>,
    security_indexes: SecurityIndexes,
}

/// Authorization indexes are primary security state for every caller-facing read.
/// They are maintained with each clone-on-write transaction and independently
/// rebuilt and compared before publication/import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SecurityIndexes {
    histories_by_workspace: BTreeMap<LogicalId, BTreeSet<LogicalId>>,
    observations_by_workspace: BTreeMap<LogicalId, BTreeSet<LogicalId>>,
    journal_by_workspace: BTreeMap<LogicalId, Vec<usize>>,
    events_by_workspace: BTreeMap<LogicalId, Vec<WorkspaceEventIndexEntry>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceEventIndexEntry {
    workspace_seq: CommitSeq,
    ordinal: u32,
    journal_index: usize,
    kind: WorkspaceEventCandidateKind,
}

#[derive(Serialize)]
struct JournalDigestInput<'a> {
    commit_seq: CommitSeq,
    previous_digest: &'a Option<String>,
    event: &'a JournalEvent,
}

impl ContextDb {
    /// Creates an empty database with a stable caller-selected namespace.
    pub fn new(database_id: impl Into<String>) -> Result<Self> {
        let database_id = database_id.into();
        if database_id.trim().is_empty() {
            return Err(ReferenceError::Invariant(
                "database identifier must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(State {
                database_id,
                head: 0,
                watermarks: Watermarks::default(),
                histories: BTreeMap::new(),
                observations: BTreeMap::new(),
                tombstones: BTreeMap::new(),
                journal: Vec::new(),
                idempotency: BTreeMap::new(),
                contents: BTreeMap::new(),
                security_indexes: SecurityIndexes::default(),
            })),
        })
    }

    /// Returns a coherent handle to the current state.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let state = self.read_state()?;
        Ok(snapshot_for(&state, state.head))
    }

    /// Opens a retained logical snapshot by commit sequence.
    pub fn snapshot_at(&self, commit_seq: CommitSeq) -> Result<Snapshot> {
        let state = self.read_state()?;
        validate_snapshot(&state, commit_seq)?;
        Ok(snapshot_for(&state, commit_seq))
    }

    /// Returns current global freshness.
    pub fn watermarks(&self) -> Result<Watermarks> {
        Ok(self.read_state()?.watermarks.clone())
    }

    /// Returns freshness as of an exact retained snapshot.
    pub fn watermarks_for(&self, snapshot: &Snapshot) -> Result<Watermarks> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        Ok(watermarks_at(&state, snapshot.commit_seq))
    }

    /// Returns gap-free freshness counters scoped to one trusted workspace.
    pub fn watermarks_for_workspace(
        &self,
        snapshot: &Snapshot,
        workspace: &str,
    ) -> Result<Watermarks> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        Ok(workspace_watermarks_at(
            &state,
            workspace,
            snapshot.commit_seq,
        ))
    }

    /// Resolves a public tenant-local snapshot ordinal to its internal MVCC commit.
    ///
    /// Zero is the workspace genesis. Positive values address the exact indexed
    /// journal record for this workspace and cannot select another workspace's
    /// otherwise interleaved commit.
    pub fn snapshot_for_workspace(
        &self,
        workspace: &str,
        workspace_seq: CommitSeq,
    ) -> Result<Snapshot> {
        let state = self.read_state()?;
        let commit_seq = if workspace_seq == 0 {
            0
        } else {
            let index = usize::try_from(workspace_seq.saturating_sub(1)).map_err(|_| {
                ReferenceError::SnapshotNotFound {
                    requested: workspace_seq,
                    head: workspace_journal_len(&state, workspace),
                }
            })?;
            let journal_index = state
                .security_indexes
                .journal_by_workspace
                .get(workspace)
                .and_then(|positions| positions.get(index))
                .copied()
                .ok_or_else(|| ReferenceError::SnapshotNotFound {
                    requested: workspace_seq,
                    head: workspace_journal_len(&state, workspace),
                })?;
            state
                .journal
                .get(journal_index)
                .map(|record| record.commit_seq)
                .ok_or_else(|| {
                    ReferenceError::Invariant(
                        "workspace journal index refers outside the journal".to_owned(),
                    )
                })?
        };
        Ok(snapshot_for(&state, commit_seq))
    }

    /// Clones at most one fixed-size tenant-local event-candidate page after the
    /// supplied position. Cursor selection happens against the security index
    /// before any journal metadata is cloned.
    pub fn workspace_event_page(
        &self,
        workspace: &str,
        after_workspace_seq: CommitSeq,
        after_ordinal: u32,
        limit: usize,
    ) -> Result<WorkspaceEventPage> {
        if limit == 0 || limit > MAX_WORKSPACE_JOURNAL_PAGE {
            return Err(ReferenceError::ResourceExhausted);
        }
        let state = self.read_state()?;
        if after_workspace_seq > workspace_journal_len(&state, workspace) {
            return Err(ReferenceError::SnapshotNotFound {
                requested: after_workspace_seq,
                head: workspace_journal_len(&state, workspace),
            });
        }
        let entries = state
            .security_indexes
            .events_by_workspace
            .get(workspace)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let start = entries.partition_point(|entry| {
            (entry.workspace_seq, entry.ordinal) <= (after_workspace_seq, after_ordinal)
        });
        let end = start.saturating_add(limit).min(entries.len());
        let mut candidates = Vec::with_capacity(end.saturating_sub(start));
        for entry in &entries[start..end] {
            let record = state.journal.get(entry.journal_index).ok_or_else(|| {
                ReferenceError::Invariant(
                    "workspace event index refers outside the journal".to_owned(),
                )
            })?;
            candidates.push(WorkspaceEventCandidate {
                workspace_seq: entry.workspace_seq,
                ordinal: entry.ordinal,
                commit_seq: record.commit_seq,
                record_digest: record.record_digest.clone(),
                kind: entry.kind.clone(),
            });
        }
        let scanned_through = candidates
            .last()
            .map_or((after_workspace_seq, after_ordinal), |candidate| {
                (candidate.workspace_seq, candidate.ordinal)
            });
        Ok(WorkspaceEventPage {
            candidates,
            scanned_through,
            has_more: end < entries.len(),
        })
    }

    /// Atomically captures an immutable observation record and its erasable content.
    pub fn observe(&self, input: ObservationInput) -> Result<CommitReceipt> {
        self.observe_with_failpoint(input, Failpoint::None)
    }

    /// Validates and captures one canonical immutable observation.
    pub fn observe_core(
        &self,
        observation: &contextdb_core::ObservationUnit,
        idempotency_key: impl Into<String>,
    ) -> Result<CommitReceipt> {
        self.observe(crate::core_adapter::observation(
            observation,
            idempotency_key,
        )?)
    }

    /// Observation commit with a deterministic crash failpoint for conformance testing.
    pub fn observe_with_failpoint(
        &self,
        input: ObservationInput,
        failpoint: Failpoint,
    ) -> Result<CommitReceipt> {
        validate_observation(&input)?;
        let request_digest = operation_digest("observe", &input)?;
        let key_digest = key_digest(&input.idempotency_key);
        let mut guard = self.write_state()?;
        if let Some(receipt) = replay_or_conflict(&guard, &key_digest, &request_digest)? {
            return Ok(receipt);
        }
        if guard.observations.contains_key(&input.observation_id)
            || guard.histories.contains_key(&input.observation_id)
            || guard.tombstones.contains_key(&input.observation_id)
        {
            return Err(ReferenceError::Invariant(format!(
                "external identifier {} has already been used",
                input.observation_id
            )));
        }

        let mut next = guard.clone();
        let commit_seq = next_commit(next.head)?;
        let (observation_content, observation_value) = make_content_ref(
            "observation",
            &input.observation_id,
            commit_seq,
            &input.content,
        )?;
        next.contents
            .insert(observation_content.id.clone(), observation_value);
        next.observations.insert(
            input.observation_id.clone(),
            ObservationRecord {
                observation_id: input.observation_id.clone(),
                accepted_seq: commit_seq,
                access: input.access.clone(),
                content: observation_content,
                metadata: input.metadata.clone(),
            },
        );
        next.security_indexes
            .observations_by_workspace
            .entry(input.access.workspace.clone())
            .or_default()
            .insert(input.observation_id.clone());

        let request_value = serde_json::to_value(&input)
            .map_err(|error| ReferenceError::Serialization(error.to_string()))?;
        let (request_content, request_value) = make_content_ref(
            "journal-observation",
            &input.observation_id,
            commit_seq,
            &request_value,
        )?;
        next.contents
            .insert(request_content.id.clone(), request_value);
        append_journal(
            &mut next,
            commit_seq,
            JournalEvent::ObservationAccepted {
                observation_id: input.observation_id,
                request_digest: request_digest.clone(),
                request_content,
            },
        )?;
        next.head = commit_seq;
        next.watermarks.journal = commit_seq;

        let receipt = CommitReceipt {
            commit_seq,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: next.watermarks.clone(),
        };
        next.idempotency.insert(
            key_digest,
            IdempotencyRecord {
                request_digest,
                receipt: receipt.clone(),
            },
        );
        verify_security_indexes(&next)?;
        publish(&mut guard, next, failpoint)?;
        Ok(receipt)
    }

    /// Atomically validates and publishes a semantic mutation set.
    pub fn commit(&self, transaction: SemanticTransaction) -> Result<CommitReceipt> {
        self.commit_with_failpoint(transaction, Failpoint::None)
    }

    /// Semantic commit with a deterministic crash failpoint for conformance testing.
    pub fn commit_with_failpoint(
        &self,
        transaction: SemanticTransaction,
        failpoint: Failpoint,
    ) -> Result<CommitReceipt> {
        if transaction.idempotency_key.trim().is_empty() {
            return Err(ReferenceError::Invariant(
                "idempotency key must not be empty".to_owned(),
            ));
        }
        if transaction.mutations.is_empty() {
            return Err(ReferenceError::Invariant(
                "semantic transaction must contain at least one mutation".to_owned(),
            ));
        }
        let request_digest = operation_digest("semantic", &transaction)?;
        let key_digest = key_digest(&transaction.idempotency_key);
        let mut guard = self.write_state()?;
        if let Some(receipt) = replay_or_conflict(&guard, &key_digest, &request_digest)? {
            return Ok(receipt);
        }
        if transaction.base_seq != guard.head {
            return Err(ReferenceError::SnapshotConflict {
                expected: transaction.base_seq,
                current: guard.head,
            });
        }

        let mut next = guard.clone();
        let commit_seq = next_commit(next.head)?;
        let mut affected_ids = BTreeSet::new();
        for mutation in &transaction.mutations {
            apply_mutation(&mut next, mutation, commit_seq, &mut affected_ids)?;
        }
        validate_complete_state(&next, commit_seq)?;

        let request_value = serde_json::to_value(&transaction)
            .map_err(|error| ReferenceError::Serialization(error.to_string()))?;
        let (request_content, request_value) = make_content_ref(
            "journal-semantic",
            &request_digest,
            commit_seq,
            &request_value,
        )?;
        next.contents
            .insert(request_content.id.clone(), request_value);
        append_journal(
            &mut next,
            commit_seq,
            JournalEvent::SemanticPublished {
                request_digest: request_digest.clone(),
                request_content,
                affected_ids,
            },
        )?;
        next.head = commit_seq;
        next.watermarks = Watermarks {
            journal: commit_seq,
            semantic: commit_seq,
            lexical: commit_seq,
            vector: commit_seq,
            graph: commit_seq,
        };
        let receipt = CommitReceipt {
            commit_seq,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: next.watermarks.clone(),
        };
        next.idempotency.insert(
            key_digest,
            IdempotencyRecord {
                request_digest,
                receipt: receipt.clone(),
            },
        );
        verify_security_indexes(&next)?;
        publish(&mut guard, next, failpoint)?;
        Ok(receipt)
    }

    /// Validates and atomically publishes the canonical `contextdb-core` mutation contract.
    ///
    /// The caller-supplied idempotency key belongs to the transport/gateway and is deliberately
    /// separate from the model-independent core mutation. Every canonical value is converted by a
    /// lossless adapter after `Validate` succeeds; the exact canonical mutation bytes remain in the
    /// journal for replay.
    pub fn commit_core(
        &self,
        mutation: &contextdb_core::SemanticMutationSet,
        idempotency_key: impl Into<String>,
    ) -> Result<CommitReceipt> {
        mutation.validate()?;
        let idempotency_key = idempotency_key.into();
        if idempotency_key.trim().is_empty() {
            return Err(ReferenceError::Invariant(
                "idempotency key must not be empty".to_owned(),
            ));
        }
        let request_digest = operation_digest("semantic-core", mutation)?;
        let key_digest = key_digest(&idempotency_key);
        let state = self.read_state()?;
        if let Some(receipt) = replay_or_conflict(&state, &key_digest, &request_digest)? {
            return Ok(receipt);
        }
        drop(state);
        let transaction = core_transaction(self, mutation, idempotency_key)?;
        self.commit_with_canonical_request(transaction, mutation)
    }

    fn commit_with_canonical_request<T: Serialize>(
        &self,
        transaction: SemanticTransaction,
        canonical_request: &T,
    ) -> Result<CommitReceipt> {
        if transaction.mutations.is_empty() {
            return Err(ReferenceError::Invariant(
                "canonical mutation has no material primary-state writes".to_owned(),
            ));
        }
        let request_digest = operation_digest("semantic-core", canonical_request)?;
        let key_digest = key_digest(&transaction.idempotency_key);
        let mut guard = self.write_state()?;
        if let Some(receipt) = replay_or_conflict(&guard, &key_digest, &request_digest)? {
            return Ok(receipt);
        }
        if transaction.base_seq != guard.head {
            return Err(ReferenceError::SnapshotConflict {
                expected: transaction.base_seq,
                current: guard.head,
            });
        }
        let mut next = guard.clone();
        let commit_seq = next_commit(next.head)?;
        let mut affected_ids = BTreeSet::new();
        for mutation in &transaction.mutations {
            apply_mutation(&mut next, mutation, commit_seq, &mut affected_ids)?;
        }
        validate_complete_state(&next, commit_seq)?;
        let request_value = serde_json::to_value(canonical_request)
            .map_err(|error| ReferenceError::Serialization(error.to_string()))?;
        let (request_content, request_value) = make_content_ref(
            "journal-semantic-core",
            &request_digest,
            commit_seq,
            &request_value,
        )?;
        next.contents
            .insert(request_content.id.clone(), request_value);
        append_journal(
            &mut next,
            commit_seq,
            JournalEvent::SemanticPublished {
                request_digest: request_digest.clone(),
                request_content,
                affected_ids,
            },
        )?;
        next.head = commit_seq;
        next.watermarks = Watermarks {
            journal: commit_seq,
            semantic: commit_seq,
            lexical: commit_seq,
            vector: commit_seq,
            graph: commit_seq,
        };
        let receipt = CommitReceipt {
            commit_seq,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: next.watermarks.clone(),
        };
        next.idempotency.insert(
            key_digest,
            IdempotencyRecord {
                request_digest,
                receipt: receipt.clone(),
            },
        );
        verify_security_indexes(&next)?;
        publish(&mut guard, next, Failpoint::None)?;
        Ok(receipt)
    }

    /// Materializes one revision only after its policy metadata authorizes the caller.
    pub fn get(
        &self,
        id: &str,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<MaterializedRecord> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        materialize_at(&state, id, snapshot.commit_seq, principal)
    }

    /// Resolves trusted, non-content metadata under the same policy used for
    /// materialization. Every private miss collapses to [`ReferenceError::Unauthorized`].
    pub fn authorized_record_metadata(
        &self,
        id: &str,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<LogicalRecordMetadata> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        Ok(
            private_revision_metadata(&state, id, snapshot.commit_seq, principal)?
                .record
                .clone(),
        )
    }

    /// Materializes only when trusted stored metadata matches the requested
    /// family. Missing, deleted, denied, and wrong-family IDs are indistinguishable.
    pub fn get_typed(
        &self,
        id: &str,
        expected_kind: RecordKind,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<MaterializedRecord> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        let revision = private_revision_metadata(&state, id, snapshot.commit_seq, principal)?;
        if revision.record.kind != expected_kind {
            return Err(ReferenceError::Unauthorized);
        }
        materialize_revision(&state, revision)
    }

    /// Returns typed history only after trusted current metadata and the exact
    /// stored family have authorized the request.
    pub fn history_typed(
        &self,
        id: &str,
        expected_kind: RecordKind,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<Vec<MaterializedRecord>> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        let selected = private_revision_metadata(&state, id, snapshot.commit_seq, principal)?;
        if selected.record.kind != expected_kind {
            return Err(ReferenceError::Unauthorized);
        }
        let history = state
            .histories
            .get(id)
            .ok_or(ReferenceError::Unauthorized)?;
        let mut result = Vec::new();
        for revision in history
            .iter()
            .filter(|revision| revision.transaction_from <= snapshot.commit_seq)
        {
            if revision.record.kind != expected_kind {
                return Err(ReferenceError::Invariant(format!(
                    "record kind changed inside history for {id}"
                )));
            }
            if principal.allows(&revision.record.access) {
                result.push(materialize_revision(&state, revision)?);
            }
        }
        if result.is_empty() {
            return Err(ReferenceError::Unauthorized);
        }
        Ok(result)
    }

    /// Materializes an immutable raw observation only after policy authorization.
    pub fn get_observation(
        &self,
        id: &str,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<MaterializedObservation> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        if state.tombstones.contains_key(id) {
            return Err(not_found("observation", id));
        }
        let record = state
            .observations
            .get(id)
            .filter(|record| record.accepted_seq <= snapshot.commit_seq)
            .ok_or_else(|| not_found("observation", id))?;
        if !principal.allows(&record.access) {
            return Err(ReferenceError::Unauthorized);
        }
        let content = state
            .contents
            .get(&record.content.id)
            .cloned()
            .ok_or_else(|| not_found("observation content", &record.content.id))?;
        if canonical::digest(&content)? != record.content.digest {
            return Err(ReferenceError::Invariant(format!(
                "content digest mismatch for observation {id}"
            )));
        }
        Ok(MaterializedObservation {
            record: record.clone(),
            content,
        })
    }

    /// Authorizes immutable observation metadata without touching its content.
    pub fn authorize_observation(
        &self,
        id: &str,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<()> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        if state.tombstones.contains_key(id) {
            return Err(ReferenceError::Unauthorized);
        }
        let authorized = state
            .observations
            .get(id)
            .filter(|record| record.accepted_seq <= snapshot.commit_seq)
            .is_some_and(|record| principal.allows(&record.access));
        if !authorized {
            return Err(ReferenceError::Unauthorized);
        }
        Ok(())
    }

    /// Returns all visible revisions, ordered by transaction start, after per-revision policy checks.
    pub fn history(
        &self,
        id: &str,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<Vec<MaterializedRecord>> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        if state.tombstones.contains_key(id) {
            return Err(not_found("record", id));
        }
        let history = state
            .histories
            .get(id)
            .ok_or_else(|| not_found("record", id))?;
        if !current_use_policy_allows(&state, id, principal) {
            return Err(ReferenceError::Unauthorized);
        }
        let mut result = Vec::new();
        for revision in history
            .iter()
            .filter(|revision| revision.transaction_from <= snapshot.commit_seq)
        {
            if principal.allows(&revision.record.access) {
                result.push(materialize_revision(&state, revision)?);
            }
        }
        if result.is_empty() {
            return Err(ReferenceError::Unauthorized);
        }
        Ok(result)
    }

    /// Returns current records of one family in stable ID order.
    pub fn scan_kind(
        &self,
        kind: RecordKind,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<Traced<Vec<MaterializedRecord>>> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        let mut records = Vec::new();
        let candidate_ids = state
            .security_indexes
            .histories_by_workspace
            .get(&principal.workspace);
        ensure_workspace_candidate_budget(candidate_ids)?;
        for id in candidate_ids.into_iter().flatten() {
            let history = state.histories.get(id).ok_or_else(|| {
                ReferenceError::Invariant(
                    "workspace history index refers to a missing record".to_owned(),
                )
            })?;
            if state.tombstones.contains_key(id) {
                continue;
            }
            let Some(revision) = revision_at(history, snapshot.commit_seq) else {
                continue;
            };
            if revision.record.kind == kind
                && revision.record.lifecycle == Lifecycle::Active
                && principal.allows(&revision.record.access)
                && current_use_policy_allows(&state, id, principal)
            {
                records.push(materialize_revision(&state, revision)?);
            }
        }
        let selected_ids = records
            .iter()
            .map(|record| record.revision.id.clone())
            .collect();
        Ok(Traced {
            trace: trace(
                &state,
                snapshot.commit_seq,
                &principal.workspace,
                "exact_scan",
                records.len(),
                selected_ids,
            ),
            value: records,
        })
    }

    /// Searches normalized text by an exact deterministic token-overlap score.
    pub fn lexical_search(
        &self,
        query: &str,
        limit: usize,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<Traced<Vec<SearchHit>>> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        let query_tokens = tokens(query);
        if query_tokens.is_empty() || limit == 0 {
            return Ok(Traced {
                value: Vec::new(),
                trace: trace(
                    &state,
                    snapshot.commit_seq,
                    &principal.workspace,
                    "exact_lexical",
                    0,
                    Vec::new(),
                ),
            });
        }
        let mut authorized_candidates = 0_usize;
        let mut hits = Vec::new();
        let candidate_ids = state
            .security_indexes
            .histories_by_workspace
            .get(&principal.workspace);
        ensure_workspace_candidate_budget(candidate_ids)?;
        for id in candidate_ids.into_iter().flatten() {
            let history = state.histories.get(id).ok_or_else(|| {
                ReferenceError::Invariant(
                    "workspace history index refers to a missing record".to_owned(),
                )
            })?;
            if state.tombstones.contains_key(id) {
                continue;
            }
            let Some(revision) = revision_at(history, snapshot.commit_seq) else {
                continue;
            };
            if revision.record.lifecycle != Lifecycle::Active
                || !principal.allows(&revision.record.access)
                || !current_use_policy_allows(&state, id, principal)
            {
                continue;
            }
            authorized_candidates = authorized_candidates.saturating_add(1);
            let content = content_for_revision(&state, revision)?;
            let Some(search_text) = content.search_text else {
                continue;
            };
            let document_tokens = tokens(&search_text);
            let matched = query_tokens
                .iter()
                .filter(|token| document_tokens.contains(*token))
                .count();
            if matched > 0 {
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "bounded exact-oracle token counts"
                )]
                let score = matched as f32 / query_tokens.len() as f32;
                hits.push(SearchHit {
                    id: id.clone(),
                    score,
                });
            }
        }
        sort_hits(&mut hits);
        hits.truncate(limit);
        let selected_ids = hits.iter().map(|hit| hit.id.clone()).collect();
        Ok(Traced {
            trace: trace(
                &state,
                snapshot.commit_seq,
                &principal.workspace,
                "exact_lexical",
                authorized_candidates,
                selected_ids,
            ),
            value: hits,
        })
    }

    /// Searches full-precision vectors by exact dot product after authorization.
    pub fn vector_search(
        &self,
        query: &[f32],
        limit: usize,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<Traced<Vec<SearchHit>>> {
        if query.is_empty() || query.iter().any(|component| !component.is_finite()) {
            return Err(ReferenceError::Invariant(
                "query vector must be non-empty and finite".to_owned(),
            ));
        }
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        let mut authorized_candidates = 0_usize;
        let mut hits = Vec::new();
        if limit > 0 {
            let candidate_ids = state
                .security_indexes
                .histories_by_workspace
                .get(&principal.workspace);
            ensure_workspace_candidate_budget(candidate_ids)?;
            for id in candidate_ids.into_iter().flatten() {
                let history = state.histories.get(id).ok_or_else(|| {
                    ReferenceError::Invariant(
                        "workspace history index refers to a missing record".to_owned(),
                    )
                })?;
                if state.tombstones.contains_key(id) {
                    continue;
                }
                let Some(revision) = revision_at(history, snapshot.commit_seq) else {
                    continue;
                };
                if revision.record.lifecycle != Lifecycle::Active
                    || !principal.allows(&revision.record.access)
                    || !current_use_policy_allows(&state, id, principal)
                {
                    continue;
                }
                authorized_candidates = authorized_candidates.saturating_add(1);
                let content = content_for_revision(&state, revision)?;
                let Some(vector) = content.vector else {
                    continue;
                };
                if vector.len() != query.len() {
                    continue;
                }
                let score = vector
                    .iter()
                    .zip(query)
                    .map(|(left, right)| left * right)
                    .sum();
                hits.push(SearchHit {
                    id: id.clone(),
                    score,
                });
            }
        }
        sort_hits(&mut hits);
        hits.truncate(limit);
        let selected_ids = hits.iter().map(|hit| hit.id.clone()).collect();
        Ok(Traced {
            trace: trace(
                &state,
                snapshot.commit_seq,
                &principal.workspace,
                "exact_vector",
                authorized_candidates,
                selected_ids,
            ),
            value: hits,
        })
    }

    /// Performs bounded breadth-first traversal over authorized edge and node revisions.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the bounded typed traversal contract"
    )]
    pub fn traverse(
        &self,
        start: &[LogicalId],
        direction: Direction,
        predicates: &BTreeSet<LogicalId>,
        max_hops: u8,
        max_nodes: usize,
        snapshot: &Snapshot,
        principal: &Principal,
    ) -> Result<Traced<Vec<LogicalId>>> {
        let state = self.read_state()?;
        validate_snapshot_handle(&state, snapshot)?;
        for id in start {
            let revision = current_authorized_metadata(&state, id, snapshot.commit_seq, principal)
                .ok_or(ReferenceError::Unauthorized)?;
            if revision.record.kind != RecordKind::Node {
                return Err(ReferenceError::Invariant(format!(
                    "traversal start {id} is not a node"
                )));
            }
        }
        if max_hops == 0 || max_nodes == 0 {
            return Ok(Traced {
                value: Vec::new(),
                trace: trace(
                    &state,
                    snapshot.commit_seq,
                    &principal.workspace,
                    "exact_traverse",
                    0,
                    Vec::new(),
                ),
            });
        }

        let mut queue = VecDeque::new();
        let mut visited = start.iter().cloned().collect::<BTreeSet<_>>();
        for id in start.iter().cloned() {
            queue.push_back((id, 0_u8));
        }
        let mut result = Vec::new();
        let mut authorized_edges = 0_usize;
        let candidate_ids = state
            .security_indexes
            .histories_by_workspace
            .get(&principal.workspace);
        ensure_workspace_candidate_budget(candidate_ids)?;
        let mut scanned_candidates = 0_usize;
        while let Some((node, hops)) = queue.pop_front() {
            if hops >= max_hops {
                continue;
            }
            let mut neighbours = BTreeSet::new();
            for edge_id in candidate_ids.into_iter().flatten() {
                scanned_candidates = scanned_candidates.saturating_add(1);
                if scanned_candidates > MAX_WORKSPACE_CANDIDATES {
                    return Err(ReferenceError::ResourceExhausted);
                }
                let history = state.histories.get(edge_id).ok_or_else(|| {
                    ReferenceError::Invariant(
                        "workspace history index refers to a missing record".to_owned(),
                    )
                })?;
                if state.tombstones.contains_key(edge_id) {
                    continue;
                }
                let Some(edge) = revision_at(history, snapshot.commit_seq) else {
                    continue;
                };
                if edge.record.kind != RecordKind::Edge
                    || edge.record.lifecycle != Lifecycle::Active
                    || !principal.allows(&edge.record.access)
                    || !current_use_policy_allows(&state, edge_id, principal)
                {
                    continue;
                }
                let links = &edge.record.links;
                if !predicates.is_empty()
                    && links
                        .predicate
                        .as_ref()
                        .is_none_or(|predicate| !predicates.contains(predicate))
                {
                    continue;
                }
                let outgoing = matches!(direction, Direction::Outgoing | Direction::Both)
                    && links.source.as_deref() == Some(node.as_str());
                let incoming = matches!(direction, Direction::Incoming | Direction::Both)
                    && links.target.as_deref() == Some(node.as_str());
                let neighbour = if outgoing {
                    links.target.as_ref()
                } else if incoming {
                    links.source.as_ref()
                } else {
                    None
                };
                if let Some(neighbour) = neighbour
                    && current_authorized_metadata(
                        &state,
                        neighbour,
                        snapshot.commit_seq,
                        principal,
                    )
                    .is_some_and(|record| record.record.kind == RecordKind::Node)
                {
                    authorized_edges = authorized_edges.saturating_add(1);
                    neighbours.insert(neighbour.clone());
                }
            }
            for neighbour in neighbours {
                if visited.insert(neighbour.clone()) {
                    result.push(neighbour.clone());
                    if result.len() >= max_nodes {
                        break;
                    }
                    queue.push_back((neighbour, hops.saturating_add(1)));
                }
            }
            if result.len() >= max_nodes {
                break;
            }
        }
        Ok(Traced {
            trace: trace(
                &state,
                snapshot.commit_seq,
                &principal.workspace,
                "exact_traverse",
                authorized_edges,
                result.clone(),
            ),
            value: result,
        })
    }

    /// Returns immutable journal metadata for replay/audit.
    pub fn journal(&self) -> Result<Vec<JournalRecord>> {
        Ok(self.read_state()?.journal.clone())
    }

    /// Returns a non-content hard-deletion proof, if one exists.
    pub fn tombstone(&self, id: &str) -> Result<Option<DeletionTombstone>> {
        Ok(self.read_state()?.tombstones.get(id).cloned())
    }

    /// Exports canonical logical JSON including retained history and non-deleted content.
    pub fn export(&self) -> Result<Vec<u8>> {
        let state = self.read_state()?;
        canonical::to_vec(&logical_export(&state))
    }

    /// Imports a complete logical export into a new deterministic in-memory engine.
    pub fn import(bytes: &[u8]) -> Result<Self> {
        let export: LogicalExport = serde_json::from_slice(bytes)
            .map_err(|error| ReferenceError::InvalidImport(error.to_string()))?;
        validate_export(&export)?;
        let mut state = State {
            database_id: export.database_id,
            head: export.head,
            watermarks: export.watermarks,
            histories: export.histories,
            observations: export.observations,
            tombstones: export.tombstones,
            journal: export.journal,
            idempotency: export.idempotency,
            contents: export.contents,
            security_indexes: SecurityIndexes::default(),
        };
        state.security_indexes = rebuild_security_indexes(&state)?;
        verify_security_indexes(&state)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
        })
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, State>> {
        self.inner.read().map_err(|_| ReferenceError::LockPoisoned)
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, State>> {
        self.inner.write().map_err(|_| ReferenceError::LockPoisoned)
    }
}

fn logical_export(state: &State) -> LogicalExport {
    LogicalExport {
        format: EXPORT_FORMAT.to_owned(),
        database_id: state.database_id.clone(),
        head: state.head,
        watermarks: state.watermarks.clone(),
        histories: state.histories.clone(),
        observations: state.observations.clone(),
        tombstones: state.tombstones.clone(),
        journal: state.journal.clone(),
        idempotency: state.idempotency.clone(),
        contents: state.contents.clone(),
    }
}

fn core_transaction(
    db: &ContextDb,
    mutation: &contextdb_core::SemanticMutationSet,
    idempotency_key: String,
) -> Result<SemanticTransaction> {
    let head = db.snapshot()?.commit_seq;
    if mutation.base_snapshot.commit_seq.get() != head {
        return Err(ReferenceError::SnapshotConflict {
            expected: mutation.base_snapshot.commit_seq.get(),
            current: head,
        });
    }
    if !mutation.observation_appends.is_empty() {
        return Err(ReferenceError::Invariant(
            "core mutation observation_appends must enter through observe_core before semantic publication"
                .to_owned(),
        ));
    }
    let state = db.read_state()?;
    let mut existing_records = BTreeMap::new();
    for (id, history) in &state.histories {
        if state.tombstones.contains_key(id) {
            continue;
        }
        if let Some(revision) = revision_at(history, state.head) {
            let content = content_for_revision(&state, revision)?;
            existing_records.insert(id.clone(), (revision.record.kind, content.value));
        }
    }
    drop(state);
    let records = crate::core_adapter::mutation_records(mutation, &existing_records)?;
    let mutations = records
        .into_iter()
        .map(|record| Mutation::Put {
            record,
            expected_revision: None,
        })
        .collect();
    Ok(SemanticTransaction {
        base_seq: head,
        idempotency_key,
        mutations,
    })
}

fn validate_export(export: &LogicalExport) -> Result<()> {
    if export.format != EXPORT_FORMAT {
        return Err(ReferenceError::InvalidImport(format!(
            "unsupported export format {}",
            export.format
        )));
    }
    if export.database_id.trim().is_empty() {
        return Err(ReferenceError::InvalidImport(
            "database identifier is empty".to_owned(),
        ));
    }
    if export.head != export.journal.len() as u64 {
        return Err(ReferenceError::InvalidImport(
            "head does not match contiguous journal length".to_owned(),
        ));
    }
    let mut previous_digest = None;
    for (index, record) in export.journal.iter().enumerate() {
        let expected_seq = u64::try_from(index)
            .map_err(|error| ReferenceError::InvalidImport(error.to_string()))?
            .checked_add(1)
            .ok_or_else(|| ReferenceError::InvalidImport("journal sequence overflow".to_owned()))?;
        if record.commit_seq != expected_seq || record.previous_digest != previous_digest {
            return Err(ReferenceError::InvalidImport(
                "journal sequence or digest chain is invalid".to_owned(),
            ));
        }
        let actual = journal_digest(record.commit_seq, &record.previous_digest, &record.event)?;
        if actual != record.record_digest {
            return Err(ReferenceError::InvalidImport(
                "journal record digest mismatch".to_owned(),
            ));
        }
        previous_digest = Some(record.record_digest.clone());
    }
    for (id, history) in &export.histories {
        let mut previous_to = None;
        for (index, revision) in history.iter().enumerate() {
            let expected_revision = u32::try_from(index)
                .map_err(|error| ReferenceError::InvalidImport(error.to_string()))?
                .checked_add(1)
                .ok_or_else(|| ReferenceError::InvalidImport("revision overflow".to_owned()))?;
            if revision.id != *id
                || revision.revision != expected_revision
                || revision.transaction_from == 0
                || revision.transaction_from > export.head
                || previous_to != Some(revision.transaction_from) && index > 0
            {
                return Err(ReferenceError::InvalidImport(format!(
                    "invalid revision chain for {id}"
                )));
            }
            if !revision.record.valid_time.is_valid() {
                return Err(ReferenceError::InvalidImport(format!(
                    "invalid domain-time interval for {id}"
                )));
            }
            previous_to = revision.transaction_to;
            if !export.tombstones.contains_key(id)
                && !export.contents.contains_key(&revision.content.id)
            {
                return Err(ReferenceError::InvalidImport(format!(
                    "missing content {} for {id}",
                    revision.content.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_observation(input: &ObservationInput) -> Result<()> {
    if input.idempotency_key.trim().is_empty() || input.observation_id.trim().is_empty() {
        return Err(ReferenceError::Invariant(
            "observation and idempotency identifiers must not be empty".to_owned(),
        ));
    }
    validate_access(&input.access)
}

fn validate_access(access: &AccessLabel) -> Result<()> {
    if access.workspace.trim().is_empty() || access.owners.is_empty() {
        return Err(ReferenceError::Invariant(
            "access label requires a workspace and at least one owner".to_owned(),
        ));
    }
    if access.owners.iter().any(|owner| owner.trim().is_empty())
        || access
            .audience
            .iter()
            .any(|audience| audience.trim().is_empty())
        || access.scopes.iter().any(|scope| scope.trim().is_empty())
        || access
            .purposes
            .iter()
            .any(|purpose| purpose.trim().is_empty())
    {
        return Err(ReferenceError::Invariant(
            "policy identifiers must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn operation_digest<T: Serialize>(operation: &str, value: &T) -> Result<String> {
    #[derive(Serialize)]
    struct DigestInput<'a, T> {
        operation: &'a str,
        value: &'a T,
    }
    canonical::digest(&DigestInput { operation, value })
}

fn key_digest(key: &str) -> String {
    blake3::hash(key.as_bytes()).to_hex().to_string()
}

fn replay_or_conflict(
    state: &State,
    key_digest: &str,
    request_digest: &str,
) -> Result<Option<CommitReceipt>> {
    let Some(existing) = state.idempotency.get(key_digest) else {
        return Ok(None);
    };
    if existing.request_digest != request_digest {
        return Err(ReferenceError::IdempotencyConflict {
            key_digest: key_digest.to_owned(),
        });
    }
    let mut receipt = existing.receipt.clone();
    receipt.replayed = true;
    Ok(Some(receipt))
}

fn next_commit(head: CommitSeq) -> Result<CommitSeq> {
    head.checked_add(1)
        .ok_or_else(|| ReferenceError::Invariant("commit sequence exhausted".to_owned()))
}

fn publish(guard: &mut State, next: State, failpoint: Failpoint) -> Result<()> {
    if failpoint == Failpoint::BeforePublish {
        return Err(ReferenceError::InjectedCrash("before_publish"));
    }
    *guard = next;
    if failpoint == Failpoint::AfterPublish {
        return Err(ReferenceError::InjectedCrash("after_publish"));
    }
    Ok(())
}

fn make_content_ref<T: Serialize>(
    class: &str,
    owner: &str,
    commit_seq: CommitSeq,
    content: &T,
) -> Result<(ContentRef, Value)> {
    let digest = canonical::digest(content)?;
    let value = serde_json::to_value(content)
        .map_err(|error| ReferenceError::Serialization(error.to_string()))?;
    Ok((
        ContentRef {
            id: format!("{class}:{owner}:{commit_seq}:{digest}"),
            digest,
        },
        value,
    ))
}

fn append_journal(state: &mut State, commit_seq: CommitSeq, event: JournalEvent) -> Result<()> {
    let previous_digest = state
        .journal
        .last()
        .map(|record| record.record_digest.clone());
    let record_digest = journal_digest(commit_seq, &previous_digest, &event)?;
    let workspace_candidates = journal_event_workspace_candidates(state, commit_seq, &event)?;
    let journal_index = state.journal.len();
    state.journal.push(JournalRecord {
        commit_seq,
        previous_digest,
        record_digest,
        event,
    });
    for (workspace, candidates) in workspace_candidates {
        let positions = state
            .security_indexes
            .journal_by_workspace
            .entry(workspace.clone())
            .or_default();
        positions.push(journal_index);
        let workspace_seq =
            u64::try_from(positions.len()).map_err(|_| ReferenceError::ResourceExhausted)?;
        let events = state
            .security_indexes
            .events_by_workspace
            .entry(workspace)
            .or_default();
        events.extend(
            candidates
                .into_iter()
                .map(|(ordinal, kind)| WorkspaceEventIndexEntry {
                    workspace_seq,
                    ordinal,
                    journal_index,
                    kind,
                }),
        );
    }
    Ok(())
}

fn journal_digest(
    commit_seq: CommitSeq,
    previous_digest: &Option<String>,
    event: &JournalEvent,
) -> Result<String> {
    canonical::digest(&JournalDigestInput {
        commit_seq,
        previous_digest,
        event,
    })
}

fn apply_mutation(
    state: &mut State,
    mutation: &Mutation,
    commit_seq: CommitSeq,
    affected_ids: &mut BTreeSet<LogicalId>,
) -> Result<()> {
    match mutation {
        Mutation::Put {
            record,
            expected_revision,
        } => put_record(state, record, *expected_revision, commit_seq, affected_ids),
        Mutation::Correct {
            target,
            replacement,
        } => {
            if !replacement.links.supersedes.contains(target) {
                return Err(ReferenceError::Invariant(
                    "correction replacement must identify its superseded target".to_owned(),
                ));
            }
            revise_lifecycle(
                state,
                target,
                Lifecycle::Superseded,
                commit_seq,
                affected_ids,
            )?;
            put_record(state, replacement, Some(0), commit_seq, affected_ids)
        }
        Mutation::Retract { target } => revise_lifecycle(
            state,
            target,
            Lifecycle::Retracted,
            commit_seq,
            affected_ids,
        ),
        Mutation::Delete {
            target,
            requested_by,
            reason,
        } => hard_delete(
            state,
            target,
            requested_by,
            reason,
            commit_seq,
            affected_ids,
        ),
    }
}

fn put_record(
    state: &mut State,
    record: &LogicalRecord,
    expected_revision: Option<u32>,
    commit_seq: CommitSeq,
    affected_ids: &mut BTreeSet<LogicalId>,
) -> Result<()> {
    validate_record(state, record, commit_seq)?;
    if state.tombstones.contains_key(&record.id) || state.observations.contains_key(&record.id) {
        return Err(ReferenceError::Invariant(format!(
            "external identifier {} cannot be reused",
            record.id
        )));
    }
    let current_revision = state
        .histories
        .get(&record.id)
        .and_then(|history| revision_at(history, state.head))
        .map(|revision| (revision.revision, revision.record.kind));
    let current_workspace = state
        .histories
        .get(&record.id)
        .and_then(|history| revision_at(history, state.head))
        .map(|revision| revision.record.access.workspace.clone());
    match (expected_revision, current_revision) {
        (Some(0), None) | (None, None) => {}
        (Some(expected), Some((actual, _))) if expected == actual => {}
        (None, Some(_)) => {}
        (Some(expected), Some((actual, _))) => {
            return Err(ReferenceError::Invariant(format!(
                "revision precondition failed for {}: expected {expected}, current {actual}",
                record.id
            )));
        }
        (Some(expected), None) => {
            return Err(ReferenceError::Invariant(format!(
                "revision precondition failed for {}: expected {expected}, record is absent",
                record.id
            )));
        }
    }
    if let Some((_, kind)) = current_revision
        && kind != record.kind
    {
        return Err(ReferenceError::Invariant(format!(
            "record kind cannot change for {}",
            record.id
        )));
    }
    if current_workspace
        .as_ref()
        .is_some_and(|workspace| workspace != &record.access.workspace)
    {
        return Err(ReferenceError::Invariant(format!(
            "record workspace cannot change for {}",
            record.id
        )));
    }
    let next_revision = current_revision.map_or(1, |(revision, _)| revision.saturating_add(1));
    if next_revision == u32::MAX {
        return Err(ReferenceError::Invariant(format!(
            "revision sequence exhausted for {}",
            record.id
        )));
    }
    if let Some(history) = state.histories.get_mut(&record.id)
        && let Some(current) = history.last_mut()
    {
        current.transaction_to = Some(commit_seq);
    }
    let content = RecordContent {
        value: record.value.clone(),
        search_text: record.search_text.clone(),
        vector: record.vector.clone(),
        attributes: record.attributes.clone(),
    };
    let (content_ref, content_value) =
        make_content_ref("record", &record.id, commit_seq, &content)?;
    state.contents.insert(content_ref.id.clone(), content_value);
    state
        .histories
        .entry(record.id.clone())
        .or_default()
        .push(StoredRevision {
            id: record.id.clone(),
            revision: next_revision,
            transaction_from: commit_seq,
            transaction_to: None,
            record: LogicalRecordMetadata {
                kind: record.kind,
                access: record.access.clone(),
                valid_time: record.valid_time,
                lifecycle: record.lifecycle,
                links: record.links.clone(),
            },
            content: content_ref,
        });
    state
        .security_indexes
        .histories_by_workspace
        .entry(record.access.workspace.clone())
        .or_default()
        .insert(record.id.clone());
    affected_ids.insert(record.id.clone());
    Ok(())
}

fn validate_record(state: &State, record: &LogicalRecord, at_seq: CommitSeq) -> Result<()> {
    if record.id.trim().is_empty() || !record.valid_time.is_valid() {
        return Err(ReferenceError::Invariant(
            "record identifier and valid-time interval must be valid".to_owned(),
        ));
    }
    validate_access(&record.access)?;
    if record
        .vector
        .as_ref()
        .is_some_and(|vector| vector.is_empty() || vector.iter().any(|value| !value.is_finite()))
    {
        return Err(ReferenceError::Invariant(
            "record vector must be non-empty and finite".to_owned(),
        ));
    }
    for evidence in &record.links.evidence {
        require_kind(state, evidence, RecordKind::Evidence, at_seq)?;
    }
    match record.kind {
        RecordKind::Claim => {
            let subject =
                record.links.subject.as_ref().ok_or_else(|| {
                    ReferenceError::Invariant("claim requires a subject".to_owned())
                })?;
            require_kind(state, subject, RecordKind::Node, at_seq)?;
            if record.links.predicate.as_deref().is_none_or(str::is_empty) {
                return Err(ReferenceError::Invariant(
                    "claim requires a predicate".to_owned(),
                ));
            }
            validate_cardinality(state, record, at_seq)?;
        }
        RecordKind::Edge => {
            let source =
                record.links.source.as_ref().ok_or_else(|| {
                    ReferenceError::Invariant("edge requires a source".to_owned())
                })?;
            let target =
                record.links.target.as_ref().ok_or_else(|| {
                    ReferenceError::Invariant("edge requires a target".to_owned())
                })?;
            require_kind(state, source, RecordKind::Node, at_seq)?;
            require_kind(state, target, RecordKind::Node, at_seq)?;
            if record.links.predicate.as_deref().is_none_or(str::is_empty) {
                return Err(ReferenceError::Invariant(
                    "edge requires a predicate".to_owned(),
                ));
            }
        }
        RecordKind::Conflict => validate_conflict(state, record, at_seq)?,
        _ => {}
    }
    Ok(())
}

fn validate_cardinality(state: &State, candidate: &LogicalRecord, at_seq: CommitSeq) -> Result<()> {
    if !candidate.links.single_valued || candidate.lifecycle != Lifecycle::Active {
        return Ok(());
    }
    for (id, history) in &state.histories {
        if *id == candidate.id || state.tombstones.contains_key(id) {
            continue;
        }
        let Some(other) = revision_at(history, at_seq) else {
            continue;
        };
        let same_slot = other.record.kind == RecordKind::Claim
            && other.record.lifecycle == Lifecycle::Active
            && other.record.links.single_valued
            && other.record.links.subject == candidate.links.subject
            && other.record.links.predicate == candidate.links.predicate
            && other.record.access.workspace == candidate.access.workspace
            && other.record.access.scopes == candidate.access.scopes;
        let same_conflict = candidate.links.conflict_set.is_some()
            && candidate.links.conflict_set == other.record.links.conflict_set;
        if same_slot && !same_conflict {
            return Err(ReferenceError::Invariant(format!(
                "single-valued claim {} conflicts with {id} without a conflict set",
                candidate.id
            )));
        }
    }
    Ok(())
}

fn validate_conflict(state: &State, record: &LogicalRecord, at_seq: CommitSeq) -> Result<()> {
    if record.links.conflict_members.len() < 2 {
        return Err(ReferenceError::Invariant(
            "conflict set requires at least two claim members".to_owned(),
        ));
    }
    let mut signature = None;
    for member in &record.links.conflict_members {
        require_kind(state, member, RecordKind::Claim, at_seq)?;
        let claim = state
            .histories
            .get(member)
            .and_then(|history| revision_at(history, at_seq))
            .ok_or_else(|| not_found("claim", member))?;
        let current = (
            claim.record.links.subject.clone(),
            claim.record.links.predicate.clone(),
            claim.record.access.workspace.clone(),
            claim.record.access.scopes.clone(),
        );
        if signature
            .as_ref()
            .is_some_and(|expected| *expected != current)
        {
            return Err(ReferenceError::Invariant(
                "conflict members must share subject, predicate, workspace, and scope".to_owned(),
            ));
        }
        signature = Some(current);
    }
    Ok(())
}

fn validate_complete_state(state: &State, at_seq: CommitSeq) -> Result<()> {
    for (id, history) in &state.histories {
        if state.tombstones.contains_key(id) {
            continue;
        }
        let Some(revision) = revision_at(history, at_seq) else {
            continue;
        };
        match revision.record.kind {
            RecordKind::Claim => {
                if let Some(conflict_id) = &revision.record.links.conflict_set {
                    let conflict = state
                        .histories
                        .get(conflict_id)
                        .and_then(|history| revision_at(history, at_seq))
                        .filter(|conflict| {
                            conflict.record.kind == RecordKind::Conflict
                                && conflict.record.lifecycle == Lifecycle::Active
                        })
                        .ok_or_else(|| {
                            ReferenceError::Invariant(format!(
                                "claim {id} refers to missing active conflict set {conflict_id}"
                            ))
                        })?;
                    if !conflict.record.links.conflict_members.contains(id) {
                        return Err(ReferenceError::Invariant(format!(
                            "conflict set {conflict_id} does not contain referring claim {id}"
                        )));
                    }
                }
            }
            RecordKind::Conflict => {
                for member in &revision.record.links.conflict_members {
                    let claim = state
                        .histories
                        .get(member)
                        .and_then(|history| revision_at(history, at_seq))
                        .ok_or_else(|| not_found("claim", member))?;
                    if claim.record.links.conflict_set.as_deref() != Some(id.as_str()) {
                        return Err(ReferenceError::Invariant(format!(
                            "conflict member {member} does not refer back to {id}"
                        )));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn require_kind(state: &State, id: &str, kind: RecordKind, at_seq: CommitSeq) -> Result<()> {
    if state.tombstones.contains_key(id) {
        return Err(not_found("record", id));
    }
    let revision = state
        .histories
        .get(id)
        .and_then(|history| revision_at(history, at_seq))
        .ok_or_else(|| not_found("record", id))?;
    if revision.record.kind != kind || revision.record.lifecycle != Lifecycle::Active {
        return Err(ReferenceError::Invariant(format!(
            "record {id} is not an active {kind:?}"
        )));
    }
    Ok(())
}

fn revise_lifecycle(
    state: &mut State,
    target: &str,
    lifecycle: Lifecycle,
    commit_seq: CommitSeq,
    affected_ids: &mut BTreeSet<LogicalId>,
) -> Result<()> {
    if state.tombstones.contains_key(target) {
        return Err(not_found("record", target));
    }
    let current = state
        .histories
        .get(target)
        .and_then(|history| revision_at(history, state.head))
        .cloned()
        .ok_or_else(|| not_found("record", target))?;
    let content = content_for_revision(state, &current)?;
    let record = LogicalRecord {
        id: current.id.clone(),
        kind: current.record.kind,
        access: current.record.access,
        valid_time: current.record.valid_time,
        lifecycle,
        links: current.record.links,
        value: content.value,
        search_text: content.search_text,
        vector: content.vector,
        attributes: content.attributes,
    };
    put_record(
        state,
        &record,
        Some(current.revision),
        commit_seq,
        affected_ids,
    )
}

fn hard_delete(
    state: &mut State,
    target: &str,
    requested_by: &str,
    reason: &str,
    commit_seq: CommitSeq,
    affected_ids: &mut BTreeSet<LogicalId>,
) -> Result<()> {
    if target.trim().is_empty() || requested_by.trim().is_empty() || reason.trim().is_empty() {
        return Err(ReferenceError::Invariant(
            "deletion target, actor, and reason must not be empty".to_owned(),
        ));
    }
    if state.tombstones.contains_key(target)
        || (!state.histories.contains_key(target) && !state.observations.contains_key(target))
    {
        return Err(not_found("deletion target", target));
    }

    let mut closure = BTreeSet::from([target.to_owned()]);
    loop {
        let mut discovered = BTreeSet::new();
        for (id, history) in &state.histories {
            if closure.contains(id) || state.tombstones.contains_key(id) {
                continue;
            }
            let Some(current) = revision_at(history, state.head) else {
                continue;
            };
            let links = &current.record.links;
            if links
                .subject
                .iter()
                .chain(links.source.iter())
                .chain(links.target.iter())
                .any(|id| closure.contains(id))
                || links.evidence.iter().any(|id| closure.contains(id))
                || links.supersedes.iter().any(|id| closure.contains(id))
                || links.conflict_members.iter().any(|id| closure.contains(id))
            {
                discovered.insert(id.clone());
            }
        }
        if discovered.is_empty() {
            break;
        }
        closure.extend(discovered);
    }

    for id in &closure {
        let mut erased = BTreeSet::new();
        if let Some(history) = state.histories.get(id) {
            erased.extend(history.iter().map(|revision| revision.content.id.clone()));
        }
        if let Some(observation) = state.observations.get(id) {
            erased.insert(observation.content.id.clone());
        }
        for record in &state.journal {
            match &record.event {
                JournalEvent::ObservationAccepted {
                    observation_id,
                    request_content,
                    ..
                } if observation_id == id => {
                    erased.insert(request_content.id.clone());
                }
                JournalEvent::SemanticPublished {
                    affected_ids: journal_ids,
                    request_content,
                    ..
                } if journal_ids.contains(id) => {
                    erased.insert(request_content.id.clone());
                }
                _ => {}
            }
        }
        for content_ref in &erased {
            state.contents.remove(content_ref);
        }
        let tombstone_reason = if id == target {
            reason.to_owned()
        } else {
            format!("dependency_of:{target}")
        };
        remove_security_candidate(state, id);
        state.tombstones.insert(
            id.clone(),
            DeletionTombstone {
                target: id.clone(),
                requested_by: requested_by.to_owned(),
                reason: tombstone_reason,
                effective_seq: commit_seq,
                erased_content_refs: erased,
            },
        );
        affected_ids.insert(id.clone());
    }
    Ok(())
}

fn ensure_workspace_candidate_budget(candidate_ids: Option<&BTreeSet<LogicalId>>) -> Result<()> {
    if candidate_ids.is_some_and(|ids| ids.len() > MAX_WORKSPACE_CANDIDATES) {
        return Err(ReferenceError::ResourceExhausted);
    }
    Ok(())
}

fn remove_security_candidate(state: &mut State, id: &str) {
    let history_workspace = state
        .histories
        .get(id)
        .and_then(|history| revision_at(history, state.head))
        .map(|revision| revision.record.access.workspace.clone());
    let observation_workspace = state
        .observations
        .get(id)
        .map(|observation| observation.access.workspace.clone());
    if let Some(workspace) = history_workspace
        && let Some(ids) = state
            .security_indexes
            .histories_by_workspace
            .get_mut(&workspace)
    {
        ids.remove(id);
        if ids.is_empty() {
            state
                .security_indexes
                .histories_by_workspace
                .remove(&workspace);
        }
    }
    if let Some(workspace) = observation_workspace
        && let Some(ids) = state
            .security_indexes
            .observations_by_workspace
            .get_mut(&workspace)
    {
        ids.remove(id);
        if ids.is_empty() {
            state
                .security_indexes
                .observations_by_workspace
                .remove(&workspace);
        }
    }
}

fn journal_event_workspace_candidates(
    state: &State,
    commit_seq: CommitSeq,
    event: &JournalEvent,
) -> Result<BTreeMap<LogicalId, Vec<(u32, WorkspaceEventCandidateKind)>>> {
    let mut workspaces = BTreeMap::<_, Vec<_>>::new();
    match event {
        JournalEvent::ObservationAccepted { observation_id, .. } => {
            let observation = state.observations.get(observation_id).ok_or_else(|| {
                ReferenceError::Invariant(
                    "journal observation is missing authorization metadata".to_owned(),
                )
            })?;
            if observation.accepted_seq > commit_seq {
                return Err(ReferenceError::Invariant(
                    "journal observation predates its authorization metadata".to_owned(),
                ));
            }
            workspaces
                .entry(observation.access.workspace.clone())
                .or_default()
                .push((
                    0,
                    WorkspaceEventCandidateKind::ObservationAccepted {
                        observation_id: observation_id.clone(),
                    },
                ));
        }
        JournalEvent::SemanticPublished { affected_ids, .. } => {
            for id in affected_ids {
                let workspace = if let Some(revision) = state
                    .histories
                    .get(id)
                    .and_then(|history| revision_at(history, commit_seq))
                {
                    revision.record.access.workspace.clone()
                } else if let Some(observation) = state.observations.get(id) {
                    observation.access.workspace.clone()
                } else {
                    return Err(ReferenceError::Invariant(format!(
                        "journal target {id} is missing authorization metadata"
                    )));
                };
                let candidates = workspaces.entry(workspace).or_default();
                if candidates.len() >= MAX_WORKSPACE_CANDIDATES {
                    return Err(ReferenceError::ResourceExhausted);
                }
                candidates.push((
                    u32::try_from(candidates.len())
                        .map_err(|_| ReferenceError::ResourceExhausted)?,
                    WorkspaceEventCandidateKind::SemanticRecordChanged {
                        record_id: id.clone(),
                    },
                ));
            }
            for candidates in workspaces.values_mut() {
                candidates.push((
                    u32::try_from(candidates.len())
                        .map_err(|_| ReferenceError::ResourceExhausted)?,
                    WorkspaceEventCandidateKind::SemanticWatermark,
                ));
            }
        }
    }
    Ok(workspaces)
}

fn rebuild_security_indexes(state: &State) -> Result<SecurityIndexes> {
    let mut indexes = SecurityIndexes::default();
    for (id, history) in &state.histories {
        if state.tombstones.contains_key(id) {
            continue;
        }
        if let Some(revision) = revision_at(history, state.head) {
            indexes
                .histories_by_workspace
                .entry(revision.record.access.workspace.clone())
                .or_default()
                .insert(id.clone());
        }
    }
    for (id, observation) in &state.observations {
        if !state.tombstones.contains_key(id) {
            indexes
                .observations_by_workspace
                .entry(observation.access.workspace.clone())
                .or_default()
                .insert(id.clone());
        }
    }
    for (journal_index, record) in state.journal.iter().enumerate() {
        for (workspace, candidates) in
            journal_event_workspace_candidates(state, record.commit_seq, &record.event)?
        {
            let positions = indexes
                .journal_by_workspace
                .entry(workspace.clone())
                .or_default();
            positions.push(journal_index);
            let workspace_seq =
                u64::try_from(positions.len()).map_err(|_| ReferenceError::ResourceExhausted)?;
            indexes
                .events_by_workspace
                .entry(workspace)
                .or_default()
                .extend(
                    candidates
                        .into_iter()
                        .map(|(ordinal, kind)| WorkspaceEventIndexEntry {
                            workspace_seq,
                            ordinal,
                            journal_index,
                            kind,
                        }),
                );
        }
    }
    Ok(indexes)
}

fn verify_security_indexes(state: &State) -> Result<()> {
    let expected = rebuild_security_indexes(state)?;
    if state.security_indexes != expected {
        return Err(ReferenceError::Invariant(
            "workspace authorization index membership diverged from primary metadata".to_owned(),
        ));
    }
    Ok(())
}

fn private_revision_metadata<'a>(
    state: &'a State,
    id: &str,
    commit_seq: CommitSeq,
    principal: &Principal,
) -> Result<&'a StoredRevision> {
    let revision = state
        .histories
        .get(id)
        .and_then(|history| revision_at(history, commit_seq));
    if state.tombstones.contains_key(id)
        || revision.is_none()
        || !current_use_policy_allows(state, id, principal)
    {
        return Err(ReferenceError::Unauthorized);
    }
    let revision = revision.ok_or(ReferenceError::Unauthorized)?;
    if !principal.allows(&revision.record.access) {
        return Err(ReferenceError::Unauthorized);
    }
    Ok(revision)
}

fn revision_at(history: &[StoredRevision], commit_seq: CommitSeq) -> Option<&StoredRevision> {
    history.iter().rev().find(|revision| {
        revision.transaction_from <= commit_seq
            && revision.transaction_to.is_none_or(|end| commit_seq < end)
    })
}

fn current_authorized_metadata<'a>(
    state: &'a State,
    id: &str,
    commit_seq: CommitSeq,
    principal: &Principal,
) -> Option<&'a StoredRevision> {
    if !current_use_policy_allows(state, id, principal) {
        return None;
    }
    state
        .histories
        .get(id)
        .and_then(|history| revision_at(history, commit_seq))
        .filter(|revision| {
            revision.record.lifecycle == Lifecycle::Active
                && principal.allows(&revision.record.access)
        })
}

fn current_use_policy_allows(state: &State, id: &str, principal: &Principal) -> bool {
    if state.tombstones.contains_key(id) {
        return false;
    }
    state
        .histories
        .get(id)
        .and_then(|history| revision_at(history, state.head))
        .is_some_and(|revision| {
            !matches!(
                revision.record.lifecycle,
                Lifecycle::Suppressed | Lifecycle::Retracted
            ) && principal.allows(&revision.record.access)
        })
}

fn materialize_at(
    state: &State,
    id: &str,
    commit_seq: CommitSeq,
    principal: &Principal,
) -> Result<MaterializedRecord> {
    if state.tombstones.contains_key(id) {
        return Err(not_found("record", id));
    }
    let revision = state
        .histories
        .get(id)
        .and_then(|history| revision_at(history, commit_seq))
        .ok_or_else(|| not_found("record", id))?;
    if !current_use_policy_allows(state, id, principal) {
        return Err(ReferenceError::Unauthorized);
    }
    if !principal.allows(&revision.record.access) {
        return Err(ReferenceError::Unauthorized);
    }
    materialize_revision(state, revision)
}

fn materialize_revision(state: &State, revision: &StoredRevision) -> Result<MaterializedRecord> {
    Ok(MaterializedRecord {
        revision: revision.clone(),
        content: content_for_revision(state, revision)?,
    })
}

fn content_for_revision(state: &State, revision: &StoredRevision) -> Result<RecordContent> {
    let value = state
        .contents
        .get(&revision.content.id)
        .ok_or_else(|| not_found("content", &revision.content.id))?;
    let actual_digest = canonical::digest(value)?;
    if actual_digest != revision.content.digest {
        return Err(ReferenceError::Invariant(format!(
            "content digest mismatch for {}",
            revision.id
        )));
    }
    serde_json::from_value(value.clone())
        .map_err(|error| ReferenceError::Serialization(error.to_string()))
}

fn snapshot_for(state: &State, commit_seq: CommitSeq) -> Snapshot {
    Snapshot {
        database_id: state.database_id.clone(),
        commit_seq,
        semantic_generation: watermarks_at(state, commit_seq).semantic,
        storage_generation: 0,
    }
}

fn validate_snapshot(state: &State, commit_seq: CommitSeq) -> Result<()> {
    if commit_seq > state.head {
        return Err(ReferenceError::SnapshotNotFound {
            requested: commit_seq,
            head: state.head,
        });
    }
    Ok(())
}

fn validate_snapshot_handle(state: &State, snapshot: &Snapshot) -> Result<()> {
    if snapshot.database_id != state.database_id {
        return Err(ReferenceError::Invariant(
            "snapshot belongs to a different database".to_owned(),
        ));
    }
    validate_snapshot(state, snapshot.commit_seq)
}

fn watermarks_at(state: &State, commit_seq: CommitSeq) -> Watermarks {
    let mut watermarks = Watermarks::default();
    for record in state
        .journal
        .iter()
        .take_while(|record| record.commit_seq <= commit_seq)
    {
        watermarks.journal = record.commit_seq;
        if matches!(record.event, JournalEvent::SemanticPublished { .. }) {
            watermarks.semantic = record.commit_seq;
            watermarks.lexical = record.commit_seq;
            watermarks.vector = record.commit_seq;
            watermarks.graph = record.commit_seq;
        }
    }
    watermarks
}

fn workspace_journal_len(state: &State, workspace: &str) -> CommitSeq {
    state
        .security_indexes
        .journal_by_workspace
        .get(workspace)
        .map_or(0, |positions| {
            u64::try_from(positions.len()).unwrap_or(u64::MAX)
        })
}

fn workspace_watermarks_at(state: &State, workspace: &str, commit_seq: CommitSeq) -> Watermarks {
    let mut watermarks = Watermarks::default();
    let Some(positions) = state.security_indexes.journal_by_workspace.get(workspace) else {
        return watermarks;
    };
    for journal_index in positions {
        let Some(record) = state.journal.get(*journal_index) else {
            break;
        };
        if record.commit_seq > commit_seq {
            break;
        }
        watermarks.journal = watermarks.journal.saturating_add(1);
        if matches!(record.event, JournalEvent::SemanticPublished { .. }) {
            watermarks.semantic = watermarks.semantic.saturating_add(1);
            watermarks.lexical = watermarks.semantic;
            watermarks.vector = watermarks.semantic;
            watermarks.graph = watermarks.semantic;
        }
    }
    watermarks
}

fn trace(
    state: &State,
    commit_seq: CommitSeq,
    workspace: &str,
    operation: &str,
    authorized_candidates: usize,
    selected_ids: Vec<LogicalId>,
) -> ReadTrace {
    let watermarks = workspace_watermarks_at(state, workspace, commit_seq);
    ReadTrace {
        snapshot_seq: watermarks.journal,
        operation: operation.to_owned(),
        authorized_candidates,
        selected_ids,
        watermarks,
    }
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn sort_hits(hits: &mut [SearchHit]) {
    hits.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn not_found(kind: &'static str, id: &str) -> ReferenceError {
    ReferenceError::NotFound {
        kind,
        id: id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Consent, Sensitivity};
    use serde_json::json;

    fn access(workspace: &str, subject: &str) -> AccessLabel {
        AccessLabel {
            workspace: workspace.to_owned(),
            scopes: BTreeSet::new(),
            owners: BTreeSet::from([subject.to_owned()]),
            audience: BTreeSet::from([subject.to_owned()]),
            audience_purpose_grants: BTreeMap::new(),
            purposes: BTreeSet::from(["recall".to_owned()]),
            sensitivity: Sensitivity::Private,
            consent: Consent::Granted,
            retrievable: true,
        }
    }

    fn record(id: &str, workspace: &str, subject: &str, kind: RecordKind) -> LogicalRecord {
        LogicalRecord {
            id: id.to_owned(),
            kind,
            access: access(workspace, subject),
            valid_time: crate::model::ValidTime::UNBOUNDED,
            lifecycle: Lifecycle::Active,
            links: crate::model::SemanticLinks::default(),
            value: json!({"sentinel": id}),
            search_text: Some(format!("tenant-local {id}")),
            vector: Some(vec![1.0, 0.0]),
            attributes: BTreeMap::new(),
        }
    }

    fn principal(workspace: &str, subject: &str) -> Principal {
        Principal {
            subject: subject.to_owned(),
            audiences: BTreeSet::from([subject.to_owned()]),
            workspace: workspace.to_owned(),
            scopes: BTreeSet::new(),
            purpose: "recall".to_owned(),
            clearance: Sensitivity::Private,
        }
    }

    #[test]
    fn lexical_tokens_are_case_and_punctuation_insensitive() {
        assert_eq!(tokens("Japan-bar, JAPAN"), tokens("japan bar"));
    }

    #[test]
    fn wrong_family_is_rejected_before_corrupt_protected_content_is_materialized() {
        let db = ContextDb::new("typed-private-read").expect("database");
        db.commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "seed-evidence".to_owned(),
            mutations: vec![Mutation::Put {
                record: record("evidence:one", "workspace:a", "alice", RecordKind::Evidence),
                expected_revision: None,
            }],
        })
        .expect("seed evidence");
        let snapshot = db.snapshot().expect("snapshot");
        {
            let mut state = db.write_state().expect("state");
            let content_id = state.histories["evidence:one"][0].content.id.clone();
            state
                .contents
                .insert(content_id, json!({"tampered": "must not be read"}));
        }
        let caller = principal("workspace:a", "alice");
        assert_eq!(
            db.get_typed("evidence:one", RecordKind::Node, &snapshot, &caller),
            Err(ReferenceError::Unauthorized)
        );
        assert_eq!(
            db.history_typed("evidence:one", RecordKind::Node, &snapshot, &caller),
            Err(ReferenceError::Unauthorized)
        );
        assert!(matches!(
            db.get_typed("evidence:one", RecordKind::Evidence, &snapshot, &caller),
            Err(ReferenceError::Invariant(_))
        ));
    }

    #[test]
    fn workspace_indexes_make_forbidden_tenants_non_influential_and_round_trip() {
        let db = ContextDb::new("workspace-security-index").expect("database");
        db.commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "tenant-a".to_owned(),
            mutations: vec![Mutation::Put {
                record: record("a:one", "workspace:a", "alice", RecordKind::SemanticObject),
                expected_revision: None,
            }],
        })
        .expect("tenant A commit");
        let a_principal = principal("workspace:a", "alice");
        let before_snapshot = db.snapshot().expect("before snapshot");
        let before = db
            .lexical_search("tenant-local", 10, &before_snapshot, &a_principal)
            .expect("before search");

        let mutations = (0..MAX_WORKSPACE_JOURNAL_PAGE.saturating_add(32))
            .map(|index| Mutation::Put {
                record: record(
                    &format!("b:{index:03}"),
                    "workspace:b",
                    "bob",
                    RecordKind::SemanticObject,
                ),
                expected_revision: None,
            })
            .collect();
        db.commit(SemanticTransaction {
            base_seq: before_snapshot.commit_seq,
            idempotency_key: "tenant-b".to_owned(),
            mutations,
        })
        .expect("tenant B commit");
        let after_snapshot = db.snapshot().expect("after snapshot");
        let after = db
            .lexical_search("tenant-local", 10, &after_snapshot, &a_principal)
            .expect("after search");
        assert_eq!(before, after);
        assert_eq!(after.trace.snapshot_seq, 1);
        assert_eq!(after.trace.watermarks.journal, 1);
        assert_eq!(after.trace.watermarks.semantic, 1);

        assert_eq!(
            db.snapshot_for_workspace("workspace:a", 0)
                .expect("workspace genesis")
                .commit_seq,
            0
        );
        assert_eq!(
            db.snapshot_for_workspace("workspace:a", 1)
                .expect("workspace snapshot")
                .commit_seq,
            1
        );
        assert!(matches!(
            db.snapshot_for_workspace("workspace:a", 2),
            Err(ReferenceError::SnapshotNotFound {
                requested: 2,
                head: 1
            })
        ));
        let page = db
            .workspace_event_page("workspace:a", 0, 0, 10)
            .expect("workspace page");
        assert_eq!(page.candidates.len(), 2);
        assert_eq!(page.candidates[0].workspace_seq, 1);
        assert_eq!(page.candidates[0].ordinal, 0);
        assert_eq!(page.candidates[0].commit_seq, 1);
        assert!(matches!(
            page.candidates[0].kind,
            WorkspaceEventCandidateKind::SemanticRecordChanged { .. }
        ));
        assert!(matches!(
            page.candidates[1].kind,
            WorkspaceEventCandidateKind::SemanticWatermark
        ));
        let first_large_page = db
            .workspace_event_page("workspace:b", 0, 0, MAX_WORKSPACE_JOURNAL_PAGE)
            .expect("bounded large workspace page");
        assert_eq!(
            first_large_page.candidates.len(),
            MAX_WORKSPACE_JOURNAL_PAGE
        );
        assert!(first_large_page.has_more);
        let second_large_page = db
            .workspace_event_page(
                "workspace:b",
                first_large_page.scanned_through.0,
                first_large_page.scanned_through.1,
                MAX_WORKSPACE_JOURNAL_PAGE,
            )
            .expect("resumed large workspace page");
        assert_eq!(second_large_page.candidates.len(), 33);
        assert!(!second_large_page.has_more);
        assert!(matches!(
            second_large_page
                .candidates
                .last()
                .map(|candidate| &candidate.kind),
            Some(WorkspaceEventCandidateKind::SemanticWatermark)
        ));

        let imported = ContextDb::import(&db.export().expect("export")).expect("import");
        assert_eq!(
            imported
                .lexical_search(
                    "tenant-local",
                    10,
                    &imported.snapshot().expect("imported snapshot"),
                    &a_principal,
                )
                .expect("imported search"),
            after
        );
        assert_eq!(
            imported
                .workspace_event_page("workspace:a", 0, 0, 10)
                .expect("imported page"),
            page
        );
    }

    #[test]
    fn record_workspace_is_immutable_and_candidate_budget_fails_closed() {
        let db = ContextDb::new("workspace-immutability").expect("database");
        db.commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "seed".to_owned(),
            mutations: vec![Mutation::Put {
                record: record(
                    "record:one",
                    "workspace:a",
                    "alice",
                    RecordKind::SemanticObject,
                ),
                expected_revision: None,
            }],
        })
        .expect("seed");
        let error = db
            .commit(SemanticTransaction {
                base_seq: 1,
                idempotency_key: "move-workspace".to_owned(),
                mutations: vec![Mutation::Put {
                    record: record(
                        "record:one",
                        "workspace:b",
                        "alice",
                        RecordKind::SemanticObject,
                    ),
                    expected_revision: Some(1),
                }],
            })
            .expect_err("workspace move");
        assert!(matches!(error, ReferenceError::Invariant(_)));
        assert_eq!(db.snapshot().expect("unchanged head").commit_seq, 1);

        let oversized: BTreeSet<_> = (0..=MAX_WORKSPACE_CANDIDATES)
            .map(|index| format!("candidate:{index}"))
            .collect();
        assert_eq!(
            ensure_workspace_candidate_budget(Some(&oversized)),
            Err(ReferenceError::ResourceExhausted)
        );
    }
}
