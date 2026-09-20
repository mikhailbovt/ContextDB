//! Persistent raw-source generations, advanced from the native capture outbox.

mod gc;
mod verify;
pub use gc::RawReclaimProgress;
pub(super) use gc::retained_generations;

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{ContentDigest, EventEnvelope, EventKind, ObservationId, RawSource};
use contextdb_index::{RAW_ANALYZER, RawLexicalDocument};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, Capability, ErrorCode, ServiceError, ServiceResult,
};
use contextdb_storage::{
    Durability, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine, WriteTransaction,
};
use serde::{Deserialize, Serialize};

use super::{
    NativeService, canonical_digest, decode, digest_bytes, encode, exhausted, integrity,
    require_capability, require_sync, storage_error,
};

pub(super) const INDEX_FEATURE: &str = "continuous-raw-index-v1";
pub(super) const GC_FEATURE: &str = "continuous-raw-generation-gc-v1";
pub(super) const REMOVAL_FEATURE: &str = "continuous-raw-removal-v1";
pub(super) const MAX_DOMAINS: usize = 1024;
pub(super) const MAX_TAIL: usize = 128;
const MAX_INDEX_TERMS: usize = 16_384;
const MAX_GENERATIONS: u64 = 3;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexState {
    pub active: Option<u64>,
    pub building: Option<u64>,
    pub next: u64,
    /// Legacy stores retained every generation from one through `next`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained: Option<BTreeSet<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaiming: Option<gc::Reclaiming>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Generation {
    pub number: u64,
    #[serde(default, skip_serializing_if = "legacy_custody")]
    pub custody_version: u16,
    pub analyzer: String,
    pub through: u64,
    pub authorization_epoch: u64,
    pub projected_sources: u64,
    /// Prepared source removals through this native prefix are omitted entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_through: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexedOriginal {
    pub source: RawSource,
    pub event_digest: ContentDigest,
    pub commit: u64,
    pub policy_domain: String,
    pub lexical_complete: bool,
    pub first_terms: BTreeMap<String, contextdb_index::RawTokenSpan>,
    pub parents: BTreeSet<ObservationId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyDomain {
    pub policies: Vec<AccessPolicy>,
    pub first_commit: u64,
}

/// Progress is a native maintenance receipt, not semantic-understanding coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProjectionProgress {
    /// Generation being incrementally constructed or updated.
    pub generation: u64,
    /// Complete capture prefix consumed by this generation.
    pub through: u64,
    /// Originals represented, including lexical omissions, excluding prepared removals.
    pub projected_sources: u64,
    /// True when all outbox work visible at the build snapshot was consumed.
    pub caught_up: bool,
}

/// An explicit, monotonic source revocation; it does not erase historical bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalRevocationReceipt {
    /// The source whose current retrieval permission was revoked.
    pub event_id: ObservationId,
    /// Workspace-local native mutation position.
    pub workspace_commit: u64,
    /// Authorization epoch invalidating old indexed views and dependent sources.
    pub authorization_epoch: u64,
}

impl NativeService {
    pub(crate) fn require_raw_source_prunable<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        receipt: &contextdb_service::CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let state: IndexState = self
            .raw_value(snapshot, &state_key(workspace))?
            .unwrap_or_default();
        for number in retained_generations(&state)? {
            let generation: Generation = self
                .raw_value(snapshot, &generation_key(workspace, number))?
                .ok_or_else(|| integrity("pruning found a missing raw generation"))?;
            budget
                .charge(1, encode(&generation)?.len() as u64)
                .map_err(budget_error)?;
            if (generation.through >= receipt.workspace_commit
                && !self.source_prepared_at(
                    snapshot,
                    workspace,
                    receipt.event_id,
                    generation.removal_through,
                    budget,
                )?)
                || snapshot
                    .get(
                        &self.keyspaces.continuous,
                        &doc_key(workspace, number, receipt.event_id),
                    )
                    .map_err(storage_error)?
                    .is_some()
            {
                return Err(ServiceError::new(
                    ErrorCode::IndexTooStale,
                    "rebuild and reclaim raw generations before pruning their originals",
                    true,
                ));
            }
        }
        Ok(())
    }

    /// Bounded maintenance outside the interactive query. Original analysis runs
    /// outside the writer lock; publication compares generation and policy epoch.
    /// `rebuild` starts a separate generation and switches it only after catch-up.
    pub fn project_originals(
        &self,
        context: &AuthenticatedRequestContext,
        rebuild: bool,
        max_events: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RawProjectionProgress> {
        require_capability(context, Capability::Admin)?;
        if max_events == 0 || max_events > 256 {
            return Err(super::invalid(
                "projection batch must contain 1..256 events",
            ));
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        self.require_custody_rebuilt(&snapshot, &workspace)?;
        let (_, world) = self.select_snapshot(&snapshot, &context.request.workspace_id, None)?;
        let state: IndexState = self
            .raw_value(&snapshot, &state_key(&workspace))?
            .unwrap_or_default();
        let auth = self.raw_authorization_epoch(&snapshot, &workspace)?;
        let mut retained = retained_generations(&state)?;
        let mut next = state.clone();
        let fresh = rebuild || (state.active.is_none() && state.building.is_none());
        let mut generation = if fresh {
            if state.building.is_some() {
                return Err(super::invalid("a raw generation is already building"));
            }
            if retained.len() >= MAX_GENERATIONS as usize {
                return Err(exhausted(
                    "retained raw generation limit reached; maintenance is required",
                ));
            }
            next.next = next
                .next
                .checked_add(1)
                .ok_or_else(|| exhausted("raw generation identity exhausted"))?;
            retained.insert(next.next);
            next.retained = Some(retained);
            next.building = Some(next.next);
            Generation {
                number: next.next,
                custody_version: super::custody::CUSTODY_VERSION,
                analyzer: RAW_ANALYZER.into(),
                through: 0,
                authorization_epoch: auth,
                projected_sources: 0,
                removal_through: self
                    .suppression
                    .as_ref()
                    .filter(|ledger| ledger.supports_removal())
                    .map(|_| world.watermarks.journal),
            }
        } else {
            let number = state
                .building
                .or(state.active)
                .ok_or_else(|| integrity("raw generation is absent"))?;
            self.raw_value(&snapshot, &generation_key(&workspace, number))?
                .ok_or_else(|| integrity("raw generation manifest is absent"))?
        };
        if generation.authorization_epoch != auth
            || generation.analyzer != RAW_ANALYZER
            || generation.custody_version != super::custody::CUSTODY_VERSION
        {
            return Err(stale_index());
        }
        let expected_generation = generation.clone();
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&generation.through.to_be_bytes());
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries: max_events as usize,
                    max_bytes: 2 * 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        if page.entries.is_empty() && !fresh && state.building.is_none() {
            return Ok(RawProjectionProgress {
                generation: generation.number,
                through: generation.through,
                projected_sources: generation.projected_sources,
                caught_up: true,
            });
        }
        let mut rows = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut caught_up = page.continuation.is_none();
        for entry in page.entries {
            budget.charge(1, 0).map_err(budget_error)?;
            let work: super::capture::CaptureWork = decode(&entry.value, "raw projection work")?;
            let accepted = self.captured_receipt_metadata(&snapshot, work.event_id)?;
            if entry.key != super::capture::work_key(&workspace, work.workspace_commit)
                || accepted.workspace_id.to_string() != context.request.workspace_id
                || self.capture_work_for_receipt(&snapshot, &accepted)? != work
            {
                return Err(integrity(
                    "raw projection work differs from accepted control",
                ));
            }
            if self.source_prepared_at(
                &snapshot,
                &workspace,
                work.event_id,
                generation.removal_through,
                budget,
            )? {
                generation.through = work.workspace_commit;
                continue;
            }
            let original = self.load_captured_original(&snapshot, work.event_id)?;
            if original.receipt.workspace_commit != work.workspace_commit
                || original.receipt.event_digest != work.event_digest
            {
                return Err(integrity("raw projection work differs from its original"));
            }
            let source = RawSource::from(&original.event);
            let length = source.byte_length.unwrap_or_default();
            if length > budget.remaining_bytes() {
                if generation == expected_generation {
                    return Err(exhausted(
                        "one original exceeds the projection byte allowance",
                    ));
                }
                caught_up = false;
                break;
            }
            budget.charge(0, length).map_err(budget_error)?;
            let mut policy = PolicyDomain {
                policies: self.stored_custody_policies(&snapshot, work.event_id)?,
                first_commit: work.workspace_commit,
            };
            let domain = canonical_digest(&policy.policies)?;
            let document = self.build_raw_document(
                &snapshot,
                &original.event,
                work.workspace_commit,
                work.event_digest,
                &domain,
                budget,
            )?;
            let key = domain_key(&workspace, generation.number, &domain);
            if let Some(previous) = rows.get(&key) {
                policy.first_commit = decode::<PolicyDomain>(previous, "raw domain")?.first_commit;
            } else if let Some(previous) = self.raw_value::<PolicyDomain, _>(&snapshot, &key)? {
                policy.first_commit = previous.first_commit;
            }
            let value = encode(&policy)?;
            budget
                .charge(0, (key.len() + value.len()) as u64)
                .map_err(budget_error)?;
            rows.insert(key, value);
            for key in domain_eligibility_keys(&workspace, generation.number, &domain, &policy)? {
                let value = encode(&domain)?;
                budget
                    .charge(0, (key.len() + value.len()) as u64)
                    .map_err(budget_error)?;
                rows.insert(key, value);
            }
            for (key, value) in document_rows(&workspace, generation.number, &document)? {
                budget
                    .charge(0, (key.len() + value.len()) as u64)
                    .map_err(budget_error)?;
                rows.insert(key, value);
            }
            generation.through = work.workspace_commit;
            generation.projected_sources += 1;
        }
        if caught_up {
            generation.through = world.watermarks.journal;
        }
        if next.building == Some(generation.number) && caught_up {
            next.active = next.building.take();
        }
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        self.require_custody_rebuilt(&tx, &workspace)?;
        let current: IndexState = self
            .raw_value(&tx, &state_key(&workspace))?
            .unwrap_or_default();
        if current != state || self.raw_authorization_epoch(&tx, &workspace)? != auth {
            return Err(stale_index());
        }
        if !fresh
            && self
                .raw_value::<Generation, _>(&tx, &generation_key(&workspace, generation.number))?
                != Some(expected_generation)
        {
            return Err(ServiceError::new(
                ErrorCode::Unavailable,
                "raw generation advanced concurrently; retry projection",
                true,
            ));
        }
        self.enable_raw_index_format(&mut tx)?;
        if generation.removal_through.is_some() {
            self.enable_capture_extension(&mut tx, REMOVAL_FEATURE)?;
        }
        if next.retained.is_some() {
            self.enable_capture_extension(&mut tx, GC_FEATURE)?;
        }
        for (key, value) in rows {
            budget.check().map_err(budget_error)?;
            tx.put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            state_key(&workspace),
            encode(&next)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.keyspaces.continuous,
            generation_key(&workspace, generation.number),
            encode(&generation)?,
        )
        .map_err(storage_error)?;
        let progress = RawProjectionProgress {
            generation: generation.number,
            through: generation.through,
            projected_sources: generation.projected_sources,
            caught_up,
        };
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        let digest = canonical_digest(&(&workspace, &generation))?;
        self.finish_frame(
            &mut tx,
            &frame,
            "raw_projection",
            digest.as_bytes(),
            &digest,
            &progress,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(progress)
    }

    /// Revoke a current original and invalidate every dependent indexed view in
    /// its workspace atomically. Historical reads do not restore this permission.
    pub fn revoke_original(
        &self,
        context: &AuthenticatedRequestContext,
        event_id: ObservationId,
        idempotency_key: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<OriginalRevocationReceipt> {
        require_capability(context, Capability::Admin)?;
        super::validate_identifier(idempotency_key, "source revocation retry key")?;
        let digest = canonical_digest(&(context.authorization_binding_digest()?, event_id))?;
        let key = canonical_digest(&(
            "original_revocation/v1",
            &context.request.workspace_id,
            idempotency_key,
        ))?;
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(receipt) = self.replay(&tx, key.as_bytes(), "original_revocation", &digest)? {
            return Ok(receipt);
        }
        let external = self.record_external_revocation(&tx, context, event_id, budget)?;
        let receipt = self.revoke_original_in_transaction(
            &mut tx,
            context,
            event_id,
            key.as_bytes(),
            &digest,
        )?;
        if let Some(checkpoint) = external {
            self.publish_suppression_checkpoint(&mut tx, context, checkpoint)?;
        }
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }

    pub(super) fn revoke_original_in_transaction<T: WriteTransaction>(
        &self,
        tx: &mut T,
        context: &AuthenticatedRequestContext,
        event_id: ObservationId,
        key: &[u8],
        digest: &str,
    ) -> ServiceResult<OriginalRevocationReceipt> {
        if let Some(receipt) = self.replay(tx, key, "original_revocation", digest)? {
            return Ok(receipt);
        }
        let observation = digest_bytes(event_id.to_string().as_bytes());
        let mut policy: super::StoredObservationPolicy = decode(
            &tx.get(&self.keyspaces.observations_policy, observation.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(super::not_found)?,
            "original policy",
        )?;
        if policy.access.workspace_id != context.request.workspace_id {
            return Err(super::permission_denied());
        }
        let original = self.captured_receipt_metadata(tx, event_id)?;
        self.enable_raw_index_format(tx)?;
        let frame = self.begin_frame(tx, &context.request.workspace_id, false)?;
        let epoch = self
            .raw_authorization_epoch(tx, &frame.workspace_digest)?
            .checked_add(1)
            .ok_or_else(|| exhausted("authorization epoch overflow"))?;
        policy.access.retrievable = false;
        self.invalidate_custody(
            tx,
            &frame.workspace_digest,
            original.workspace_commit,
            epoch,
        )?;
        tx.put(
            &self.keyspaces.observations_policy,
            observation.into_bytes(),
            encode(&policy)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.keyspaces.continuous,
            auth_key(&frame.workspace_digest),
            encode(&epoch)?,
        )
        .map_err(storage_error)?;
        for scope in &policy.access.scopes {
            tx.put(
                &self.keyspaces.continuous,
                super::capture::scope_key(&frame.workspace_digest, scope),
                encode(&frame.state.watermarks.journal)?,
            )
            .map_err(storage_error)?;
        }
        let receipt = OriginalRevocationReceipt {
            event_id,
            workspace_commit: frame.state.watermarks.journal,
            authorization_epoch: epoch,
        };
        tx.put(
            &self.keyspaces.continuous,
            revocation_key(&frame.workspace_digest, epoch),
            encode(&receipt)?,
        )
        .map_err(storage_error)?;
        self.finish_frame(tx, &frame, "original_revocation", key, digest, &receipt)?;
        Ok(receipt)
    }

    fn build_raw_document<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        commit: u64,
        event_digest: ContentDigest,
        policy_domain: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<IndexedOriginal> {
        let source = RawSource::from(event);
        let mut first_terms = BTreeMap::new();
        let mut complete = source.byte_length.is_none();
        if let (Some(length), Some(digest)) = (source.byte_length, source.payload_digest)
            && event.kind != EventKind::ModelRequested
            && length <= 1024 * 1024
        {
            let bytes = self.original_range_for_custody(snapshot, event, 0, length)?;
            budget.check().map_err(budget_error)?;
            if let Some(document) =
                RawLexicalDocument::from_original(event.event_id, digest, &bytes)
                    .map_err(|_| integrity("raw index original digest mismatch"))?
            {
                complete = document.first_terms.len() <= MAX_INDEX_TERMS;
                first_terms = document
                    .first_terms
                    .into_iter()
                    .filter(|(term, _)| term.len() <= contextdb_index::MAX_RAW_QUERY_BYTES)
                    .take(MAX_INDEX_TERMS)
                    .collect();
            } else {
                complete = true;
            }
        }
        Ok(IndexedOriginal {
            source,
            event_digest,
            commit,
            policy_domain: policy_domain.into(),
            lexical_complete: complete,
            first_terms,
            parents: event
                .parent_event_ids
                .iter()
                .chain(event.supersedes_event_id.iter())
                .copied()
                .collect(),
        })
    }

    pub(super) fn raw_value<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        key: &[u8],
    ) -> ServiceResult<Option<T>> {
        snapshot
            .get(&self.keyspaces.continuous, key)
            .map_err(storage_error)?
            .map(|bytes| decode(&bytes, "raw index record"))
            .transpose()
    }

    pub(super) fn raw_authorization_epoch<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
    ) -> ServiceResult<u64> {
        Ok(self
            .raw_value(snapshot, &auth_key(workspace))?
            .unwrap_or_default())
    }

    pub(super) fn lock_index_publication(
        &self,
        budget: &QueryBudget,
    ) -> ServiceResult<super::publication::PublicationGuard<'_>> {
        self.writes.enter(|| budget.check().map_err(budget_error))
    }

    fn enable_raw_index_format<T: WriteTransaction>(&self, tx: &mut T) -> ServiceResult<()> {
        self.enable_capture_format(tx)?;
        let mut manifest: super::Manifest = decode(
            &tx.get(&self.keyspaces.meta, super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if manifest.features.insert(INDEX_FEATURE.into()) {
            manifest.checksum = super::manifest_checksum(&manifest)?;
            tx.put(
                &self.keyspaces.meta,
                super::META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }
}

fn legacy_custody(version: &u16) -> bool {
    *version == 0
}

pub(super) fn state_key(workspace: &str) -> Vec<u8> {
    format!("raw/state/{workspace}").into_bytes()
}
pub(super) fn auth_key(workspace: &str) -> Vec<u8> {
    format!("raw/auth/{workspace}").into_bytes()
}
pub(super) fn revocation_key(workspace: &str, epoch: u64) -> Vec<u8> {
    format!("raw/revocation/{workspace}/{epoch:020}").into_bytes()
}
pub(super) fn generation_key(workspace: &str, generation: u64) -> Vec<u8> {
    format!("raw/generation/{workspace}/{generation:020}").into_bytes()
}
pub(super) fn generation_prefix(workspace: &str, generation: u64) -> String {
    format!("raw/g/{workspace}/{generation:020}/")
}
pub(super) fn domain_key(workspace: &str, generation: u64, domain: &str) -> Vec<u8> {
    format!(
        "{}domain/{domain}",
        generation_prefix(workspace, generation)
    )
    .into_bytes()
}
pub(super) fn doc_key(workspace: &str, generation: u64, id: ObservationId) -> Vec<u8> {
    format!("{}doc/{id}", generation_prefix(workspace, generation)).into_bytes()
}

pub(super) fn domain_eligibility_keys(
    workspace: &str,
    generation: u64,
    domain: &str,
    policy: &PolicyDomain,
) -> ServiceResult<Vec<Vec<u8>>> {
    // Custody labels are canonicalized by digest, not ancestry. Every label
    // must authorize the caller, so any scoped label is a valid routing seed.
    let routing_policy = policy
        .policies
        .iter()
        .find(|policy| !policy.scopes.is_empty())
        .ok_or_else(|| integrity("raw domain has no scoped policy"))?;
    Ok(routing_policy
        .scopes
        .iter()
        .map(|scope| {
            format!(
                "{}eligibility/{}/{domain}",
                generation_prefix(workspace, generation),
                digest_bytes(scope.as_bytes())
            )
            .into_bytes()
        })
        .collect())
}

pub(super) fn document_rows(
    workspace: &str,
    generation: u64,
    document: &IndexedOriginal,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut rows = BTreeMap::from([(
        doc_key(workspace, generation, document.source.event_id),
        encode(document)?,
    )]);
    let base = format!(
        "{}route/{}/",
        generation_prefix(workspace, generation),
        document.policy_domain
    );
    let suffix = format!("{:020}/{}", document.commit, document.source.event_id);
    let id = encode(&document.source.event_id)?;
    let mut routes = vec![
        "all/".into(),
        format!("source/{}/", document.source.source_id),
    ];
    if let Some(session) = document.source.session_id {
        routes.push(format!("session/{session}/"));
    }
    for parent in &document.parents {
        routes.push(format!("child/{parent}/"));
    }
    for term in document.first_terms.keys() {
        routes.push(format!("term/{}/", digest_bytes(term.as_bytes())));
    }
    if !document.lexical_complete {
        routes.push("unindexed/".into());
    }
    for route in routes {
        rows.insert(format!("{base}{route}{suffix}").into_bytes(), id.clone());
    }
    // Signed timestamps are biased into unsigned order without changing original time.
    let time = (document.source.recorded_at.0 as u64) ^ (1_u64 << 63);
    rows.insert(format!("{base}time/{time:020}/{suffix}").into_bytes(), id);
    Ok(rows)
}

pub(super) fn budget_error(reason: QueryLimit) -> ServiceError {
    let message = match reason {
        QueryLimit::Work => "indexed work budget exhausted",
        QueryLimit::Bytes => "indexed byte budget exhausted",
        QueryLimit::Deadline => "indexed deadline exceeded",
        QueryLimit::Cancelled => "indexed query cancelled",
    };
    ServiceError::new(ErrorCode::BudgetExhausted, message, false)
}

pub(super) fn stale_index() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "raw index cannot establish current authorization or bounded capture coverage; advance or rebuild its generation",
        true,
    )
}
