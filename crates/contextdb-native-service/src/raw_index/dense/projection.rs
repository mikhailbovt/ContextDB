//! Bounded encoding outside the writer, followed by native owner publication.

use super::*;
use contextdb_service::TextEmbeddingAdapter;

impl NativeService {
    /// Encode whole finite source-span plans from an existing BM25 outbox prefix.
    /// The local encoder owns no storage. Each source's complete plan, its exact
    /// vectors, progress and authenticated receipt publish in one Sync frame.
    /// Failure/cancellation publishes no prefix; retry may repeat inference.
    pub fn project_original_spans(
        &self,
        context: &AuthenticatedRequestContext,
        encoder: &dyn TextEmbeddingAdapter,
        max_events: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseProjectionReceipt> {
        for capability in [
            Capability::Admin,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            require_capability(context, capability)?;
        }
        if !(1..=64).contains(&max_events) {
            return Err(crate::invalid("dense batch requires 1..64 events"));
        }
        let frozen_profile = {
            let profile = encoder.profile();
            validate_profile(profile)?;
            budget.charge(1, 8192).map_err(budget_error)?;
            profile.clone()
        };
        budget.check().map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, budget, |reader| {
            self.require_custody_rebuilt(reader, &workspace)
        })?;
        let state: IndexState = self
            .dense_read(&snapshot, &state_key(&workspace), budget)?
            .unwrap_or_default();
        let number = state.active.ok_or_else(stale_index)?;
        let generation: Generation = self
            .dense_read(&snapshot, &generation_key(&workspace, number), budget)?
            .ok_or_else(|| integrity("dense raw generation absent"))?;
        if generation.bm25.is_none()
            || generation.authorization_epoch
                != self.dense_authorization_epoch(&snapshot, &workspace, budget)?
            || generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != RAW_ANALYZER
        {
            return Err(stale_index());
        }
        generation
            .bm25
            .as_ref()
            .ok_or_else(|| integrity("dense BM25 profile absent"))?
            .validate()?;
        self.require_dense_base_feature(&snapshot, budget)?;
        self.validate_dense_generation(&snapshot, &workspace, &generation, budget)?;
        if generation.dense.is_none() {
            self.admit_first_dense_projection(&snapshot, &workspace, number, budget)?;
        }
        let mut dense = generation
            .dense
            .clone()
            .map(Ok)
            .unwrap_or_else(|| DenseManifest::empty(&frozen_profile))?;
        if dense.profile != frozen_profile || dense.profile != *encoder.profile() {
            return Err(integrity("dense resume changed encoder compatibility"));
        }
        let previous = dense.clone();
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&dense.through.to_be_bytes());
        budget.charge(1, 0).map_err(budget_error)?;
        let cap = usize::try_from(
            budget
                .remaining_bytes()
                .saturating_sub(256)
                .min(4 * 64 * 1024)
                / 4,
        )
        .map_err(|_| exhausted("dense outbox allowance overflow"))?;
        if cap < 1024 {
            return Err(exhausted("dense outbox allowance exhausted"));
        }
        budget
            .charge(1, cap as u64 * 4 + 256)
            .map_err(budget_error)?;
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries: max_events as usize,
                    max_bytes: cap,
                },
            )
            .map_err(storage_error)?;
        let mut rows = BTreeMap::new();
        let mut forwarded = Vec::new();
        let mut stopped = page.continuation.is_some();
        for entry in page.entries {
            budget.charge(1, 0).map_err(budget_error)?;
            let work: crate::capture::CaptureWork = decode(&entry.value, "dense accepted outbox")?;
            if work.workspace_commit > generation.through {
                stopped = false;
                break;
            }
            if work.workspace_commit <= dense.through
                || entry.key != crate::capture::work_key(&workspace, work.workspace_commit)
            {
                return Err(integrity("dense outbox order or key differs"));
            }
            let (receipt, _) = self.capture_recovery_metadata(&snapshot, work.event_id, budget)?;
            let accepted =
                self.capture_work_for_receipt_with_budget(&snapshot, &receipt, budget)?;
            if accepted != work
                || receipt.database_id != self.database_id
                || receipt.workspace_id.to_string() != context.request.workspace_id
            {
                return Err(integrity("dense outbox differs from accepted capture"));
            }
            if self.source_prepared_at(
                &snapshot,
                &workspace,
                work.event_id,
                generation.removal_through,
                budget,
            )? {
                dense.through = work.workspace_commit;
                continue;
            }
            // No administrative custody reader supplies neural input implicitly.
            self.authorized_capture_policy_with_budget(&snapshot, context, work.event_id, budget)?;
            self.authorize_derived_custody_with_budget(&snapshot, context, work.event_id, budget)?;
            let original =
                self.load_captured_original_with_budget(&snapshot, work.event_id, budget)?;
            if original.receipt != receipt {
                return Err(integrity("dense original receipt differs"));
            }
            let raw_cap = (RawSource::from(&original.event)
                .byte_length
                .unwrap_or_default()
                .saturating_mul(32)
                + 8192)
                .min(1024 * 1024) as usize;
            let raw: IndexedOriginal = self
                .dense_read_from(
                    &snapshot,
                    &self.keyspaces.continuous,
                    &doc_key(&workspace, number, work.event_id),
                    raw_cap,
                    budget,
                )?
                .ok_or_else(|| integrity("dense source has no published raw document"))?;
            if raw.source != RawSource::from(&original.event)
                || raw.event_digest != work.event_digest
                || raw.commit != work.workspace_commit
            {
                return Err(integrity(
                    "dense source differs from published raw identity",
                ));
            }
            let policies =
                self.stored_custody_policies_with_budget(&snapshot, work.event_id, budget)?;
            if canonical_digest(&policies)? != raw.policy_domain {
                return Err(stale_index());
            }
            let (omission, plan, bytes) = self.dense_plan(
                &snapshot,
                &original.event,
                &dense.profile,
                Some(context),
                budget,
            )?;
            // Reserve the entire finite source bundle before any inference.
            let source_cap = 1 + plan.len();
            if rows.len() + source_cap + 1 > MAX_PROJECTION_ROWS {
                stopped = true;
                break;
            }
            let mut document = DenseDocument {
                source: raw.source.clone(),
                event_digest: work.event_digest,
                commit: work.workspace_commit,
                policy_domain: raw.policy_domain.clone(),
                profile_digest: dense.profile_digest,
                omission,
                spans: Vec::new(),
                token: String::new(),
            };
            let mut source_rows = BTreeMap::new();
            for (ordinal, span) in plan.into_iter().enumerate() {
                let text = std::str::from_utf8(&bytes[span.start as usize..span.end as usize])
                    .map_err(|_| integrity("dense source span ceased to be UTF-8"))?;
                if encoder.profile() != &dense.profile {
                    return Err(integrity("dense encoder changed before callback"));
                }
                self.admit_dense_forward(
                    context,
                    &workspace,
                    work.event_id,
                    generation.authorization_epoch,
                    budget,
                )?;
                let embedded = encoder.embed(EmbeddingTextKind::Source, text, budget)?;
                if encoder.profile() != &dense.profile {
                    return Err(integrity("dense encoder changed after callback"));
                }
                embedded.validate(&dense.profile, EmbeddingTextKind::Source, text, budget)?;
                if embedded.tokens_digest.as_bytes() == &[0; 32] {
                    return Err(integrity("dense exact token observation absent"));
                }
                budget
                    .charge(1, embedded.values.len() as u64 * 32 + 4096)
                    .map_err(budget_error)?;
                let mut vector = DenseVector {
                    source: raw.source.clone(),
                    event_digest: work.event_digest,
                    commit: work.workspace_commit,
                    policy_domain: raw.policy_domain.clone(),
                    profile_digest: dense.profile_digest,
                    ordinal: ordinal as u32,
                    span: span.clone(),
                    input_digest: embedded.input_digest,
                    tokens_digest: embedded.tokens_digest,
                    token_count: embedded.token_count,
                    values_bits: embedded
                        .values
                        .iter()
                        .map(|value| value.to_bits())
                        .collect(),
                    vector_digest: embedded.vector_digest,
                    token: String::new(),
                };
                self.sign_dense_vector(&mut vector)?;
                let value = encode(&vector)?;
                if value.len() > MAX_DENSE_ROW_BYTES {
                    return Err(exhausted("dense vector row exceeds its bound"));
                }
                budget.charge(1, value.len() as u64).map_err(budget_error)?;
                source_rows.insert(
                    vector_key(&workspace, number, work.event_id, ordinal as u32),
                    value,
                );
                document.spans.push(DenseSpan {
                    span,
                    vector_digest: embedded.vector_digest,
                });
            }
            budget
                .charge(1, MAX_DENSE_ROW_BYTES as u64 * 3)
                .map_err(budget_error)?;
            self.sign_dense_document(&mut document)?;
            let value = encode(&document)?;
            if value.len() > MAX_DENSE_ROW_BYTES {
                return Err(exhausted("dense document row exceeds its bound"));
            }
            budget.charge(1, value.len() as u64).map_err(budget_error)?;
            source_rows.insert(document_key(&workspace, number, work.event_id), value);
            rows.extend(source_rows);
            dense.accept(&document)?;
            dense.through = work.workspace_commit;
            forwarded.push(work.event_id);
        }
        if !stopped {
            dense.through = generation.through;
        }
        dense.validate(generation.through)?;
        if dense.through == generation.through && dense.sources != generation.projected_sources {
            return Err(integrity(
                "dense outbox coverage differs from published raw sources",
            ));
        }
        if generation.dense.is_some() && dense == previous {
            return self
                .dense_read(&snapshot, &receipt_key(&workspace, number), budget)?
                .ok_or_else(|| integrity("dense retry receipt absent"));
        }
        if encoder.profile() != &dense.profile {
            return Err(integrity("dense encoder changed before publication"));
        }
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        crate::budgeted::metadata(&tx, budget, |reader| {
            self.require_custody_rebuilt(reader, &workspace)
        })?;
        if self.dense_read::<IndexState, _>(&tx, &state_key(&workspace), budget)? != Some(state)
            || self.dense_read::<Generation, _>(&tx, &generation_key(&workspace, number), budget)?
                != Some(generation.clone())
            || self.dense_authorization_epoch(&tx, &workspace, budget)?
                != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        for id in forwarded {
            self.authorized_capture_policy_with_budget(&tx, context, id, budget)?;
            self.authorize_derived_custody_with_budget(&tx, context, id, budget)?;
        }
        if encoder.profile() != &dense.profile {
            return Err(integrity("dense encoder changed at publication fence"));
        }
        budget
            .charge(1, MAX_DENSE_ROW_BYTES as u64 * 4)
            .map_err(budget_error)?;
        let frame = crate::budgeted::metadata(&tx, budget, |reader| {
            self.begin_frame(reader, &context.request.workspace_id, false)
        })?;
        let mut receipt = DenseProjectionReceipt {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            generation: number,
            raw_through: generation.through,
            raw_sources: generation.projected_sources,
            authorization_epoch: generation.authorization_epoch,
            through: dense.through,
            sources: dense.sources,
            embedded_sources: dense.embedded_sources,
            spans: dense.spans,
            omitted_sources: dense.omitted_sources,
            caught_up: dense.through == generation.through,
            profile: dense.profile.clone(),
            profile_digest: dense.profile_digest,
            commitment: dense.commitment,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_dense_receipt(&mut receipt)?;
        self.enable_capture_extension(&mut tx, FEATURE)?;
        for (key, value) in rows {
            budget.check().map_err(budget_error)?;
            tx.put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            receipt_key(&workspace, number),
            encode(&receipt)?,
        )
        .map_err(storage_error)?;
        let mut next_generation = generation;
        next_generation.dense = Some(dense);
        tx.put(
            &self.keyspaces.continuous,
            generation_key(&workspace, number),
            encode(&next_generation)?,
        )
        .map_err(storage_error)?;
        let request_digest = canonical_digest(&receipt)?;
        self.finish_frame(
            &mut tx,
            &frame,
            OPERATION,
            request_digest.as_bytes(),
            &request_digest,
            &receipt,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }
}

pub(crate) fn receipt_key(workspace: &str, generation: u64) -> Vec<u8> {
    format!("{}dense/receipt", generation_prefix(workspace, generation)).into_bytes()
}

impl NativeService {
    /// Each host callback is a new model-processing boundary. A prior span's
    /// permission or snapshot cannot authorize forwarding after revocation.
    fn admit_dense_forward(
        &self,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        event: ObservationId,
        authorization_epoch: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for capability in [
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            require_capability(context, capability)?;
        }
        budget.check().map_err(budget_error)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&current, budget, |reader| {
            self.require_custody_ready(reader, workspace)
        })?;
        if self.dense_authorization_epoch(&current, workspace, budget)? != authorization_epoch {
            return Err(stale_index());
        }
        self.authorized_capture_policy_with_budget(&current, context, event, budget)?;
        self.authorize_derived_custody_with_budget(&current, context, event, budget)?;
        Ok(())
    }
    pub(in crate::raw_index) fn dense_read<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<T>> {
        self.dense_read_from(
            snapshot,
            &self.keyspaces.continuous,
            key,
            MAX_DENSE_ROW_BYTES,
            budget,
        )
    }
    pub(in crate::raw_index) fn dense_read_from<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        keyspace: &contextdb_storage::Keyspace,
        key: &[u8],
        max_bytes: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<T>> {
        budget.charge(1, 0).map_err(budget_error)?;
        let cap = usize::try_from(
            (budget.remaining_bytes().saturating_sub(256) / 4).min(max_bytes as u64),
        )
        .map_err(|_| exhausted("dense read allowance overflow"))?;
        if cap <= key.len() + 128 {
            return Err(exhausted("dense metadata allowance exhausted"));
        }
        // Conservative allowance covers bounded ciphertext/plaintext, typed
        // decode and the envelope before storage can allocate or decrypt it.
        budget
            .charge(1, cap as u64 * 4 + 256)
            .map_err(budget_error)?;
        let page = snapshot
            .scan_prefix_page(
                keyspace,
                ScanPageRequest {
                    prefix: key,
                    start_after: None,
                    max_entries: 1,
                    max_bytes: cap,
                },
            )
            .map_err(storage_error)?;
        let Some(row) = page.entries.into_iter().next() else {
            return Ok(None);
        };
        if row.key != key || row.value.len() > max_bytes {
            return Err(integrity("dense exact row key or size differs"));
        }
        decode(&row.value, "dense exact row").map(Some)
    }
    fn dense_authorization_epoch<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<u64> {
        Ok(self
            .dense_read(snapshot, &auth_key(workspace), budget)?
            .unwrap_or_default())
    }
    pub(super) fn sign_dense_receipt(
        &self,
        receipt: &mut DenseProjectionReceipt,
    ) -> ServiceResult<()> {
        receipt.token.clear();
        receipt.token = crate::keyed_token(&self.token_key, RECEIPT_DOMAIN, &encode(receipt)?);
        Ok(())
    }
    pub(super) fn check_dense_receipt(
        &self,
        receipt: &DenseProjectionReceipt,
    ) -> ServiceResult<()> {
        let mut expected = receipt.clone();
        self.sign_dense_receipt(&mut expected)?;
        if expected.token != receipt.token
            || receipt.database_id != self.database_id
            || receipt.generation == 0
            || receipt.global_commit == 0
            || receipt.profile_digest != receipt.profile.digest()?
            || receipt.caught_up != (receipt.through == receipt.raw_through)
            || receipt.raw_sources > receipt.raw_through
            || receipt.sources > receipt.raw_sources
            || (receipt.caught_up && receipt.sources != receipt.raw_sources)
        {
            return Err(integrity("dense retained receipt authentication differs"));
        }
        validate_profile(&receipt.profile)
    }
}
