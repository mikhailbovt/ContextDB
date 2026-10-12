//! Complete bounded append construction outside the native writer lock.
use super::super::publication::GraphInput;
use super::super::tail::AuthenticatedDensePrefixAnchor;
use super::types::*;
use super::types::{FEATURE, MAX_NODES, OPERATION, ROW_BYTES};
use super::verification::{LOCATOR_OPERATION, seal_request_digest};
use super::*;

#[cfg(test)]
mod tests;

impl NativeService {
    /// Resolve the accepted predecessor of an active segment sequence. A missing
    /// sequence is admitted only after checking retained declarations and rows.
    /// The returned reference is a CAS expectation, never processing authority.
    pub fn original_span_segment_head(
        &self,
        context: &AuthenticatedRequestContext,
        generation_number: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<DirectoryRef>> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, budget)?;
        for capability in [
            Capability::Admin,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, budget)?;
        }
        budget.charge(1, 32768).map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, budget, |r| {
            self.require_custody_ready(r, &workspace)
        })?;
        let state: IndexState = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(generation_number) {
            return Err(stale_index());
        }
        let generation: Generation = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, generation_number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if self.graph_epoch(&snapshot, &workspace, budget)? != generation.authorization_epoch {
            return Err(stale_index());
        }
        let base = self.accepted_graph_receipt(&snapshot, &workspace, &generation, budget)?;
        self.admit_tail_generation(&generation, &base.manifest, budget)?;
        self.tail_dense_receipt(&snapshot, &workspace, &generation, budget)?;
        let world = self.current_segment_heads(&snapshot, &context.request.workspace_id, budget)?;
        if let Some(reference) = &generation.dense_segments {
            self.accepted_current_segment_head(
                &snapshot,
                &context.request.workspace_id,
                &generation,
                budget,
            )?;
            budget.charge(1, 4096).map_err(budget_error)?;
            return Ok(Some(reference.clone()));
        }
        if world
            .segment_heads
            .as_ref()
            .is_some_and(|heads| heads.contains_key(&generation_number))
        {
            return Err(integrity(
                "segment resume pointer differs from retained workspace head",
            ));
        }
        self.no_prior_segment_declaration(&snapshot, &workspace, generation_number, budget)?;
        self.require_no_segment_rows(&snapshot, &workspace, generation_number, budget)?;
        Ok(None)
    }

    /// Seal one complete accepted dense interval against its exact predecessor.
    /// This operator operation neither rebuilds the base nor enables a reader.
    pub fn seal_original_span_segment(
        &self,
        context: &AuthenticatedRequestContext,
        request: &SealRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseSegmentPublication> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, budget)?;
        for capability in [
            Capability::Admin,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, budget)?;
        }
        budget.charge(1, 32768).map_err(budget_error)?;
        request.validate()?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        if request.target.database_id != self.database_id
            || request.target.workspace_id != context.request.workspace_id
        {
            return Err(crate::invalid(
                "segment request crosses the native owner workspace",
            ));
        }
        let request_digest = seal_request_digest(&self.database_id, &workspace, request)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, budget, |r| {
            self.require_custody_rebuilt(r, &workspace)
        })?;
        if let Some(stored) = self.graph_read::<crate::StoredIdempotency, _>(
            &snapshot,
            &self.keyspaces.idempotency,
            request_digest.as_bytes(),
            budget,
        )? {
            budget
                .charge(1, ROW_BYTES as u64 * 4)
                .map_err(budget_error)?;
            let publication: DenseSegmentPublication =
                decode(&stored.response_bytes, "segment exact retry")?;
            let reference =
                self.segment_publication_ref(&snapshot, publication.delta.global_commit, budget)?;
            self.check_segment_publication(
                &snapshot,
                &workspace,
                &reference,
                &publication,
                budget,
            )?;
            if reference.request_digest != request_digest {
                return Err(integrity("segment exact retry request differs"));
            }
            // Return historical acceptance only. Never reinstall a former head.
            return Ok(publication);
        }
        let state: IndexState = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(request.generation) {
            return Err(stale_index());
        }
        let generation: Generation = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, request.generation),
                budget,
            )?
            .ok_or_else(stale_index)?;
        let base = self.accepted_graph_receipt(&snapshot, &workspace, &generation, budget)?;
        self.admit_tail_generation(&generation, &base.manifest, budget)?;
        if base.manifest.nodes == 0
            || self.graph_epoch(&snapshot, &workspace, budget)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        self.tail_dense_receipt(&snapshot, &workspace, &generation, budget)?;
        let live_target: DenseProjectionReceipt = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &dense::receipt_key(&workspace, generation.number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if live_target != request.target || generation.dense_segments != request.previous {
            return Err(stale_index());
        }
        let workspace_state =
            self.current_segment_heads(&snapshot, &context.request.workspace_id, budget)?;
        let previous = match &request.previous {
            Some(_) => Some(self.accepted_current_segment_head(
                &snapshot,
                &context.request.workspace_id,
                &generation,
                budget,
            )?),
            None => {
                if workspace_state
                    .segment_heads
                    .as_ref()
                    .is_some_and(|h| h.contains_key(&generation.number))
                {
                    return Err(integrity(
                        "segment pointer stripped from its retained workspace head",
                    ));
                }
                self.no_prior_segment_declaration(
                    &snapshot,
                    &workspace,
                    generation.number,
                    budget,
                )?;
                self.require_no_segment_rows(&snapshot, &workspace, generation.number, budget)?;
                None
            }
        };
        let ordinal = request
            .previous
            .as_ref()
            .map_or(Some(1), |p| p.count.checked_add(1))
            .ok_or_else(|| exhausted("segment ordinal exhausted"))?;
        budget.charge(1, KEY_BYTES * 2).map_err(budget_error)?;
        let locator_key = retained_locator_key(&workspace, generation.number, ordinal)?;
        if crate::budgeted::read_value(
            &snapshot,
            &self.keyspaces.idempotency,
            &locator_key,
            ROW_BYTES,
            budget,
        )?
        .is_some()
        {
            return Err(integrity(
                "next segment ordinal already has retained acceptance",
            ));
        }
        let before = previous
            .as_ref()
            .map_or(&base.manifest.dense, |head| head.covered());
        let after = generation.dense.as_ref().ok_or_else(stale_index)?;
        let nodes = after
            .spans
            .checked_sub(before.spans)
            .ok_or_else(stale_index)?;
        if after.through <= before.through || nodes > MAX_NODES {
            return Err(exhausted(
                "segment interval requires a new prefix and at most 256 complete spans",
            ));
        }
        let witness = match &previous {
            Some(head) => self.dense_prefix_witness(
                &snapshot,
                &workspace,
                &generation,
                AuthenticatedDensePrefixAnchor::accepted_segment(head),
                MAX_WORK as usize,
                true,
                budget,
            )?,
            None => self.tracked_base_dense_prefix_witness(
                &snapshot,
                &workspace,
                &generation,
                &base,
                MAX_WORK as usize,
                budget,
            )?,
        };
        if !witness.complete {
            return Err(exhausted(
                "segment complete accepted interval exceeds 128 work items",
            ));
        }
        let interval = witness
            .interval
            .ok_or_else(|| integrity("complete segment interval digest absent"))?;
        if interval.work_items == 0 {
            return Err(crate::invalid("empty segment interval"));
        }
        let inputs = self.segment_inputs(
            &snapshot,
            Some(context),
            &workspace,
            &generation,
            before,
            &witness.documents,
            budget,
        )?;
        if inputs.len() as u64 != nodes {
            return Err(integrity(
                "segment span census differs from complete interval",
            ));
        }
        budget.charge(1, 65536).map_err(budget_error)?;
        let mut manifest = DenseDeltaManifest {
            revision: 1,
            binding: DeltaGenerationBinding {
                generation: generation.number,
                custody_version: generation.custody_version,
                analyzer: generation.analyzer.clone(),
                bm25: generation.bm25.clone().ok_or_else(stale_index)?,
                authorization_epoch: generation.authorization_epoch,
                removal_through: generation.removal_through,
                raw_through: generation.through,
                raw_sources: generation.projected_sources,
            },
            ordinal,
            base: self.segment_base_ref(&snapshot, &base, budget)?,
            before: before.clone(),
            after: after.clone(),
            target_dense: self.segment_publication_ref(
                &snapshot,
                live_target.global_commit,
                budget,
            )?,
            interval_digest: interval.digest,
            work_items: interval.work_items,
            nodes,
            cohorts: Vec::new(),
            builder_revision: contextdb_index::ANN_PARTITION_BUILD_REVISION_V2.into(),
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        let rows =
            self.construct_segment(&workspace, &generation, &mut manifest, &inputs, budget)?;
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        crate::budgeted::metadata(&tx, budget, |r| self.require_custody_rebuilt(r, &workspace))?;
        if self.graph_read::<IndexState, _>(
            &tx,
            &self.keyspaces.continuous,
            &state_key(&workspace),
            budget,
        )? != Some(state)
            || self
                .graph_read::<Generation, _>(
                    &tx,
                    &self.keyspaces.continuous,
                    &generation_key(&workspace, generation.number),
                    budget,
                )?
                .as_ref()
                != Some(&generation)
            || self.graph_epoch(&tx, &workspace, budget)? != generation.authorization_epoch
            || self.current_segment_heads(&tx, &context.request.workspace_id, budget)?
                != workspace_state
        {
            return Err(stale_index());
        }
        // Includes zero-span omissions; all captured inputs remain whole.
        for document in &witness.documents {
            self.authorized_capture_policy_with_budget(
                &tx,
                context,
                document.source.event_id,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                &tx,
                context,
                document.source.event_id,
                budget,
            )?;
        }
        for input in &inputs {
            if self.stored_custody_policies_with_budget(
                &tx,
                input.vector.source.event_id,
                budget,
            )? != input.policies
            {
                return Err(stale_index());
            }
        }
        let mut frame = crate::budgeted::metadata(&tx, budget, |r| {
            self.begin_frame(r, &context.request.workspace_id, false)
        })?;
        let mut delta = DenseDeltaReceipt {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            manifest,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_delta_receipt(&mut delta, budget)?;
        budget
            .charge(1, ROW_BYTES as u64 * 4)
            .map_err(budget_error)?;
        let mut head = DenseSegmentDirectoryHead {
            revision: 1,
            generation: generation.number,
            base: delta.manifest.base.clone(),
            count: ordinal,
            latest: SegmentRef {
                ordinal,
                global_commit: frame.global_commit,
                manifest_digest: delta.manifest.content_digest,
                receipt_digest: digest(&encode(&delta)?),
            },
            covered: delta.manifest.after.clone(),
            previous: request.previous.clone(),
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        self.finalize_segment_directory_head(&workspace, &mut head, budget)?;
        let mut directory = DenseSegmentDirectoryReceipt {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            head,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_segment_directory_receipt(&mut directory, budget)?;
        let publication = DenseSegmentPublication { delta, directory };
        publication.validate()?;
        let response = encode(&publication)?;
        if response.len() > MAX_PUBLICATION_BYTES {
            return Err(exhausted(
                "segment accepted response exceeds retained row allowance",
            ));
        }
        let reference = DirectoryRef {
            count: ordinal,
            global_commit: frame.global_commit,
            request_digest: request_digest.clone(),
            response_digest: digest_bytes(&response),
            content_digest: publication.directory.head.content_digest,
        };
        let heads = frame.state.segment_heads.get_or_insert_with(BTreeMap::new);
        if heads.insert(generation.number, reference.clone()) != request.previous {
            return Err(integrity(
                "segment append predecessor differs from certified workspace map",
            ));
        }
        self.enable_capture_extension(&mut tx, FEATURE)?;
        for (key, value) in rows {
            budget.charge(1, value.len() as u64).map_err(budget_error)?;
            tx.put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            delta_receipt_key(&workspace, generation.number, ordinal)?,
            encode(&publication.delta)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.keyspaces.continuous,
            directory_head_key(&workspace, generation.number)?,
            encode(&publication.directory)?,
        )
        .map_err(storage_error)?;
        let mut next = generation;
        next.dense_segments = Some(reference);
        tx.put(
            &self.keyspaces.continuous,
            generation_key(&workspace, next.number),
            encode(&next)?,
        )
        .map_err(storage_error)?;
        self.finish_frame(
            &mut tx,
            &frame,
            OPERATION,
            request_digest.as_bytes(),
            &request_digest,
            &publication,
        )?;
        // The event hash exists only after finish_frame. Its retained locator is
        // atomically committed in the same transaction and uses the usual codec.
        let accepted = self.segment_publication_ref(&tx, frame.global_commit, budget)?;
        let mut locator = RetainedSegmentLocator {
            revision: 1,
            workspace_digest: workspace.clone(),
            generation: next.number,
            ordinal,
            publication: accepted,
            token: String::new(),
        };
        self.sign_retained_segment_locator(&workspace, &mut locator, budget)?;
        let bytes = encode(&locator)?;
        let wrapped = crate::StoredIdempotency {
            schema_version: crate::SCHEMA_VERSION,
            operation: LOCATOR_OPERATION.into(),
            request_digest: canonical_digest(&locator)?,
            response_digest: digest_bytes(&bytes),
            response_bytes: bytes,
        };
        tx.put(&self.keyspaces.idempotency, locator_key, encode(&wrapped)?)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(publication)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "exact prefix, native source access and shared allowance remain separate"
    )]
    pub(super) fn segment_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        workspace: &str,
        generation: &Generation,
        before: &DenseManifest,
        documents: &[DenseDocument],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<GraphInput>> {
        let latest = generation.dense.as_ref().ok_or_else(stale_index)?;
        let mut inputs = Vec::new();
        for doc in documents {
            if doc.commit <= before.through || doc.commit > latest.through {
                return Err(integrity("segment document escapes interval"));
            }
            if let Some(context) = context {
                self.authorized_capture_policy_with_budget(
                    snapshot,
                    context,
                    doc.source.event_id,
                    budget,
                )?;
                self.authorize_derived_custody_with_budget(
                    snapshot,
                    context,
                    doc.source.event_id,
                    budget,
                )?;
            }
            budget.charge(1, KEY_BYTES).map_err(budget_error)?;
            let raw: IndexedOriginal = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &doc_key(workspace, generation.number, doc.source.event_id),
                    budget,
                )?
                .ok_or_else(|| integrity("segment actual raw source metadata absent"))?;
            self.verify_projected_causal_metadata(snapshot, workspace, &raw, budget)?;
            if raw.source != doc.source
                || raw.event_digest != doc.event_digest
                || raw.commit != doc.commit
                || raw.policy_domain != doc.policy_domain
            {
                return Err(integrity("segment full original source/version differs"));
            }
            let policies =
                self.stored_custody_policies_with_budget(snapshot, doc.source.event_id, budget)?;
            budget.charge(1, 65536).map_err(budget_error)?;
            if canonical_digest(&policies)? != doc.policy_domain {
                return Err(integrity("segment compound policy differs"));
            }
            let policy_bytes = encode(&policies)?.len();
            if policy_bytes > ROW_BYTES / 2 {
                return Err(exhausted("segment policy exceeds cohort allowance"));
            }
            for (ordinal, span) in doc.spans.iter().enumerate() {
                if inputs.len() == MAX_NODES as usize {
                    return Err(exhausted("segment entire source plan exceeds 256 spans"));
                }
                budget.charge(1, KEY_BYTES).map_err(budget_error)?;
                let vector: DenseVector = self
                    .graph_read(
                        snapshot,
                        &self.keyspaces.continuous,
                        &vector_key(
                            workspace,
                            generation.number,
                            doc.source.event_id,
                            ordinal as u32,
                        ),
                        budget,
                    )?
                    .ok_or_else(|| integrity("segment exact vector absent"))?;
                budget
                    .charge(
                        1,
                        vector.values_bits.len() as u64 * 12 + 16384 + policy_bytes as u64 * 4,
                    )
                    .map_err(budget_error)?;
                self.check_dense_vector_token(&vector)?;
                if vector.source != doc.source
                    || vector.event_digest != doc.event_digest
                    || vector.commit != doc.commit
                    || vector.ordinal != ordinal as u32
                    || vector.span != span.span
                    || vector.policy_domain != doc.policy_domain
                    || vector.profile_digest != latest.profile_digest
                    || vector.vector_digest != span.vector_digest
                    || vector.values_bits.len() != latest.profile.dimensions as usize
                {
                    return Err(integrity(
                        "segment vector differs from complete tagged source plan",
                    ));
                }
                let values: Vec<f32> = vector
                    .values_bits
                    .iter()
                    .map(|bits| f32::from_bits(*bits))
                    .collect();
                if values.iter().any(|v| !v.is_finite()) || values.iter().all(|v| *v == 0.0) {
                    return Err(integrity("segment vector has no finite cosine direction"));
                }
                inputs.push(GraphInput {
                    vector,
                    values,
                    policies: policies.clone(),
                });
            }
        }
        Ok(inputs)
    }

    pub(super) fn require_no_segment_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, KEY_BYTES).map_err(budget_error)?;
        let mut prefix = graph_prefix(workspace, generation);
        prefix.extend_from_slice(b"segment");
        let page = crate::budgeted::metadata(snapshot, budget, |r| {
            r.scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: None,
                    max_entries: 1,
                    max_bytes: ROW_BYTES + 1024,
                },
            )
            .map_err(storage_error)
        })?;
        if !page.entries.is_empty() || page.continuation.is_some() {
            return Err(integrity("orphan segment rows precede first acceptance"));
        }
        Ok(())
    }

    pub(super) fn no_prior_segment_declaration<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let mut after = None;
        loop {
            let page = crate::budgeted::metadata(snapshot, budget, |r| {
                r.scan_prefix_page(
                    &self.keyspaces.events,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 32,
                        max_bytes: ROW_BYTES + 1024,
                    },
                )
                .map_err(storage_error)
            })?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64 * 4)
                    .map_err(budget_error)?;
                let event: crate::StoredEvent =
                    decode(&row.value, "segment first acceptance declaration")?;
                if event.operation == OPERATION && event.workspace_digest == workspace {
                    let reference =
                        self.segment_publication_ref(snapshot, event.global_commit, budget)?;
                    let stored: crate::StoredIdempotency = self
                        .graph_read(
                            snapshot,
                            &self.keyspaces.idempotency,
                            event.request_digest.as_bytes(),
                            budget,
                        )?
                        .ok_or_else(|| integrity("segment declaration response absent"))?;
                    budget
                        .charge(1, ROW_BYTES as u64 * 4)
                        .map_err(budget_error)?;
                    let publication: DenseSegmentPublication =
                        decode(&stored.response_bytes, "segment declaration")?;
                    self.check_segment_publication(
                        snapshot,
                        workspace,
                        &reference,
                        &publication,
                        budget,
                    )?;
                    if publication.delta.manifest.binding.generation == generation {
                        return Err(integrity(
                            "accepted segment generation was jointly stripped",
                        ));
                    }
                }
            }
            let Some(next) = page.continuation else {
                return Ok(());
            };
            if after
                .as_ref()
                .is_some_and(|previous: &Vec<u8>| next <= *previous)
            {
                return Err(integrity("segment declaration scan made no progress"));
            }
            after = Some(next);
        }
    }
}
