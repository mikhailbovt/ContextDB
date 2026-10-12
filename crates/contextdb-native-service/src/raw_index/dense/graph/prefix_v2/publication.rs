//! Bounded genuine prefix construction, followed by one owner transaction.

use super::verification::{LOCATOR_OPERATION, decode_allowance, request_digest};
use super::*;

impl NativeService {
    /// Publish an immutable finite base from the current accepted dense prefix.
    /// Full raw counters are preserved. This does not enable a serving profile.
    pub fn publish_original_span_prefix_base(
        &self,
        context: &AuthenticatedRequestContext,
        request: &DensePrefixBaseRequestV2,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DensePrefixBaseReceiptV2> {
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
        if request.target.database_id != self.database_id
            || request.target.workspace_id != context.request.workspace_id
        {
            return Err(crate::invalid(
                "prefix request crosses the native owner workspace",
            ));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request_hash = request_digest(&self.database_id, &workspace, request)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, budget, |reader| {
            self.require_custody_rebuilt(reader, &workspace)
        })?;
        if let Some(stored) = self.prefix_read::<crate::StoredIdempotency, _>(
            &snapshot,
            &self.keyspaces.idempotency,
            request_hash.as_bytes(),
            budget,
        )? {
            decode_allowance(&stored.response_bytes, types::MAX_PUBLICATION_BYTES, budget)?;
            let receipt: DensePrefixBaseReceiptV2 =
                decode(&stored.response_bytes, "prefix exact retry")?;
            let reference =
                self.prefix_publication_ref(&snapshot, receipt.global_commit, budget)?;
            self.check_prefix_base_acceptance(&snapshot, &workspace, &reference, &receipt, budget)?;
            if reference.request_digest != request_hash
                || self.accepted_prefix_base(&snapshot, &workspace, request.generation, budget)?
                    != receipt
            {
                return Err(integrity(
                    "prefix exact retry differs from retained acceptance",
                ));
            }
            // An exact retry returns the historical response without any write.
            return Ok(receipt);
        }
        let state: IndexState = self
            .prefix_read(
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
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, request.generation),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if generation.number != request.generation
            || generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != RAW_ANALYZER
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || self.graph_epoch(&snapshot, &workspace, budget)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        self.validate_raw_bm25_generation(&snapshot, &generation, budget)?;
        if generation.bm25.is_none() {
            return Err(stale_index());
        }
        let world = self.current_prefix_bases(&snapshot, &context.request.workspace_id, budget)?;
        if generation.dense_prefix_base.is_some()
            || world
                .prefix_bases
                .as_ref()
                .is_some_and(|roots| roots.contains_key(&generation.number))
        {
            return Err(integrity(
                "prefix generation already has an accepted immutable base",
            ));
        }
        // First activation alone walks native declarations under this parent.
        if self
            .prefix_base_declarations(&snapshot, budget)?
            .contains_key(&(workspace.clone(), generation.number))
        {
            return Err(integrity("accepted prefix base was jointly stripped"));
        }
        if self
            .graph_declarations(&snapshot, budget)?
            .contains_key(&(workspace.clone(), generation.number))
        {
            return Err(integrity(
                "prefix base cannot replace an accepted v1 graph family",
            ));
        }
        budget
            .charge(2, types::KEY_BYTES * 2)
            .map_err(budget_error)?;
        let locator_key = retained_locator_key(&workspace, generation.number)?;
        if crate::budgeted::read_value(
            &snapshot,
            &self.keyspaces.idempotency,
            &locator_key,
            types::ROW_BYTES,
            budget,
        )?
        .is_some()
        {
            return Err(integrity(
                "orphan retained prefix-base locator precedes activation",
            ));
        }
        self.require_no_prefix_base_rows(&snapshot, &workspace, generation.number, budget)?;
        let old_graph_prefix = graph_prefix(&workspace, generation.number);
        let old_rows = crate::budgeted::metadata(&snapshot, budget, |reader| {
            reader
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &old_graph_prefix,
                        start_after: None,
                        max_entries: 1,
                        max_bytes: types::ROW_BYTES + types::KEY_BYTES as usize,
                    },
                )
                .map_err(storage_error)
        })?;
        if !old_rows.entries.is_empty() || old_rows.continuation.is_some() {
            return Err(integrity("orphan v1 graph rows precede prefix activation"));
        }
        let target = self.verify_current_prefix_dense_target(
            &snapshot,
            &workspace,
            &generation,
            &request.target,
            budget,
        )?;
        if target.manifest().spans == 0 || target.manifest().spans > types::MAX_NODES {
            return Err(exhausted(
                "prefix base requires 1..4096 complete source spans",
            ));
        }
        let admitted_global_commit =
            crate::budgeted::metadata(&snapshot, budget, |reader| self.global_head(reader))?;
        let build = self.prefix_build_input(
            &snapshot,
            Some(context),
            &workspace,
            &generation,
            &target,
            budget,
        )?;
        budget.charge(1, 32768).map_err(budget_error)?;
        let mut manifest = DensePrefixBaseManifestV2 {
            revision: 2,
            raw: PrefixRawBindingV2::from_generation(&generation, budget)?,
            admitted_known_at: world.watermarks.journal,
            admitted_global_commit,
            target: target.reference().clone(),
            prefix: target.manifest().clone(),
            interval: build.interval,
            nodes: target.manifest().spans,
            cohorts: Vec::new(),
            builder_revision: contextdb_index::ANN_PARTITION_BUILD_REVISION_V2.into(),
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        let rows = self.construct_prefix_base(
            &workspace,
            &generation,
            &mut manifest,
            &build.inputs,
            budget,
        )?;
        let _guard = self.lock_index_publication(budget)?;
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        crate::budgeted::metadata(&transaction, budget, |reader| {
            self.require_custody_rebuilt(reader, &workspace)
        })?;
        if self.prefix_read::<IndexState, _>(
            &transaction,
            &self.keyspaces.continuous,
            &state_key(&workspace),
            budget,
        )? != Some(state)
            || self
                .prefix_read::<Generation, _>(
                    &transaction,
                    &self.keyspaces.continuous,
                    &generation_key(&workspace, generation.number),
                    budget,
                )?
                .as_ref()
                != Some(&generation)
            || self.graph_epoch(&transaction, &workspace, budget)? != generation.authorization_epoch
            || self.current_prefix_bases(&transaction, &context.request.workspace_id, budget)?
                != world
            || crate::budgeted::metadata(&transaction, budget, |reader| self.global_head(reader))?
                != admitted_global_commit
        {
            return Err(stale_index());
        }
        self.recheck_current_prefix_dense_target(
            &transaction,
            &workspace,
            &generation,
            &request.target,
            budget,
        )?;
        for document in &build.documents {
            self.authorized_capture_policy_with_budget(
                &transaction,
                context,
                document.source.event_id,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                &transaction,
                context,
                document.source.event_id,
                budget,
            )?;
        }
        for input in &build.inputs {
            if self.stored_custody_policies_with_budget(
                &transaction,
                input.vector.source.event_id,
                budget,
            )? != input.policies
            {
                return Err(stale_index());
            }
        }
        let mut frame = crate::budgeted::metadata(&transaction, budget, |reader| {
            self.begin_frame(reader, &context.request.workspace_id, false)
        })?;
        let mut receipt = DensePrefixBaseReceiptV2 {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            manifest,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_prefix_base_receipt(&mut receipt, budget)?;
        let response = encode(&receipt)?;
        if response.len() > types::MAX_PUBLICATION_BYTES {
            return Err(exhausted(
                "prefix response exceeds retained numeric-byte row allowance",
            ));
        }
        budget
            .charge(
                rows.len() as u64 + 16,
                response.len() as u64 * 16 + types::ROW_BYTES as u64 * 4,
            )
            .map_err(budget_error)?;
        let reference = PrefixBaseRefV2 {
            global_commit: frame.global_commit,
            request_digest: request_hash.clone(),
            response_digest: digest_bytes(&response),
            receipt_digest: digest(&response),
            content_digest: receipt.manifest.content_digest,
        };
        reference.validate()?;
        if frame
            .state
            .prefix_bases
            .get_or_insert_with(BTreeMap::new)
            .insert(generation.number, reference.clone())
            .is_some()
        {
            return Err(integrity(
                "prefix publication replaced a certified predecessor",
            ));
        }
        self.enable_capture_extension(&mut transaction, types::FEATURE)?;
        for (key, value) in rows {
            budget
                .charge(1, (key.len() + value.len()) as u64 * 4 + 256)
                .map_err(budget_error)?;
            transaction
                .put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        transaction
            .put(
                &self.keyspaces.continuous,
                receipt_key(&workspace, generation.number)?,
                response,
            )
            .map_err(storage_error)?;
        let mut next = generation;
        next.dense_prefix_base = Some(reference);
        transaction
            .put(
                &self.keyspaces.continuous,
                generation_key(&workspace, next.number),
                encode(&next)?,
            )
            .map_err(storage_error)?;
        self.finish_frame(
            &mut transaction,
            &frame,
            types::OPERATION,
            request_hash.as_bytes(),
            &request_hash,
            &receipt,
        )?;
        // The event hash is available only after the cycle-free root stamp.
        let accepted = self.prefix_publication_ref(&transaction, frame.global_commit, budget)?;
        let mut locator = RetainedPrefixBaseLocatorV2 {
            revision: 2,
            workspace_digest: workspace.clone(),
            generation: next.number,
            publication: accepted,
            token: String::new(),
        };
        self.sign_retained_prefix_base_locator(&workspace, &mut locator, budget)?;
        let bytes = encode(&locator)?;
        let wrapped = crate::StoredIdempotency {
            schema_version: crate::SCHEMA_VERSION,
            operation: LOCATOR_OPERATION.into(),
            request_digest: canonical_digest(&locator)?,
            response_digest: digest_bytes(&bytes),
            response_bytes: bytes,
        };
        transaction
            .put(&self.keyspaces.idempotency, locator_key, encode(&wrapped)?)
            .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }

    pub(super) fn require_no_prefix_base_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, types::KEY_BYTES).map_err(budget_error)?;
        let prefix = prefix_key(workspace, generation)?;
        let page = crate::budgeted::metadata(snapshot, budget, |reader| {
            reader
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: None,
                        max_entries: 1,
                        max_bytes: types::ROW_BYTES + types::KEY_BYTES as usize,
                    },
                )
                .map_err(storage_error)
        })?;
        if !page.entries.is_empty() || page.continuation.is_some() {
            return Err(integrity("orphan prefix-base rows precede activation"));
        }
        Ok(())
    }
}
