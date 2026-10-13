//! Complete bounded interval construction followed by one native owner Sync.

use super::super::prefix_v2::verification::decode_allowance;
use super::verification::seal_request_digest;
use super::*;

impl NativeService {
    /// Resolve the current accepted prefix directory as an operator CAS target.
    /// A returned reference is metadata and confers no serving permission.
    pub fn original_span_prefix_segment_head(
        &self,
        context: &AuthenticatedRequestContext,
        generation_number: u64,
        parent: &mut QueryBudget,
    ) -> ServiceResult<Option<PrefixSegmentDirectoryRefV2>> {
        self.admit_prefix_segment_operator(context, parent)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, parent, |reader| {
            self.require_custody_ready(reader, &workspace)
        })?;
        let state: IndexState = self
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                parent,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(generation_number) {
            return Err(stale_index());
        }
        let generation: Generation = self
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, generation_number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        self.current_prefix_segment_base(&snapshot, context, &workspace, &generation, parent)?;
        self.validate_dense_generation(&snapshot, &workspace, &generation, parent)?;
        if let Some(reference) = &generation.dense_prefix_segments {
            self.accepted_current_prefix_segment(
                &snapshot,
                &context.request.workspace_id,
                &generation,
                parent,
            )?;
            parent.charge(1, 4096).map_err(budget_error)?;
            return Ok(Some(reference.clone()));
        }
        self.require_no_prefix_segment_predecessor(
            &snapshot,
            &context.request.workspace_id,
            &generation,
            parent,
        )?;
        Ok(None)
    }

    /// Seal one complete genuine dense interval without rebuilding its prefix base.
    /// The operator must maintain the source projection separately.
    pub fn seal_original_span_prefix_segment(
        &self,
        context: &AuthenticatedRequestContext,
        request: &PrefixSegmentSealRequestV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentPublicationV2> {
        self.admit_prefix_segment_operator(context, parent)?;
        request.validate()?;
        if request.target.database_id != self.database_id
            || request.target.workspace_id != context.request.workspace_id
        {
            return Err(crate::invalid(
                "prefix interval request crosses its native workspace",
            ));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request_hash = seal_request_digest(&self.database_id, &workspace, request)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, parent, |reader| {
            self.require_custody_rebuilt(reader, &workspace)
        })?;
        if let Some(stored) = self.prefix_read::<crate::StoredIdempotency, _>(
            &snapshot,
            &self.keyspaces.idempotency,
            request_hash.as_bytes(),
            parent,
        )? {
            decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
            let publication: PrefixSegmentPublicationV2 =
                decode(&stored.response_bytes, "prefix interval exact retry")?;
            let reference =
                self.prefix_publication_ref(&snapshot, publication.delta.global_commit, parent)?;
            self.check_prefix_segment_publication(
                &snapshot,
                &workspace,
                &reference,
                &publication,
                parent,
            )?;
            if reference.request_digest != request_hash
                || self.accepted_prefix_segment_for_ordinal(
                    &snapshot,
                    &workspace,
                    request.generation,
                    publication.delta.manifest.ordinal,
                    parent,
                )? != publication
            {
                return Err(integrity(
                    "prefix interval exact retry differs from retained ordinal",
                ));
            }
            // A historical exact response never reinstalls its former current head.
            return Ok(publication);
        }
        let state: IndexState = self
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                parent,
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
                parent,
            )?
            .ok_or_else(stale_index)?;
        let base =
            self.current_prefix_segment_base(&snapshot, context, &workspace, &generation, parent)?;
        let base_ref = self.prefix_segment_base_reference(&snapshot, &workspace, &base, parent)?;
        if generation.dense_prefix_segments != request.previous {
            return Err(stale_index());
        }
        let world =
            self.current_prefix_segment_heads(&snapshot, &context.request.workspace_id, parent)?;
        let previous = if request.previous.is_some() {
            Some(self.accepted_current_prefix_segment(
                &snapshot,
                &context.request.workspace_id,
                &generation,
                parent,
            )?)
        } else {
            self.require_no_prefix_segment_predecessor(
                &snapshot,
                &context.request.workspace_id,
                &generation,
                parent,
            )?;
            None
        };
        let ordinal = request
            .previous
            .as_ref()
            .map_or(Some(1), |head| head.count.checked_add(1))
            .ok_or_else(|| exhausted("prefix interval ordinal exhausted"))?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let locator_key = retained_locator_key(&workspace, generation.number, ordinal)?;
        if crate::budgeted::read_value(
            &snapshot,
            &self.keyspaces.idempotency,
            &locator_key,
            types::ROW_BYTES,
            parent,
        )?
        .is_some()
        {
            return Err(integrity(
                "next prefix interval already has retained acceptance",
            ));
        }
        let target_ref = self.recheck_current_prefix_dense_target(
            &snapshot,
            &workspace,
            &generation,
            &request.target,
            parent,
        )?;
        let after =
            self.verify_prefix_segment_dense_state(&snapshot, &workspace, &target_ref, parent)?;
        let before_ref = previous
            .as_ref()
            .map_or(&base.manifest.target, |p| &p.directory.head.covered_dense);
        let before =
            self.verify_prefix_segment_dense_state(&snapshot, &workspace, before_ref, parent)?;
        let expected_before = previous
            .as_ref()
            .map_or(&base.manifest.prefix, |p| &p.directory.head.covered);
        if before.manifest() != expected_before
            || before.manifest().profile != after.manifest().profile
        {
            return Err(integrity(
                "prefix interval before state differs from its accepted predecessor",
            ));
        }
        let start = if let Some(previous) = &previous {
            self.verify_prefix_segment_capture_boundary(
                &snapshot,
                &workspace,
                &previous.directory.head.ending,
                parent,
            )?
        } else {
            let complete = self.verify_accepted_prefix_dense_target(
                &snapshot,
                &workspace,
                &base.manifest.target,
                parent,
            )?;
            self.first_prefix_segment_capture_boundary(&snapshot, &workspace, &complete, parent)?
        };
        let interval = self
            .verify_prefix_segment_interval(&snapshot, &workspace, before, after, start, parent)?;
        let nodes = interval
            .after()
            .manifest()
            .spans
            .checked_sub(interval.before().manifest().spans)
            .filter(|count| *count <= types::MAX_NODES)
            .ok_or_else(|| exhausted("prefix interval exceeds256 whole source vectors"))?;
        let build = self.prefix_segment_build_input(
            &snapshot,
            Some(context),
            &workspace,
            &generation,
            &base_ref,
            &interval,
            parent,
        )?;
        if build.inputs.len() as u64 != nodes {
            return Err(integrity("prefix interval complete vector census differs"));
        }
        let admitted_global_commit =
            crate::budgeted::metadata(&snapshot, parent, |reader| self.global_head(reader))?;
        parent.charge(1, 65536).map_err(budget_error)?;
        let mut manifest = PrefixDeltaManifestV2 {
            revision: 2,
            raw: PrefixRawBindingV2::from_generation(&generation, parent)?,
            admitted_known_at: world.watermarks.journal,
            admitted_global_commit,
            ordinal,
            base: base_ref,
            before: interval.before().manifest().clone(),
            after: interval.after().manifest().clone(),
            before_dense: interval.before().reference().clone(),
            target_dense: interval.after().reference().clone(),
            start: interval.start().reference().clone(),
            end: interval.end().reference().clone(),
            interval: build.interval,
            nodes,
            cohorts: Vec::new(),
            builder_revision: contextdb_index::ANN_PARTITION_BUILD_REVISION_V2.into(),
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        let rows = self.construct_prefix_segment(
            &workspace,
            &generation,
            &mut manifest,
            &build.inputs,
            parent,
        )?;
        let _guard = self.lock_index_publication(parent)?;
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        crate::budgeted::metadata(&transaction, parent, |reader| {
            self.require_custody_rebuilt(reader, &workspace)
        })?;
        if self.prefix_read::<IndexState, _>(
            &transaction,
            &self.keyspaces.continuous,
            &state_key(&workspace),
            parent,
        )? != Some(state)
            || self
                .prefix_read::<Generation, _>(
                    &transaction,
                    &self.keyspaces.continuous,
                    &generation_key(&workspace, generation.number),
                    parent,
                )?
                .as_ref()
                != Some(&generation)
            || self.graph_epoch(&transaction, &workspace, parent)? != generation.authorization_epoch
            || self.current_prefix_segment_heads(
                &transaction,
                &context.request.workspace_id,
                parent,
            )? != world
            || crate::budgeted::metadata(&transaction, parent, |reader| self.global_head(reader))?
                != admitted_global_commit
        {
            return Err(stale_index());
        }
        self.current_prefix_segment_base(&transaction, context, &workspace, &generation, parent)?;
        self.recheck_current_prefix_dense_target(
            &transaction,
            &workspace,
            &generation,
            &request.target,
            parent,
        )?;
        for document in &build.documents {
            self.authorized_capture_policy_with_budget(
                &transaction,
                context,
                document.source.event_id,
                parent,
            )?;
            self.authorize_derived_custody_with_budget(
                &transaction,
                context,
                document.source.event_id,
                parent,
            )?;
        }
        for input in &build.inputs {
            if self.stored_custody_policies_with_budget(
                &transaction,
                input.vector.source.event_id,
                parent,
            )? != input.policies
            {
                return Err(stale_index());
            }
        }
        let mut frame = crate::budgeted::metadata(&transaction, parent, |reader| {
            self.begin_frame(reader, &context.request.workspace_id, false)
        })?;
        let mut delta = PrefixDeltaReceiptV2 {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            manifest,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_prefix_delta_receipt(&mut delta, parent)?;
        let delta_bytes = segments::crypto::metered_encode(&delta, parent, MAX_PUBLICATION_BYTES)?;
        parent.charge(1, 65536).map_err(budget_error)?;
        let mut head = PrefixSegmentDirectoryHeadV2 {
            revision: 2,
            generation: generation.number,
            base: delta.manifest.base.clone(),
            count: ordinal,
            latest: PrefixSegmentRefV2 {
                ordinal,
                global_commit: frame.global_commit,
                manifest_digest: delta.manifest.content_digest,
                receipt_digest: digest(&delta_bytes),
            },
            covered: delta.manifest.after.clone(),
            covered_dense: delta.manifest.target_dense.clone(),
            ending: delta.manifest.end.clone(),
            previous: request.previous.clone(),
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        head.content_digest = self.prefix_segment_directory_digest(&workspace, &head, parent)?;
        let mut directory = PrefixSegmentDirectoryReceiptV2 {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            head,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_prefix_segment_directory_receipt(&mut directory, parent)?;
        let publication = PrefixSegmentPublicationV2 { delta, directory };
        publication.validate()?;
        let response =
            segments::crypto::metered_encode(&publication, parent, MAX_PUBLICATION_BYTES)?;
        parent
            .charge(
                rows.len() as u64 + 16,
                response.len() as u64 * 16 + types::ROW_BYTES as u64 * 4,
            )
            .map_err(budget_error)?;
        let reference = PrefixSegmentDirectoryRefV2 {
            count: ordinal,
            global_commit: frame.global_commit,
            request_digest: request_hash.clone(),
            response_digest: digest_bytes(&response),
            content_digest: publication.directory.head.content_digest,
        };
        if frame
            .state
            .prefix_segment_heads
            .get_or_insert_with(BTreeMap::new)
            .insert(generation.number, reference.clone())
            != request.previous
        {
            return Err(integrity(
                "prefix interval append differs from certified predecessor",
            ));
        }
        self.enable_capture_extension(&mut transaction, types::FEATURE)?;
        for (key, value) in rows {
            parent
                .charge(1, (key.len() + value.len()) as u64 * 4 + 256)
                .map_err(budget_error)?;
            transaction
                .put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        transaction
            .put(
                &self.keyspaces.continuous,
                delta_receipt_key(&workspace, generation.number, ordinal)?,
                delta_bytes,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.continuous,
                directory_head_key(&workspace, generation.number)?,
                segments::crypto::metered_encode(&publication.directory, parent, types::ROW_BYTES)?,
            )
            .map_err(storage_error)?;
        let mut next = generation;
        next.dense_prefix_segments = Some(reference);
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
            &publication,
        )?;
        let mut locator = RetainedPrefixSegmentLocatorV2 {
            revision: 2,
            workspace_digest: workspace,
            generation: next.number,
            ordinal,
            publication: self.prefix_publication_ref(&transaction, frame.global_commit, parent)?,
            token: String::new(),
        };
        self.sign_retained_prefix_segment_locator(
            &locator.workspace_digest.clone(),
            &mut locator,
            parent,
        )?;
        let bytes = segments::crypto::metered_encode(&locator, parent, MAX_PUBLICATION_BYTES)?;
        let wrapped = crate::StoredIdempotency {
            schema_version: crate::SCHEMA_VERSION,
            operation: LOCATOR_OPERATION.into(),
            request_digest: canonical_digest(&locator)?,
            response_digest: digest_bytes(&bytes),
            response_bytes: bytes,
        };
        transaction
            .put(
                &self.keyspaces.idempotency,
                locator_key,
                segments::crypto::metered_encode(&wrapped, parent, types::ROW_BYTES)?,
            )
            .map_err(storage_error)?;
        parent.check().map_err(budget_error)?;
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(publication)
    }

    fn admit_prefix_segment_operator(
        &self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, parent)?;
        for capability in [
            Capability::Admin,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, parent)?;
        }
        parent.charge(1, 32768).map_err(budget_error)
    }

    pub(in crate::raw_index::dense::graph) fn current_prefix_segment_base<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<prefix_v2::types::DensePrefixBaseReceiptV2> {
        if generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != RAW_ANALYZER
            || generation.bm25.is_none()
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || generation.dense_prefix_base.is_none()
            || self.graph_epoch(snapshot, workspace, parent)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        self.validate_raw_bm25_generation(snapshot, generation, parent)?;
        let base = self.accepted_prefix_base(snapshot, workspace, generation.number, parent)?;
        self.check_prefix_generation_binding(snapshot, workspace, generation, &base, parent)?;
        let world =
            self.current_prefix_segment_heads(snapshot, &context.request.workspace_id, parent)?;
        if world
            .prefix_bases
            .as_ref()
            .and_then(|roots| roots.get(&generation.number))
            != generation.dense_prefix_base.as_ref()
        {
            return Err(integrity(
                "prefix segment base differs from certified current root",
            ));
        }
        Ok(base)
    }

    pub(in crate::raw_index::dense::graph) fn require_no_prefix_segment_predecessor<
        S: ReadSnapshot,
    >(
        &self,
        snapshot: &S,
        workspace_id: &str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let world = self.current_prefix_segment_heads(snapshot, workspace_id, parent)?;
        if generation.dense_prefix_segments.is_some()
            || world
                .prefix_segment_heads
                .as_ref()
                .is_some_and(|roots| roots.contains_key(&generation.number))
            || self
                .prefix_segment_declarations(snapshot, parent)?
                .keys()
                .any(|(owner, number, _)| owner == &workspace && *number == generation.number)
        {
            return Err(integrity(
                "accepted prefix interval predecessor was stripped",
            ));
        }
        parent.charge(1, KEY_BYTES * 2).map_err(budget_error)?;
        let family_prefix = format!(
            "{}dense/prefix-segment-v2/",
            generation_prefix(&workspace, generation.number)
        )
        .into_bytes();
        for prefix in [
            family_prefix,
            directory_head_key(&workspace, generation.number)?,
        ] {
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.continuous,
                        ScanPageRequest {
                            prefix: &prefix,
                            start_after: None,
                            max_entries: 1,
                            max_bytes: types::ROW_BYTES + KEY_BYTES as usize,
                        },
                    )
                    .map_err(storage_error)
            })?;
            if !page.entries.is_empty() || page.continuation.is_some() {
                return Err(integrity("orphan prefix interval rows precede activation"));
            }
        }
        Ok(())
    }
}
