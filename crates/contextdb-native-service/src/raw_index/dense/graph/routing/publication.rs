//! Complete operator construction followed by one current native owner Sync.

use super::super::prefix_v2::verification::decode_allowance;
use super::verification::directory_router_request_digest;
use super::*;

impl NativeService {
    /// Resolve the current complete fine-directory target and router predecessor.
    /// This metadata grants neither serving nor permission to read source content.
    pub fn original_span_directory_router_target(
        &self,
        context: &AuthenticatedRequestContext,
        generation_number: u64,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterPublishRequestV1> {
        self.admit_directory_router_operator(context, parent)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, parent, |reader| {
            self.require_custody_ready(reader, &workspace)
        })?;
        let generation: Generation = self
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, generation_number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let base = self.accepted_prefix_base(&snapshot, &workspace, generation_number, parent)?;
        let coverage = DirectoryRouterCoverageV1 {
            base: self.prefix_segment_base_reference(&snapshot, &workspace, &base, parent)?,
            directory: generation.dense_prefix_segments.clone(),
        };
        let proof = self.verify_current_router_directory(
            &snapshot,
            context,
            generation_number,
            &coverage,
            parent,
        )?;
        if generation.dense_directory_router.is_some() {
            self.accepted_current_directory_router(
                &snapshot,
                &context.request.workspace_id,
                proof.generation(),
                parent,
            )?;
        } else {
            self.require_no_directory_router_predecessor(
                &snapshot,
                &context.request.workspace_id,
                proof.generation(),
                parent,
            )?;
        }
        parent.charge(1, 8192).map_err(budget_error)?;
        let result = DirectoryRouterPublishRequestV1 {
            generation: generation_number,
            previous: generation.dense_directory_router,
            coverage,
        };
        result.validate()?;
        Ok(result)
    }

    /// Publish a complete finite coarse router without changing reader behavior.
    /// Centroids are derived from genuine admitted fine vectors by the native owner.
    pub fn publish_original_span_directory_router(
        &self,
        context: &AuthenticatedRequestContext,
        request: &DirectoryRouterPublishRequestV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterReceiptV1> {
        self.admit_directory_router_operator(context, parent)?;
        request.validate()?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request_hash =
            directory_router_request_digest(&self.database_id, &workspace, request, parent)?;
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
            let receipt: DirectoryRouterReceiptV1 = decode(
                &stored.response_bytes,
                "directory router exact historical retry",
            )?;
            let reference =
                self.prefix_publication_ref(&snapshot, receipt.global_commit, parent)?;
            self.check_directory_router_acceptance(
                &snapshot, &workspace, &reference, &receipt, parent,
            )?;
            if reference.request_digest != request_hash
                || self.accepted_directory_router(
                    &snapshot,
                    &workspace,
                    request.generation,
                    receipt.manifest.serial,
                    parent,
                )? != receipt
            {
                return Err(integrity(
                    "directory router retry differs from retained acceptance",
                ));
            }
            return Ok(receipt);
        }
        let proof = self.verify_current_router_directory(
            &snapshot,
            context,
            request.generation,
            &request.coverage,
            parent,
        )?;
        let generation = proof.generation();
        if generation.dense_directory_router != request.previous {
            return Err(stale_index());
        }
        if let Some(previous) = &request.previous {
            let accepted = self.accepted_current_directory_router(
                &snapshot,
                &context.request.workspace_id,
                generation,
                parent,
            )?;
            if self.directory_router_reference(&snapshot, &accepted, parent)? != *previous {
                return Err(integrity(
                    "directory router predecessor differs from accepted root",
                ));
            }
            if accepted.manifest.coverage == request.coverage {
                return Err(stale_index());
            }
        } else {
            self.require_no_directory_router_predecessor(
                &snapshot,
                &context.request.workspace_id,
                generation,
                parent,
            )?;
        }
        let serial = request
            .previous
            .as_ref()
            .map_or(Some(1), |previous| previous.serial.checked_add(1))
            .ok_or_else(|| exhausted("directory router revision exhausted"))?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let locator_key = retained_locator_key(&workspace, generation.number, serial)?;
        if crate::budgeted::read_value(
            &snapshot,
            &self.keyspaces.idempotency,
            &locator_key,
            ROW_BYTES,
            parent,
        )?
        .is_some()
        {
            return Err(integrity(
                "next directory router has retained native acceptance",
            ));
        }
        let state: IndexState = self
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                parent,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(generation.number) {
            return Err(stale_index());
        }
        let world = proof
            .world()
            .ok_or_else(|| integrity("current router proof lost owner state"))?;
        let admitted_global_commit =
            crate::budgeted::metadata(&snapshot, parent, |reader| self.global_head(reader))?;
        let build = self.router_build_input(&snapshot, Some(context), &proof, parent)?;
        parent.charge(1, 65536).map_err(budget_error)?;
        let mut manifest = DirectoryRouterManifestV1 {
            revision: 1,
            serial,
            previous: request.previous.clone(),
            raw: PrefixRawBindingV2::from_generation(generation, parent)?,
            admitted_known_at: world.watermarks.journal,
            admitted_global_commit,
            coverage: request.coverage.clone(),
            covered: proof.covered().clone(),
            covered_dense: proof.covered_dense().clone(),
            ending: proof.ending().clone(),
            coverage_count: build.coverage_count,
            coverage_digest: build.coverage_digest,
            recipe: DirectoryRouterRecipeV1::fixed(),
            source_profile_digest: proof.covered().profile_digest,
            source_space_id: proof.covered().vector_space_id,
            coarse_space_digest: ContentDigest::from_bytes([0; 32]),
            coarse_space_id: proof.covered().vector_space_id,
            representatives: build.inputs.len() as u64,
            cohorts: Vec::new(),
            builder_revision: contextdb_index::ANN_PARTITION_BUILD_REVISION_V2.into(),
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        let rows = self.construct_directory_router(
            &workspace,
            generation,
            &mut manifest,
            &build.inputs,
            parent,
        )?;
        parent
            .charge(build.inputs.len() as u64 + 1, 65536)
            .map_err(budget_error)?;
        let mut policies = BTreeMap::new();
        for input in &build.inputs {
            parent.charge(1, 2048).map_err(budget_error)?;
            if let Some(previous) = policies.insert(input.policy_domain.as_str(), &input.policies)
                && previous != &input.policies
            {
                return Err(integrity(
                    "directory router current policy conjunction collision",
                ));
            }
        }
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
                != Some(generation)
            || &self.current_directory_router_heads(
                &transaction,
                &context.request.workspace_id,
                parent,
            )? != world
            || self.graph_epoch(&transaction, &workspace, parent)? != generation.authorization_epoch
            || crate::budgeted::metadata(&transaction, parent, |reader| self.global_head(reader))?
                != admitted_global_commit
        {
            return Err(stale_index());
        }
        let current = self.verify_current_router_directory(
            &transaction,
            context,
            generation.number,
            &request.coverage,
            parent,
        )?;
        if current.generation() != generation || current.world() != Some(world) {
            return Err(stale_index());
        }
        for source in &build.source_checks {
            parent.check().map_err(budget_error)?;
            self.authorized_capture_policy_with_budget(
                &transaction,
                context,
                source.event_id,
                parent,
            )?;
            self.authorize_derived_custody_with_budget(
                &transaction,
                context,
                source.event_id,
                parent,
            )?;
            let expected = policies
                .get(source.policy_domain.as_str())
                .ok_or_else(|| integrity("directory router contributor lost its full policy"))?;
            if self.stored_custody_policies_with_budget(&transaction, source.event_id, parent)?
                != **expected
            {
                return Err(stale_index());
            }
        }
        let mut frame = crate::budgeted::metadata(&transaction, parent, |reader| {
            self.begin_frame(reader, &context.request.workspace_id, false)
        })?;
        let mut receipt = DirectoryRouterReceiptV1 {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            manifest,
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.sign_directory_router_receipt(&mut receipt, parent)?;
        let response = segments::crypto::metered_encode(&receipt, parent, MAX_PUBLICATION_BYTES)?;
        parent
            .charge(
                rows.len() as u64 + 16,
                response.len() as u64 * 16 + ROW_BYTES as u64 * 4,
            )
            .map_err(budget_error)?;
        let reference = DirectoryRouterRefV1 {
            serial,
            global_commit: frame.global_commit,
            request_digest: request_hash.clone(),
            response_digest: digest_bytes(&response),
            receipt_digest: digest(&response),
            content_digest: receipt.manifest.content_digest,
        };
        reference.validate()?;
        if frame
            .state
            .directory_routers
            .get_or_insert_with(BTreeMap::new)
            .insert(generation.number, reference.clone())
            != request.previous
        {
            return Err(integrity(
                "directory router acceptance replaced a different predecessor",
            ));
        }
        self.enable_capture_extension(&mut transaction, FEATURE)?;
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
                receipt_key(&workspace, generation.number, serial)?,
                response.clone(),
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.continuous,
                head_key(&workspace, generation.number)?,
                response,
            )
            .map_err(storage_error)?;
        let generation_bytes = segments::crypto::metered_json_len(generation, parent, ROW_BYTES)?;
        parent
            .charge(1, generation_bytes as u64 * 16 + 8192)
            .map_err(budget_error)?;
        let mut next = generation.clone();
        next.dense_directory_router = Some(reference);
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
            OPERATION,
            request_hash.as_bytes(),
            &request_hash,
            &receipt,
        )?;
        let mut locator = RetainedDirectoryRouterLocatorV1 {
            revision: 1,
            workspace_digest: workspace.clone(),
            generation: next.number,
            serial,
            publication: self.prefix_publication_ref(&transaction, frame.global_commit, parent)?,
            token: String::new(),
        };
        self.sign_retained_directory_router_locator(&workspace, &mut locator, parent)?;
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
                segments::crypto::metered_encode(&wrapped, parent, ROW_BYTES)?,
            )
            .map_err(storage_error)?;
        parent.check().map_err(budget_error)?;
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }

    fn admit_directory_router_operator(
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

    fn require_no_directory_router_predecessor<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let world = self.current_directory_router_heads(snapshot, workspace_id, parent)?;
        if generation.dense_directory_router.is_some()
            || world
                .directory_routers
                .as_ref()
                .is_some_and(|roots| roots.contains_key(&generation.number))
            || self
                .directory_router_declarations(snapshot, parent)?
                .keys()
                .any(|(owner, number, _)| owner == &workspace && *number == generation.number)
        {
            return Err(integrity(
                "accepted directory router predecessor was stripped",
            ));
        }
        parent.charge(1, KEY_BYTES * 2).map_err(budget_error)?;
        let prefix = format!(
            "{}dense/directory-router-v1/",
            generation_prefix(&workspace, generation.number)
        )
        .into_bytes();
        for prefix in [prefix, head_key(&workspace, generation.number)?] {
            let page = crate::budgeted::metadata(snapshot, parent, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.continuous,
                        ScanPageRequest {
                            prefix: &prefix,
                            start_after: None,
                            max_entries: 1,
                            max_bytes: ROW_BYTES + KEY_BYTES as usize,
                        },
                    )
                    .map_err(storage_error)
            })?;
            if !page.entries.is_empty() || page.continuation.is_some() {
                return Err(integrity(
                    "orphan directory router rows precede native acceptance",
                ));
            }
        }
        Ok(())
    }
}
