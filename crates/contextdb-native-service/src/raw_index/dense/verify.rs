//! Verify owner commitments and exact source plans without neural re-embedding.

use super::*;

impl DenseProjectionReceipt {
    pub(in crate::raw_index) fn manifest(&self) -> ServiceResult<DenseManifest> {
        let manifest = DenseManifest {
            profile: self.profile.clone(),
            profile_digest: self.profile_digest,
            vector_space_id: self.profile.vector_space_id()?,
            through: self.through,
            sources: self.sources,
            embedded_sources: self.embedded_sources,
            spans: self.spans,
            omitted_sources: self.omitted_sources,
            commitment: self.commitment,
        };
        manifest.validate(self.raw_through)?;
        Ok(manifest)
    }
}

impl NativeService {
    /// First activation alone checks retained declarations. Normal resume uses
    /// its authenticated point-bound receipt, not a repeated journal walk.
    pub(super) fn admit_first_dense_projection<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let prefix = format!("{}dense/", generation_prefix(workspace, generation)).into_bytes();
        let cap = usize::try_from(
            (budget.remaining_bytes().saturating_sub(256) / 4).min(MAX_DENSE_ROW_BYTES as u64),
        )
        .map_err(|_| exhausted("dense activation allowance overflow"))?;
        if cap <= prefix.len() + 128 {
            return Err(exhausted("dense activation allowance exhausted"));
        }
        budget
            .charge(2, cap as u64 * 4 + 256)
            .map_err(budget_error)?;
        if !snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: None,
                    max_entries: 1,
                    max_bytes: cap,
                },
            )
            .map_err(storage_error)?
            .entries
            .is_empty()
        {
            return Err(integrity("orphan dense rows precede generation activation"));
        }
        let mut after: Option<Vec<u8>> = None;
        let mut declared = false;
        loop {
            let cap =
                usize::try_from((budget.remaining_bytes().saturating_sub(256) / 4).min(256 * 1024))
                    .map_err(|_| exhausted("dense declaration allowance overflow"))?;
            if cap < 1024 {
                return Err(exhausted("dense declaration allowance exhausted"));
            }
            budget
                .charge(33, cap as u64 * 4 + 256)
                .map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.events,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 32,
                        max_bytes: cap,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                let event: crate::StoredEvent = decode(&row.value, "dense activation declaration")?;
                if event.operation != OPERATION {
                    continue;
                }
                declared = true;
                if row.key != event.global_commit.to_be_bytes() {
                    return Err(integrity("dense declaration journal key differs"));
                }
                let stored: crate::StoredIdempotency = self
                    .dense_read_from(
                        snapshot,
                        &self.keyspaces.idempotency,
                        event.request_digest.as_bytes(),
                        MAX_DENSE_ROW_BYTES,
                        budget,
                    )?
                    .ok_or_else(|| integrity("dense activation lost its retained receipt"))?;
                let receipt: DenseProjectionReceipt =
                    decode(&stored.response_bytes, "dense activation receipt")?;
                if stored.schema_version != crate::SCHEMA_VERSION
                    || stored.operation != OPERATION
                    || stored.request_digest != event.request_digest
                    || stored.response_digest != event.response_digest
                    || stored.response_digest != digest_bytes(&stored.response_bytes)
                {
                    return Err(integrity("dense activation receipt binding differs"));
                }
                self.check_dense_publication(&event, &receipt)?;
                if event.workspace_digest == workspace && receipt.generation == generation {
                    return Err(integrity(
                        "dense activation cannot replace a stripped accepted generation",
                    ));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|previous| &next <= previous) {
                return Err(integrity("dense declaration scan made no progress"));
            }
            after = Some(next);
        }
        if declared {
            self.require_dense_feature(snapshot, budget)?;
        }
        Ok(())
    }
    pub(in crate::raw_index) fn has_dense_source_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        event: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let document: Option<DenseDocument> = self.dense_read(
            snapshot,
            &document_key(workspace, generation, event),
            budget,
        )?;
        if document.is_some() {
            return Ok(true);
        }
        budget.charge(1, 0).map_err(budget_error)?;
        let prefix = format!(
            "{}dense/vector/{event}/",
            generation_prefix(workspace, generation)
        )
        .into_bytes();
        let cap = usize::try_from(
            (budget.remaining_bytes().saturating_sub(256) / 4).min(MAX_DENSE_ROW_BYTES as u64),
        )
        .map_err(|_| exhausted("dense pruning allowance overflow"))?;
        if cap <= prefix.len() + 128 {
            return Err(exhausted("dense pruning allowance exhausted"));
        }
        budget
            .charge(1, cap as u64 * 4 + 256)
            .map_err(budget_error)?;
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: None,
                    max_entries: 1,
                    max_bytes: cap,
                },
            )
            .map_err(storage_error)?;
        Ok(!page.entries.is_empty())
    }
    /// Shared topology may outlive source-owned member rows during paged GC.
    /// Refuse pruning while any graph row remains, even if its profile was lost.
    pub(in crate::raw_index) fn has_dense_graph_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let prefix = graph::graph_prefix(workspace, generation);
        let graph_present = crate::budgeted::metadata(snapshot, budget, |reader| {
            reader
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: None,
                        max_entries: 1,
                        max_bytes: 128 * 1024,
                    },
                )
                .map(|page| !page.entries.is_empty())
                .map_err(storage_error)
        })?;
        if graph_present {
            return Ok(true);
        }
        // Shared prefix topology also outlives member rows during paged GC.
        // Check rows even if a malformed generation has lost its declaration.
        budget
            .charge(1, graph::prefix_v2::types::KEY_BYTES)
            .map_err(budget_error)?;
        let prefix = graph::prefix_v2::types::prefix_key(workspace, generation)?;
        let prefix_present = crate::budgeted::metadata(snapshot, budget, |reader| {
            reader
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: None,
                        max_entries: 1,
                        max_bytes: 128 * 1024,
                    },
                )
                .map(|page| !page.entries.is_empty() || page.continuation.is_some())
                .map_err(storage_error)
        })?;
        if prefix_present {
            return Ok(true);
        }
        budget
            .charge(2, graph::prefix_segments_v2::types::KEY_BYTES * 2)
            .map_err(budget_error)?;
        let family = format!(
            "{}dense/prefix-segment-v2/",
            generation_prefix(workspace, generation)
        )
        .into_bytes();
        let head = graph::prefix_segments_v2::types::directory_head_key(workspace, generation)?;
        for prefix in [family, head] {
            let present = crate::budgeted::metadata(snapshot, budget, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.continuous,
                        ScanPageRequest {
                            prefix: &prefix,
                            start_after: None,
                            max_entries: 1,
                            max_bytes: graph::prefix_segments_v2::types::ROW_BYTES + 1024,
                        },
                    )
                    .map(|page| !page.entries.is_empty() || page.continuation.is_some())
                    .map_err(storage_error)
            })?;
            if present {
                return Ok(true);
            }
        }
        budget
            .charge(2, graph::routing::types::KEY_BYTES * 2)
            .map_err(budget_error)?;
        let family = format!(
            "{}dense/directory-router-v1/",
            generation_prefix(workspace, generation)
        )
        .into_bytes();
        let head = graph::routing::types::head_key(workspace, generation)?;
        for prefix in [family, head] {
            let present = crate::budgeted::metadata(snapshot, budget, |reader| {
                reader
                    .scan_prefix_page(
                        &self.keyspaces.continuous,
                        ScanPageRequest {
                            prefix: &prefix,
                            start_after: None,
                            max_entries: 1,
                            max_bytes: graph::routing::types::ROW_BYTES
                                + graph::routing::types::KEY_BYTES as usize,
                        },
                    )
                    .map(|page| !page.entries.is_empty() || page.continuation.is_some())
                    .map_err(storage_error)
            })?;
            if present {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(in crate::raw_index) fn verify_dense_receipt_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        bytes: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if bytes.len() > MAX_DENSE_ROW_BYTES {
            return Err(integrity("observed dense receipt exceeds its bound"));
        }
        budget
            .charge(1, bytes.len() as u64 * 2)
            .map_err(budget_error)?;
        let receipt: DenseProjectionReceipt = decode(bytes, "observed dense receipt")?;
        self.check_dense_receipt(&receipt)?;
        if receipt.generation != generation.number
            || receipt.authorization_epoch != generation.authorization_epoch
            || receipt.raw_through > generation.through
            || generation.dense.as_ref() != Some(&receipt.manifest()?)
        {
            return Err(integrity("observed dense receipt differs from generation"));
        }
        self.require_dense_feature(snapshot, budget)
    }
    pub(in crate::raw_index) fn require_dense_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest = self.dense_format_manifest(snapshot, budget)?;
        if !manifest.features.contains(FEATURE) {
            return Err(integrity("dense format feature absent"));
        }
        Ok(())
    }
    pub(super) fn require_dense_base_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest = self.dense_format_manifest(snapshot, budget)?;
        if !manifest.features.contains(bm25::FEATURE)
            || !manifest.features.contains(crate::capture::RECOVERY_FEATURE)
            || !manifest.features.contains(crate::custody::CUSTODY_FEATURE)
        {
            return Err(integrity(
                "dense base capture, custody or BM25 feature absent",
            ));
        }
        Ok(())
    }
    fn dense_format_manifest<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<crate::Manifest> {
        let manifest: crate::Manifest = self
            .dense_read_from(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                256 * 1024,
                budget,
            )?
            .ok_or_else(|| integrity("dense native format manifest absent"))?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        Ok(manifest)
    }

    pub(in crate::raw_index) fn validate_dense_generation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let receipt: Option<DenseProjectionReceipt> =
            self.dense_read(snapshot, &receipt_key(workspace, generation.number), budget)?;
        match (&generation.dense, receipt) {
            (None, None) => Ok(()),
            (Some(dense), Some(receipt)) => {
                self.require_dense_feature(snapshot, budget)?;
                dense.validate(generation.through)?;
                self.check_dense_receipt(&receipt)?;
                if receipt.generation != generation.number
                    || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
                    || receipt.authorization_epoch != generation.authorization_epoch
                    || receipt.raw_through > generation.through
                    || receipt.raw_sources > generation.projected_sources
                    || (receipt.raw_through == generation.through
                        && receipt.raw_sources != generation.projected_sources)
                    || receipt.manifest()? != *dense
                {
                    return Err(integrity(
                        "dense generation differs from authenticated receipt",
                    ));
                }
                let event: crate::StoredEvent = self
                    .dense_read_from(
                        snapshot,
                        &self.keyspaces.events,
                        &receipt.global_commit.to_be_bytes(),
                        MAX_DENSE_ROW_BYTES,
                        budget,
                    )?
                    .ok_or_else(|| integrity("dense receipt publication absent"))?;
                self.check_dense_publication(&event, &receipt)?;
                Ok(())
            }
            _ => Err(integrity("dense generation or latest receipt was stripped")),
        }
    }

    pub(in crate::raw_index) fn check_dense_publication(
        &self,
        event: &crate::StoredEvent,
        receipt: &DenseProjectionReceipt,
    ) -> ServiceResult<()> {
        self.check_dense_receipt(receipt)?;
        receipt.manifest()?;
        if event.schema_version != crate::SCHEMA_VERSION
            || event.operation != OPERATION
            || event.global_commit != receipt.global_commit
            || event.workspace_digest != digest_bytes(receipt.workspace_id.as_bytes())
            || receipt.raw_through >= event.workspace_commit
            || event.event_digest != crate::event_digest(event)?
            || event.request_digest != canonical_digest(receipt)?
            || event.response_digest != digest_bytes(&encode(receipt)?)
        {
            return Err(integrity("dense accepted publication binding differs"));
        }
        Ok(())
    }

    pub(in crate::raw_index) fn accepted_dense_generations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<(String, u64), DenseProjectionReceipt>> {
        let mut latest = BTreeMap::<(String, u64), DenseProjectionReceipt>::new();
        let mut budget = crate::retention::audit_budget();
        let mut previous_global = 0;
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: crate::StoredEvent = decode(&row.value, "dense retained declaration")?;
            if event.operation != OPERATION {
                continue;
            }
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
            if row.key != event.global_commit.to_be_bytes()
                || event.global_commit <= previous_global
            {
                return Err(integrity("dense publication order differs"));
            }
            previous_global = event.global_commit;
            let bytes = snapshot
                .get(&self.keyspaces.idempotency, event.request_digest.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("dense accepted receipt absent"))?;
            if bytes.len() > MAX_DENSE_ROW_BYTES {
                return Err(integrity("dense accepted receipt exceeds its bound"));
            }
            budget
                .charge(1, bytes.len() as u64 * 2)
                .map_err(budget_error)?;
            let stored: crate::StoredIdempotency = decode(&bytes, "dense retained receipt")?;
            let receipt: DenseProjectionReceipt =
                decode(&stored.response_bytes, "dense retained progress")?;
            if stored.schema_version != crate::SCHEMA_VERSION
                || stored.operation != OPERATION
                || stored.request_digest != event.request_digest
                || stored.response_digest != event.response_digest
                || stored.response_digest != digest_bytes(&stored.response_bytes)
            {
                return Err(integrity("dense idempotency binding differs"));
            }
            self.check_dense_publication(&event, &receipt)?;
            let identity = (event.workspace_digest, receipt.generation);
            if latest.get(&identity).is_some_and(|previous| {
                receipt.profile != previous.profile
                    || receipt.authorization_epoch != previous.authorization_epoch
                    || receipt.through < previous.through
                    || receipt.raw_through < previous.raw_through
                    || receipt.raw_sources < previous.raw_sources
                    || receipt.sources < previous.sources
                    || receipt.embedded_sources < previous.embedded_sources
                    || receipt.spans < previous.spans
                    || receipt.omitted_sources < previous.omitted_sources
            }) {
                return Err(integrity(
                    "dense accepted profile or prefix moved backwards",
                ));
            }
            latest.insert(identity, receipt);
        }
        if !latest.is_empty() {
            self.require_dense_feature(snapshot, &mut budget)?;
        }
        Ok(latest)
    }

    pub(in crate::raw_index) fn validate_dense_declaration(
        &self,
        workspace: &str,
        generation: &Generation,
        declaration: Option<&DenseProjectionReceipt>,
    ) -> ServiceResult<()> {
        match (&generation.dense, declaration) {
            (None, None) => Ok(()),
            (Some(dense), Some(receipt))
                if receipt.authorization_epoch == generation.authorization_epoch
                    && receipt.generation == generation.number
                    && digest_bytes(receipt.workspace_id.as_bytes()) == workspace
                    && receipt.raw_sources <= generation.projected_sources
                    && (receipt.raw_through != generation.through
                        || receipt.raw_sources == generation.projected_sources)
                    && receipt.raw_through <= generation.through
                    && receipt.manifest()? == *dense =>
            {
                Ok(())
            }
            _ => Err(integrity(
                "dense manifest differs from retained accepted declaration",
            )),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "accepted source, frozen generation and parent budget stay explicit"
    )]
    pub(in crate::raw_index) fn reconstruct_dense_source<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        original: &EventEnvelope,
        commit: u64,
        event_digest: ContentDigest,
        domain: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ReconstructedDenseSource> {
        let dense = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("dense row has no generation profile"))?;
        dense.validate(generation.through)?;
        let document: DenseDocument = self
            .dense_read(
                snapshot,
                &document_key(workspace, generation.number, original.event_id),
                budget,
            )?
            .ok_or_else(|| integrity("dense source document absent"))?;
        let (omission, plan, bytes) =
            self.dense_plan(snapshot, original, &dense.profile, None, budget)?;
        if document.source != RawSource::from(original)
            || document.event_digest != event_digest
            || document.commit != commit
            || document.commit > dense.through
            || document.policy_domain != domain
            || document.profile_digest != dense.profile_digest
            || document.omission != omission
            || document.spans.len() != plan.len()
            || document.spans.len() > MAX_SOURCE_SPANS
        {
            return Err(integrity("dense document differs from exact original plan"));
        }
        budget
            .charge(1, MAX_DENSE_ROW_BYTES as u64 * 3)
            .map_err(budget_error)?;
        self.check_dense_document_token(&document)?;
        let mut rows = BTreeMap::new();
        for (ordinal, span) in plan.iter().enumerate() {
            let vector: DenseVector = self
                .dense_read(
                    snapshot,
                    &vector_key(
                        workspace,
                        generation.number,
                        original.event_id,
                        ordinal as u32,
                    ),
                    budget,
                )?
                .ok_or_else(|| integrity("dense exact vector absent"))?;
            if document.spans[ordinal].span != *span
                || vector.source != document.source
                || vector.event_digest != event_digest
                || vector.commit != commit
                || vector.policy_domain != domain
                || vector.ordinal != ordinal as u32
                || vector.span != *span
                || vector.profile_digest != dense.profile_digest
                || vector.vector_digest != document.spans[ordinal].vector_digest
            {
                return Err(integrity("dense vector identity or source plan differs"));
            }
            self.validate_dense_vector(
                &dense.profile,
                &vector,
                &bytes[span.start as usize..span.end as usize],
                budget,
            )?;
            rows.insert(
                vector_key(
                    workspace,
                    generation.number,
                    original.event_id,
                    ordinal as u32,
                ),
                encode(&vector)?,
            );
        }
        rows.insert(
            document_key(workspace, generation.number, original.event_id),
            encode(&document)?,
        );
        Ok((document, rows))
    }

    fn validate_dense_vector(
        &self,
        profile: &TextEmbeddingProfile,
        vector: &DenseVector,
        text: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if vector.values_bits.len() != profile.dimensions as usize
            || vector.tokens_digest.as_bytes() == &[0; 32]
        {
            return Err(integrity(
                "dense vector dimensions or exact token observation differs",
            ));
        }
        budget
            .charge(1, vector.values_bits.len() as u64 * 32 + 4096)
            .map_err(budget_error)?;
        self.check_dense_vector_token(vector)?;
        let embedded = EmbeddedText {
            profile_digest: vector.profile_digest,
            kind: EmbeddingTextKind::Source,
            text_digest: vector.span.span_digest,
            input_digest: vector.input_digest,
            tokens_digest: vector.tokens_digest,
            token_count: vector.token_count,
            values: vector
                .values_bits
                .iter()
                .map(|bits| f32::from_bits(*bits))
                .collect(),
            vector_digest: vector.vector_digest,
        };
        embedded.validate(
            profile,
            EmbeddingTextKind::Source,
            std::str::from_utf8(text).map_err(|_| integrity("dense original span is not UTF-8"))?,
            budget,
        )
    }

    /// Reclaimed pages may already have deleted the document or other vectors.
    /// Each remaining vector independently binds its source and exact encoder
    /// observation with an owner tag; no missing row is invented for inventory.
    #[allow(
        clippy::too_many_arguments,
        reason = "copy address, immutable source and shared budget are independent bindings"
    )]
    pub(in crate::raw_index) fn verify_dense_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        key: &[u8],
        value: &[u8],
        original: &EventEnvelope,
        commit: u64,
        event_digest: ContentDigest,
        domain: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let dense = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("dense copy profile absent"))?;
        self.require_dense_feature(snapshot, budget)?;
        dense.validate(generation.through)?;
        if value.len() > MAX_DENSE_ROW_BYTES || commit > dense.through {
            return Err(integrity("dense copy exceeds its admitted prefix or size"));
        }
        let workspace = digest_bytes(original.workspace_id.to_string().as_bytes());
        let (omission, plan, bytes) =
            self.dense_plan(snapshot, original, &dense.profile, None, budget)?;
        if key == document_key(&workspace, generation.number, original.event_id) {
            let document: DenseDocument = decode(value, "dense observed document")?;
            if document.source != RawSource::from(original)
                || document.event_digest != event_digest
                || document.commit != commit
                || document.policy_domain != domain
                || document.profile_digest != dense.profile_digest
                || document.omission != omission
                || document.spans.len() != plan.len()
                || document
                    .spans
                    .iter()
                    .zip(plan)
                    .any(|(entry, span)| entry.span != span)
            {
                return Err(integrity("dense observed document source differs"));
            }
            budget
                .charge(1, value.len() as u64 * 2)
                .map_err(budget_error)?;
            self.check_dense_document_token(&document)
        } else {
            let vector: DenseVector = decode(value, "dense observed vector")?;
            let ordinal = vector.ordinal as usize;
            if vector.source != RawSource::from(original)
                || vector.event_digest != event_digest
                || vector.commit != commit
                || vector.policy_domain != domain
                || vector.profile_digest != dense.profile_digest
                || plan.get(ordinal) != Some(&vector.span)
                || key
                    != vector_key(
                        &workspace,
                        generation.number,
                        original.event_id,
                        vector.ordinal,
                    )
            {
                return Err(integrity("dense observed vector source or range differs"));
            }
            self.validate_dense_vector(
                &dense.profile,
                &vector,
                &bytes[vector.span.start as usize..vector.span.end as usize],
                budget,
            )
        }
    }
}
