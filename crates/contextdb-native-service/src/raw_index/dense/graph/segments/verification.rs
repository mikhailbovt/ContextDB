//! Retained owner acceptance; immutable rows never rely on mutable siblings.
use super::types::*;
use super::types::{FEATURE, OPERATION, ROW_BYTES};
use super::*;

pub(crate) const LOCATOR_OPERATION: &str = "raw_span_ann_segment_locator";

/// Only this module can mint the ending anchor consumed by prefix replay.
pub(in crate::raw_index::dense::graph) struct VerifiedSegmentHead {
    publication: DenseSegmentPublication,
}
impl VerifiedSegmentHead {
    pub(in crate::raw_index::dense::graph) fn covered(&self) -> &DenseManifest {
        &self.publication.directory.head.covered
    }
    pub(super) fn publication(&self) -> &DenseSegmentPublication {
        &self.publication
    }
}

pub(super) fn seal_request_digest(
    database: &str,
    workspace: &str,
    request: &SealRequest,
) -> ServiceResult<String> {
    canonical_digest(&(OPERATION, database, workspace, request))
}

// Format bounds constrain the read; they are not allocation fees. Reserve the
// actual borrowed value before later clones, canonical buffers and owner tags.
fn value_allowance<T: Serialize>(
    value: &T,
    cap: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let bytes = crypto::metered_json_len(value, budget, cap)?;
    budget
        .charge(1, bytes as u64 * 16 + 4096)
        .map_err(budget_error)
}

fn decode_allowance(bytes: &[u8], cap: usize, budget: &mut QueryBudget) -> ServiceResult<()> {
    if bytes.len() > cap {
        return Err(integrity("retained segment response exceeds its bound"));
    }
    budget
        .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 16 + 4096)
        .map_err(budget_error)
}

impl NativeService {
    fn segment_accepted_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        operation: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(crate::StoredEvent, crate::StoredIdempotency)> {
        reference.validate()?;
        let event: crate::StoredEvent = self
            .graph_read(
                snapshot,
                &self.keyspaces.events,
                &reference.global_commit.to_be_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("segment accepted journal event absent"))?;
        let stored: crate::StoredIdempotency = self
            .graph_read(
                snapshot,
                &self.keyspaces.idempotency,
                reference.request_digest.as_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("segment accepted response absent"))?;
        value_allowance(&(&event, &stored), 2 * ROW_BYTES, budget)?;
        if event.schema_version != crate::SCHEMA_VERSION
            || event.operation != operation
            || event.workspace_digest != workspace
            || event.global_commit != reference.global_commit
            || event.event_digest != reference.event_digest
            || event.event_digest != crate::event_digest(&event)?
            || event.request_digest != reference.request_digest
            || event.response_digest != reference.response_digest
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != operation
            || stored.request_digest != reference.request_digest
            || stored.response_digest != reference.response_digest
            || stored.response_digest != digest_bytes(&stored.response_bytes)
        {
            return Err(integrity("segment accepted publication point join differs"));
        }
        Ok((event, stored))
    }

    pub(super) fn segment_publication_ref<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global_commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AcceptedPublicationRef> {
        let event: crate::StoredEvent = self
            .graph_read(
                snapshot,
                &self.keyspaces.events,
                &global_commit.to_be_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("segment referenced journal event absent"))?;
        value_allowance(&event, ROW_BYTES, budget)?;
        if event.global_commit != global_commit
            || event.event_digest != crate::event_digest(&event)?
        {
            return Err(integrity("segment referenced journal identity differs"));
        }
        Ok(AcceptedPublicationRef {
            global_commit,
            event_digest: event.event_digest,
            request_digest: event.request_digest,
            response_digest: event.response_digest,
        })
    }

    pub(super) fn segment_base_ref<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &DenseGraphReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BaseRef> {
        value_allowance(receipt, ROW_BYTES, budget)?;
        Ok(BaseRef {
            publication: self.segment_publication_ref(snapshot, receipt.global_commit, budget)?,
            receipt_digest: digest(&encode(receipt)?),
            graph_digest: receipt.manifest.content_digest,
        })
    }

    fn segment_target_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseProjectionReceipt> {
        let (event, stored) =
            self.segment_accepted_rows(snapshot, workspace, reference, dense::OPERATION, budget)?;
        decode_allowance(&stored.response_bytes, ROW_BYTES, budget)?;
        let receipt: DenseProjectionReceipt =
            decode(&stored.response_bytes, "segment target receipt")?;
        self.check_dense_receipt(&receipt)?;
        if receipt.global_commit != reference.global_commit
            || receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || receipt.raw_through >= event.workspace_commit
            || canonical_digest(&receipt)? != reference.request_digest
            || encode(&receipt)? != stored.response_bytes
        {
            return Err(integrity("segment target dense acceptance differs"));
        }
        Ok(receipt)
    }

    pub(super) fn check_segment_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        reference: &AcceptedPublicationRef,
        publication: &DenseSegmentPublication,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        value_allowance(publication, MAX_PUBLICATION_BYTES, budget)?;
        publication.validate()?;
        self.check_delta_receipt(&publication.delta, budget)?;
        self.check_segment_directory_receipt(&publication.directory, budget)?;
        let (event, stored) =
            self.segment_accepted_rows(snapshot, workspace, reference, OPERATION, budget)?;
        let delta = &publication.delta.manifest;
        let (base_event, base_stored) = self.segment_accepted_rows(
            snapshot,
            workspace,
            &delta.base.publication,
            super::super::OPERATION,
            budget,
        )?;
        decode_allowance(&base_stored.response_bytes, ROW_BYTES, budget)?;
        let base: DenseGraphReceipt = decode(&base_stored.response_bytes, "segment retained base")?;
        self.check_graph_publication(&base_event, &base)?;
        if digest(&base_stored.response_bytes) != delta.base.receipt_digest
            || base.manifest.content_digest != delta.base.graph_digest
            || base.manifest.generation != delta.binding.generation
            || base.manifest.authorization_epoch != delta.binding.authorization_epoch
            || base.manifest.dense.spans == 0
            || base.manifest.dense.profile != delta.before.profile
            || base.manifest.dense.vector_space_id != delta.before.vector_space_id
            || (delta.ordinal == 1 && delta.before != base.manifest.dense)
        {
            return Err(integrity("segment immutable base acceptance differs"));
        }
        let frozen = self.graph_base(&base.manifest)?;
        if frozen.custody_version != delta.binding.custody_version
            || frozen.analyzer != delta.binding.analyzer
            || frozen.bm25.as_ref() != Some(&delta.binding.bm25)
            || frozen.removal_through != delta.binding.removal_through
        {
            return Err(integrity("segment immutable generation envelope differs"));
        }
        let target =
            self.segment_target_receipt(snapshot, workspace, &delta.target_dense, budget)?;
        value_allowance(&publication.directory.head.previous, ROW_BYTES, budget)?;
        let request = SealRequest {
            generation: delta.binding.generation,
            previous: publication.directory.head.previous.clone(),
            target,
        };
        value_allowance(
            &(OPERATION, &self.database_id, workspace, &request),
            2 * ROW_BYTES,
            budget,
        )?;
        request.validate()?;
        let t = &request.target;
        if publication.delta.database_id != self.database_id
            || digest_bytes(publication.delta.workspace_id.as_bytes()) != workspace
            || reference.global_commit != publication.delta.global_commit
            || event.workspace_commit <= delta.after.through
            || t.authorization_epoch != delta.binding.authorization_epoch
            || t.raw_through != delta.binding.raw_through
            || t.raw_sources != delta.binding.raw_sources
            || t.profile != delta.after.profile
            || t.profile_digest != delta.after.profile_digest
            || t.through != delta.after.through
            || t.sources != delta.after.sources
            || t.embedded_sources != delta.after.embedded_sources
            || t.spans != delta.after.spans
            || t.omitted_sources != delta.after.omitted_sources
            || t.commitment != delta.after.commitment
            || seal_request_digest(&self.database_id, workspace, &request)?
                != reference.request_digest
            || encode(publication)? != stored.response_bytes
        {
            return Err(integrity(
                "segment request target or combined acceptance differs",
            ));
        }
        self.require_segment_feature(snapshot, budget)
    }

    /// Exact retained ordinal lookup; remains valid after generation-row GC.
    pub(crate) fn accepted_segment_for_ordinal<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        ordinal: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseSegmentPublication> {
        budget.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = retained_locator_key(workspace, generation, ordinal)?;
        let wrapped: crate::StoredIdempotency = self
            .graph_read(snapshot, &self.keyspaces.idempotency, &key, budget)?
            .ok_or_else(|| integrity("retained segment ordinal locator absent"))?;
        decode_allowance(&wrapped.response_bytes, ROW_BYTES, budget)?;
        let locator: RetainedSegmentLocator =
            decode(&wrapped.response_bytes, "retained segment locator")?;
        self.check_retained_segment_locator(workspace, &locator, budget)?;
        if locator.workspace_digest != workspace
            || locator.generation != generation
            || locator.ordinal != ordinal
            || wrapped.schema_version != crate::SCHEMA_VERSION
            || wrapped.operation != LOCATOR_OPERATION
            || wrapped.request_digest != canonical_digest(&locator)?
            || wrapped.response_digest != digest_bytes(&wrapped.response_bytes)
            || wrapped.response_bytes != encode(&locator)?
        {
            return Err(integrity("retained segment locator envelope differs"));
        }
        let (_, stored) = self.segment_accepted_rows(
            snapshot,
            workspace,
            &locator.publication,
            OPERATION,
            budget,
        )?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, budget)?;
        let publication: DenseSegmentPublication =
            decode(&stored.response_bytes, "retained segment publication")?;
        self.check_segment_publication(
            snapshot,
            workspace,
            &locator.publication,
            &publication,
            budget,
        )?;
        if publication.delta.manifest.binding.generation != generation
            || publication.delta.manifest.ordinal != ordinal
        {
            return Err(integrity("retained segment ordinal acceptance differs"));
        }
        Ok(publication)
    }

    pub(super) fn accepted_current_segment_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedSegmentHead> {
        let state = self.current_segment_heads(snapshot, workspace_id, budget)?;
        let reference = generation
            .dense_segments
            .as_ref()
            .ok_or_else(|| integrity("current segment generation pointer absent"))?;
        if state
            .segment_heads
            .as_ref()
            .and_then(|heads| heads.get(&generation.number))
            != Some(reference)
        {
            return Err(integrity(
                "current segment pointer differs from accepted workspace head",
            ));
        }
        let workspace = &state.workspace_digest;
        let publication = self.accepted_segment_for_ordinal(
            snapshot,
            workspace,
            generation.number,
            reference.count,
            budget,
        )?;
        let live: DenseSegmentDirectoryReceipt = self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &directory_head_key(workspace, generation.number)?,
                budget,
            )?
            .ok_or_else(|| integrity("current segment live directory receipt absent"))?;
        value_allowance(&live, ROW_BYTES, budget)?;
        let accepted =
            self.segment_publication_ref(snapshot, publication.delta.global_commit, budget)?;
        if live != publication.directory
            || reference.global_commit != accepted.global_commit
            || reference.request_digest != accepted.request_digest
            || reference.response_digest != accepted.response_digest
            || reference.content_digest != live.head.content_digest
            || generation.number != live.head.generation
            || generation.dense_graph.as_ref().map(|g| g.content_digest)
                != Some(live.head.base.graph_digest)
            || generation.authorization_epoch
                != publication.delta.manifest.binding.authorization_epoch
            || generation.removal_through != publication.delta.manifest.binding.removal_through
        {
            return Err(integrity("current segment directory acceptance differs"));
        }
        Ok(VerifiedSegmentHead { publication })
    }

    /// Historical reconstruction may consume an authenticated immutable ending
    /// head, but this proof never grants current serving authority.
    pub(super) fn accepted_retained_segment_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        ordinal: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedSegmentHead> {
        Ok(VerifiedSegmentHead {
            publication: self
                .accepted_segment_for_ordinal(snapshot, workspace, generation, ordinal, budget)?,
        })
    }

    pub(in crate::raw_index) fn accepted_dense_segment_generations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<(String, u64), DenseSegmentPublication>> {
        let mut declarations = BTreeMap::<(String, u64), DenseSegmentPublication>::new();
        let mut after = None;
        loop {
            let page = crate::budgeted::metadata(snapshot, budget, |r| {
                r.scan_prefix_page(
                    &self.keyspaces.events,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 32,
                        max_bytes: crate::MAX_JSON_BYTES + 4096,
                    },
                )
                .map_err(storage_error)
            })?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64 * 4 + 4096)
                    .map_err(budget_error)?;
                let event: crate::StoredEvent =
                    decode(&row.value, "retained segment declaration event")?;
                if event.operation != OPERATION {
                    continue;
                }
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
                decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, budget)?;
                let decoded: DenseSegmentPublication =
                    decode(&stored.response_bytes, "segment declaration response")?;
                let publication = self.accepted_segment_for_ordinal(
                    snapshot,
                    &event.workspace_digest,
                    decoded.delta.manifest.binding.generation,
                    decoded.delta.manifest.ordinal,
                    budget,
                )?;
                if publication != decoded
                    || publication.delta.global_commit != reference.global_commit
                {
                    return Err(integrity(
                        "segment ordinal declaration differs from accepted event",
                    ));
                }
                let key = (
                    event.workspace_digest,
                    publication.delta.manifest.binding.generation,
                );
                match declarations.get(&key) {
                    None if publication.delta.manifest.ordinal == 1
                        && publication.directory.head.previous.is_none() => {}
                    Some(previous) => {
                        let p = &previous.delta.manifest;
                        let next = &publication.delta.manifest;
                        let previous_reference = self.segment_publication_ref(
                            snapshot,
                            previous.delta.global_commit,
                            budget,
                        )?;
                        let expected = DirectoryRef {
                            count: p.ordinal,
                            global_commit: previous_reference.global_commit,
                            request_digest: previous_reference.request_digest,
                            response_digest: previous_reference.response_digest,
                            content_digest: previous.directory.head.content_digest,
                        };
                        if p.ordinal.checked_add(1) != Some(next.ordinal)
                            || publication.directory.head.previous.as_ref() != Some(&expected)
                            || next.before != previous.directory.head.covered
                            || next.base != p.base
                            || next.binding.generation != p.binding.generation
                            || next.binding.custody_version != p.binding.custody_version
                            || next.binding.analyzer != p.binding.analyzer
                            || next.binding.bm25 != p.binding.bm25
                            || next.binding.authorization_epoch != p.binding.authorization_epoch
                            || next.binding.removal_through != p.binding.removal_through
                            || next.binding.raw_through < p.binding.raw_through
                            || next.binding.raw_sources < p.binding.raw_sources
                        {
                            return Err(integrity(
                                "accepted segment append history is not contiguous",
                            ));
                        }
                    }
                    _ => {
                        return Err(integrity(
                            "accepted segment history starts after its first ordinal",
                        ));
                    }
                }
                // Values move into the map. Only a possible cascading BTree
                // split needs new storage; bound its height before insertion.
                let levels =
                    u64::from(usize::BITS - declarations.len().saturating_add(1).leading_zeros())
                        + 2;
                let node_bytes =
                    12 * size_of::<((String, u64), DenseSegmentPublication)>() as u64 + 256;
                budget
                    .charge(levels * 12, levels * node_bytes)
                    .map_err(budget_error)?;
                declarations.insert(key, publication);
            }
            let Some(next) = page.continuation else { break };
            if after
                .as_ref()
                .is_some_and(|previous: &Vec<u8>| next <= *previous)
            {
                return Err(integrity("segment declaration page made no progress"));
            }
            after = Some(next);
        }
        Ok(declarations)
    }

    pub(in crate::raw_index) fn validate_dense_segment_declaration<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        declaration: Option<&DenseSegmentPublication>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        match (&generation.dense_segments, declaration) {
            (None, None) => Ok(()),
            (Some(reference), Some(publication)) => {
                let accepted = self.segment_publication_ref(
                    snapshot,
                    publication.delta.global_commit,
                    budget,
                )?;
                let state =
                    self.current_segment_heads(snapshot, &publication.delta.workspace_id, budget)?;
                let m = &publication.delta.manifest;
                if state.workspace_digest != workspace
                    || state
                        .segment_heads
                        .as_ref()
                        .and_then(|heads| heads.get(&generation.number))
                        != Some(reference)
                    || reference.count != m.ordinal
                    || reference.global_commit != accepted.global_commit
                    || reference.request_digest != accepted.request_digest
                    || reference.response_digest != accepted.response_digest
                    || reference.content_digest != publication.directory.head.content_digest
                    || m.binding.generation != generation.number
                    || m.binding.custody_version != generation.custody_version
                    || m.binding.analyzer != generation.analyzer
                    || Some(&m.binding.bm25) != generation.bm25.as_ref()
                    || m.binding.authorization_epoch != generation.authorization_epoch
                    || m.binding.removal_through != generation.removal_through
                    || m.binding.raw_through > generation.through
                    || m.binding.raw_sources > generation.projected_sources
                    || generation
                        .dense_graph
                        .as_ref()
                        .map(|base| base.content_digest)
                        != Some(m.base.graph_digest)
                    || generation.dense.as_ref().is_none_or(|dense| {
                        dense.profile != m.after.profile
                            || dense.profile_digest != m.after.profile_digest
                            || dense.vector_space_id != m.after.vector_space_id
                            || dense.through < m.after.through
                            || dense.sources < m.after.sources
                            || dense.spans < m.after.spans
                    })
                {
                    return Err(integrity(
                        "retained segment generation differs from accepted directory",
                    ));
                }
                Ok(())
            }
            _ => Err(integrity(
                "segment generation pointer differs from retained accepted declaration",
            )),
        }
    }

    pub(super) fn require_segment_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest: crate::Manifest = self
            .graph_read(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                budget,
            )?
            .ok_or_else(|| integrity("segment format manifest absent"))?;
        value_allowance(&manifest, ROW_BYTES, budget)?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(FEATURE) {
            return Err(integrity("retained segment format declaration absent"));
        }
        Ok(())
    }
}
