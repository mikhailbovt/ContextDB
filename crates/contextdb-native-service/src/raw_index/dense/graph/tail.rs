//! Complete accepted dense-prefix extension, then bounded exact tail scoring.
//! There is no source-body loader, corpus census, builder, encoder or writer.
use super::*;
use contextdb_index::AnnPartitionQueryCompletionV2;
use contextdb_service::{CaptureDurability, CaptureReceipt, NATIVE_CAPTURE_DOMAIN};

const MAX_TAIL_WORK: usize = 128;
const MAX_TAIL_VECTORS: usize = 256;
struct Witness {
    documents: Vec<DenseDocument>,
    complete: bool,
}

impl NativeService {
    /// Query the immutable owner ANN base plus a proved finite extension of its
    /// dense prefix. Work limits return only base observations; dense lag and
    /// projected-source omissions remain explicit, never invented vectors.
    pub fn search_original_spans_with_tail(
        &self,
        context: &AuthenticatedRequestContext,
        query_text: &str,
        query: &EmbeddedText,
        limits: DenseGraphTailQueryLimits,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseGraphTailQueryResult> {
        for c in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            require_capability(context, c)?;
        }
        query::validate_limits(limits.graph)?;
        if !(1..=MAX_TAIL_WORK).contains(&limits.max_tail_work)
            || !(1..=MAX_TAIL_VECTORS).contains(&limits.max_tail_vectors)
        {
            return Err(crate::invalid(
                "native graph tail caps require 1..128 work and 1..256 vectors",
            ));
        }
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
        let number = state.active.ok_or_else(stale_index)?;
        let generation: Generation = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        let receipt = self.accepted_graph_receipt(&snapshot, &workspace, &generation, budget)?;
        self.admit_tail_generation(&generation, &receipt.manifest, budget)?;
        self.tail_dense_receipt(&snapshot, &workspace, &generation, budget)?;
        let raw_lag = self.graph_tail_fence(context, &workspace, &generation, &receipt, budget)?;
        let latest = generation.dense.as_ref().ok_or_else(stale_index)?;
        query.validate(
            &latest.profile,
            EmbeddingTextKind::Query,
            query_text,
            budget,
        )?;
        let witness = self.dense_tail_witness(
            &snapshot,
            &workspace,
            &generation,
            &receipt,
            limits.max_tail_work,
            budget,
        )?;
        let discovery = self.search_graph_base(
            &snapshot,
            context,
            &workspace,
            &generation,
            &receipt,
            query,
            limits.graph,
            true,
            budget,
        )?;
        let mut base = discovery.result;
        let mut admitted_sources = discovery.admitted_sources;
        let dense_lag = latest.through < generation.through;
        let mut completion = if witness.complete {
            DenseGraphTailCompletion::Complete
        } else {
            DenseGraphTailCompletion::TailWorkLimit
        };
        let mut tail_vector_reads = 0_u64;
        let mut scoring_complete = witness.complete;
        let mut permitted_tail_omissions = false;
        budget
            .charge(1, (limits.max_tail_vectors * 512) as u64)
            .map_err(budget_error)?;
        let mut identities = BTreeMap::<RepresentationId, ContentDigest>::new();
        let mut spans = BTreeSet::new();
        if witness.complete {
            for doc in witness.documents {
                budget.check().map_err(budget_error)?;
                let policies = self.stored_custody_policies_with_budget(
                    &snapshot,
                    doc.source.event_id,
                    budget,
                )?;
                if canonical_digest(&policies)? != doc.policy_domain {
                    return Err(integrity(
                        "tail document differs from complete custody policy",
                    ));
                }
                if policies
                    .iter()
                    .any(|p| !crate::policy_allows(&context.request, p))
                {
                    continue;
                }
                // Current source permission and derived processing admission
                // precede every vector; forbidden domains produce no IDs/counts.
                self.tail_source_fence(
                    context,
                    &workspace,
                    &generation,
                    &receipt,
                    doc.source.event_id,
                    &policies,
                    budget,
                )?;
                budget
                    .charge(
                        1,
                        2048 + doc
                            .source
                            .source_version
                            .as_ref()
                            .map_or(0, |s| s.len() as u64 * 8),
                    )
                    .map_err(budget_error)?;
                if admitted_sources
                    .insert(doc.source.event_id, doc.source.clone())
                    .is_some()
                {
                    return Err(integrity("tail source overlaps admitted immutable base"));
                }
                permitted_tail_omissions |= matches!(
                    doc.omission,
                    Some(
                        DenseOmission::Unavailable
                            | DenseOmission::NonText
                            | DenseOmission::TooLarge
                    )
                ) || doc.source.upstream_truncated
                    || doc.source.coverage != contextdb_core::EventCoverage::CompleteObservation;
                // Even after scoring stops, admit the bounded permitted source
                // frontier so later preparation cannot discard its controls.
                if !scoring_complete {
                    continue;
                }
                for (ordinal, span) in doc.spans.iter().enumerate() {
                    if tail_vector_reads >= limits.max_tail_vectors as u64 {
                        completion = DenseGraphTailCompletion::TailVectorLimit;
                        scoring_complete = false;
                        break;
                    }
                    if base.vector_reads >= limits.graph.max_vector_reads as u64 {
                        completion = DenseGraphTailCompletion::VectorLimit;
                        scoring_complete = false;
                        break;
                    }
                    if base.discovered >= limits.graph.max_discovered as u64 {
                        completion = DenseGraphTailCompletion::DiscoveryLimit;
                        scoring_complete = false;
                        break;
                    }
                    self.tail_source_fence(
                        context,
                        &workspace,
                        &generation,
                        &receipt,
                        doc.source.event_id,
                        &policies,
                        budget,
                    )?;
                    let v: DenseVector = self
                        .graph_read(
                            &snapshot,
                            &self.keyspaces.continuous,
                            &vector_key(&workspace, number, doc.source.event_id, ordinal as u32),
                            budget,
                        )?
                        .ok_or_else(|| integrity("tail exact vector absent"))?;
                    self.check_dense_vector_token(&v)?;
                    if v.source != doc.source
                        || v.event_digest != doc.event_digest
                        || v.commit != doc.commit
                        || v.ordinal != ordinal as u32
                        || v.span != span.span
                        || v.profile_digest != latest.profile_digest
                        || v.policy_domain != doc.policy_domain
                        || v.vector_digest != span.vector_digest
                    {
                        return Err(integrity(
                            "tail vector identity differs from complete tagged document",
                        ));
                    }
                    budget
                        .charge(
                            1,
                            8192 + v
                                .source
                                .source_version
                                .as_ref()
                                .map_or(0, |s| s.len() as u64 * 8),
                        )
                        .map_err(budget_error)?;
                    let (full, id) = identity(&self.database_id, &workspace, number, &v)?;
                    if identities.insert(id, full).is_some() {
                        return Err(integrity(
                            "tail representation identity repeats or collides",
                        ));
                    }
                    // The immutable graph cutoff makes sources disjoint. A
                    // colliding compact ID is still refused by exact point lookup.
                    if self
                        .graph_read::<GraphMember, _>(
                            &snapshot,
                            &self.keyspaces.continuous,
                            &member_key(&workspace, number, id),
                            budget,
                        )?
                        .is_some()
                    {
                        return Err(integrity(
                            "tail representation collides with immutable graph base",
                        ));
                    }
                    let source_span = (
                        v.source.event_id,
                        v.span.payload_digest,
                        v.span.start,
                        v.span.end,
                        v.span.span_digest,
                    );
                    if !spans.insert(source_span) {
                        return Err(integrity("tail repeats an exact source span version"));
                    }
                    budget
                        .charge(
                            1,
                            2048 + v
                                .source
                                .source_version
                                .as_ref()
                                .map_or(0, |s| s.len() as u64 * 6),
                        )
                        .map_err(budget_error)?;
                    let source = v.source.clone();
                    let exact_span = v.span.clone();
                    let values = query::query_vector_values(&latest.profile, v, budget)?;
                    let score = tail_cosine(&query.values, &values, budget)?;
                    base.vector_reads += 1;
                    base.discovered += 1;
                    tail_vector_reads += 1;
                    base.hits.push(DenseGraphHit {
                        representation_id: id,
                        source,
                        span: exact_span,
                        score,
                    });
                }
            }
        }
        if completion == DenseGraphTailCompletion::Complete {
            if raw_lag {
                completion = DenseGraphTailCompletion::RawLag;
            } else if dense_lag {
                completion = DenseGraphTailCompletion::DenseLag;
            } else if base.completion != AnnPartitionQueryCompletionV2::Complete {
                completion = DenseGraphTailCompletion::BaseLimit;
            }
        }
        budget
            .charge(base.hits.len() as u64 * 16 + 1, 0)
            .map_err(budget_error)?;
        base.hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.representation_id.cmp(&b.representation_id))
        });
        base.hits.truncate(limits.graph.limit);
        if self.graph_tail_fence(context, &workspace, &generation, &receipt, budget)? != raw_lag {
            return Err(stale_index());
        }
        let proved = if witness.complete {
            latest
        } else {
            &receipt.manifest.dense
        };
        Ok(DenseGraphTailQueryResult {
            hits: base.hits,
            completion,
            base_completion: base.completion,
            tail_witness_complete: witness.complete,
            tail_scoring_complete: scoring_complete,
            dense_lag,
            raw_lag,
            permitted_tail_omissions,
            graph_digest: receipt.manifest.content_digest,
            observed_dense_commitment: latest.commitment,
            proven_dense_commitment: proved.commitment,
            base_through: receipt.manifest.dense.through,
            observed_dense_through: latest.through,
            proven_through: proved.through,
            raw_through: generation.through,
            node_reads: base.node_reads,
            vector_reads: base.vector_reads,
            discovered: base.discovered,
            tail_vector_reads,
            admitted_sources,
        })
    }

    fn admit_tail_generation(
        &self,
        generation: &Generation,
        graph: &DenseGraphManifest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.graph_tag_allowance(graph, 8192, budget)?;
        let frozen = self.graph_base(graph)?;
        let current = generation.dense.as_ref().ok_or_else(stale_index)?;
        current.validate(generation.through)?;
        if generation.number != frozen.number
            || generation.authorization_epoch != frozen.authorization_epoch
            || generation.removal_through != frozen.removal_through
            || generation.custody_version != frozen.custody_version
            || generation.analyzer != frozen.analyzer
            || generation.bm25 != frozen.bm25
            || generation.dense_graph.as_ref() != Some(graph)
            || generation.through < frozen.through
            || generation.projected_sources < frozen.projected_sources
            || current.profile != graph.dense.profile
            || current.profile_digest != graph.dense.profile_digest
            || current.vector_space_id != graph.dense.vector_space_id
            || current.through < graph.dense.through
            || current.sources < graph.dense.sources
            || current.spans < graph.dense.spans
            || current.embedded_sources < graph.dense.embedded_sources
            || current.omitted_sources < graph.dense.omitted_sources
        {
            return Err(stale_index());
        }
        generation
            .bm25
            .as_ref()
            .ok_or_else(stale_index)?
            .validate()?;
        Ok(())
    }
    fn tail_dense_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let latest: DenseProjectionReceipt = self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &super::super::receipt_key(workspace, generation.number),
                budget,
            )?
            .ok_or_else(|| integrity("tail dense accepted receipt absent"))?;
        budget.charge(1, 32768).map_err(budget_error)?;
        self.check_dense_receipt(&latest)?;
        let dense = generation.dense.as_ref().ok_or_else(stale_index)?;
        if latest.generation != generation.number
            || digest_bytes(latest.workspace_id.as_bytes()) != workspace
            || latest.authorization_epoch != generation.authorization_epoch
            || latest.raw_through > generation.through
            || latest.raw_sources > generation.projected_sources
            || (latest.raw_through == generation.through
                && latest.raw_sources != generation.projected_sources)
            || latest.profile != dense.profile
            || latest.profile_digest != dense.profile_digest
            || latest.through != dense.through
            || latest.sources != dense.sources
            || latest.embedded_sources != dense.embedded_sources
            || latest.spans != dense.spans
            || latest.omitted_sources != dense.omitted_sources
            || latest.commitment != dense.commitment
        {
            return Err(integrity(
                "tail latest dense receipt differs from frozen generation",
            ));
        }
        let event: crate::StoredEvent = self
            .graph_read(
                snapshot,
                &self.keyspaces.events,
                &latest.global_commit.to_be_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("tail dense accepted event absent"))?;
        let stored: crate::StoredIdempotency = self
            .graph_read(
                snapshot,
                &self.keyspaces.idempotency,
                event.request_digest.as_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("tail dense retained receipt absent"))?;
        budget.charge(1, 32768).map_err(budget_error)?;
        if event.operation != super::super::OPERATION
            || event.schema_version != crate::SCHEMA_VERSION
            || event.global_commit != latest.global_commit
            || event.workspace_digest != workspace
            || latest.raw_through >= event.workspace_commit
            || event.event_digest != crate::event_digest(&event)?
            || event.request_digest != canonical_digest(&latest)?
            || event.response_digest != digest_bytes(&encode(&latest)?)
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != event.operation
            || stored.request_digest != event.request_digest
            || stored.response_digest != event.response_digest
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || stored.response_bytes != encode(&latest)?
        {
            return Err(integrity("tail latest dense retained receipt differs"));
        }
        Ok(())
    }
    pub(super) fn graph_tail_fence(
        &self,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        generation: &Generation,
        receipt: &DenseGraphReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        budget.check().map_err(budget_error)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&current, budget, |r| {
            self.require_custody_ready(r, workspace)
        })?;
        let state: IndexState = self
            .graph_read(
                &current,
                &self.keyspaces.continuous,
                &state_key(workspace),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(generation.number)
            || self.graph_epoch(&current, workspace, budget)? != generation.authorization_epoch
            || self
                .graph_read::<Generation, _>(
                    &current,
                    &self.keyspaces.continuous,
                    &generation_key(workspace, generation.number),
                    budget,
                )?
                .as_ref()
                != Some(generation)
            || self.accepted_graph_receipt(&current, workspace, generation, budget)? != *receipt
        {
            return Err(stale_index());
        }
        self.admit_tail_generation(generation, &receipt.manifest, budget)?;
        self.tail_dense_receipt(&current, workspace, generation, budget)?;
        for c in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            require_capability(context, c)?;
        }
        self.tail_raw_lag(&current, workspace, generation.through, budget)
    }
    fn tail_raw_lag<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        through: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        budget.charge(1, 1024).map_err(budget_error)?;
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&through.to_be_bytes());
        let page = crate::budgeted::metadata(snapshot, budget, |r| {
            r.scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries: 1,
                    max_bytes: 4096,
                },
            )
            .map_err(storage_error)
        })?;
        if page.entries.is_empty() && page.continuation.is_some() {
            return Err(integrity("raw lag page has no complete absence boundary"));
        }
        let Some(row) = page.entries.into_iter().next() else {
            return Ok(false);
        };
        let work: crate::capture::CaptureWork =
            decode(&row.value, "unprojected accepted capture work")?;
        if work.workspace_commit <= through
            || row.key != crate::capture::work_key(workspace, work.workspace_commit)
        {
            return Err(integrity("raw lag outbox binding differs"));
        }
        let (receipt, recovery) =
            self.capture_recovery_metadata(snapshot, work.event_id, budget)?;
        if recovery.is_none()
            || self.capture_work_for_receipt_with_budget(snapshot, &receipt, budget)? != work
        {
            return Err(integrity("raw lag capture control differs"));
        }
        self.tail_capture_publication(snapshot, workspace, &receipt, &work, budget)?;
        Ok(true)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "current source, accepted base and parent allowance remain explicit"
    )]
    fn tail_source_fence(
        &self,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        generation: &Generation,
        receipt: &DenseGraphReceipt,
        event: ObservationId,
        policies: &[AccessPolicy],
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.graph_tail_fence(context, workspace, generation, receipt, budget)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.authorized_capture_policy_with_budget(&current, context, event, budget)?;
        self.authorize_derived_custody_with_budget(&current, context, event, budget)?;
        if self.stored_custody_policies_with_budget(&current, event, budget)? != policies {
            return Err(stale_index());
        }
        Ok(())
    }
    fn dense_tail_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        receipt: &DenseGraphReceipt,
        max_work: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Witness> {
        let latest = generation.dense.as_ref().ok_or_else(stale_index)?;
        budget
            .charge(1, 8192 + max_work as u64 * 512)
            .map_err(budget_error)?;
        let mut witness = receipt.manifest.dense.clone();
        let mut documents = Vec::new();
        if witness == *latest {
            return Ok(Witness {
                documents,
                complete: true,
            });
        }
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&witness.through.to_be_bytes());
        let page = crate::budgeted::metadata(snapshot, budget, |r| {
            r.scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries: max_work,
                    max_bytes: 256 * 1024,
                },
            )
            .map_err(storage_error)
        })?;
        let mut last = witness.through;
        let mut beyond = false;
        for row in page.entries {
            budget.charge(1, 1024).map_err(budget_error)?;
            let work: crate::capture::CaptureWork = decode(&row.value, "dense tail accepted work")?;
            if row.key != crate::capture::work_key(workspace, work.workspace_commit)
                || work.workspace_commit <= last
            {
                return Err(integrity("dense tail outbox identity or order differs"));
            }
            last = work.workspace_commit;
            if work.workspace_commit > latest.through {
                beyond = true;
                break;
            }
            let (captured, recovery) =
                self.capture_recovery_metadata(snapshot, work.event_id, budget)?;
            if recovery.is_none()
                || work.recovery_digest.is_none()
                || self.capture_work_for_receipt_with_budget(snapshot, &captured, budget)? != work
            {
                return Err(integrity("dense tail accepted control differs"));
            }
            self.tail_capture_publication(snapshot, workspace, &captured, &work, budget)?;
            if self.source_prepared_at(
                snapshot,
                workspace,
                work.event_id,
                generation.removal_through,
                budget,
            )? {
                continue;
            }
            let doc: DenseDocument = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &document_key(workspace, generation.number, work.event_id),
                    budget,
                )?
                .ok_or_else(|| integrity("tail tagged document absent"))?;
            budget
                .charge(
                    1,
                    8192 + doc.spans.len() as u64 * 1024
                        + doc
                            .source
                            .source_version
                            .as_ref()
                            .map_or(0, |s| s.len() as u64 * 8),
                )
                .map_err(budget_error)?;
            self.check_dense_document_token(&doc)?;
            if doc.source.event_id != work.event_id
                || doc.event_digest != work.event_digest
                || doc.commit != work.workspace_commit
                || doc.profile_digest != latest.profile_digest
                || doc.source.payload_digest != captured.payload_digest
                || doc.spans.len() > MAX_SOURCE_SPANS
                || (doc.omission.is_some() && !doc.spans.is_empty())
                || (doc.omission.is_none() && doc.spans.is_empty())
                || doc.spans.iter().any(|s| {
                    s.span.event_id != doc.source.event_id
                        || Some(s.span.payload_digest) != doc.source.payload_digest
                        || s.span.start >= s.span.end
                        || doc
                            .source
                            .byte_length
                            .is_none_or(|length| s.span.end > length)
                })
            {
                return Err(integrity(
                    "tail document source/version or exact spans differ",
                ));
            }
            witness.accept(&doc)?;
            documents.push(doc);
        }
        let complete = beyond || last >= latest.through || page.continuation.is_none();
        if !complete {
            return Ok(Witness {
                documents: Vec::new(),
                complete: false,
            });
        }
        witness.through = latest.through;
        if witness != *latest {
            return Err(integrity(
                "dense tail complete prefix witness differs from accepted latest manifest",
            ));
        }
        Ok(Witness {
            documents,
            complete: true,
        })
    }
    fn tail_capture_publication<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        receipt: &CaptureReceipt,
        work: &crate::capture::CaptureWork,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, 8192).map_err(budget_error)?;
        let mut unsigned = receipt.clone();
        unsigned.token.clear();
        let token = crate::keyed_token(
            &self.token_key,
            b"contextdb/capture-receipt/v1\0",
            &encode(&unsigned)?,
        );
        if receipt.token != token
            || receipt.domain != NATIVE_CAPTURE_DOMAIN
            || receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.to_string().as_bytes()) != workspace
            || receipt.event_id != work.event_id
            || receipt.workspace_commit != work.workspace_commit
            || receipt.event_digest != work.event_digest
            || receipt.durability != CaptureDurability::Sync
        {
            return Err(integrity("tail source receipt authentication differs"));
        }
        let (global, _) = crate::budgeted::metadata(snapshot, budget, |r| {
            self.select_snapshot(
                r,
                &receipt.workspace_id.to_string(),
                Some(receipt.workspace_commit),
            )
        })?;
        let event: crate::StoredEvent = self
            .graph_read(
                snapshot,
                &self.keyspaces.events,
                &global.to_be_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("tail accepted source event absent"))?;
        if event.operation != "capture"
            || event.schema_version != crate::SCHEMA_VERSION
            || event.global_commit != global
            || event.workspace_commit != receipt.workspace_commit
            || event.workspace_digest != workspace
            || event.accepted_original.as_ref() != Some(work)
            || event.event_digest != crate::event_digest(&event)?
            || event.response_digest != digest_bytes(&encode(receipt)?)
        {
            return Err(integrity("tail source has no matching accepted capture"));
        }
        Ok(())
    }
}

fn tail_cosine(left: &[f32], right: &[f32], budget: &mut QueryBudget) -> ServiceResult<f32> {
    if left.len() != right.len() {
        return Err(integrity("tail score dimensions differ"));
    }
    budget.charge(left.len() as u64, 0).map_err(budget_error)?;
    // Same full f32 cosine arithmetic and stable ordering as portable ANN.
    let dot = left.iter().zip(right).map(|(a, b)| a * b).sum::<f32>();
    let ln = left.iter().map(|v| v * v).sum::<f32>().sqrt();
    let rn = right.iter().map(|v| v * v).sum::<f32>().sqrt();
    let score = dot / (ln * rn);
    if !score.is_finite() {
        return Err(integrity("tail score is nonfinite"));
    }
    Ok(score)
}
