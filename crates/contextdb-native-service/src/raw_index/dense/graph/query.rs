//! Hot traversal has only point readers; no graph build or source-body scan.
use super::*;
use contextdb_index::{
    AnnObjectKeyV2, AnnObjectReadRequestV2, AnnObjectReadResponseV2, AnnObjectV2,
    AnnPartitionQueryCompletionV2, AnnPartitionQueryErrorV2, AnnPartitionQueryLimitsV2,
    AnnPartitionQueryReaderV2, AnnPartitionQueryV2, search_ann_partition_v2,
};

struct Reader<'a, S> {
    native: &'a NativeService,
    snapshot: &'a S,
    context: &'a AuthenticatedRequestContext,
    workspace: &'a str,
    generation: &'a Generation,
    receipt: &'a DenseGraphReceipt,
    cohort: &'a GraphCohort,
    partition: &'a AnnPartitionManifestV2,
    budget: &'a mut QueryBudget,
    members: BTreeMap<RepresentationId, GraphMember>,
    with_tail: bool,
}
pub(super) struct GraphBaseDiscovery {
    pub(super) result: DenseGraphQueryResult,
    pub(super) admitted_sources: BTreeMap<ObservationId, RawSource>,
}
impl NativeService {
    fn graph_query_fence(
        &self,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        generation: &Generation,
        receipt: &DenseGraphReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
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
            || self.current_graph_receipt(&current, workspace, generation, budget)? != *receipt
        {
            return Err(stale_index());
        }
        let context_cost = crate::budgeted::auth::ContextCost::for_context(context, budget)?;
        for c in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            context_cost.require_capability(context, c, budget)?;
        }
        Ok(())
    }
    /// Query one fixed owner ANN base using already supplied exact query
    /// embedding observations. No source text is forwarded or materialized by
    /// traversal. Returned spans remain discovery, not a disclosure lease.
    pub fn search_original_spans(
        &self,
        context: &AuthenticatedRequestContext,
        query_text: &str,
        query: &EmbeddedText,
        limits: DenseGraphQueryLimits,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseGraphQueryResult> {
        let context_cost = crate::budgeted::auth::ContextCost::for_context(context, budget)?;
        for c in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            context_cost.require_capability(context, c, budget)?;
        }
        validate_limits(limits)?;
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
        let receipt = self.current_graph_receipt(&snapshot, &workspace, &generation, budget)?;
        self.graph_query_fence(context, &workspace, &generation, &receipt, budget)?;
        query.validate(
            &receipt.manifest.dense.profile,
            EmbeddingTextKind::Query,
            query_text,
            budget,
        )?;
        let result = self.search_graph_base(
            &snapshot,
            context,
            &workspace,
            &generation,
            &receipt,
            query,
            limits,
            false,
            budget,
        )?;
        self.graph_query_fence(context, &workspace, &generation, &receipt, budget)?;
        Ok(result.result)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "frozen base, current envelope and parent budget remain explicit"
    )]
    pub(super) fn search_graph_base<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        generation: &Generation,
        receipt: &DenseGraphReceipt,
        query: &EmbeddedText,
        limits: DenseGraphQueryLimits,
        with_tail: bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<GraphBaseDiscovery> {
        let number = generation.number;
        budget
            .charge(1, (limits.max_discovered.min(MAX_NODES) * 2048) as u64)
            .map_err(budget_error)?;
        let space = vector_space(&receipt.manifest.dense);
        let mut hits = Vec::new();
        let mut admitted_sources = BTreeMap::<ObservationId, RawSource>::new();
        let mut completion = AnnPartitionQueryCompletionV2::Complete;
        let (mut node_reads, mut vector_reads, mut discovered) = (0_u64, 0_u64, 0_u64);
        for summary in &receipt.manifest.cohorts {
            let cohort: GraphCohort = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &cohort_key(workspace, number, &summary.policy_domain),
                    budget,
                )?
                .ok_or_else(|| integrity("query graph cohort absent"))?;
            let partition = self.check_graph_cohort(&receipt.manifest, &cohort, budget)?;
            // No forbidden cohort/member identities or counts cross this API.
            if cohort
                .policies
                .iter()
                .any(|p| !crate::policy_allows(&context.request, p))
            {
                continue;
            }
            let nr = limits.max_node_reads.saturating_sub(node_reads as usize);
            let vr = limits
                .max_vector_reads
                .saturating_sub(vector_reads as usize);
            let dr = limits.max_discovered.saturating_sub(discovered as usize);
            if nr == 0 {
                completion = AnnPartitionQueryCompletionV2::NodeLimit;
                break;
            }
            if vr == 0 {
                completion = AnnPartitionQueryCompletionV2::VectorLimit;
                break;
            }
            if dr == 0 {
                completion = AnnPartitionQueryCompletionV2::DiscoveryLimit;
                break;
            }
            let beam = limits.ef_search.min(dr);
            let mut reader = Reader {
                native: self,
                snapshot,
                context,
                workspace,
                generation,
                receipt,
                cohort: &cohort,
                partition: &partition,
                budget,
                members: BTreeMap::new(),
                with_tail,
            };
            let result = search_ann_partition_v2(
                &mut reader,
                &partition,
                &space,
                AnnPartitionQueryV2 {
                    values: &query.values,
                    limit: limits.limit.min(beam),
                },
                AnnPartitionQueryLimitsV2 {
                    max_node_reads: nr,
                    max_vector_reads: vr,
                    max_discovered: dr,
                    ef_search: beam,
                },
            )
            .map_err(|e| match e {
                AnnPartitionQueryErrorV2::Reader(e) => e,
                other => ann_error(other),
            })?;
            node_reads += result.trace.node_reads;
            vector_reads += result.trace.vector_reads;
            discovered += result.trace.discovered;
            for hit in result.hits {
                let member = reader
                    .members
                    .get(&hit.representation_id)
                    .ok_or_else(|| integrity("query hit was not admitted"))?;
                reader.budget.charge(1, 1024).map_err(budget_error)?;
                hits.push(DenseGraphHit {
                    representation_id: hit.representation_id,
                    source: member.source.clone(),
                    span: member.span.clone(),
                    score: hit.score,
                });
            }
            if with_tail {
                for member in reader.members.values() {
                    reader
                        .budget
                        .charge(
                            1,
                            2048 + member
                                .source
                                .source_version
                                .as_ref()
                                .map_or(0, |s| s.len() as u64 * 8),
                        )
                        .map_err(budget_error)?;
                    if admitted_sources
                        .get(&member.source.event_id)
                        .is_some_and(|previous| previous != &member.source)
                    {
                        return Err(integrity("admitted graph source version differs"));
                    }
                    admitted_sources
                        .entry(member.source.event_id)
                        .or_insert_with(|| member.source.clone());
                }
            }
            if result.completion != AnnPartitionQueryCompletionV2::Complete {
                completion = result.completion;
                break;
            }
        }
        budget
            .charge(hits.len() as u64 * 16 + 1, 0)
            .map_err(budget_error)?;
        hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.representation_id.cmp(&b.representation_id))
        });
        hits.truncate(limits.limit);
        Ok(GraphBaseDiscovery {
            result: DenseGraphQueryResult {
                hits,
                completion,
                node_reads,
                vector_reads,
                discovered,
                graph_digest: receipt.manifest.content_digest,
            },
            admitted_sources,
        })
    }
}
impl<S: ReadSnapshot> Reader<'_, S> {
    fn fence(&mut self) -> ServiceResult<()> {
        if self.with_tail {
            self.native
                .graph_tail_fence(
                    self.context,
                    self.workspace,
                    self.generation,
                    self.receipt,
                    self.budget,
                )
                .map(|_| ())
        } else {
            self.native.graph_query_fence(
                self.context,
                self.workspace,
                self.generation,
                self.receipt,
                self.budget,
            )
        }
    }
    fn fresh_member(&mut self, member: &GraphMember) -> ServiceResult<()> {
        self.fence()?;
        let current = self
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.native.authorized_capture_policy_with_budget(
            &current,
            self.context,
            member.source.event_id,
            self.budget,
        )?;
        self.native.authorize_derived_custody_with_budget(
            &current,
            self.context,
            member.source.event_id,
            self.budget,
        )?;
        if self.native.stored_custody_policies_with_budget(
            &current,
            member.source.event_id,
            self.budget,
        )? != self.cohort.policies
        {
            return Err(stale_index());
        }
        Ok(())
    }
}
impl<S: ReadSnapshot> AnnPartitionQueryReaderV2 for Reader<'_, S> {
    type Error = ServiceError;
    fn charge(&mut self, work: u64, bytes: u64) -> ServiceResult<()> {
        self.budget.charge(work, bytes).map_err(budget_error)
    }
    fn acknowledge_partition(
        &mut self,
        partition: &AnnPartitionManifestV2,
        space: &VectorSpace,
    ) -> ServiceResult<()> {
        if partition != self.partition || space != &vector_space(&self.receipt.manifest.dense) {
            return Err(integrity("query partition/space differs"));
        }
        self.fence()
    }
    fn admit_member(
        &mut self,
        partition: &AnnPartitionManifestV2,
        id: RepresentationId,
    ) -> ServiceResult<()> {
        if partition != self.partition {
            return Err(integrity("query member partition differs"));
        }
        let row: GraphMember = self
            .native
            .graph_read(
                self.snapshot,
                &self.native.keyspaces.continuous,
                &member_key(self.workspace, self.generation.number, id),
                self.budget,
            )?
            .ok_or_else(|| integrity("query graph member absent"))?;
        self.native.check_graph_member(
            self.workspace,
            &self.receipt.manifest,
            &row,
            self.budget,
        )?;
        if row.representation_id != id || row.policy_domain != self.cohort.policy_domain {
            return Err(integrity("query member cohort differs"));
        }
        self.fresh_member(&row)?;
        self.budget.charge(1, 2048).map_err(budget_error)?;
        self.members.insert(id, row);
        Ok(())
    }
    fn read_node(
        &mut self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> ServiceResult<AnnObjectReadResponseV2> {
        request.validate().map_err(ann_error)?;
        let id_bytes = request
            .key
            .as_bytes()
            .get(42..58)
            .ok_or_else(|| integrity("query node key invalid"))?;
        let id = RepresentationId::from_uuid(uuid::Uuid::from_slice(id_bytes).map_err(ann_error)?)
            .map_err(ann_error)?;
        if !self.members.contains_key(&id)
            || request.key
                != &AnnObjectKeyV2::node(self.generation.number, self.partition.partition_key, id)
                    .map_err(ann_error)?
        {
            return Err(integrity("query node has no admitted exact member"));
        }
        let row: GraphNode = self
            .native
            .graph_read(
                self.snapshot,
                &self.native.keyspaces.continuous,
                &node_key(self.workspace, self.generation.number, id),
                self.budget,
            )?
            .ok_or_else(|| integrity("query graph node absent"))?;
        let node = self
            .native
            .check_graph_node(&self.receipt.manifest, &row, self.budget)?;
        if node.representation_id != id
            || row.policy_domain != self.cohort.policy_domain
            || row.canonical_node.len() > request.max_bytes
        {
            return Err(integrity("query node binding/cap differs"));
        }
        let object =
            AnnObjectV2::new(request.key.clone(), row.canonical_node).map_err(ann_error)?;
        AnnObjectReadResponseV2::new(request, Some(object)).map_err(ann_error)
    }
    fn read_vector(
        &mut self,
        id: RepresentationId,
        dimensions: usize,
        max_bytes: usize,
    ) -> ServiceResult<Vec<f32>> {
        self.budget.charge(1, 2048).map_err(budget_error)?;
        let member = self
            .members
            .get(&id)
            .cloned()
            .ok_or_else(|| integrity("query vector has no admitted member"))?;
        self.fresh_member(&member)?;
        let v: DenseVector = self
            .native
            .graph_read(
                self.snapshot,
                &self.native.keyspaces.continuous,
                &vector_key(
                    self.workspace,
                    self.generation.number,
                    member.source.event_id,
                    member.ordinal,
                ),
                self.budget,
            )?
            .ok_or_else(|| integrity("query exact vector absent"))?;
        self.native.check_dense_vector_token(&v)?;
        if v.source != member.source
            || v.event_digest != member.event_digest
            || v.commit != member.commit
            || v.ordinal != member.ordinal
            || v.span != member.span
            || v.policy_domain != member.policy_domain
            || v.profile_digest != member.profile_digest
            || v.vector_digest != member.vector_digest
            || v.values_bits.len() != dimensions
            || dimensions != self.receipt.manifest.dense.profile.dimensions as usize
            || dimensions * 4 > max_bytes
            || v.tokens_digest.as_bytes() == &[0; 32]
            || v.token_count == 0
            || v.token_count > self.receipt.manifest.dense.profile.max_input_tokens
        {
            return Err(integrity("query vector source/profile differs"));
        }
        query_vector_values(&self.receipt.manifest.dense.profile, v, self.budget)
    }
}

pub(super) fn validate_limits(limits: DenseGraphQueryLimits) -> ServiceResult<()> {
    if limits.limit == 0
        || limits.limit > MAX_NODES
        || limits.ef_search < limits.limit
        || [
            limits.max_node_reads,
            limits.max_vector_reads,
            limits.max_discovered,
            limits.ef_search,
        ]
        .iter()
        .any(|v| *v == 0 || *v > contextdb_index::ANN_PARTITION_QUERY_MAX_READS_V2)
        || limits.ef_search > limits.max_discovered
    {
        return Err(crate::invalid("native graph query caps invalid"));
    }
    Ok(())
}
pub(super) fn query_vector_values(
    profile: &TextEmbeddingProfile,
    v: DenseVector,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<f32>> {
    let dimensions = profile.dimensions as usize;
    if v.values_bits.len() != dimensions
        || v.tokens_digest.as_bytes() == &[0; 32]
        || v.token_count == 0
        || v.token_count > profile.max_input_tokens
    {
        return Err(integrity("query vector profile/token binding differs"));
    }
    budget
        .charge(dimensions as u64, dimensions as u64 * 4)
        .map_err(budget_error)?;
    let mut hash = blake3::Hasher::new();
    let mut norm = 0_f64;
    let mut values = Vec::with_capacity(dimensions);
    for bits in v.values_bits {
        let value = f32::from_bits(bits);
        if !value.is_finite() {
            return Err(integrity("query vector is nonfinite"));
        }
        norm += f64::from(value).powi(2);
        hash.update(&value.to_le_bytes());
        values.push(value);
    }
    if (norm - 1.0).abs() > 0.001
        || ContentDigest::from_bytes(*hash.finalize().as_bytes()) != v.vector_digest
    {
        return Err(integrity(
            "query vector values differ from owner commitment",
        ));
    }
    Ok(values)
}
