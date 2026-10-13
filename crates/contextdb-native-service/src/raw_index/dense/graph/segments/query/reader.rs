//! One authenticated namespace, point reads only, and one shared query ledger.

use super::ledger::{Caps, QueryLedger};
use super::view::VerifiedSegmentQueryView;
use crate::raw_index::dense::graph::segments::types::{
    DenseDeltaManifest, SegCohort, SegMember, SegNode,
};
use crate::raw_index::dense::graph::segments::{crypto::metered_json_len, types};
use crate::raw_index::dense::graph::{self, DenseGraphHit, DenseGraphReceipt, GraphCohort};
use crate::raw_index::dense::{DenseManifest, DenseVector};
use crate::{NativeService, integrity, raw_index::budget_error, storage_error};
use contextdb_core::{ContentDigest, OriginalSourceSpan, RawSource, RepresentationId};
use contextdb_index::{
    AnnObjectKeyV2, AnnObjectReadRequestV2, AnnObjectReadResponseV2, AnnObjectV2,
    AnnPartitionManifestV2, AnnPartitionQueryCompletionV2, AnnPartitionQueryErrorV2,
    AnnPartitionQueryLimitsV2, AnnPartitionQueryReaderV2, AnnPartitionQueryV2, VectorSpace,
    search_ann_partition_v2,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, EmbeddedText, EmbeddingTextKind, ServiceError,
    ServiceResult,
};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};
use std::{collections::BTreeMap, mem::size_of};

#[derive(Clone, Copy)]
pub(super) enum Namespace<'a> {
    Base {
        receipt: &'a DenseGraphReceipt,
        cohort: &'a GraphCohort,
    },
    Delta {
        manifest: &'a DenseDeltaManifest,
        cohort: &'a SegCohort,
    },
}

impl Namespace<'_> {
    fn policies(&self) -> &[AccessPolicy] {
        match self {
            Self::Base { cohort, .. } => &cohort.policies,
            Self::Delta { cohort, .. } => &cohort.policies,
        }
    }
    fn domain(&self) -> &str {
        match self {
            Self::Base { cohort, .. } => &cohort.policy_domain,
            Self::Delta { cohort, .. } => &cohort.policy_domain,
        }
    }
    fn dense(&self) -> &DenseManifest {
        match self {
            Self::Base { receipt, .. } => &receipt.manifest.dense,
            Self::Delta { manifest, .. } => &manifest.after,
        }
    }
    fn member_key(
        &self,
        workspace: &str,
        generation: u64,
        id: RepresentationId,
    ) -> ServiceResult<Vec<u8>> {
        match self {
            Self::Base { .. } => Ok(graph::member_key(workspace, generation, id)),
            Self::Delta { manifest, .. } => {
                types::segment_member_key(workspace, generation, manifest.ordinal, id)
            }
        }
    }
    fn node_key(
        &self,
        workspace: &str,
        generation: u64,
        id: RepresentationId,
    ) -> ServiceResult<Vec<u8>> {
        match self {
            Self::Base { .. } => Ok(graph::node_key(workspace, generation, id)),
            Self::Delta { manifest, .. } => {
                types::segment_node_key(workspace, generation, manifest.ordinal, id)
            }
        }
    }
}

pub(super) struct PartitionDiscovery {
    pub(super) hits: Vec<DenseGraphHit>,
    pub(super) completion: AnnPartitionQueryCompletionV2,
    pub(super) node_reads: u64,
    pub(super) vector_reads: u64,
    pub(super) discovered: u64,
}

#[derive(Clone)]
struct Member {
    identity_digest: ContentDigest,
    source: RawSource,
    event_digest: ContentDigest,
    commit: u64,
    ordinal: u32,
    span: OriginalSourceSpan,
    profile_digest: ContentDigest,
    vector_digest: ContentDigest,
    scored: bool,
}

struct Reader<'a, S> {
    native: &'a NativeService,
    snapshot: &'a S,
    context: &'a AuthenticatedRequestContext,
    view: &'a VerifiedSegmentQueryView,
    namespace: Namespace<'a>,
    partition: &'a AnnPartitionManifestV2,
    space: &'a VectorSpace,
    ledger: &'a mut QueryLedger,
    parent: &'a mut QueryBudget,
    members: BTreeMap<RepresentationId, Member>,
    scored_hits: Vec<DenseGraphHit>,
    max_scores: usize,
}

#[allow(
    clippy::too_many_arguments,
    reason = "pinned view, namespace, allocated caps and shared parent remain explicit"
)]
pub(super) fn search_partition<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedSegmentQueryView,
    namespace: Namespace<'_>,
    partition: &AnnPartitionManifestV2,
    embedded: &EmbeddedText,
    assigned: Caps,
    ef_search: usize,
    ledger: &mut QueryLedger,
    parent: &mut QueryBudget,
) -> ServiceResult<PartitionDiscovery> {
    parent.check().map_err(budget_error)?;
    if assigned.nodes == 0 || assigned.vectors == 0 || assigned.discovered == 0 || ef_search == 0 {
        return Err(crate::invalid(
            "segment partition requires positive allocated caps",
        ));
    }
    native.check_segment_query_view(context, view, parent)?;
    let admitted_partition = match namespace {
        Namespace::Base { receipt, cohort } => {
            if receipt != view.base() {
                return Err(integrity("segment query base differs from admitted view"));
            }
            native.graph_tag_allowance(&receipt.manifest, 8192, parent)?;
            native.check_graph_receipt(receipt)?;
            native.check_graph_cohort(&receipt.manifest, cohort, parent)?
        }
        Namespace::Delta { manifest, cohort } => {
            let bytes = metered_json_len(manifest, parent, types::ROW_BYTES)?;
            parent
                .charge(1, bytes as u64 * 4 + 8192)
                .map_err(budget_error)?;
            manifest.validate()?;
            let generation = view.generation();
            let latest = view.profile_dense();
            if manifest.binding.generation != generation.number
                || manifest.binding.custody_version != generation.custody_version
                || manifest.binding.analyzer != generation.analyzer
                || generation.bm25.as_ref() != Some(&manifest.binding.bm25)
                || manifest.binding.authorization_epoch != generation.authorization_epoch
                || manifest.binding.removal_through != generation.removal_through
                || manifest.ordinal
                    > generation
                        .dense_segments
                        .as_ref()
                        .map_or(0, |head| head.count)
                || manifest.base.graph_digest != view.base().manifest.content_digest
                || manifest.before.through < view.base().manifest.dense.through
                || manifest.binding.raw_through > generation.through
                || manifest.binding.raw_sources > generation.projected_sources
                || manifest.after.through > latest.through
                || manifest.after.profile != latest.profile
                || manifest.after.profile_digest != latest.profile_digest
                || manifest.after.vector_space_id != latest.vector_space_id
            {
                return Err(integrity(
                    "segment query namespace differs from admitted prefix",
                ));
            }
            native.check_segment_cohort(view.workspace(), manifest, cohort, parent)?
        }
    };
    if admitted_partition != *partition
        || namespace.dense().profile_digest != view.profile_dense().profile_digest
        || embedded.kind != EmbeddingTextKind::Query
        || embedded.profile_digest != view.profile_dense().profile_digest
        || embedded.tokens_digest.as_bytes() == &[0; 32]
        || embedded.token_count == 0
        || embedded.token_count > view.profile_dense().profile.max_input_tokens
    {
        return Err(integrity(
            "segment query partition or supplied encoder space differs",
        ));
    }
    charge_policy_check(context, namespace.policies(), parent)?;
    if namespace
        .policies()
        .iter()
        .any(|policy| !crate::policy_allows(&context.request, policy))
    {
        return Err(crate::permission_denied());
    }
    let dense = namespace.dense();
    parent
        .charge(
            1,
            dense.profile.model_family.len() as u64 * 4
                + dense.profile.model_revision.len() as u64 * 4
                + 2048,
        )
        .map_err(budget_error)?;
    let space = graph::vector_space(dense);
    let beam = ef_search.min(assigned.discovered);
    let max_scores = assigned
        .vectors
        .min(assigned.discovered)
        .min(partition.node_count as usize);
    parent
        .charge(
            1,
            max_scores as u64 * size_of::<DenseGraphHit>() as u64 + 256,
        )
        .map_err(budget_error)?;
    let mut reader = Reader {
        native,
        snapshot,
        context,
        view,
        namespace,
        partition,
        space: &space,
        ledger,
        parent,
        members: BTreeMap::new(),
        scored_hits: Vec::with_capacity(max_scores),
        max_scores,
    };
    let result = search_ann_partition_v2(
        &mut reader,
        partition,
        &space,
        AnnPartitionQueryV2 {
            values: &embedded.values,
            limit: beam,
        },
        AnnPartitionQueryLimitsV2 {
            max_node_reads: assigned.nodes,
            max_vector_reads: assigned.vectors,
            max_discovered: assigned.discovered,
            ef_search: beam,
        },
    )
    .map_err(|error| match error {
        AnnPartitionQueryErrorV2::Reader(error) => error,
        other => graph::ann_error(other),
    })?;
    reader.fence()?;
    if reader.scored_hits.len() as u64 != result.trace.vector_reads {
        return Err(integrity(
            "segment scored observations differ from actual vector reads",
        ));
    }
    // The local beam governs traversal only. Global source ranking needs every
    // validated observation, even when several spans of one source fill a beam.
    let hits = reader.scored_hits;
    Ok(PartitionDiscovery {
        hits,
        completion: result.completion,
        node_reads: result.trace.node_reads,
        vector_reads: result.trace.vector_reads,
        discovered: result.trace.discovered,
    })
}

fn charge_policy_check(
    context: &AuthenticatedRequestContext,
    policies: &[AccessPolicy],
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    let bytes = metered_json_len(&policies, parent, types::ROW_BYTES)?;
    let context_entries =
        context.request.audiences.len() as u64 + context.request.scopes.len() as u64;
    parent
        .charge(
            bytes as u64 * 32 + context_entries * policies.len() as u64 + 1,
            bytes as u64 * 2 + 4096,
        )
        .map_err(budget_error)
}

impl<S: ReadSnapshot> Reader<'_, S> {
    fn fence(&mut self) -> ServiceResult<()> {
        self.native
            .check_segment_query_view(self.context, self.view, self.parent)
    }

    fn fresh_member(&mut self, member: &Member) -> ServiceResult<()> {
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
            self.parent,
        )?;
        self.native.authorize_derived_custody_with_budget(
            &current,
            self.context,
            member.source.event_id,
            self.parent,
        )?;
        let policies = self.native.stored_custody_policies_with_budget(
            &current,
            member.source.event_id,
            self.parent,
        )?;
        let bytes = metered_json_len(&policies, self.parent, types::ROW_BYTES)?;
        self.parent
            .charge(bytes as u64 + 1, 4096)
            .map_err(budget_error)?;
        if policies != self.namespace.policies() {
            return Err(crate::raw_index::stale_index());
        }
        Ok(())
    }

    fn cache_allowance(&mut self) -> ServiceResult<()> {
        // Reserve a full BTree node at each potential split level before insert.
        let levels =
            u64::from(usize::BITS - self.members.len().saturating_add(1).leading_zeros()) + 2;
        let node = 12 * size_of::<(RepresentationId, Member)>() as u64 + 256;
        self.parent
            .charge(levels * 12, levels * node)
            .map_err(budget_error)
    }

    fn cached_clone(&mut self, id: RepresentationId) -> ServiceResult<Member> {
        let member = self
            .members
            .get(&id)
            .ok_or_else(|| integrity("segment vector has no admitted member"))?;
        self.parent
            .charge(
                1,
                size_of::<Member>() as u64
                    + member
                        .source
                        .source_version
                        .as_ref()
                        .map_or(0, |version| version.len() as u64 * 8)
                    + 256,
            )
            .map_err(budget_error)?;
        Ok(member.clone())
    }
}

impl<S: ReadSnapshot> AnnPartitionQueryReaderV2 for Reader<'_, S> {
    type Error = ServiceError;

    fn charge(&mut self, work: u64, bytes: u64) -> ServiceResult<()> {
        self.parent.charge(work, bytes).map_err(budget_error)
    }

    fn acknowledge_partition(
        &mut self,
        partition: &AnnPartitionManifestV2,
        space: &VectorSpace,
    ) -> ServiceResult<()> {
        if partition != self.partition || space != self.space {
            return Err(integrity(
                "segment query acknowledgement differs from exact partition",
            ));
        }
        self.fence()
    }

    fn admit_member(
        &mut self,
        partition: &AnnPartitionManifestV2,
        id: RepresentationId,
    ) -> ServiceResult<()> {
        if partition != self.partition {
            return Err(integrity("segment query member partition differs"));
        }
        self.fence()?;
        if self.members.contains_key(&id) {
            return Ok(());
        }
        self.parent
            .charge(1, types::KEY_BYTES)
            .map_err(budget_error)?;
        let key =
            self.namespace
                .member_key(self.view.workspace(), self.view.generation().number, id)?;
        let member = match self.namespace {
            Namespace::Base { receipt, .. } => {
                let row: graph::GraphMember = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("segment query base member is absent"))?;
                self.native.check_graph_member(
                    self.view.workspace(),
                    &receipt.manifest,
                    &row,
                    self.parent,
                )?;
                if row.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("segment query base member namespace differs"));
                }
                Member {
                    identity_digest: row.identity_digest,
                    source: row.source,
                    event_digest: row.event_digest,
                    commit: row.commit,
                    ordinal: row.ordinal,
                    span: row.span,
                    profile_digest: row.profile_digest,
                    vector_digest: row.vector_digest,
                    scored: false,
                }
            }
            Namespace::Delta { manifest, .. } => {
                let row: SegMember = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("segment query delta member is absent"))?;
                self.native.check_segment_member(
                    self.view.workspace(),
                    manifest,
                    &row,
                    self.parent,
                )?;
                if row.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("segment query delta member namespace differs"));
                }
                Member {
                    identity_digest: row.identity_digest,
                    source: row.source,
                    event_digest: row.event_digest,
                    commit: row.commit,
                    ordinal: row.ordinal,
                    span: row.span,
                    profile_digest: row.profile_digest,
                    vector_digest: row.vector_digest,
                    scored: false,
                }
            }
        };
        self.fresh_member(&member)?;
        self.ledger.admit(
            id,
            member.identity_digest,
            &member.source,
            &member.span,
            self.parent,
        )?;
        self.cache_allowance()?;
        if self.members.insert(id, member).is_some() {
            return Err(integrity("segment reader repeats an uncached local member"));
        }
        Ok(())
    }

    fn read_node(
        &mut self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> ServiceResult<AnnObjectReadResponseV2> {
        self.parent
            .charge(1, types::KEY_BYTES * 3 + 256)
            .map_err(budget_error)?;
        request.validate().map_err(graph::ann_error)?;
        let bytes = request
            .key
            .as_bytes()
            .get(42..58)
            .ok_or_else(|| integrity("segment query node object key differs"))?;
        let id =
            RepresentationId::from_uuid(uuid::Uuid::from_slice(bytes).map_err(graph::ann_error)?)
                .map_err(graph::ann_error)?;
        if !self.members.contains_key(&id)
            || request.key
                != &AnnObjectKeyV2::node(
                    self.view.generation().number,
                    self.partition.partition_key,
                    id,
                )
                .map_err(graph::ann_error)?
        {
            return Err(integrity("segment query node has no admitted exact member"));
        }
        self.fence()?;
        self.parent
            .charge(1, types::KEY_BYTES)
            .map_err(budget_error)?;
        let key =
            self.namespace
                .node_key(self.view.workspace(), self.view.generation().number, id)?;
        let canonical = match self.namespace {
            Namespace::Base { receipt, .. } => {
                let row: graph::GraphNode = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("segment query base node is absent"))?;
                let node = self
                    .native
                    .check_graph_node(&receipt.manifest, &row, self.parent)?;
                if node.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("segment query base node namespace differs"));
                }
                row.canonical_node
            }
            Namespace::Delta { manifest, .. } => {
                let row: SegNode = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("segment query delta node is absent"))?;
                let node = self.native.check_segment_node(
                    self.view.workspace(),
                    manifest,
                    &row,
                    self.parent,
                )?;
                if node.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("segment query delta node namespace differs"));
                }
                row.canonical_node
            }
        };
        if canonical.len() > request.max_bytes {
            return Err(integrity(
                "segment query node exceeds requested object bound",
            ));
        }
        self.parent
            .charge(canonical.len() as u64 + 1, types::KEY_BYTES)
            .map_err(budget_error)?;
        let object = AnnObjectV2::new(request.key.clone(), canonical).map_err(graph::ann_error)?;
        AnnObjectReadResponseV2::new(request, Some(object)).map_err(graph::ann_error)
    }

    fn read_vector(
        &mut self,
        id: RepresentationId,
        dimensions: usize,
        max_bytes: usize,
    ) -> ServiceResult<Vec<f32>> {
        self.parent.check().map_err(budget_error)?;
        if dimensions != self.view.profile_dense().profile.dimensions as usize
            || dimensions
                .checked_mul(4)
                .is_none_or(|bytes| bytes > max_bytes)
        {
            return Err(integrity(
                "segment vector request exceeds its exact dimension bound",
            ));
        }
        let member = self.cached_clone(id)?;
        self.fresh_member(&member)?;
        self.parent
            .charge(1, types::KEY_BYTES)
            .map_err(budget_error)?;
        let key = crate::raw_index::dense::vector_key(
            self.view.workspace(),
            self.view.generation().number,
            member.source.event_id,
            member.ordinal,
        );
        let vector: DenseVector = self
            .native
            .graph_read(
                self.snapshot,
                &self.native.keyspaces.continuous,
                &key,
                self.parent,
            )?
            .ok_or_else(|| integrity("segment query exact vector is absent"))?;
        self.parent
            .charge(
                1,
                vector.values_bits.len() as u64 * 16
                    + 8192
                    + vector
                        .source
                        .source_version
                        .as_ref()
                        .map_or(0, |version| version.len() as u64 * 8),
            )
            .map_err(budget_error)?;
        self.native.check_dense_vector_token(&vector)?;
        let profile = &self.view.profile_dense().profile;
        if vector.source != member.source
            || vector.event_digest != member.event_digest
            || vector.commit != member.commit
            || vector.ordinal != member.ordinal
            || vector.span != member.span
            || vector.policy_domain != self.namespace.domain()
            || vector.profile_digest != member.profile_digest
            || vector.profile_digest != self.view.profile_dense().profile_digest
            || vector.vector_digest != member.vector_digest
            || vector.values_bits.len() != dimensions
            || dimensions != profile.dimensions as usize
            || dimensions
                .checked_mul(4)
                .is_none_or(|bytes| bytes > max_bytes)
            || vector.tokens_digest.as_bytes() == &[0; 32]
            || vector.token_count == 0
            || vector.token_count > profile.max_input_tokens
        {
            return Err(integrity(
                "segment query vector full source/profile binding differs",
            ));
        }
        graph::query::query_vector_values(profile, vector, self.parent)
    }

    fn observe_score(&mut self, id: RepresentationId, score: f32) -> ServiceResult<()> {
        self.parent.check().map_err(budget_error)?;
        if !score.is_finite() || self.scored_hits.len() >= self.max_scores {
            return Err(integrity(
                "segment score observation exceeds its finite vector bound",
            ));
        }
        let member = self.members.get_mut(&id).ok_or_else(|| {
            integrity("segment scored observation has no locally admitted member")
        })?;
        if member.scored {
            return Err(integrity(
                "segment scored observation repeats a cached vector",
            ));
        }
        // The full finite buffer was admitted before traversal. Only this exact
        // source's variable clone is allocated here; push cannot grow the buffer.
        self.parent
            .charge(
                1,
                size_of::<DenseGraphHit>() as u64
                    + member
                        .source
                        .source_version
                        .as_ref()
                        .map_or(0, |version| version.len() as u64 * 8)
                    + 256,
            )
            .map_err(budget_error)?;
        self.scored_hits.push(DenseGraphHit {
            representation_id: id,
            source: member.source.clone(),
            span: member.span.clone(),
            score,
        });
        member.scored = true;
        Ok(())
    }
}
