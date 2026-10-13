//! Authenticated point reads for coarse routing and genuine fine source spans.
use super::*;
use crate::raw_index::dense::graph::{prefix_segments_v2, prefix_v2};
use crate::raw_index::dense::vector_key as source_vector_key;
use contextdb_index::{
    AnnObjectKeyV2, AnnObjectReadRequestV2, AnnObjectReadResponseV2, AnnObjectV2,
    AnnPartitionManifestV2, AnnPartitionQueryCompletionV2, AnnPartitionQueryErrorV2,
    AnnPartitionQueryLimitsV2, AnnPartitionQueryReaderV2, AnnPartitionQueryV2, VectorSpace,
    search_ann_partition_v2,
};
use fine::VerifiedRoutedFinePath;
use ledger::{Caps, QueryLedger};
use prefix_segments_v2::types::{PrefixSegCohortV2, PrefixSegMemberV2, PrefixSegNodeV2};
use prefix_v2::types::{PrefixCohortV2, PrefixMemberV2, PrefixNodeV2};
use view::VerifiedRoutedQueryView;

pub(super) enum FineCohort {
    Base(PrefixCohortV2),
    Segment(PrefixSegCohortV2),
}
impl FineCohort {
    pub(super) fn policies(&self) -> &[AccessPolicy] {
        match self {
            Self::Base(c) => &c.policies,
            Self::Segment(c) => &c.policies,
        }
    }
    pub(super) fn domain(&self) -> &str {
        match self {
            Self::Base(c) => &c.policy_domain,
            Self::Segment(c) => &c.policy_domain,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Namespace<'a> {
    Coarse {
        cohort: &'a DirectoryRouterCohortV1,
    },
    Fine {
        path: &'a VerifiedRoutedFinePath,
        cohort: &'a FineCohort,
    },
}
impl Namespace<'_> {
    fn policies(&self) -> &[AccessPolicy] {
        match self {
            Self::Coarse { cohort } => &cohort.policies,
            Self::Fine { cohort, .. } => cohort.policies(),
        }
    }
    fn domain(&self) -> &str {
        match self {
            Self::Coarse { cohort } => &cohort.policy_domain,
            Self::Fine { cohort, .. } => cohort.domain(),
        }
    }
    fn member_key(
        &self,
        view: &VerifiedRoutedQueryView,
        id: RepresentationId,
    ) -> ServiceResult<Vec<u8>> {
        let ws = view.workspace();
        let generation = view.generation().number;
        match self {
            Self::Coarse { .. } => {
                types::member_key(ws, generation, view.router().manifest.serial, id)
            }
            Self::Fine {
                path: VerifiedRoutedFinePath::Base { .. },
                ..
            } => prefix_v2::types::member_key(ws, generation, id),
            Self::Fine {
                path: VerifiedRoutedFinePath::Segment { publication, .. },
                ..
            } => prefix_segments_v2::types::segment_member_key(
                ws,
                generation,
                publication.delta.manifest.ordinal,
                id,
            ),
        }
    }
    fn node_key(
        &self,
        view: &VerifiedRoutedQueryView,
        id: RepresentationId,
    ) -> ServiceResult<Vec<u8>> {
        let ws = view.workspace();
        let generation = view.generation().number;
        match self {
            Self::Coarse { .. } => {
                types::node_key(ws, generation, view.router().manifest.serial, id)
            }
            Self::Fine {
                path: VerifiedRoutedFinePath::Base { .. },
                ..
            } => prefix_v2::types::node_key(ws, generation, id),
            Self::Fine {
                path: VerifiedRoutedFinePath::Segment { publication, .. },
                ..
            } => prefix_segments_v2::types::segment_node_key(
                ws,
                generation,
                publication.delta.manifest.ordinal,
                id,
            ),
        }
    }
}
pub(super) struct PartitionDiscovery {
    pub(super) hits: Vec<DenseGraphHit>,
    pub(super) scores: Vec<HybridCoarseScore>,
    pub(super) completion: AnnPartitionQueryCompletionV2,
    pub(super) node_reads: u64,
    pub(super) vector_reads: u64,
    pub(super) discovered: u64,
}
#[derive(Clone)]
struct SourceMember {
    identity_digest: ContentDigest,
    source: RawSource,
    event_digest: ContentDigest,
    commit: u64,
    ordinal: u32,
    span: OriginalSourceSpan,
    profile_digest: ContentDigest,
    vector_digest: ContentDigest,
}
enum Member {
    Route(DirectoryRouterMemberV1),
    Source(SourceMember),
}
struct CachedMember {
    value: Member,
    scored: bool,
}
struct Reader<'a, S> {
    native: &'a NativeService,
    snapshot: &'a S,
    context: &'a AuthenticatedRequestContext,
    view: &'a VerifiedRoutedQueryView,
    namespace: Namespace<'a>,
    partition: &'a AnnPartitionManifestV2,
    space: &'a VectorSpace,
    ledger: &'a mut QueryLedger,
    parent: &'a mut QueryBudget,
    members: BTreeMap<RepresentationId, CachedMember>,
    sources: BTreeMap<ObservationId, DenseDocument>,
    hits: Vec<DenseGraphHit>,
    scores: Vec<HybridCoarseScore>,
    max_scores: usize,
}

pub(super) fn charge_policy(
    context: &AuthenticatedRequestContext,
    policies: &[AccessPolicy],
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    let bytes = crypto::metered_json_len(&policies, parent, ROW_BYTES)? as u64;
    parent
        .charge(
            bytes * 32
                + (context.request.audiences.len() + context.request.scopes.len()) as u64
                    * policies.len() as u64
                + 1,
            bytes * 2 + 4096,
        )
        .map_err(budget_error)
}

#[allow(
    clippy::too_many_arguments,
    reason = "accepted view, exact namespace and one shared ledger remain explicit"
)]
pub(super) fn search_partition<S: ReadSnapshot>(
    native: &NativeService,
    snapshot: &S,
    context: &AuthenticatedRequestContext,
    view: &VerifiedRoutedQueryView,
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
            "routed partition needs positive assigned caps",
        ));
    }
    native.check_routed_query_view(context, view, parent)?;
    charge_policy(context, namespace.policies(), parent)?;
    if namespace
        .policies()
        .iter()
        .any(|p| !crate::policy_allows(&context.request, p))
    {
        return Err(crate::permission_denied());
    }
    // Physical signed control bytes include the portable partition. Permission
    // precedes its decoding, acknowledgement and every member/node/vector read.
    let verified = match namespace {
        Namespace::Coarse { cohort } => {
            native.check_router_cohort(view.workspace(), &view.router().manifest, cohort, parent)?
        }
        Namespace::Fine {
            path: VerifiedRoutedFinePath::Base { receipt, .. },
            cohort: FineCohort::Base(row),
        } => native.check_prefix_cohort(view.workspace(), &receipt.manifest, row, parent)?,
        Namespace::Fine {
            path: VerifiedRoutedFinePath::Segment { publication, .. },
            cohort: FineCohort::Segment(row),
        } => native.check_prefix_segment_cohort(
            view.workspace(),
            &publication.delta.manifest,
            row,
            parent,
        )?,
        _ => {
            return Err(integrity(
                "routed fine cohort and accepted path family differ",
            ));
        }
    };
    if verified != *partition
        || embedded.kind != EmbeddingTextKind::Query
        || embedded.profile_digest != view.current_dense().profile_digest
        || embedded.token_count == 0
        || embedded.tokens_digest.as_bytes() == &[0; 32]
    {
        return Err(integrity("routed query supplied partition/profile differs"));
    }
    let space = match namespace {
        Namespace::Coarse { .. } => {
            native
                .directory_router_space(
                    &view.router().manifest.covered,
                    &view.router().manifest.recipe,
                    parent,
                )?
                .1
        }
        Namespace::Fine { path, .. } => {
            let bytes = crypto::metered_json_len(path.dense(), parent, ROW_BYTES)?;
            parent
                .charge(1, bytes as u64 * 4 + 2048)
                .map_err(budget_error)?;
            vector_space(path.dense())
        }
    };
    let beam = ef_search.min(assigned.discovered);
    let max_scores = assigned
        .vectors
        .min(assigned.discovered)
        .min(partition.node_count as usize);
    let row_bytes = match namespace {
        Namespace::Coarse { .. } => size_of::<HybridCoarseScore>(),
        Namespace::Fine { .. } => size_of::<DenseGraphHit>(),
    };
    parent
        .charge(1, max_scores as u64 * row_bytes as u64 + 256)
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
        sources: BTreeMap::new(),
        hits: if matches!(namespace, Namespace::Fine { .. }) {
            Vec::with_capacity(max_scores)
        } else {
            Vec::new()
        },
        scores: if matches!(namespace, Namespace::Coarse { .. }) {
            Vec::with_capacity(max_scores)
        } else {
            Vec::new()
        },
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
    .map_err(|e| match e {
        AnnPartitionQueryErrorV2::Reader(e) => e,
        other => ann_error(other),
    })?;
    reader.fence()?;
    if (reader.scores.len() + reader.hits.len()) as u64 != result.trace.vector_reads {
        return Err(integrity(
            "routed all-score observations differ from vector reads",
        ));
    }
    Ok(PartitionDiscovery {
        hits: reader.hits,
        scores: reader.scores,
        completion: result.completion,
        node_reads: result.trace.node_reads,
        vector_reads: result.trace.vector_reads,
        discovered: result.trace.discovered,
    })
}

impl<S: ReadSnapshot> Reader<'_, S> {
    fn fence(&mut self) -> ServiceResult<()> {
        self.native
            .check_routed_query_view(self.context, self.view, self.parent)
    }
    fn current_source(&mut self, source: &RawSource) -> ServiceResult<()> {
        self.fence()?;
        let current = self
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.native.authorized_capture_policy_with_budget(
            &current,
            self.context,
            source.event_id,
            self.parent,
        )?;
        self.native.authorize_derived_custody_with_budget(
            &current,
            self.context,
            source.event_id,
            self.parent,
        )?;
        let policies = self.native.stored_custody_policies_with_budget(
            &current,
            source.event_id,
            self.parent,
        )?;
        let bytes = crypto::metered_json_len(&policies, self.parent, ROW_BYTES)?;
        self.parent
            .charge(bytes as u64 + 1, 4096)
            .map_err(budget_error)?;
        if policies != self.namespace.policies() {
            return Err(stale_index());
        }
        Ok(())
    }
    fn cache_fee(&mut self) -> ServiceResult<()> {
        let levels =
            u64::from(usize::BITS - self.members.len().saturating_add(1).leading_zeros()) + 2;
        self.parent
            .charge(
                levels * 12,
                levels * (12 * size_of::<(RepresentationId, CachedMember)>() as u64 + 256),
            )
            .map_err(budget_error)
    }
    fn check_whole_member_plan(&mut self, document: &DenseDocument) -> ServiceResult<()> {
        // DenseDocument's old tag has no generation field. Every planned span
        // is therefore joined to the selected fine path's full-final-manifest
        // member authority before any vector read. These are control point
        // reads, not extra ANN discoveries or sibling vector materialization.
        for (ordinal, span) in document.spans.iter().enumerate() {
            self.fence()?;
            let encoded = crypto::metered_encode(
                &(
                    "native-span-ann-member/v1",
                    &self.native.database_id,
                    self.view.workspace(),
                    self.view.generation().number,
                    &document.source,
                    document.event_digest,
                    document.commit,
                    ordinal as u32,
                    &span.span,
                    &document.policy_domain,
                    document.profile_digest,
                    span.vector_digest,
                ),
                self.parent,
                ROW_BYTES,
            )?;
            self.parent
                .charge(encoded.len() as u64 + 1, KEY_BYTES)
                .map_err(budget_error)?;
            let full = ContentDigest::from_bytes(*blake3::hash(&encoded).as_bytes());
            let mut compact = [0; 16];
            compact.copy_from_slice(&full.as_bytes()[..16]);
            compact[6] = (compact[6] & 15) | 128;
            compact[8] = (compact[8] & 63) | 128;
            let id =
                RepresentationId::from_uuid(uuid::Uuid::from_bytes(compact)).map_err(ann_error)?;
            let key = self.namespace.member_key(self.view, id)?;
            let matches = match self.namespace {
                Namespace::Fine {
                    path: VerifiedRoutedFinePath::Base { receipt, .. },
                    ..
                } => {
                    let row: PrefixMemberV2 = self
                        .native
                        .graph_read(
                            self.snapshot,
                            &self.native.keyspaces.continuous,
                            &key,
                            self.parent,
                        )?
                        .ok_or_else(|| integrity("routed complete prefix member plan absent"))?;
                    self.native.check_prefix_member(
                        self.view.workspace(),
                        &receipt.manifest,
                        &row,
                        self.parent,
                    )?;
                    row.representation_id == id
                        && row.identity_digest == full
                        && row.source == document.source
                        && row.event_digest == document.event_digest
                        && row.commit == document.commit
                        && row.ordinal == ordinal as u32
                        && row.span == span.span
                        && row.policy_domain == document.policy_domain
                        && row.profile_digest == document.profile_digest
                        && row.vector_digest == span.vector_digest
                }
                Namespace::Fine {
                    path: VerifiedRoutedFinePath::Segment { publication, .. },
                    ..
                } => {
                    let row: PrefixSegMemberV2 = self
                        .native
                        .graph_read(
                            self.snapshot,
                            &self.native.keyspaces.continuous,
                            &key,
                            self.parent,
                        )?
                        .ok_or_else(|| integrity("routed complete interval member plan absent"))?;
                    self.native.check_prefix_segment_member(
                        self.view.workspace(),
                        &publication.delta.manifest,
                        &row,
                        self.parent,
                    )?;
                    row.representation_id == id
                        && row.identity_digest == full
                        && row.source == document.source
                        && row.event_digest == document.event_digest
                        && row.commit == document.commit
                        && row.ordinal == ordinal as u32
                        && row.span == span.span
                        && row.policy_domain == document.policy_domain
                        && row.profile_digest == document.profile_digest
                        && row.vector_digest == span.vector_digest
                }
                Namespace::Coarse { .. } => {
                    return Err(integrity("routed shared centroid cannot own a source plan"));
                }
            };
            if !matches {
                return Err(integrity(
                    "routed whole source plan differs from accepted fine members",
                ));
            }
        }
        self.fence()
    }
    fn whole_source(&mut self, member: &SourceMember) -> ServiceResult<()> {
        // Fresh authorization precedes both the complete tagged plan and raw
        // attribution metadata. No original body or sibling vector is opened.
        self.current_source(&member.source)?;
        if !self.sources.contains_key(&member.source.event_id) {
            if self.sources.len() >= 256 {
                return Err(exhausted("routed reader source controls exceed frontier"));
            }
            self.parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
            let document: DenseDocument = self
                .native
                .graph_read(
                    self.snapshot,
                    &self.native.keyspaces.continuous,
                    &document_key(
                        self.view.workspace(),
                        self.view.generation().number,
                        member.source.event_id,
                    ),
                    self.parent,
                )?
                .ok_or_else(|| integrity("routed fine whole source plan absent"))?;
            let bytes = crypto::metered_json_len(&document, self.parent, ROW_BYTES)?;
            self.parent
                .charge(bytes as u64 + 1, bytes as u64 * 8 + 8192)
                .map_err(budget_error)?;
            self.native.check_dense_document_token(&document)?;
            let raw_bytes = crate::budgeted::read_value(
                self.snapshot,
                &self.native.keyspaces.continuous,
                &doc_key(
                    self.view.workspace(),
                    self.view.generation().number,
                    member.source.event_id,
                ),
                4 * 1024 * 1024,
                self.parent,
            )?
            .ok_or_else(|| integrity("routed fine actual raw control absent"))?;
            self.parent
                .charge(
                    raw_bytes.len() as u64 + 1,
                    raw_bytes.len() as u64 * 16 + 8192,
                )
                .map_err(budget_error)?;
            let original: IndexedOriginal = decode(&raw_bytes, "routed fine source controls")?;
            self.native.verify_projected_causal_metadata(
                self.snapshot,
                self.view.workspace(),
                &original,
                self.parent,
            )?;
            if document.source != original.source
                || document.event_digest != original.event_digest
                || document.commit != original.commit
                || document.policy_domain != original.policy_domain
                || document.source != member.source
                || document.event_digest != member.event_digest
                || document.commit != member.commit
                || document.profile_digest != member.profile_digest
                || document.profile_digest != self.view.current_dense().profile_digest
                || document.policy_domain != self.namespace.domain()
                || document.omission.is_some()
                || document.spans.is_empty()
                || document.spans.len() > 64
            {
                return Err(integrity(
                    "routed whole source/version/profile control differs",
                ));
            }
            let mut previous_start = None;
            let mut previous_end = 0;
            for span in &document.spans {
                self.parent.charge(1, 0).map_err(budget_error)?;
                if span.span.event_id != document.source.event_id
                    || Some(span.span.payload_digest) != document.source.payload_digest
                    || span.span.start >= span.span.end
                    || document
                        .source
                        .byte_length
                        .is_none_or(|n| span.span.end > n)
                    || span.span.span_digest.as_bytes() == &[0; 32]
                    || span.vector_digest.as_bytes() == &[0; 32]
                    || previous_start.is_none() && span.span.start != 0
                    || previous_start.is_some_and(|start| {
                        span.span.start <= start || span.span.start > previous_end
                    })
                    || span.span.end <= previous_end
                    || span.span.end - span.span.start
                        > u64::from(self.view.current_dense().profile.source_chunk_bytes)
                {
                    return Err(integrity("routed whole source span plan is malformed"));
                }
                previous_start = Some(span.span.start);
                previous_end = span.span.end;
            }
            if Some(previous_end) != document.source.byte_length {
                return Err(integrity(
                    "routed whole span plan leaves original bytes uncovered",
                ));
            }
            self.check_whole_member_plan(&document)?;
            let levels =
                u64::from(usize::BITS - self.sources.len().saturating_add(1).leading_zeros()) + 2;
            self.parent
                .charge(
                    levels * 12,
                    levels * (12 * size_of::<(ObservationId, DenseDocument)>() as u64 + 256),
                )
                .map_err(budget_error)?;
            self.sources.insert(member.source.event_id, document);
        }
        let document = self
            .sources
            .get(&member.source.event_id)
            .ok_or_else(|| integrity("routed source cache absent"))?;
        let span = document
            .spans
            .get(member.ordinal as usize)
            .ok_or_else(|| integrity("routed member ordinal outside complete plan"))?;
        if document.source != member.source
            || document.event_digest != member.event_digest
            || document.commit != member.commit
            || document.policy_domain != self.namespace.domain()
            || document.profile_digest != member.profile_digest
            || span.span != member.span
            || span.vector_digest != member.vector_digest
        {
            return Err(integrity(
                "routed member differs from its actual whole source plan",
            ));
        }
        Ok(())
    }
    fn source_clone(&mut self, id: RepresentationId) -> ServiceResult<SourceMember> {
        let Member::Source(member) = &self
            .members
            .get(&id)
            .ok_or_else(|| integrity("routed fine vector lacks member"))?
            .value
        else {
            return Err(integrity("routed coarse identity used as source"));
        };
        self.parent
            .charge(
                1,
                size_of::<SourceMember>() as u64
                    + member
                        .source
                        .source_version
                        .as_ref()
                        .map_or(0, |v| v.len() as u64 * 8)
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
            return Err(integrity("routed exact partition acknowledgement differs"));
        }
        self.fence()
    }
    fn admit_member(
        &mut self,
        partition: &AnnPartitionManifestV2,
        id: RepresentationId,
    ) -> ServiceResult<()> {
        if partition != self.partition {
            return Err(integrity("routed member partition differs"));
        }
        self.fence()?;
        if self.members.contains_key(&id) {
            return Ok(());
        }
        self.parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = self.namespace.member_key(self.view, id)?;
        let member = match self.namespace {
            Namespace::Coarse { .. } => {
                let row: DirectoryRouterMemberV1 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed coarse member absent"))?;
                self.native.check_router_member(
                    self.view.workspace(),
                    &self.view.router().manifest,
                    &row,
                    self.parent,
                )?;
                if row.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("routed coarse member namespace differs"));
                }
                self.ledger.admit_route(
                    id,
                    row.identity_digest,
                    &row.path,
                    &row.policy_domain,
                    self.parent,
                )?;
                Member::Route(row)
            }
            Namespace::Fine {
                path: VerifiedRoutedFinePath::Base { receipt, .. },
                ..
            } => {
                let row: PrefixMemberV2 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed prefix member absent"))?;
                self.native.check_prefix_member(
                    self.view.workspace(),
                    &receipt.manifest,
                    &row,
                    self.parent,
                )?;
                if row.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("routed prefix member namespace differs"));
                }
                Member::Source(SourceMember {
                    identity_digest: row.identity_digest,
                    source: row.source,
                    event_digest: row.event_digest,
                    commit: row.commit,
                    ordinal: row.ordinal,
                    span: row.span,
                    profile_digest: row.profile_digest,
                    vector_digest: row.vector_digest,
                })
            }
            Namespace::Fine {
                path: VerifiedRoutedFinePath::Segment { publication, .. },
                ..
            } => {
                let row: PrefixSegMemberV2 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed prefix segment member absent"))?;
                self.native.check_prefix_segment_member(
                    self.view.workspace(),
                    &publication.delta.manifest,
                    &row,
                    self.parent,
                )?;
                if row.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("routed prefix segment member namespace differs"));
                }
                Member::Source(SourceMember {
                    identity_digest: row.identity_digest,
                    source: row.source,
                    event_digest: row.event_digest,
                    commit: row.commit,
                    ordinal: row.ordinal,
                    span: row.span,
                    profile_digest: row.profile_digest,
                    vector_digest: row.vector_digest,
                })
            }
        };
        if let Member::Source(source) = &member {
            self.whole_source(source)?;
            self.ledger.admit_span(
                id,
                source.identity_digest,
                &source.source,
                &source.span,
                self.parent,
            )?;
        }
        self.cache_fee()?;
        if self
            .members
            .insert(
                id,
                CachedMember {
                    value: member,
                    scored: false,
                },
            )
            .is_some()
        {
            return Err(integrity("routed reader repeats uncached identity"));
        }
        Ok(())
    }
    fn read_node(
        &mut self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> ServiceResult<AnnObjectReadResponseV2> {
        self.parent
            .charge(1, KEY_BYTES * 3 + 256)
            .map_err(budget_error)?;
        request.validate().map_err(ann_error)?;
        let bytes = request
            .key
            .as_bytes()
            .get(42..58)
            .ok_or_else(|| integrity("routed node object key differs"))?;
        let id = RepresentationId::from_uuid(uuid::Uuid::from_slice(bytes).map_err(ann_error)?)
            .map_err(ann_error)?;
        if !self.members.contains_key(&id)
            || request.key
                != &AnnObjectKeyV2::node(
                    self.view.generation().number,
                    self.partition.partition_key,
                    id,
                )
                .map_err(ann_error)?
        {
            return Err(integrity("routed node lacks admitted exact member"));
        }
        self.fence()?;
        self.parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = self.namespace.node_key(self.view, id)?;
        let canonical = match self.namespace {
            Namespace::Coarse { .. } => {
                let row: DirectoryRouterNodeV1 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed coarse node absent"))?;
                let node = self.native.check_router_node(
                    self.view.workspace(),
                    &self.view.router().manifest,
                    &row,
                    self.parent,
                )?;
                if node.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("routed coarse node namespace differs"));
                }
                row.canonical_node
            }
            Namespace::Fine {
                path: VerifiedRoutedFinePath::Base { receipt, .. },
                ..
            } => {
                let row: PrefixNodeV2 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed prefix node absent"))?;
                let node = self.native.check_prefix_node(
                    self.view.workspace(),
                    &receipt.manifest,
                    &row,
                    self.parent,
                )?;
                if node.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("routed prefix node namespace differs"));
                }
                row.canonical_node
            }
            Namespace::Fine {
                path: VerifiedRoutedFinePath::Segment { publication, .. },
                ..
            } => {
                let row: PrefixSegNodeV2 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &key,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed prefix segment node absent"))?;
                let node = self.native.check_prefix_segment_node(
                    self.view.workspace(),
                    &publication.delta.manifest,
                    &row,
                    self.parent,
                )?;
                if node.representation_id != id || row.policy_domain != self.namespace.domain() {
                    return Err(integrity("routed prefix segment node namespace differs"));
                }
                row.canonical_node
            }
        };
        if canonical.len() > request.max_bytes {
            return Err(integrity("routed node exceeds requested bytes"));
        }
        self.parent
            .charge(canonical.len() as u64 + 1, KEY_BYTES)
            .map_err(budget_error)?;
        let object = AnnObjectV2::new(request.key.clone(), canonical).map_err(ann_error)?;
        AnnObjectReadResponseV2::new(request, Some(object)).map_err(ann_error)
    }
    fn read_vector(
        &mut self,
        id: RepresentationId,
        dimensions: usize,
        max_bytes: usize,
    ) -> ServiceResult<Vec<f32>> {
        self.fence()?;
        if dimensions != self.view.current_dense().profile.dimensions as usize
            || dimensions.checked_mul(4).is_none_or(|n| n > max_bytes)
        {
            return Err(integrity("routed vector request dimension differs"));
        }
        match self.namespace {
            Namespace::Coarse { .. } => {
                let Member::Route(member) = &self
                    .members
                    .get(&id)
                    .ok_or_else(|| integrity("routed coarse vector lacks member"))?
                    .value
                else {
                    return Err(integrity("routed source used as coarse identity"));
                };
                self.parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                let row: DirectoryRouterVectorV1 = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &types::vector_key(
                            self.view.workspace(),
                            self.view.generation().number,
                            self.view.router().manifest.serial,
                            id,
                        )?,
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed coarse vector absent"))?;
                if row.representation_id != id
                    || row.identity_digest != member.identity_digest
                    || row.policy_domain != self.namespace.domain()
                    || row.vector_digest != member.vector_digest
                    || row.values_bits.len() != dimensions
                {
                    return Err(integrity("routed coarse vector/member binding differs"));
                }
                self.native.check_router_vector(
                    self.view.workspace(),
                    &self.view.router().manifest,
                    &row,
                    self.parent,
                )
            }
            Namespace::Fine { .. } => {
                let member = self.source_clone(id)?;
                self.whole_source(&member)?;
                self.parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                let vector: DenseVector = self
                    .native
                    .graph_read(
                        self.snapshot,
                        &self.native.keyspaces.continuous,
                        &source_vector_key(
                            self.view.workspace(),
                            self.view.generation().number,
                            member.source.event_id,
                            member.ordinal,
                        ),
                        self.parent,
                    )?
                    .ok_or_else(|| integrity("routed fine exact vector absent"))?;
                let bytes = crypto::metered_json_len(&vector, self.parent, ROW_BYTES)?;
                self.parent
                    .charge(1, bytes as u64 * 4 + 8192)
                    .map_err(budget_error)?;
                self.native.check_dense_vector_token(&vector)?;
                let profile = &self.view.current_dense().profile;
                if vector.source != member.source
                    || vector.event_digest != member.event_digest
                    || vector.commit != member.commit
                    || vector.ordinal != member.ordinal
                    || vector.span != member.span
                    || vector.policy_domain != self.namespace.domain()
                    || vector.profile_digest != member.profile_digest
                    || vector.profile_digest != self.view.current_dense().profile_digest
                    || vector.vector_digest != member.vector_digest
                    || vector.values_bits.len() != dimensions
                    || vector.input_digest.as_bytes() == &[0; 32]
                    || vector.tokens_digest.as_bytes() == &[0; 32]
                    || vector.token_count == 0
                    || vector.token_count > profile.max_input_tokens
                {
                    return Err(integrity("routed fine vector full source/profile differs"));
                }
                super::super::super::query::query_vector_values(profile, vector, self.parent)
            }
        }
    }
    fn observe_score(&mut self, id: RepresentationId, score: f32) -> ServiceResult<()> {
        self.parent.check().map_err(budget_error)?;
        if !score.is_finite() || self.hits.len() + self.scores.len() >= self.max_scores {
            return Err(integrity(
                "routed score exceeds finite prepaid observations",
            ));
        }
        let member = self
            .members
            .get_mut(&id)
            .ok_or_else(|| integrity("routed score lacks admitted member"))?;
        if member.scored {
            return Err(integrity("routed score repeats cached vector"));
        }
        match &member.value {
            Member::Route(row) => {
                let bytes = crypto::metered_json_len(
                    &(&row.path, &row.policy_domain),
                    self.parent,
                    ROW_BYTES,
                )?;
                self.parent
                    .charge(
                        1,
                        bytes as u64 * 4 + size_of::<HybridCoarseScore>() as u64 + 256,
                    )
                    .map_err(budget_error)?;
                self.scores.push(HybridCoarseScore {
                    representation_id: id,
                    identity_digest: row.identity_digest,
                    path: row.path.clone(),
                    fine_partition_digest: row.fine_partition_digest,
                    policy_domain: row.policy_domain.clone(),
                    score_bits: score.to_bits(),
                });
            }
            Member::Source(row) => {
                self.parent
                    .charge(
                        1,
                        size_of::<DenseGraphHit>() as u64
                            + row
                                .source
                                .source_version
                                .as_ref()
                                .map_or(0, |v| v.len() as u64 * 8)
                            + 256,
                    )
                    .map_err(budget_error)?;
                self.hits.push(DenseGraphHit {
                    representation_id: id,
                    source: row.source.clone(),
                    span: row.span.clone(),
                    score,
                });
            }
        }
        member.scored = true;
        Ok(())
    }
}
