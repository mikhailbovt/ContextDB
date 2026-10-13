//! Owner-private accepted query view; immutable ordinal acceptance is not freshness.
use super::super::verification::VerifiedSegmentHead;
use super::*;

pub(crate) struct VerifiedSegmentQueryView {
    workspace: String,
    generation: Generation,
    base: DenseGraphReceipt,
    head: VerifiedSegmentHead,
    known_at: u64,
    identity: ContentDigest,
}
impl VerifiedSegmentQueryView {
    pub(super) fn workspace(&self) -> &str {
        &self.workspace
    }
    pub(super) fn generation(&self) -> &Generation {
        &self.generation
    }
    pub(super) fn base(&self) -> &DenseGraphReceipt {
        &self.base
    }
    pub(super) fn head(&self) -> &VerifiedSegmentHead {
        &self.head
    }
    pub(super) fn known_at(&self) -> u64 {
        self.known_at
    }
    pub(crate) fn identity(&self) -> ContentDigest {
        self.identity
    }
    pub(super) fn profile_dense(&self) -> &DenseManifest {
        self.generation
            .dense
            .as_ref()
            .expect("accepted query view requires current dense manifest")
    }
}

impl NativeService {
    pub(super) fn segment_query_view<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<VerifiedSegmentQueryView> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, budget)?;
        for capability in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, budget)?;
        }
        budget
            .charge(1, context.request.workspace_id.len() as u64 * 2 + 4096)
            .map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        crate::budgeted::metadata(snapshot, budget, |r| {
            self.require_custody_ready(r, &workspace)
        })?;
        let state: IndexState = self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                budget,
            )?
            .ok_or_else(stale_index)?;
        let number = state.active.ok_or_else(stale_index)?;
        let generation: Generation = self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if self.graph_epoch(snapshot, &workspace, budget)? != generation.authorization_epoch {
            return Err(stale_index());
        }
        let base = self.accepted_graph_receipt(snapshot, &workspace, &generation, budget)?;
        self.admit_tail_generation(&generation, &base.manifest, budget)?;
        self.tail_dense_receipt(snapshot, &workspace, &generation, budget)?;
        if generation.dense_segments.is_none() {
            let world =
                self.current_segment_heads(snapshot, &context.request.workspace_id, budget)?;
            if world
                .segment_heads
                .as_ref()
                .is_some_and(|heads| heads.contains_key(&generation.number))
            {
                return Err(integrity(
                    "segmented query pointer differs from retained workspace head",
                ));
            }
            self.no_prior_segment_declaration(snapshot, &workspace, generation.number, budget)?;
            self.require_no_segment_rows(snapshot, &workspace, generation.number, budget)?;
            return Err(stale_index());
        }
        let head = self.accepted_current_segment_head(
            snapshot,
            &context.request.workspace_id,
            &generation,
            budget,
        )?;
        let current = generation.dense.as_ref().ok_or_else(stale_index)?;
        let covered = head.covered();
        let binding = &head.publication().delta.manifest.binding;
        if covered.profile != current.profile
            || covered.profile_digest != current.profile_digest
            || covered.vector_space_id != current.vector_space_id
            || covered.through < base.manifest.dense.through
            || covered.through > current.through
            || covered.sources > current.sources
            || covered.spans > current.spans
            || covered.embedded_sources > current.embedded_sources
            || covered.omitted_sources > current.omitted_sources
            || (covered.through == current.through && covered != current)
            || binding.custody_version != generation.custody_version
            || binding.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&binding.bm25)
        {
            return Err(integrity(
                "segmented query covered prefix differs from current accepted generation",
            ));
        }
        let world = self.current_segment_heads(snapshot, &context.request.workspace_id, budget)?;
        let bytes = crypto::metered_encode(
            &(
                "contextdb.native-segment-query-view.v1",
                &workspace,
                &generation,
                &base,
                head.publication(),
                world.watermarks.journal,
            ),
            budget,
            4 * ROW_BYTES,
        )?;
        let identity = digest(&bytes);
        Ok(VerifiedSegmentQueryView {
            workspace,
            generation,
            base,
            head,
            known_at: world.watermarks.journal,
            identity,
        })
    }

    pub(crate) fn check_segment_query_view(
        &self,
        context: &AuthenticatedRequestContext,
        view: &VerifiedSegmentQueryView,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.check().map_err(budget_error)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let cost = crate::budgeted::auth::ContextCost::for_context(context, budget)?;
        for capability in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, budget)?;
        }
        crate::budgeted::metadata(&current, budget, |r| {
            self.require_custody_ready(r, view.workspace())
        })?;
        let world = self.current_segment_heads(&current, &context.request.workspace_id, budget)?;
        if world.workspace_digest != view.workspace()
            || world.watermarks.journal != view.known_at()
            || self.graph_epoch(&current, view.workspace(), budget)?
                != view.generation().authorization_epoch
        {
            return Err(stale_index());
        }
        budget.charge(1, 4096).map_err(budget_error)?;
        let state: IndexState = self
            .graph_read(
                &current,
                &self.keyspaces.continuous,
                &state_key(view.workspace()),
                budget,
            )?
            .ok_or_else(stale_index)?;
        let generation: Generation = self
            .graph_read(
                &current,
                &self.keyspaces.continuous,
                &generation_key(view.workspace(), view.generation().number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(generation.number) || &generation != view.generation() {
            return Err(stale_index());
        }
        let live: types::DenseSegmentDirectoryReceipt = self
            .graph_read(
                &current,
                &self.keyspaces.continuous,
                &types::directory_head_key(view.workspace(), generation.number)?,
                budget,
            )?
            .ok_or_else(|| integrity("segmented query current directory row absent"))?;
        let compared_bytes = crypto::metered_json_len(
            &(&live, &view.head().publication().directory),
            budget,
            2 * ROW_BYTES,
        )?;
        budget
            .charge(1, compared_bytes as u64 * 4 + 256)
            .map_err(budget_error)?;
        if live != view.head().publication().directory {
            return Err(integrity(
                "segmented query directory changed during traversal",
            ));
        }
        self.tail_dense_receipt(&current, view.workspace(), &generation, budget)?;
        if self.accepted_graph_receipt(&current, view.workspace(), &generation, budget)?
            != *view.base()
        {
            return Err(stale_index());
        }
        budget.check().map_err(budget_error)
    }

    /// Current accepted head binding before any owned query processing callback.
    pub(crate) fn admit_owned_segmented_query_embedding_profile(
        &self,
        context: &AuthenticatedRequestContext,
        profile: &TextEmbeddingProfile,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(ContentDigest, VerifiedSegmentQueryView)> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let view = self.segment_query_view(&snapshot, context, budget)?;
        budget.charge(1, 16384).map_err(budget_error)?;
        profile.validate()?;
        if profile != &view.profile_dense().profile
            || profile.digest()? != view.profile_dense().profile_digest
        {
            return Err(crate::invalid(
                "segmented query encoder differs from accepted original vector space",
            ));
        }
        self.check_segment_query_view(context, &view, budget)?;
        Ok((view.base().manifest.content_digest, view))
    }
}
