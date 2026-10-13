//! Point-admitted serving authority. No maintenance census or ANN work.

use super::super::super::prefix_segments_v2::types::{
    PrefixSegmentDirectoryReceiptV2, PrefixSegmentPublicationV2,
};
use super::super::super::prefix_v2::types::DensePrefixBaseReceiptV2;
use super::super::super::prefix_v2::verification::decode_allowance;
use super::super::super::segments::crypto::{metered_encode, metered_json_len};
use super::super::types::cohort_key;
use super::super::verification::directory_router_request_digest;
use super::super::*;
use std::mem::size_of;

#[path = "points.rs"]
mod points;
pub(in crate::raw_index::dense::graph::routing) use points::{
    RoutedPointBase, RoutedPointDirectory,
};

pub(crate) struct VerifiedRoutedQueryView {
    workspace: String,
    generation: Generation,
    world: crate::WorkspaceState,
    base: DensePrefixBaseReceiptV2,
    router: DirectoryRouterReceiptV1,
    head: Option<PrefixSegmentPublicationV2>,
    current_receipt: DenseProjectionReceipt,
    current_dense_ref: AcceptedPublicationRef,
    principal: String,
    allowed_cohorts: Vec<DirectoryRouterCohortV1>,
    identity: ContentDigest,
}
impl VerifiedRoutedQueryView {
    pub(crate) fn workspace(&self) -> &str {
        &self.workspace
    }
    pub(crate) fn generation(&self) -> &Generation {
        &self.generation
    }
    pub(crate) fn base(&self) -> &DensePrefixBaseReceiptV2 {
        &self.base
    }
    pub(super) fn current_directory(&self) -> Option<&PrefixSegmentPublicationV2> {
        self.head.as_ref()
    }
    pub(crate) fn router(&self) -> &DirectoryRouterReceiptV1 {
        &self.router
    }
    pub(crate) fn current_dense(&self) -> &DenseManifest {
        self.generation
            .dense
            .as_ref()
            .expect("private routed view requires dense")
    }
    pub(crate) fn current_dense_ref(&self) -> &AcceptedPublicationRef {
        &self.current_dense_ref
    }
    pub(crate) fn ending(&self) -> &CaptureBoundaryRefV2 {
        &self.router.manifest.ending
    }
    pub(crate) fn identity(&self) -> ContentDigest {
        self.identity
    }
    pub(crate) fn known_at(&self) -> u64 {
        self.world.watermarks.journal
    }
    pub(crate) fn allowed_cohorts(&self) -> &[DirectoryRouterCohortV1] {
        &self.allowed_cohorts
    }
}

impl NativeService {
    pub(crate) fn routed_query_view<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedRoutedQueryView> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, parent)?;
        for capability in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, parent)?;
        }
        parent
            .charge(1, context.request.workspace_id.len() as u64 * 4 + 8192)
            .map_err(budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        crate::budgeted::metadata(snapshot, parent, |r| {
            self.require_custody_ready(r, &workspace)
        })?;
        let world =
            self.current_directory_router_heads(snapshot, &context.request.workspace_id, parent)?;
        parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
        let state: IndexState = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let number = state.active.ok_or_else(stale_index)?;
        let generation: Generation = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        if generation.number != number
            || generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != RAW_ANALYZER
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || self.graph_epoch(snapshot, &workspace, parent)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        self.validate_raw_bm25_generation(snapshot, &generation, parent)?;
        self.validate_dense_generation(snapshot, &workspace, &generation, parent)?;
        let root = generation
            .dense_directory_router
            .as_ref()
            .ok_or_else(stale_index)?;
        if world
            .directory_routers
            .as_ref()
            .and_then(|m| m.get(&number))
            != Some(root)
            || world.prefix_bases.as_ref().and_then(|m| m.get(&number))
                != generation.dense_prefix_base.as_ref()
            || world
                .prefix_segment_heads
                .as_ref()
                .and_then(|m| m.get(&number))
                != generation.dense_prefix_segments.as_ref()
        {
            return Err(integrity(
                "routed view differs from certified current four maps",
            ));
        }
        let router = self.routed_point_router(snapshot, &workspace, number, root, parent)?;
        let admitted_base =
            self.routed_point_base(snapshot, &workspace, &generation, &world, parent)?;
        let base = &admitted_base.receipt;
        if router.manifest.coverage.base != admitted_base.reference
            || router.manifest.coverage.directory != generation.dense_prefix_segments
        {
            return Err(stale_index());
        }
        let admitted_directory = if generation.dense_prefix_segments.is_some() {
            Some(self.routed_point_directory(
                snapshot,
                &workspace,
                &generation,
                &world,
                &admitted_base,
                parent,
            )?)
        } else {
            None
        };
        if admitted_directory
            .as_ref()
            .map(|directory| &directory.reference)
            != generation.dense_prefix_segments.as_ref()
        {
            return Err(integrity(
                "routed admitted directory differs from current head",
            ));
        }
        let covered = &router.manifest.covered;
        let head = admitted_directory
            .as_ref()
            .map(|directory| &directory.publication);
        let (covered_receipt, covered_ref) = admitted_directory.as_ref().map_or(
            (&admitted_base.target, &base.manifest.target),
            |directory| {
                (
                    &directory.covered,
                    &directory.publication.directory.head.covered_dense,
                )
            },
        );
        parent.charge(1, 8192).map_err(budget_error)?;
        let covered_manifest = covered_receipt.manifest()?;
        if &covered_manifest != covered
            || router.manifest.covered_dense != *covered_ref
            || covered_receipt.generation != number
            || covered_receipt.authorization_epoch != generation.authorization_epoch
        {
            return Err(integrity("routed covered dense acceptance differs"));
        }
        self.verify_prefix_segment_capture_boundary(
            snapshot,
            &workspace,
            &router.manifest.ending,
            parent,
        )?;
        match head {
            Some(head)
                if head.directory.head.covered != *covered
                    || head.directory.head.covered_dense != router.manifest.covered_dense
                    || head.directory.head.ending != router.manifest.ending =>
            {
                return Err(integrity("routed sealed ending differs from fine head"));
            }
            None if base.manifest.prefix != *covered
                || base.manifest.target != router.manifest.covered_dense =>
            {
                return Err(integrity("routed base-only dense target differs"));
            }
            _ => {}
        }
        let current: DenseProjectionReceipt = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &dense::receipt_key(&workspace, number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let current_ref = self.prefix_publication_ref(snapshot, current.global_commit, parent)?;
        let current_manifest = if current_ref == *covered_ref {
            if current != *covered_receipt {
                return Err(integrity("routed current/covered dense receipt differs"));
            }
            covered_manifest
        } else {
            let (accepted, manifest) =
                self.prefix_dense_target_binding(snapshot, &workspace, &current_ref, parent)?;
            if accepted != current {
                return Err(integrity("routed current dense receipt differs"));
            }
            manifest
        };
        let latest = generation.dense.as_ref().ok_or_else(stale_index)?;
        self.check_routed_projection_recency(
            snapshot,
            &workspace,
            &generation,
            &current,
            &current_ref,
            &world,
            parent,
        )?;
        let raw = &router.manifest.raw;
        if &current_manifest != latest
            || current.generation != number
            || current.authorization_epoch != generation.authorization_epoch
            || raw.generation != number
            || raw.custody_version != generation.custody_version
            || raw.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&raw.bm25)
            || raw.authorization_epoch != generation.authorization_epoch
            || raw.removal_through != generation.removal_through
            || raw.through > generation.through
            || raw.projected_sources > generation.projected_sources
            || (raw.through == generation.through
                && raw.projected_sources != generation.projected_sources)
            || covered.profile != latest.profile
            || covered.profile_digest != latest.profile_digest
            || covered.vector_space_id != latest.vector_space_id
            || covered.through > latest.through
            || covered.sources > latest.sources
            || covered.spans > latest.spans
            || covered.embedded_sources > latest.embedded_sources
            || covered.omitted_sources > latest.omitted_sources
            || (covered.through == latest.through && covered != latest)
            || router.manifest.ending.work.workspace_commit > covered.through
            || router.manifest.ending.global_commit > router.manifest.covered_dense.global_commit
        {
            return Err(integrity(
                "routed actual raw/dense/profile/capture admission differs",
            ));
        }
        let (space_digest, space) =
            self.directory_router_space(covered, &router.manifest.recipe, parent)?;
        if space_digest != router.manifest.coarse_space_digest
            || space.id != router.manifest.coarse_space_id
        {
            return Err(integrity(
                "routed coarse space differs from genuine query profile",
            ));
        }
        parent
            .charge(
                1,
                MAX_COHORTS as u64 * size_of::<DirectoryRouterCohortV1>() as u64 + 8192,
            )
            .map_err(budget_error)?;
        let mut allowed_cohorts = Vec::with_capacity(MAX_COHORTS);
        for summary in &router.manifest.cohorts {
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let row: DirectoryRouterCohortV1 = self
                .prefix_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &cohort_key(
                        &workspace,
                        number,
                        router.manifest.serial,
                        &summary.policy_domain,
                    )?,
                    parent,
                )?
                .ok_or_else(|| integrity("routed policy control row absent"))?;
            self.check_router_cohort_control(&workspace, &router.manifest, &row, parent)?;
            let bytes = metered_json_len(&row.policies, parent, ROW_BYTES)?;
            parent
                .charge(
                    bytes as u64 * 32
                        + row.policies.len() as u64
                            * (context.request.audiences.len() + context.request.scopes.len())
                                as u64
                        + 1,
                    0,
                )
                .map_err(budget_error)?;
            if row
                .policies
                .iter()
                .all(|p| crate::policy_allows(&context.request, p))
            {
                allowed_cohorts.push(row);
            }
        }
        let principal = cost.binding_digest(context, parent)?;
        // The accepted full router root plus exact principal already fixes each
        // admitted policy control. Do not duplicate up to 64 full opaque rows.
        let bytes = metered_encode(
            &(
                "contextdb.native-routed-query-view.v1",
                &workspace,
                &generation,
                &router,
                &current_ref,
                &world,
                &principal,
            ),
            parent,
            8 * ROW_BYTES,
        )?;
        parent
            .charge(
                bytes.len() as u64 + 1,
                size_of::<VerifiedRoutedQueryView>() as u64 + 256,
            )
            .map_err(budget_error)?;
        let view = VerifiedRoutedQueryView {
            workspace,
            generation,
            world,
            base: admitted_base.receipt,
            router,
            head: admitted_directory.map(|directory| directory.publication),
            current_receipt: current,
            current_dense_ref: current_ref,
            principal,
            allowed_cohorts,
            identity: digest(&bytes),
        };
        self.check_routed_query_view(context, &view, parent)?;
        Ok(view)
    }

    pub(in crate::raw_index::dense::graph::routing) fn routed_point_router<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        root: &DirectoryRouterRefV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterReceiptV1> {
        self.require_directory_router_feature(snapshot, parent)?;
        let reference = self.prefix_publication_ref(snapshot, root.global_commit, parent)?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(
                snapshot,
                &self.keyspaces.idempotency,
                &retained_locator_key(workspace, generation, root.serial)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed retained locator absent"))?;
        decode_allowance(&stored.response_bytes, MAX_PUBLICATION_BYTES, parent)?;
        let locator: RetainedDirectoryRouterLocatorV1 =
            decode(&stored.response_bytes, "routed point locator")?;
        self.check_retained_directory_router_locator(workspace, &locator, parent)?;
        let encoded = metered_encode(&locator, parent, MAX_PUBLICATION_BYTES)?;
        if locator.publication != reference
            || locator.generation != generation
            || locator.serial != root.serial
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != LOCATOR_OPERATION
            || stored.request_digest != digest_bytes(&encoded)
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || encoded != stored.response_bytes
            || reference.request_digest != root.request_digest
            || reference.response_digest != root.response_digest
        {
            return Err(integrity("routed locator/current native root differs"));
        }
        let receipt =
            self.directory_router_point_receipt(snapshot, workspace, &reference, parent)?;
        let bytes = metered_encode(&receipt, parent, MAX_PUBLICATION_BYTES)?;
        let (event, _) =
            self.prefix_accepted_response(snapshot, workspace, &reference, OPERATION, parent)?;
        parent.charge(1, 16384).map_err(budget_error)?;
        let request = DirectoryRouterPublishRequestV1 {
            generation,
            previous: receipt.manifest.previous.clone(),
            coverage: receipt.manifest.coverage.clone(),
        };
        if receipt.manifest.serial != root.serial
            || digest(&bytes) != root.receipt_digest
            || receipt.manifest.content_digest != root.content_digest
            || receipt.manifest.raw.generation != generation
            || receipt.manifest.admitted_global_commit.checked_add(1) != Some(receipt.global_commit)
            || receipt.manifest.admitted_known_at.checked_add(1) != Some(event.workspace_commit)
            || directory_router_request_digest(&self.database_id, workspace, &request, parent)?
                != reference.request_digest
        {
            return Err(integrity(
                "routed native primary/request/root admission differs",
            ));
        }
        let live: DirectoryRouterReceiptV1 = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &head_key(workspace, generation)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed live head absent"))?;
        if live != receipt {
            return Err(integrity("routed live head differs from native acceptance"));
        }
        Ok(receipt)
    }

    pub(crate) fn admit_owned_routed_query_embedding_profile(
        &self,
        context: &AuthenticatedRequestContext,
        profile: &TextEmbeddingProfile,
        parent: &mut QueryBudget,
    ) -> ServiceResult<(ContentDigest, VerifiedRoutedQueryView)> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let view = self.routed_query_view(&snapshot, context, parent)?;
        let bytes = metered_json_len(profile, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 4 + 8192)
            .map_err(budget_error)?;
        profile.validate()?;
        if profile != &view.current_dense().profile
            || profile.digest()? != view.current_dense().profile_digest
        {
            return Err(crate::invalid(
                "routed query encoder differs from admitted source profile",
            ));
        }
        Ok((view.identity(), view))
    }

    pub(crate) fn check_routed_query_view(
        &self,
        context: &AuthenticatedRequestContext,
        view: &VerifiedRoutedQueryView,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.routed_view_fence(context, view, true, parent)
    }

    fn routed_view_fence(
        &self,
        context: &AuthenticatedRequestContext,
        view: &VerifiedRoutedQueryView,
        strict_journal: bool,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, parent)?;
        for capability in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, parent)?;
        }
        if cost.binding_digest(context, parent)? != view.principal {
            return Err(stale_index());
        }
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&current, parent, |r| {
            self.require_custody_ready(r, view.workspace())
        })?;
        let world =
            self.current_directory_router_heads(&current, &context.request.workspace_id, parent)?;
        if world.workspace_digest != view.workspace
            || (strict_journal && world.watermarks.journal != view.known_at())
            || world.segment_heads != view.world.segment_heads
            || world.prefix_bases != view.world.prefix_bases
            || world.prefix_segment_heads != view.world.prefix_segment_heads
            || world.directory_routers != view.world.directory_routers
            || self.graph_epoch(&current, view.workspace(), parent)?
                != view.generation.authorization_epoch
        {
            return Err(stale_index());
        }
        parent.charge(4, KEY_BYTES * 4).map_err(budget_error)?;
        let state: IndexState = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &state_key(view.workspace()),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let generation: Generation = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &generation_key(view.workspace(), view.generation.number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let router: DirectoryRouterReceiptV1 = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &head_key(view.workspace(), generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed live head disappeared"))?;
        let dense: DenseProjectionReceipt = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &dense::receipt_key(view.workspace(), generation.number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        if state.active != Some(generation.number)
            || generation != view.generation
            || router != view.router
            || dense != view.current_receipt
        {
            return Err(stale_index());
        }
        let base: DensePrefixBaseReceiptV2 = self
            .prefix_read(
                &current,
                &self.keyspaces.continuous,
                &prefix_v2::types::receipt_key(view.workspace(), generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed live base disappeared"))?;
        if base != view.base {
            return Err(stale_index());
        }
        if let Some(head) = &view.head {
            let live: PrefixSegmentDirectoryReceiptV2 = self
                .prefix_read(
                    &current,
                    &self.keyspaces.continuous,
                    &prefix_segments_v2::types::directory_head_key(
                        view.workspace(),
                        generation.number,
                    )?,
                    parent,
                )?
                .ok_or_else(|| integrity("routed fine directory disappeared"))?;
            if live != head.directory {
                return Err(stale_index());
            }
        }
        parent.check().map_err(budget_error)
    }

    /// Lease callers separately prove the allowed ModelRequested occurrence;
    /// this checker admits exact sealed roots without assuming the old journal.
    pub(crate) fn check_routed_query_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        binding: &crate::router_trace::hybrid::routed::HybridRoutedBinding,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let view = self.routed_query_view(snapshot, context, parent)?;
        let bytes = metered_encode(view.generation(), parent, ROW_BYTES)?;
        if view.generation().number != binding.generation
            || digest(&bytes) != binding.generation_digest
            || view.router.manifest.coverage.base != binding.base
            || view.router.manifest.coverage.directory != binding.directory
            || view.generation.dense_directory_router.as_ref() != Some(&binding.router)
        {
            return Err(stale_index());
        }
        Ok(())
    }
}
