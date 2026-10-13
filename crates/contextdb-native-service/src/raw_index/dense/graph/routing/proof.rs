//! Current owner authority and immutable historical replay are distinct mints.

use super::super::prefix_segments_v2::types::{CaptureBoundaryRefV2, PrefixSegmentPublicationV2};
use super::super::prefix_v2::types::{PrefixBaseRefV2, PrefixRawBindingV2};
use super::super::segments::crypto::metered_json_len;
use super::*;

pub(super) struct VerifiedRouterDirectory {
    generation: Generation,
    world: Option<crate::WorkspaceState>,
    base: prefix_v2::types::DensePrefixBaseReceiptV2,
    head: Option<PrefixSegmentPublicationV2>,
    coverage: DirectoryRouterCoverageV1,
    ending: CaptureBoundaryRefV2,
    context_binding: Option<String>,
}

impl VerifiedRouterDirectory {
    pub(super) fn generation(&self) -> &Generation {
        &self.generation
    }
    pub(super) fn world(&self) -> Option<&crate::WorkspaceState> {
        self.world.as_ref()
    }
    pub(super) fn base(&self) -> &prefix_v2::types::DensePrefixBaseReceiptV2 {
        &self.base
    }
    pub(super) fn head(&self) -> Option<&PrefixSegmentPublicationV2> {
        self.head.as_ref()
    }
    pub(super) fn coverage(&self) -> &DirectoryRouterCoverageV1 {
        &self.coverage
    }
    pub(super) fn covered(&self) -> &DenseManifest {
        self.head
            .as_ref()
            .map_or(&self.base.manifest.prefix, |p| &p.delta.manifest.after)
    }
    pub(super) fn covered_dense(&self) -> &AcceptedPublicationRef {
        self.head.as_ref().map_or(&self.base.manifest.target, |p| {
            &p.delta.manifest.target_dense
        })
    }
    pub(super) fn ending(&self) -> &CaptureBoundaryRefV2 {
        &self.ending
    }
    pub(super) fn context_binding(&self) -> Option<&str> {
        self.context_binding.as_deref()
    }
}

/// A replay envelope uses the SIGNED FULL raw admission fields and a separately
/// authenticated dense target. It does not claim that target was the latest
/// live projection when the router was admitted.
pub(super) fn replay_generation(
    raw: &PrefixRawBindingV2,
    dense: &DenseManifest,
    base: Option<&PrefixBaseRefV2>,
    parent: &mut QueryBudget,
) -> ServiceResult<Generation> {
    let bytes = metered_json_len(&(raw, dense, base), parent, ROW_BYTES * 2)?;
    parent
        .charge(bytes as u64 + 1, bytes as u64 * 32 + 16384)
        .map_err(budget_error)?;
    raw.validate()?;
    dense.validate(raw.through)?;
    Ok(Generation {
        number: raw.generation,
        custody_version: raw.custody_version,
        analyzer: raw.analyzer.clone(),
        through: raw.through,
        authorization_epoch: raw.authorization_epoch,
        projected_sources: raw.projected_sources,
        removal_through: raw.removal_through,
        bm25: Some(raw.bm25.clone()),
        dense: Some(dense.clone()),
        dense_graph: None,
        dense_segments: None,
        dense_prefix_base: base.cloned(),
        dense_prefix_segments: None,
        dense_directory_router: None,
    })
}

impl NativeService {
    pub(super) fn verify_current_router_directory<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        generation_number: u64,
        expected: &DirectoryRouterCoverageV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedRouterDirectory> {
        parent.check().map_err(budget_error)?;
        let metadata_bytes = metered_json_len(expected, parent, ROW_BYTES)?;
        parent
            .charge(metadata_bytes as u64 + 1, 0)
            .map_err(budget_error)?;
        expected.validate()?;
        let cost = crate::budgeted::auth::ContextCost::for_context(context, parent)?;
        for capability in [
            Capability::Admin,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            cost.require_capability(context, capability, parent)?;
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        crate::budgeted::metadata(snapshot, parent, |reader| {
            self.require_custody_ready(reader, &workspace)
        })?;
        parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
        let state: IndexState = self
            .prefix_read(
                snapshot,
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
                snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, generation_number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        if generation.number != generation_number {
            return Err(stale_index());
        }
        let base =
            self.current_prefix_segment_base(snapshot, context, &workspace, &generation, parent)?;
        self.validate_dense_generation(snapshot, &workspace, &generation, parent)?;
        let world =
            self.current_directory_router_heads(snapshot, &context.request.workspace_id, parent)?;
        let head = if generation.dense_prefix_segments.is_some() {
            Some(self.accepted_current_prefix_segment(
                snapshot,
                &context.request.workspace_id,
                &generation,
                parent,
            )?)
        } else {
            self.require_no_prefix_segment_predecessor(
                snapshot,
                &context.request.workspace_id,
                &generation,
                parent,
            )?;
            None
        };
        let base_reference =
            self.prefix_segment_base_reference(snapshot, &workspace, &base, parent)?;
        if expected.base != base_reference || expected.directory != generation.dense_prefix_segments
        {
            return Err(integrity(
                "router coverage differs from current accepted base/directory",
            ));
        }
        let ending =
            self.router_directory_ending(snapshot, &workspace, &base, head.as_ref(), parent)?;
        let bytes = metered_json_len(expected, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 4096)
            .map_err(budget_error)?;
        let proof = VerifiedRouterDirectory {
            generation,
            world: Some(world),
            base,
            head,
            coverage: expected.clone(),
            ending,
            context_binding: Some(crate::budgeted::auth::binding_digest(context, parent)?),
        };
        self.check_router_covered_state(&proof)?;
        Ok(proof)
    }

    /// Only native accepted router authority can mint historical replay. No
    /// current WorkspaceState or source disclosure authority is fabricated.
    pub(super) fn verify_accepted_router_directory<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        receipt: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedRouterDirectory> {
        parent.check().map_err(budget_error)?;
        let reference = self.prefix_publication_ref(snapshot, receipt.global_commit, parent)?;
        self.check_directory_router_acceptance(snapshot, workspace, &reference, receipt, parent)?;
        let manifest = &receipt.manifest;
        let base =
            self.accepted_prefix_base(snapshot, workspace, manifest.raw.generation, parent)?;
        if self.prefix_segment_base_reference(snapshot, workspace, &base, parent)?
            != manifest.coverage.base
        {
            return Err(integrity("historical router lost its accepted prefix base"));
        }
        let head = match &manifest.coverage.directory {
            None => None,
            Some(expected) => {
                let publication = self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    workspace,
                    manifest.raw.generation,
                    expected.count,
                    parent,
                )?;
                if self.prefix_segment_directory_reference(
                    snapshot,
                    &publication.directory,
                    parent,
                )? != *expected
                {
                    return Err(integrity(
                        "historical router directory differs from immutable acceptance",
                    ));
                }
                Some(publication)
            }
        };
        let base_ref = self.prefix_base_reference(snapshot, &base, parent)?;
        let mut generation =
            replay_generation(&manifest.raw, &manifest.covered, Some(&base_ref), parent)?;
        let bytes = metered_json_len(&manifest.coverage, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 16 + 8192)
            .map_err(budget_error)?;
        generation.dense_prefix_segments = manifest.coverage.directory.clone();
        self.check_prefix_generation_binding(snapshot, workspace, &generation, &base, parent)?;
        if let Some(head) = &head {
            self.check_prefix_segment_generation_binding(
                snapshot,
                workspace,
                &generation,
                head,
                parent,
            )?;
        }
        let ending =
            self.router_directory_ending(snapshot, workspace, &base, head.as_ref(), parent)?;
        let proof = VerifiedRouterDirectory {
            generation,
            world: None,
            base,
            head,
            coverage: manifest.coverage.clone(),
            ending,
            context_binding: None,
        };
        if proof.covered() != &manifest.covered
            || proof.covered_dense() != &manifest.covered_dense
            || proof.ending() != &manifest.ending
        {
            return Err(integrity(
                "historical router covered dense/capture state differs",
            ));
        }
        self.check_router_covered_state(&proof)?;
        Ok(proof)
    }

    fn router_directory_ending<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        base: &prefix_v2::types::DensePrefixBaseReceiptV2,
        head: Option<&PrefixSegmentPublicationV2>,
        parent: &mut QueryBudget,
    ) -> ServiceResult<CaptureBoundaryRefV2> {
        let boundary = match head {
            Some(head) => self.verify_prefix_segment_capture_boundary(
                snapshot,
                workspace,
                &head.directory.head.ending,
                parent,
            )?,
            None => {
                let target = self.verify_accepted_prefix_dense_target(
                    snapshot,
                    workspace,
                    &base.manifest.target,
                    parent,
                )?;
                self.first_prefix_segment_capture_boundary(snapshot, workspace, &target, parent)?
            }
        };
        let bytes = metered_json_len(boundary.reference(), parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 1024)
            .map_err(budget_error)?;
        Ok(boundary.reference().clone())
    }

    fn check_router_covered_state(&self, proof: &VerifiedRouterDirectory) -> ServiceResult<()> {
        let covered = proof.covered();
        let latest = proof.generation.dense.as_ref().ok_or_else(stale_index)?;
        if covered.profile != latest.profile
            || covered.profile_digest != latest.profile_digest
            || covered.vector_space_id != latest.vector_space_id
            || covered.through > latest.through
            || covered.sources > latest.sources
            || covered.spans > latest.spans
            || covered.embedded_sources > latest.embedded_sources
            || covered.omitted_sources > latest.omitted_sources
            || (covered.through == latest.through && covered != latest)
        {
            return Err(integrity(
                "router covered prefix escapes actual dense admission",
            ));
        }
        Ok(())
    }
}
