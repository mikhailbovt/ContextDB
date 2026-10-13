//! Current administrative targets; observations grant no serving or source access.

use super::super::prefix_segments_v2::types as interval_types;
use super::super::prefix_v2::types as prefix_types;
use super::query::{RoutedPointBase, RoutedPointDirectory};
use super::*;
use crate::raw_index::retained_generations;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Exact accepted metadata for explicit prefix and router maintenance.
///
/// A stale router remains visible for an operator to replace. This observation
/// does not certify source permissions, original/vector availability, an actual
/// capture-work count, serving readiness or approximate retrieval quality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRoutedMaintenanceTarget {
    /// Actual active raw generation; no reduced raw admission is constructed.
    pub generation: u64,
    /// Current certified workspace journal cutoff at the returned snapshot.
    pub known_at: u64,
    /// Full current raw cutoff, which may be ahead of Dense and fine coverage.
    pub raw_through: u64,
    /// Full current projected raw source total, including lexical omissions.
    pub raw_sources: u64,
    /// Current native authorization epoch shared by all accepted targets.
    pub authorization_epoch: u64,
    /// Actual current projection receipt; absent before the first projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dense: Option<DenseProjectionReceipt>,
    /// Independently accepted immutable prefix base, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<prefix_types::DensePrefixBaseReceiptV2>,
    /// Actual latest accepted fine directory receipt, not a directory census.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<interval_types::PrefixSegmentDirectoryReceiptV2>,
    /// Exact current directory CAS predecessor, absent for a base-only target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_ref: Option<PrefixSegmentDirectoryRefV2>,
    /// Actual accepted Dense receipt at the fine base/directory endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<DenseProjectionReceipt>,
    /// Accepted current router revision, including legitimate stale coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<DirectoryRouterReceiptV1>,
    /// Exact base and optional fine-directory coverage; false if no router exists.
    pub router_matches_directory: bool,
    /// Whether the Dense receipt carries the exact current full raw envelope.
    pub dense_matches_raw: bool,
}

struct StatusSnapshot {
    world: crate::WorkspaceState,
    index: IndexState,
    generation: Generation,
}

impl NativeService {
    /// Read authenticated current maintenance metadata without source or ANN reads.
    ///
    /// Some(Dense) also closes the complete accepted native suffix from its actual
    /// publication to the certified head. All point and suffix work shares the
    /// supplied parent; resource refusal returns no partial status. The first
    /// publisher's independent census/orphan proof is not replaced by this read.
    pub fn original_span_routed_maintenance_target(
        &self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<NativeRoutedMaintenanceTarget> {
        let cost = crate::budgeted::auth::ContextCost::for_context(context, parent)?;
        for capability in [
            Capability::Admin,
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
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let observed = self.routed_status_snapshot(&snapshot, context, &workspace, parent)?;
        let generation = &observed.generation;
        self.validate_raw_bm25_generation(&snapshot, generation, parent)?;
        self.validate_dense_generation(&snapshot, &workspace, generation, parent)?;

        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let dense: Option<DenseProjectionReceipt> = self.prefix_read(
            &snapshot,
            &self.keyspaces.continuous,
            &dense::receipt_key(&workspace, generation.number),
            parent,
        )?;
        match (&generation.dense, &dense) {
            (Some(latest), Some(receipt)) => {
                let reference =
                    self.prefix_publication_ref(&snapshot, receipt.global_commit, parent)?;
                let (accepted, manifest) =
                    self.prefix_dense_target_binding(&snapshot, &workspace, &reference, parent)?;
                if &accepted != receipt || &manifest != latest {
                    return Err(integrity("routed status current dense target differs"));
                }
                self.check_routed_projection_recency(
                    &snapshot,
                    &workspace,
                    generation,
                    receipt,
                    &reference,
                    &observed.world,
                    parent,
                )?;
            }
            (None, None) => {}
            _ => return Err(integrity("routed status lost its current dense target")),
        }

        let admitted_base = if generation.dense_prefix_base.is_some() {
            Some(self.routed_point_base(
                &snapshot,
                &workspace,
                generation,
                &observed.world,
                parent,
            )?)
        } else {
            parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
            self.routed_status_absent(
                &snapshot,
                &self.keyspaces.continuous,
                &prefix_types::receipt_key(&workspace, generation.number)?,
                parent,
            )?;
            self.routed_status_absent(
                &snapshot,
                &self.keyspaces.idempotency,
                &prefix_types::retained_locator_key(&workspace, generation.number)?,
                parent,
            )?;
            None
        };

        let admitted_directory = if generation.dense_prefix_segments.is_some() {
            Some(
                self.routed_point_directory(
                    &snapshot,
                    &workspace,
                    generation,
                    &observed.world,
                    admitted_base
                        .as_ref()
                        .ok_or_else(|| integrity("routed status directory lost its base"))?,
                    parent,
                )?,
            )
        } else {
            parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
            self.routed_status_absent(
                &snapshot,
                &self.keyspaces.continuous,
                &interval_types::directory_head_key(&workspace, generation.number)?,
                parent,
            )?;
            self.routed_status_absent(
                &snapshot,
                &self.keyspaces.idempotency,
                &interval_types::retained_locator_key(&workspace, generation.number, 1)?,
                parent,
            )?;
            None
        };

        let covered = admitted_directory
            .as_ref()
            .map(|directory| &directory.covered)
            .or_else(|| admitted_base.as_ref().map(|base| &base.target));

        let router = if let Some(root) = &generation.dense_directory_router {
            Some(self.routed_point_router(
                &snapshot,
                &workspace,
                generation.number,
                root,
                parent,
            )?)
        } else {
            parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
            self.routed_status_absent(
                &snapshot,
                &self.keyspaces.continuous,
                &head_key(&workspace, generation.number)?,
                parent,
            )?;
            self.routed_status_absent(
                &snapshot,
                &self.keyspaces.idempotency,
                &retained_locator_key(&workspace, generation.number, 1)?,
                parent,
            )?;
            None
        };
        let router_matches_directory = if let Some(router) = &router {
            self.routed_status_router_coverage(
                &snapshot,
                &workspace,
                generation,
                admitted_base
                    .as_ref()
                    .ok_or_else(|| integrity("routed status router lost its base"))?,
                router,
                admitted_directory.as_ref(),
                parent,
            )?
        } else {
            false
        };
        if router_matches_directory {
            let accepted_router = router
                .as_ref()
                .ok_or_else(|| integrity("routed status matching router absent"))?;
            let covered =
                covered.ok_or_else(|| integrity("routed status matching router lost coverage"))?;
            parent.charge(1, 8192).map_err(budget_error)?;
            if accepted_router.manifest.covered != covered.manifest()? {
                return Err(integrity("routed status matching router endpoint differs"));
            }
            if let Some(directory) = &admitted_directory {
                let router = &accepted_router.manifest;
                if router.covered_dense != directory.publication.directory.head.covered_dense
                    || router.ending != directory.publication.directory.head.ending
                {
                    return Err(integrity("routed status matching fine ending differs"));
                }
            }
        }

        let dense_matches_raw = dense.as_ref().is_some_and(|receipt| {
            receipt.raw_through == generation.through
                && receipt.raw_sources == generation.projected_sources
        });
        if let Some(covered) = covered {
            let bytes = segments::crypto::metered_json_len(covered, parent, ROW_BYTES)?;
            parent
                .charge(bytes as u64 + 1, bytes as u64 * 16 + 4096)
                .map_err(budget_error)?;
        }
        let covered = covered.cloned();
        parent.charge(1, 8192).map_err(budget_error)?;
        let result = NativeRoutedMaintenanceTarget {
            generation: generation.number,
            known_at: observed.world.watermarks.journal,
            raw_through: generation.through,
            raw_sources: generation.projected_sources,
            authorization_epoch: generation.authorization_epoch,
            dense,
            base: admitted_base.map(|base| base.receipt),
            directory: admitted_directory.map(|directory| directory.publication.directory),
            directory_ref: generation.dense_prefix_segments.clone(),
            covered,
            router,
            router_matches_directory,
            dense_matches_raw,
        };
        self.routed_status_fence(context, &workspace, &observed, &result, parent)?;
        parent.check().map_err(budget_error)?;
        Ok(result)
    }

    fn routed_status_snapshot<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<StatusSnapshot> {
        crate::budgeted::metadata(snapshot, parent, |reader| {
            self.require_custody_ready(reader, workspace)
        })?;
        let world =
            self.current_directory_router_heads(snapshot, &context.request.workspace_id, parent)?;
        parent
            .charge(2, KEY_BYTES * 2 + 4096)
            .map_err(budget_error)?;
        let index: IndexState = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &state_key(workspace),
                parent,
            )?
            .ok_or_else(stale_index)?;
        if index
            .retained
            .as_ref()
            .is_some_and(|retained| retained.len() > MAX_GENERATIONS as usize)
        {
            return Err(integrity(
                "routed status retained generation set exceeds its bound",
            ));
        }
        retained_generations(&index)?;
        if index.building.is_some() {
            return Err(stale_index());
        }
        let number = index.active.ok_or_else(stale_index)?;
        let generation: Generation = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &generation_key(workspace, number),
                parent,
            )?
            .ok_or_else(|| integrity("routed status active generation absent"))?;
        if generation.number != number
            || generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != RAW_ANALYZER
            || generation.bm25.is_none()
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || self.graph_epoch(snapshot, workspace, parent)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        if generation.through > world.watermarks.journal
            || generation.projected_sources > generation.through
            || world.prefix_bases.as_ref().and_then(|m| m.get(&number))
                != generation.dense_prefix_base.as_ref()
            || world
                .prefix_segment_heads
                .as_ref()
                .and_then(|m| m.get(&number))
                != generation.dense_prefix_segments.as_ref()
            || world
                .directory_routers
                .as_ref()
                .and_then(|m| m.get(&number))
                != generation.dense_directory_router.as_ref()
            || (generation.dense.is_none()
                && (generation.dense_prefix_base.is_some()
                    || generation.dense_prefix_segments.is_some()
                    || generation.dense_directory_router.is_some()))
            || (generation.dense_prefix_base.is_none()
                && (generation.dense_prefix_segments.is_some()
                    || generation.dense_directory_router.is_some()))
        {
            return Err(integrity(
                "routed status current roots or raw envelope differ",
            ));
        }
        Ok(StatusSnapshot {
            world,
            index,
            generation,
        })
    }

    fn routed_status_absent<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        space: &contextdb_storage::Keyspace,
        key: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if crate::budgeted::read_value(snapshot, space, key, ROW_BYTES, parent)?.is_some() {
            return Err(integrity("routed status found an untracked target row"));
        }
        Ok(())
    }

    fn routed_status_fence(
        &self,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        observed: &StatusSnapshot,
        result: &NativeRoutedMaintenanceTarget,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let latest = self.routed_status_snapshot(&current, context, workspace, parent)?;
        if latest.world != observed.world
            || latest.index != observed.index
            || latest.generation != observed.generation
        {
            return Err(stale_index());
        }
        self.validate_raw_bm25_generation(&current, &latest.generation, parent)?;
        self.validate_dense_generation(&current, workspace, &latest.generation, parent)?;
        parent.charge(4, KEY_BYTES * 4).map_err(budget_error)?;
        let dense: Option<DenseProjectionReceipt> = self.prefix_read(
            &current,
            &self.keyspaces.continuous,
            &dense::receipt_key(workspace, latest.generation.number),
            parent,
        )?;
        let base: Option<prefix_types::DensePrefixBaseReceiptV2> = self.prefix_read(
            &current,
            &self.keyspaces.continuous,
            &prefix_types::receipt_key(workspace, latest.generation.number)?,
            parent,
        )?;
        let directory: Option<interval_types::PrefixSegmentDirectoryReceiptV2> = self.prefix_read(
            &current,
            &self.keyspaces.continuous,
            &interval_types::directory_head_key(workspace, latest.generation.number)?,
            parent,
        )?;
        let router: Option<DirectoryRouterReceiptV1> = self.prefix_read(
            &current,
            &self.keyspaces.continuous,
            &head_key(workspace, latest.generation.number)?,
            parent,
        )?;
        if dense != result.dense
            || base != result.base
            || directory != result.directory
            || router != result.router
        {
            return Err(stale_index());
        }
        parent.check().map_err(budget_error)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Same-snapshot admitted base/directory targets avoid repeating native point proofs"
    )]
    fn routed_status_router_coverage<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        base: &RoutedPointBase,
        router: &DirectoryRouterReceiptV1,
        directory: Option<&RoutedPointDirectory>,
        parent: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let manifest = &router.manifest;
        let raw = &manifest.raw;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("routed status router lost Dense"))?;
        if manifest.coverage.base != base.reference
            || raw.generation != generation.number
            || raw.custody_version != generation.custody_version
            || raw.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&raw.bm25)
            || raw.authorization_epoch != generation.authorization_epoch
            || raw.removal_through != generation.removal_through
            || raw.through > generation.through
            || raw.projected_sources > generation.projected_sources
            || (raw.through == generation.through
                && raw.projected_sources != generation.projected_sources)
        {
            return Err(integrity(
                "routed status router raw or base binding differs",
            ));
        }
        match (
            &manifest.coverage.directory,
            &generation.dense_prefix_segments,
        ) {
            (Some(old), Some(current))
                if old.count > current.count || (old.count == current.count && old != current) =>
            {
                return Err(integrity("routed status router directory moved backwards"));
            }
            (Some(_), None) => {
                return Err(integrity("routed status router lost its fine directory"));
            }
            _ => {}
        }
        let (accepted_covered, covered_ref) =
            directory.map_or((&base.target, &base.receipt.manifest.target), |directory| {
                (
                    &directory.covered,
                    &directory.publication.directory.head.covered_dense,
                )
            });
        let historical;
        let covered_receipt = if manifest.covered_dense == *covered_ref {
            accepted_covered
        } else {
            historical = self
                .prefix_dense_target_binding(snapshot, workspace, &manifest.covered_dense, parent)?
                .0;
            &historical
        };
        parent.charge(1, 8192).map_err(budget_error)?;
        let covered_manifest = covered_receipt.manifest()?;
        let covered = &manifest.covered;
        if &covered_manifest != covered
            || covered_receipt.generation != generation.number
            || covered_receipt.authorization_epoch != generation.authorization_epoch
            || covered.profile != latest.profile
            || covered.profile_digest != latest.profile_digest
            || covered.vector_space_id != latest.vector_space_id
            || covered.through > latest.through
            || covered.sources > latest.sources
            || covered.embedded_sources > latest.embedded_sources
            || covered.omitted_sources > latest.omitted_sources
            || covered.spans > latest.spans
            || (covered.through == latest.through && covered != latest)
            || manifest.ending.work.workspace_commit > covered.through
            || manifest.ending.global_commit > manifest.covered_dense.global_commit
        {
            return Err(integrity(
                "routed status router covered Dense target differs",
            ));
        }
        self.verify_prefix_segment_capture_boundary(snapshot, workspace, &manifest.ending, parent)?;
        if manifest.coverage.directory.is_none()
            && (covered != &base.receipt.manifest.prefix
                || manifest.covered_dense != base.receipt.manifest.target)
        {
            return Err(integrity("routed status base-only router target differs"));
        }
        Ok(manifest.coverage.directory == generation.dense_prefix_segments)
    }
}
