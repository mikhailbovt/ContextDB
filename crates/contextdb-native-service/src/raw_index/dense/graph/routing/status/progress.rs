//! Owner-only synchronous status admission; observations alone grant no reuse.

use super::witness::{ControlReadWitness, Recorder};
use super::*;
use crate::budgeted::auth::ContextCost;
use crate::encryption::NativeSnapshot;
use crate::raw_index::dense::graph::prefix_segments_v2::heads::CertifiedCurrentHeadRows;

pub(crate) struct NativeStatusAdmissionSeed<'owner> {
    owner: &'owner NativeService,
    snapshot: NativeSnapshot,
    context: AuthenticatedRequestContext,
    principal: String,
    workspace: String,
    proof: StatusProof,
    head_rows: CertifiedCurrentHeadRows,
    witness: ControlReadWitness,
    target: NativeRoutedMaintenanceTarget,
}

pub(in crate::raw_index::dense::graph::routing) struct StatusServingParts {
    pub(in crate::raw_index::dense::graph::routing) snapshot: NativeSnapshot,
    pub(in crate::raw_index::dense::graph::routing) workspace: String,
    pub(in crate::raw_index::dense::graph::routing) world: crate::WorkspaceState,
    pub(in crate::raw_index::dense::graph::routing) state: IndexState,
    pub(in crate::raw_index::dense::graph::routing) generation: Generation,
    pub(in crate::raw_index::dense::graph::routing) base: Option<RoutedPointBase>,
    pub(in crate::raw_index::dense::graph::routing) directory: Option<RoutedPointDirectory>,
    pub(in crate::raw_index::dense::graph::routing) router: Option<DirectoryRouterReceiptV1>,
    pub(in crate::raw_index::dense::graph::routing) current: Option<DenseProjectionReceipt>,
    pub(in crate::raw_index::dense::graph::routing) current_ref: Option<AcceptedPublicationRef>,
    pub(in crate::raw_index::dense::graph::routing) head_rows: CertifiedCurrentHeadRows,
}

impl NativeStatusAdmissionSeed<'_> {
    pub(crate) fn target(&self) -> &NativeRoutedMaintenanceTarget {
        &self.target
    }
}

impl<'owner> NativeStatusAdmissionSeed<'owner> {
    pub(in crate::raw_index::dense::graph::routing) fn into_parts(
        self,
        owner: &NativeService,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<StatusServingParts> {
        if !std::ptr::eq(self.owner, owner)
            || ContextCost::for_context(context, parent)?.binding_digest(context, parent)?
                != self.principal
        {
            return Err(stale_index());
        }
        parent.check().map_err(budget_error)?;
        drop(self.context);
        let StatusSnapshot {
            world,
            index: state,
            generation,
        } = self.proof.observed;
        Ok(StatusServingParts {
            snapshot: self.snapshot,
            workspace: self.workspace,
            world,
            state,
            generation,
            base: self.proof.base,
            directory: self.proof.directory,
            router: self.proof.router,
            current: self.proof.current,
            current_ref: self.proof.current_ref,
            head_rows: self.head_rows,
        })
    }
}

impl NativeService {
    pub(crate) fn routed_status_admission_seed(
        &self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<NativeStatusAdmissionSeed<'_>> {
        let (workspace, cost) = status_context(context, parent)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (observed, head_rows) =
            self.routed_seed_snapshot(&snapshot, context, &workspace, parent)?;
        let recorder = Recorder::new(self, &snapshot, &workspace, &observed.generation, parent)?;
        let result = self.routed_status_proof(&snapshot, &recorder, &workspace, observed, parent);
        let proof = recorder.result(result)?;
        let witness = recorder.materialize(parent)?;
        let target = proof_target(&proof, parent)?;
        self.routed_status_fence(context, &workspace, &proof.observed, &target, parent)?;
        let principal = cost.binding_digest(context, parent)?;
        let context = cost.clone_context(context, parent)?;
        parent.check().map_err(budget_error)?;
        Ok(NativeStatusAdmissionSeed {
            owner: self,
            snapshot,
            context,
            principal,
            workspace,
            proof,
            head_rows,
            witness,
            target,
        })
    }

    pub(crate) fn refresh_routed_status_admission_seed<'owner>(
        &'owner self,
        mut seed: NativeStatusAdmissionSeed<'owner>,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<NativeStatusAdmissionSeed<'owner>> {
        if !std::ptr::eq(self, seed.owner) {
            return Err(stale_index());
        }
        let (workspace, cost) = status_context(context, parent)?;
        if workspace != seed.workspace || cost.binding_digest(context, parent)? != seed.principal {
            return Err(stale_index());
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (mut observed, head_rows) =
            self.routed_seed_snapshot(&snapshot, context, &workspace, parent)?;
        self.validate_raw_bm25_generation(&snapshot, &observed.generation, parent)?;
        self.validate_dense_generation(&snapshot, &workspace, &observed.generation, parent)?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let current: DenseProjectionReceipt = self
            .prefix_read(
                &snapshot,
                &self.keyspaces.continuous,
                &dense::receipt_key(&workspace, observed.generation.number),
                parent,
            )?
            .ok_or_else(stale_index)?;
        let current_ref = self.prefix_publication_ref(&snapshot, current.global_commit, parent)?;
        let (accepted, manifest) =
            self.prefix_dense_target_binding(&snapshot, &workspace, &current_ref, parent)?;
        if accepted != current || observed.generation.dense.as_ref() != Some(&manifest) {
            return Err(integrity("routed progress current Dense target differs"));
        }
        self.check_routed_projection_recency(
            &snapshot,
            &workspace,
            &observed.generation,
            &current,
            &current_ref,
            &observed.world,
            parent,
        )?;

        // Compare every generation field except the one explicitly permitted
        // Dense advancement. Moving the manifests avoids an unpaid deep clone.
        parent.charge(64, 128 * 1024).map_err(budget_error)?;
        let previous_dense = seed.proof.observed.generation.dense.take();
        let next_dense = observed.generation.dense.take();
        let same = seed.proof.observed.generation == observed.generation
            && seed.proof.observed.index == observed.index
            && seed.proof.observed.world.workspace_digest == observed.world.workspace_digest
            && seed.proof.observed.world.segment_heads == observed.world.segment_heads
            && seed.proof.observed.world.prefix_bases == observed.world.prefix_bases
            && seed.proof.observed.world.prefix_segment_heads
                == observed.world.prefix_segment_heads
            && seed.proof.observed.world.directory_routers == observed.world.directory_routers;
        seed.proof.observed.generation.dense = previous_dense;
        observed.generation.dense = next_dense;
        if !same {
            return Err(stale_index());
        }
        let previous = seed.proof.current.as_ref().ok_or_else(stale_index)?;
        if current.profile != previous.profile
            || current.profile_digest != previous.profile_digest
            || current.generation != previous.generation
            || current.authorization_epoch != previous.authorization_epoch
            || current.sources < previous.sources
            || current.spans < previous.spans
            || current.embedded_sources < previous.embedded_sources
            || current.omitted_sources < previous.omitted_sources
            || current.through < previous.through
            || current.global_commit < previous.global_commit
        {
            return Err(integrity(
                "routed progress Dense counters or profile moved backwards",
            ));
        }
        if current.through <= previous.through || current.global_commit <= previous.global_commit {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "routed progress made no strict Dense advancement",
                true,
            ));
        }
        let world_bytes = head_rows
            .workspace
            .as_deref()
            .ok_or_else(|| integrity("routed progress current world witness absent"))?;
        seed.witness.check(self, &snapshot, world_bytes, parent)?;
        let dense_matches_raw = current.raw_through == observed.generation.through
            && current.raw_sources == observed.generation.projected_sources;
        seed.target.known_at = observed.world.watermarks.journal;
        seed.target.dense = Some(paid_clone(&current, parent)?);
        seed.target.dense_matches_raw = dense_matches_raw;
        self.routed_status_fence(context, &workspace, &observed, &seed.target, parent)?;
        seed.snapshot = snapshot;
        seed.proof.observed = observed;
        seed.proof.current = Some(current);
        seed.proof.current_ref = Some(current_ref);
        seed.head_rows = head_rows;
        parent.check().map_err(budget_error)?;
        Ok(seed)
    }

    fn routed_seed_snapshot(
        &self,
        snapshot: &NativeSnapshot,
        context: &AuthenticatedRequestContext,
        workspace: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<(StatusSnapshot, CertifiedCurrentHeadRows)> {
        crate::budgeted::metadata(snapshot, parent, |reader| {
            self.require_custody_ready(reader, workspace)
        })?;
        let (world, rows) = self.current_directory_router_heads_with_rows(
            snapshot,
            &context.request.workspace_id,
            parent,
        )?;
        let observed = self.routed_status_index(snapshot, workspace, world, parent)?;
        Ok((observed, rows))
    }
}

fn status_context(
    context: &AuthenticatedRequestContext,
    parent: &mut QueryBudget,
) -> ServiceResult<(String, ContextCost)> {
    let cost = ContextCost::for_context(context, parent)?;
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
    Ok((digest_bytes(context.request.workspace_id.as_bytes()), cost))
}

fn paid_clone<T: Clone + Serialize>(value: &T, parent: &mut QueryBudget) -> ServiceResult<T> {
    let bytes = segments::crypto::metered_json_len(value, parent, ROW_BYTES)?;
    parent
        .charge(bytes as u64 + 1, bytes as u64 * 16 + 4096)
        .map_err(budget_error)?;
    Ok(value.clone())
}

fn proof_target(
    proof: &StatusProof,
    parent: &mut QueryBudget,
) -> ServiceResult<NativeRoutedMaintenanceTarget> {
    let generation = &proof.observed.generation;
    let dense = proof
        .current
        .as_ref()
        .map(|value| paid_clone(value, parent))
        .transpose()?;
    let base = proof
        .base
        .as_ref()
        .map(|base| paid_clone(&base.receipt, parent))
        .transpose()?;
    let directory = proof
        .directory
        .as_ref()
        .map(|directory| paid_clone(&directory.publication.directory, parent))
        .transpose()?;
    let covered = proof
        .covered()
        .map(|value| paid_clone(value, parent))
        .transpose()?;
    let router = proof
        .router
        .as_ref()
        .map(|value| paid_clone(value, parent))
        .transpose()?;
    parent.charge(1, 8192).map_err(budget_error)?;
    Ok(NativeRoutedMaintenanceTarget {
        generation: generation.number,
        known_at: proof.observed.world.watermarks.journal,
        raw_through: generation.through,
        raw_sources: generation.projected_sources,
        authorization_epoch: generation.authorization_epoch,
        dense_matches_raw: dense.as_ref().is_some_and(|receipt| {
            receipt.raw_through == generation.through
                && receipt.raw_sources == generation.projected_sources
        }),
        dense,
        base,
        directory,
        directory_ref: generation.dense_prefix_segments.clone(),
        covered,
        router,
        router_matches_directory: proof.router_matches_directory,
    })
}
