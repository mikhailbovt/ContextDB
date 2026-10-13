//! Current-root point proofs. Offline history/census verification stays separate.

use super::*;
use crate::raw_index::dense::graph::{
    prefix_segments_v2::{
        proof::VerifiedCaptureBoundary, types as interval, verification as interval_verification,
    },
    prefix_v2::{types as prefix, verification as prefix_verification},
};

pub(in crate::raw_index::dense::graph::routing) struct RoutedPointBase {
    pub(in crate::raw_index::dense::graph::routing) receipt: DensePrefixBaseReceiptV2,
    pub(in crate::raw_index::dense::graph::routing) reference: PrefixSegmentBaseRefV2,
    pub(in crate::raw_index::dense::graph::routing) target: DenseProjectionReceipt,
}

pub(in crate::raw_index::dense::graph::routing) struct RoutedPointDirectory {
    pub(in crate::raw_index::dense::graph::routing) publication: PrefixSegmentPublicationV2,
    pub(in crate::raw_index::dense::graph::routing) reference: PrefixSegmentDirectoryRefV2,
    pub(in crate::raw_index::dense::graph::routing) covered: DenseProjectionReceipt,
    pub(in crate::raw_index::dense::graph::routing) ending: VerifiedCaptureBoundary,
}

/// The caller has already authenticated this world's four stamps, active
/// generation, current epoch and custody under this SAME snapshot and parent.
/// No caller-supplied reference alone can satisfy these local current joins.
fn roots(
    workspace: &str,
    generation: &Generation,
    world: &crate::WorkspaceState,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    parent.charge(1, 4096).map_err(budget_error)?;
    let n = &generation.number;
    if world.workspace_digest != workspace
        || *n == 0
        || generation.through > world.watermarks.journal
        || generation.projected_sources > generation.through
        || generation.dense_graph.is_some()
        || generation.dense_segments.is_some()
        || world.segment_heads.as_ref().and_then(|m| m.get(n)) != generation.dense_segments.as_ref()
        || world.prefix_bases.as_ref().and_then(|m| m.get(n))
            != generation.dense_prefix_base.as_ref()
        || world.prefix_segment_heads.as_ref().and_then(|m| m.get(n))
            != generation.dense_prefix_segments.as_ref()
        || world.directory_routers.as_ref().and_then(|m| m.get(n))
            != generation.dense_directory_router.as_ref()
    {
        return Err(integrity(
            "routed point differs from certified current roots",
        ));
    }
    Ok(())
}

fn within_generation(
    raw: &PrefixRawBindingV2,
    state: &DenseManifest,
    generation: &Generation,
) -> bool {
    let Some(latest) = &generation.dense else {
        return false;
    };
    raw.generation == generation.number
        && raw.custody_version == generation.custody_version
        && raw.analyzer == generation.analyzer
        && generation.bm25.as_ref() == Some(&raw.bm25)
        && raw.authorization_epoch == generation.authorization_epoch
        && raw.removal_through == generation.removal_through
        && raw.through <= generation.through
        && raw.projected_sources <= generation.projected_sources
        && (raw.through != generation.through
            || raw.projected_sources == generation.projected_sources)
        && state.profile == latest.profile
        && state.profile_digest == latest.profile_digest
        && state.vector_space_id == latest.vector_space_id
        && state.through <= latest.through
        && state.sources <= latest.sources
        && state.spans <= latest.spans
        && state.embedded_sources <= latest.embedded_sources
        && state.omitted_sources <= latest.omitted_sources
        && (state.through != latest.through || state == latest)
}

fn clone_target(
    target: &DenseProjectionReceipt,
    parent: &mut QueryBudget,
) -> ServiceResult<DenseProjectionReceipt> {
    let bytes = metered_json_len(target, parent, MAX_PUBLICATION_BYTES)?;
    parent
        .charge(bytes as u64 + 1, bytes as u64 * 16 + 4096)
        .map_err(budget_error)?;
    Ok(target.clone())
}

impl NativeService {
    /// Resolve a current immutable base once, retaining its already admitted
    /// Dense target and full reference for the directory and serving joins.
    pub(in crate::raw_index::dense::graph::routing) fn routed_point_base<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        world: &crate::WorkspaceState,
        parent: &mut QueryBudget,
    ) -> ServiceResult<RoutedPointBase> {
        roots(workspace, generation, world, parent)?;
        let root = generation
            .dense_prefix_base
            .as_ref()
            .ok_or_else(stale_index)?;
        root.validate()?;
        self.require_prefix_base_feature(snapshot, parent)?;
        parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(
                snapshot,
                &self.keyspaces.idempotency,
                &prefix::retained_locator_key(workspace, generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed point base locator absent"))?;
        decode_allowance(
            &stored.response_bytes,
            prefix::MAX_PUBLICATION_BYTES,
            parent,
        )?;
        let locator: prefix::RetainedPrefixBaseLocatorV2 =
            decode(&stored.response_bytes, "routed point base locator")?;
        self.check_retained_prefix_base_locator(workspace, &locator, parent)?;
        let locator_bytes = metered_encode(&locator, parent, prefix::MAX_PUBLICATION_BYTES)?;
        if locator.workspace_digest != workspace
            || locator.generation != generation.number
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != prefix_verification::LOCATOR_OPERATION
            || stored.request_digest != digest_bytes(&locator_bytes)
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || locator_bytes != stored.response_bytes
            || locator.publication.global_commit != root.global_commit
            || locator.publication.request_digest != root.request_digest
            || locator.publication.response_digest != root.response_digest
        {
            return Err(integrity(
                "routed point base locator/current reference differs",
            ));
        }
        let (event, accepted) = self.prefix_accepted_response(
            snapshot,
            workspace,
            &locator.publication,
            prefix::OPERATION,
            parent,
        )?;
        decode_allowance(
            &accepted.response_bytes,
            prefix::MAX_PUBLICATION_BYTES,
            parent,
        )?;
        let receipt: DensePrefixBaseReceiptV2 =
            decode(&accepted.response_bytes, "routed point accepted base")?;
        self.check_prefix_base_receipt(&receipt, parent)?;
        let bytes = metered_encode(&receipt, parent, prefix::MAX_PUBLICATION_BYTES)?;
        let manifest = &receipt.manifest;
        let (target, target_manifest) =
            self.prefix_dense_target_binding(snapshot, workspace, &manifest.target, parent)?;
        if receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || receipt.global_commit != locator.publication.global_commit
            || manifest.admitted_global_commit.checked_add(1) != Some(receipt.global_commit)
            || manifest.admitted_known_at.checked_add(1) != Some(event.workspace_commit)
            || bytes != accepted.response_bytes
            || digest(&bytes) != root.receipt_digest
            || manifest.content_digest != root.content_digest
            || manifest.prefix != target_manifest
            || target.generation != generation.number
            || target.raw_through != manifest.raw.through
            || target.raw_sources != manifest.raw.projected_sources
            || target.authorization_epoch != manifest.raw.authorization_epoch
            || !within_generation(&manifest.raw, &manifest.prefix, generation)
        {
            return Err(integrity(
                "routed point base native/current generation binding differs",
            ));
        }
        let request_bytes = metered_json_len(&target, parent, prefix::MAX_PUBLICATION_BYTES)?;
        parent
            .charge(request_bytes as u64 + 1, request_bytes as u64 * 16 + 4096)
            .map_err(budget_error)?;
        let request = prefix::DensePrefixBaseRequestV2 {
            generation: generation.number,
            target: clone_target(&target, parent)?,
        };
        if prefix_verification::request_digest(&self.database_id, workspace, &request)?
            != locator.publication.request_digest
        {
            return Err(integrity("routed point base canonical request differs"));
        }
        let live: DensePrefixBaseReceiptV2 = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &prefix::receipt_key(workspace, generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed point live base absent"))?;
        if live != receipt {
            return Err(integrity("routed point live base differs"));
        }
        parent.charge(1, 4096).map_err(budget_error)?;
        let reference = PrefixSegmentBaseRefV2 {
            publication: locator.publication,
            receipt_digest: root.receipt_digest,
            content_digest: root.content_digest,
        };
        reference.validate()?;
        Ok(RoutedPointBase {
            receipt,
            reference,
            target,
        })
    }

    /// Resolve ONLY the certified current ordinal, without replaying the base,
    /// previous directory chain or already accepted native targets recursively.
    pub(in crate::raw_index::dense::graph::routing) fn routed_point_directory<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        world: &crate::WorkspaceState,
        base: &RoutedPointBase,
        parent: &mut QueryBudget,
    ) -> ServiceResult<RoutedPointDirectory> {
        roots(workspace, generation, world, parent)?;
        let root = generation
            .dense_prefix_segments
            .as_ref()
            .ok_or_else(stale_index)?;
        root.validate()?;
        self.require_prefix_segment_feature(snapshot, parent)?;
        if generation.dense_prefix_base.as_ref().is_none_or(|r| {
            r.global_commit != base.reference.publication.global_commit
                || r.request_digest != base.reference.publication.request_digest
                || r.response_digest != base.reference.publication.response_digest
                || r.receipt_digest != base.reference.receipt_digest
                || r.content_digest != base.reference.content_digest
        }) {
            return Err(integrity(
                "routed point directory lost its admitted current base",
            ));
        }
        parent.charge(2, KEY_BYTES * 2).map_err(budget_error)?;
        let stored: crate::StoredIdempotency = self
            .prefix_read(
                snapshot,
                &self.keyspaces.idempotency,
                &interval::retained_locator_key(workspace, generation.number, root.count)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed point directory locator absent"))?;
        decode_allowance(
            &stored.response_bytes,
            interval::MAX_PUBLICATION_BYTES,
            parent,
        )?;
        let locator: interval::RetainedPrefixSegmentLocatorV2 =
            decode(&stored.response_bytes, "routed point directory locator")?;
        self.check_retained_prefix_segment_locator(workspace, &locator, parent)?;
        let locator_bytes = metered_encode(&locator, parent, interval::MAX_PUBLICATION_BYTES)?;
        if locator.workspace_digest != workspace
            || locator.generation != generation.number
            || locator.ordinal != root.count
            || stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != interval::LOCATOR_OPERATION
            || stored.request_digest != digest_bytes(&locator_bytes)
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || locator_bytes != stored.response_bytes
            || locator.publication.global_commit != root.global_commit
            || locator.publication.request_digest != root.request_digest
            || locator.publication.response_digest != root.response_digest
        {
            return Err(integrity(
                "routed point directory locator/current reference differs",
            ));
        }
        let (event, accepted) = self.prefix_accepted_response(
            snapshot,
            workspace,
            &locator.publication,
            interval::OPERATION,
            parent,
        )?;
        decode_allowance(
            &accepted.response_bytes,
            interval::MAX_PUBLICATION_BYTES,
            parent,
        )?;
        let publication: PrefixSegmentPublicationV2 =
            decode(&accepted.response_bytes, "routed point accepted directory")?;
        publication.validate()?;
        self.check_prefix_delta_receipt(&publication.delta, parent)?;
        self.check_prefix_segment_directory_receipt(&publication.directory, parent)?;
        let bytes = metered_encode(&publication, parent, interval::MAX_PUBLICATION_BYTES)?;
        let delta_bytes =
            metered_encode(&publication.delta, parent, interval::MAX_PUBLICATION_BYTES)?;
        let manifest = &publication.delta.manifest;
        let directory = &publication.directory;
        let before = if manifest.before_dense == base.receipt.manifest.target {
            clone_target(&base.target, parent)?
        } else {
            self.prefix_dense_target_binding(snapshot, workspace, &manifest.before_dense, parent)?
                .0
        };
        let covered = self
            .prefix_dense_target_binding(snapshot, workspace, &manifest.target_dense, parent)?
            .0;
        parent.charge(1, 32768).map_err(budget_error)?;
        if publication.delta.database_id != self.database_id
            || digest_bytes(publication.delta.workspace_id.as_bytes()) != workspace
            || publication.delta.global_commit != locator.publication.global_commit
            || manifest.admitted_global_commit.checked_add(1)
                != Some(publication.delta.global_commit)
            || manifest.admitted_known_at.checked_add(1) != Some(event.workspace_commit)
            || bytes != accepted.response_bytes
            || manifest.ordinal != root.count
            || directory.head.content_digest != root.content_digest
            || directory.head.latest.receipt_digest != digest(&delta_bytes)
            || manifest.base != base.reference
            || base.receipt.manifest.raw.custody_version != manifest.raw.custody_version
            || base.receipt.manifest.raw.analyzer != manifest.raw.analyzer
            || base.receipt.manifest.raw.bm25 != manifest.raw.bm25
            || base.receipt.manifest.raw.authorization_epoch != manifest.raw.authorization_epoch
            || base.receipt.manifest.raw.removal_through != manifest.raw.removal_through
            || base.receipt.manifest.raw.through > manifest.raw.through
            || base.receipt.manifest.raw.projected_sources > manifest.raw.projected_sources
            || (base.receipt.manifest.raw.through == manifest.raw.through
                && base.receipt.manifest.raw.projected_sources != manifest.raw.projected_sources)
            || base.receipt.manifest.prefix.profile != manifest.after.profile
            || base.receipt.manifest.prefix.profile_digest != manifest.after.profile_digest
            || base.receipt.manifest.prefix.vector_space_id != manifest.after.vector_space_id
            || base.receipt.manifest.prefix.through > manifest.before.through
            || base.receipt.manifest.prefix.sources > manifest.before.sources
            || base.receipt.manifest.prefix.spans > manifest.before.spans
            || base.receipt.manifest.prefix.embedded_sources > manifest.before.embedded_sources
            || base.receipt.manifest.prefix.omitted_sources > manifest.before.omitted_sources
            || (base.receipt.manifest.prefix.through == manifest.before.through
                && base.receipt.manifest.prefix != manifest.before)
            || (manifest.ordinal == 1
                && (base.receipt.manifest.prefix != manifest.before
                    || base.receipt.manifest.target != manifest.before_dense))
            || before.manifest()? != manifest.before
            || covered.manifest()? != manifest.after
            || before.generation != generation.number
            || covered.generation != generation.number
            || before.authorization_epoch != manifest.raw.authorization_epoch
            || covered.authorization_epoch != manifest.raw.authorization_epoch
            || covered.raw_through != manifest.raw.through
            || covered.raw_sources != manifest.raw.projected_sources
            || before.raw_through > covered.raw_through
            || before.raw_sources > covered.raw_sources
            || (before.raw_through == covered.raw_through
                && before.raw_sources != covered.raw_sources)
            || !within_generation(&manifest.raw, &manifest.after, generation)
        {
            return Err(integrity(
                "routed point directory native/current generation binding differs",
            ));
        }
        let target_bytes = metered_json_len(&covered, parent, interval::MAX_PUBLICATION_BYTES)?;
        parent
            .charge(target_bytes as u64 + 1, target_bytes as u64 * 16 + 8192)
            .map_err(budget_error)?;
        let request = interval::PrefixSegmentSealRequestV2 {
            generation: generation.number,
            previous: directory.head.previous.clone(),
            target: clone_target(&covered, parent)?,
        };
        if interval_verification::seal_request_digest(&self.database_id, workspace, &request)?
            != locator.publication.request_digest
        {
            return Err(integrity(
                "routed point directory canonical request differs",
            ));
        }
        self.verify_prefix_segment_capture_boundary(snapshot, workspace, &manifest.start, parent)?;
        let ending = self.verify_prefix_segment_capture_boundary(
            snapshot,
            workspace,
            &directory.head.ending,
            parent,
        )?;
        let live: PrefixSegmentDirectoryReceiptV2 = self
            .prefix_read(
                snapshot,
                &self.keyspaces.continuous,
                &interval::directory_head_key(workspace, generation.number)?,
                parent,
            )?
            .ok_or_else(|| integrity("routed point live directory absent"))?;
        if live != publication.directory {
            return Err(integrity("routed point live directory differs"));
        }
        parent.charge(1, 4096).map_err(budget_error)?;
        Ok(RoutedPointDirectory {
            publication,
            reference: root.clone(),
            covered,
            ending,
        })
    }
}
