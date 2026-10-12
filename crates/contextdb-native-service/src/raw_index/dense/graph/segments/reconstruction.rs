//! Administrative exact reconstruction of every accepted immutable segment.
//! This is a bounded-parent audit, never a hot query or a source-access grant.

use super::super::tail::AuthenticatedDensePrefixAnchor;
use super::crypto::{metered_encode, metered_json_len};
use super::types::{
    self, DenseSegmentPublication, DirectoryRef, KEY_BYTES, delta_receipt_key, directory_head_key,
};
use crate::raw_index::{Generation, budget_error};
use crate::{NativeService, integrity};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::ReadSnapshot;
use std::collections::BTreeMap;

type SegmentRows = BTreeMap<Vec<u8>, Vec<u8>>;
const MAP_NODE_BYTES: u64 = 2048;

fn insert_row(
    rows: &mut SegmentRows,
    key: Vec<u8>,
    value: Vec<u8>,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    // A split can propagate to the root. A binary-tree height bound exceeds this
    // balanced map's height; reserve a full node for each level and a new root.
    // Owned key/value byte buffers are moved, not cloned.
    let levels = u64::from(usize::BITS - rows.len().saturating_add(1).leading_zeros()) + 2;
    parent
        .charge(levels * 12, levels * MAP_NODE_BYTES)
        .map_err(budget_error)?;
    if rows.insert(key, value).is_some() {
        return Err(integrity(
            "segment reconstruction has a duplicate immutable row",
        ));
    }
    Ok(())
}

impl NativeService {
    pub(in crate::raw_index) fn reconstruct_dense_segment_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<SegmentRows> {
        let Some(current) = &generation.dense_segments else {
            return Ok(SegmentRows::new());
        };
        parent.charge(1, 8192).map_err(budget_error)?;
        current.validate()?;
        if !types::valid_hex(workspace) {
            return Err(integrity("segment reconstruction workspace digest differs"));
        }
        self.require_segment_feature(snapshot, parent)?;
        let generation_bytes = metered_json_len(generation, parent, types::ROW_BYTES)?;
        let mut rows = SegmentRows::new();
        for ordinal in 1..=current.count {
            let accepted = self.accepted_segment_for_ordinal(
                snapshot,
                workspace,
                generation.number,
                ordinal,
                parent,
            )?;
            self.admit_segment_reconstruction_generation(generation, &accepted, parent)?;
            let manifest = &accepted.delta.manifest;
            // Historical reconstruction must use the originally accepted raw
            // and dense endpoint, while retaining the exact immutable base.
            parent
                .charge(1, generation_bytes as u64 * 16 + 8192)
                .map_err(budget_error)?;
            let mut frozen = generation.clone();
            let manifest_bytes = metered_json_len(manifest, parent, types::ROW_BYTES)?;
            parent
                .charge(1, manifest_bytes as u64 * 8 + 8192)
                .map_err(budget_error)?;
            frozen.through = manifest.binding.raw_through;
            frozen.projected_sources = manifest.binding.raw_sources;
            frozen.dense = Some(manifest.after.clone());

            let witness = if ordinal == 1 {
                // Whole-generation reconstruction requires its live v1 base
                // row; accepted_graph_receipt also joins retained acceptance.
                let base = self.accepted_graph_receipt(snapshot, workspace, generation, parent)?;
                if accepted.directory.head.previous.is_some()
                    || manifest.before != base.manifest.dense
                    || generation.dense_graph.as_ref() != Some(&base.manifest)
                {
                    return Err(integrity(
                        "first segment reconstructed starting prefix differs",
                    ));
                }
                self.tracked_base_dense_prefix_witness(
                    snapshot,
                    workspace,
                    &frozen,
                    &base,
                    types::MAX_WORK as usize,
                    parent,
                )?
            } else {
                let previous = self.accepted_retained_segment_head(
                    snapshot,
                    workspace,
                    generation.number,
                    ordinal - 1,
                    parent,
                )?;
                let previous_publication = previous.publication();
                let previous_manifest = &previous_publication.delta.manifest;
                let reference = self.segment_publication_ref(
                    snapshot,
                    previous_publication.delta.global_commit,
                    parent,
                )?;
                let expected = DirectoryRef {
                    count: ordinal - 1,
                    global_commit: reference.global_commit,
                    request_digest: reference.request_digest,
                    response_digest: reference.response_digest,
                    content_digest: previous_publication.directory.head.content_digest,
                };
                if manifest.before != *previous.covered()
                    || accepted.directory.head.previous.as_ref() != Some(&expected)
                    || previous_manifest.base != manifest.base
                    || previous_manifest.binding.generation != manifest.binding.generation
                    || previous_manifest.binding.custody_version != manifest.binding.custody_version
                    || previous_manifest.binding.analyzer != manifest.binding.analyzer
                    || previous_manifest.binding.bm25 != manifest.binding.bm25
                    || previous_manifest.binding.authorization_epoch
                        != manifest.binding.authorization_epoch
                    || previous_manifest.binding.removal_through != manifest.binding.removal_through
                {
                    return Err(integrity(
                        "segment reconstruction accepted predecessor differs",
                    ));
                }
                self.dense_prefix_witness(
                    snapshot,
                    workspace,
                    &frozen,
                    AuthenticatedDensePrefixAnchor::accepted_segment(&previous),
                    types::MAX_WORK as usize,
                    true,
                    parent,
                )?
            };
            if !witness.complete {
                return Err(integrity(
                    "segment reconstruction lacks a complete interval witness",
                ));
            }
            let interval = witness
                .interval
                .ok_or_else(|| integrity("complete reconstructed segment interval is absent"))?;
            if interval.work_items != manifest.work_items
                || interval.digest != manifest.interval_digest
            {
                return Err(integrity(
                    "segment reconstructed accepted work commitment differs",
                ));
            }
            let inputs = self.segment_inputs(
                snapshot,
                None,
                workspace,
                &frozen,
                &manifest.before,
                &witness.documents,
                parent,
            )?;
            parent
                .charge(1, manifest_bytes as u64 * 16 + 8192)
                .map_err(budget_error)?;
            let mut rebuilt = manifest.clone();
            let reconstructed =
                self.construct_segment(workspace, &frozen, &mut rebuilt, &inputs, parent)?;
            if rebuilt != *manifest {
                return Err(integrity(
                    "segment final canonical reconstruction differs from accepted manifest",
                ));
            }
            for (key, value) in reconstructed {
                insert_row(&mut rows, key, value, parent)?;
            }
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = delta_receipt_key(workspace, generation.number, ordinal)?;
            let value = metered_encode(&accepted.delta, parent, types::ROW_BYTES)?;
            insert_row(&mut rows, key, value, parent)?;

            if ordinal == current.count {
                let reference =
                    self.segment_publication_ref(snapshot, accepted.delta.global_commit, parent)?;
                if current.global_commit != reference.global_commit
                    || current.request_digest != reference.request_digest
                    || current.response_digest != reference.response_digest
                    || current.content_digest != accepted.directory.head.content_digest
                    || current.count != accepted.directory.head.count
                {
                    return Err(integrity(
                        "segment reconstruction final generation pointer differs",
                    ));
                }
                parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                let key = directory_head_key(workspace, generation.number)?;
                let value = metered_encode(&accepted.directory, parent, types::ROW_BYTES)?;
                insert_row(&mut rows, key, value, parent)?;
            }
        }
        Ok(rows)
    }

    fn admit_segment_reconstruction_generation(
        &self,
        generation: &Generation,
        accepted: &DenseSegmentPublication,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.charge(1, 8192).map_err(budget_error)?;
        let manifest = &accepted.delta.manifest;
        let binding = &manifest.binding;
        let base = generation
            .dense_graph
            .as_ref()
            .ok_or_else(|| integrity("segment reconstruction original base is absent"))?;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("segment reconstruction latest dense prefix is absent"))?;
        if binding.generation != generation.number
            || binding.custody_version != generation.custody_version
            || binding.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&binding.bm25)
            || binding.authorization_epoch != generation.authorization_epoch
            || binding.removal_through != generation.removal_through
            || binding.raw_through > generation.through
            || binding.raw_sources > generation.projected_sources
            || manifest.base.graph_digest != base.content_digest
            || manifest.before.through < base.dense.through
            || manifest.before.profile != base.dense.profile
            || manifest.after.profile != latest.profile
            || manifest.after.profile_digest != latest.profile_digest
            || manifest.after.vector_space_id != latest.vector_space_id
            || manifest.after.through > latest.through
            || manifest.after.sources > latest.sources
            || manifest.after.embedded_sources > latest.embedded_sources
            || manifest.after.omitted_sources > latest.omitted_sources
            || manifest.after.spans > latest.spans
        {
            return Err(integrity(
                "segment reconstruction historical generation binding differs",
            ));
        }
        Ok(())
    }
}
