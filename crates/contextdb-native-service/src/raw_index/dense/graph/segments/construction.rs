//! Storage-neutral finite construction from already admitted complete source plans.
//! Neither authentic source policy nor an accepted dense interval is invented here.

use super::super::{publication::GraphInput, topology::GraphTopology};
use super::crypto::{metered_encode, metered_json_len};
use super::types::*;
use crate::{
    NativeService, exhausted, integrity,
    raw_index::{Generation, budget_error},
};
use contextdb_core::{ContentDigest, ObservationId};
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use std::collections::{BTreeMap, BTreeSet};

type SegmentRows = BTreeMap<Vec<u8>, Vec<u8>>;

impl NativeService {
    /// The publisher supplies every vector of every authenticated interval
    /// document. Counters/ordinals below reject partial bundles but cannot replace
    /// that accepted document-plan proof or a current access decision.
    pub(in crate::raw_index::dense::graph) fn construct_segment(
        &self,
        workspace: &str,
        generation: &Generation,
        manifest: &mut DenseDeltaManifest,
        inputs: &[GraphInput],
        budget: &mut QueryBudget,
    ) -> ServiceResult<SegmentRows> {
        if inputs.len() > MAX_NODES as usize || manifest.nodes != inputs.len() as u64 {
            return Err(exhausted("native segment whole-source node cap differs"));
        }
        let manifest_bytes = metered_json_len(manifest, budget, ROW_BYTES)?;
        budget
            .charge(1, manifest_bytes as u64 * 4 + 8192)
            .map_err(budget_error)?;
        manifest.binding.validate()?;
        manifest.base.validate()?;
        manifest.target_dense.validate()?;
        manifest.before.validate(generation.through)?;
        manifest.after.validate(generation.through)?;
        let sources = manifest.after.sources.checked_sub(manifest.before.sources);
        let embedded = manifest
            .after
            .embedded_sources
            .checked_sub(manifest.before.embedded_sources);
        let omitted = manifest
            .after
            .omitted_sources
            .checked_sub(manifest.before.omitted_sources);
        if !valid_hex(workspace)
            || manifest.revision != 1
            || manifest.ordinal == 0
            || !(1..=MAX_WORK).contains(&manifest.work_items)
            || manifest
                .after
                .through
                .checked_sub(manifest.before.through)
                .is_none_or(|width| u64::from(manifest.work_items) > width)
            || sources.is_none_or(|count| count > u64::from(manifest.work_items))
            || embedded
                .zip(omitted)
                .is_none_or(|(a, b)| a.checked_add(b) != sources)
            || manifest.before.spans == 0
            || manifest.before.commitment.as_bytes() == &[0; 32]
            || manifest.after.commitment.as_bytes() == &[0; 32]
            || manifest.interval_digest.as_bytes() == &[0; 32]
            || manifest.builder_revision != contextdb_index::ANN_PARTITION_BUILD_REVISION_V2
            || manifest.target_dense.global_commit <= manifest.base.publication.global_commit
            || manifest.binding.generation != generation.number
            || manifest.binding.custody_version != generation.custody_version
            || manifest.binding.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&manifest.binding.bm25)
            || manifest.binding.authorization_epoch != generation.authorization_epoch
            || manifest.binding.removal_through != generation.removal_through
            || manifest.binding.raw_through != generation.through
            || manifest.binding.raw_sources != generation.projected_sources
            || manifest.after.through > generation.through
            || manifest.after.sources > generation.projected_sources
            || (manifest.after.through == generation.through
                && manifest.after.sources != generation.projected_sources)
            || generation.dense.as_ref() != Some(&manifest.after)
            || manifest.before.profile != manifest.after.profile
            || manifest.before.profile_digest != manifest.after.profile_digest
            || manifest.before.vector_space_id != manifest.after.vector_space_id
            || manifest.after.spans.checked_sub(manifest.before.spans) != Some(manifest.nodes)
            || manifest.before.through >= manifest.after.through
        {
            return Err(integrity(
                "segment construction current interval binding differs",
            ));
        }

        // Reserve all map/set entries before growth. No source bodies or corpus
        // scan are performed; the caller retains one complete source-plan census.
        budget
            .charge(inputs.len() as u64 + 1, inputs.len() as u64 * 2048 + 256)
            .map_err(budget_error)?;
        let mut documents = BTreeMap::<ObservationId, (&GraphInput, u64, u32)>::new();
        let mut ordinals = BTreeSet::new();
        let mut domains = BTreeSet::new();
        for input in inputs {
            let vector = &input.vector;
            if input.policies.is_empty()
                || input.policies.len() > 128
                || vector.values_bits.len() != manifest.after.profile.dimensions as usize
                || input.values.len() != vector.values_bits.len()
                || vector.ordinal >= 64
                || vector.profile_digest != manifest.after.profile_digest
                || vector.commit <= manifest.before.through
                || vector.commit > manifest.after.through
                || vector.event_digest.as_bytes() == &[0; 32]
                || vector.input_digest.as_bytes() == &[0; 32]
                || vector.tokens_digest.as_bytes() == &[0; 32]
                || vector.token_count == 0
                || vector.token_count > manifest.after.profile.max_input_tokens
                || !valid_hex(&vector.policy_domain)
                || !vector.source.independent_source
                || vector.source.omission.is_some()
                || vector.span.event_id != vector.source.event_id
                || Some(vector.span.payload_digest) != vector.source.payload_digest
                || vector.span.span_digest.as_bytes() == &[0; 32]
                || vector.span.start >= vector.span.end
                || vector
                    .source
                    .byte_length
                    .is_none_or(|end| vector.span.end > end)
            {
                return Err(integrity(
                    "segment construction source/vector shape differs",
                ));
            }
            let bytes = metered_json_len(&(vector, &input.policies), budget, ROW_BYTES)?;
            metered_json_len(&input.policies, budget, ROW_BYTES / 2)?;
            // Existing owner-vector checking clones/encodes only after this
            // prepayment; topology's own copies use this same parent later.
            budget
                .charge(
                    vector.values_bits.len() as u64 + 1,
                    bytes as u64 * 16 + 8192,
                )
                .map_err(budget_error)?;
            self.check_dense_vector_token(vector)?;
            let mut hash = blake3::Hasher::new();
            let mut norm = 0_f64;
            for (value, bits) in input.values.iter().zip(&vector.values_bits) {
                budget.charge(1, 4).map_err(budget_error)?;
                if !value.is_finite() || value.to_bits() != *bits {
                    return Err(integrity("segment construction vector values differ"));
                }
                norm += f64::from(*value).powi(2);
                hash.update(&value.to_le_bytes());
            }
            if (norm - 1.0).abs() > 0.001
                || ContentDigest::from_bytes(*hash.finalize().as_bytes()) != vector.vector_digest
            {
                return Err(integrity(
                    "segment construction vector digest or normalization differs",
                ));
            }
            if !ordinals.insert((vector.source.event_id, vector.ordinal)) {
                return Err(integrity("segment construction repeats a source ordinal"));
            }
            domains.insert(vector.policy_domain.as_str());
            if domains.len() > MAX_COHORTS {
                return Err(exhausted("native segment cohort cap exceeded"));
            }
            match documents.entry(vector.source.event_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((input, 1, vector.ordinal));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (first, count, maximum) = entry.get_mut();
                    if first.vector.source != vector.source
                        || first.vector.event_digest != vector.event_digest
                        || first.vector.commit != vector.commit
                        || first.vector.profile_digest != vector.profile_digest
                        || first.vector.policy_domain != vector.policy_domain
                        || first.policies != input.policies
                    {
                        return Err(integrity(
                            "segment source bundle immutable metadata differs",
                        ));
                    }
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| exhausted("segment source span counter overflow"))?;
                    *maximum = (*maximum).max(vector.ordinal);
                }
            }
        }
        if manifest
            .after
            .embedded_sources
            .checked_sub(manifest.before.embedded_sources)
            != Some(documents.len() as u64)
            || documents
                .values()
                .any(|(_, count, maximum)| *count != u64::from(*maximum) + 1)
        {
            return Err(integrity(
                "segment construction lacks a whole encoded source bundle",
            ));
        }

        // The original portable builder uses these REAL source vectors and full
        // accepted after-profile. It does not receive a fabricated v1 receipt.
        let GraphTopology {
            members,
            cohorts,
            nodes,
            summaries,
        } =
            self.construct_graph_topology(workspace, generation, &manifest.after, inputs, budget)?;
        let row_count = members
            .len()
            .checked_add(cohorts.len())
            .and_then(|n| n.checked_add(nodes.len()))
            .ok_or_else(|| exhausted("segment publication row count overflow"))?;
        if row_count + 16 > crate::raw_index::MAX_PROJECTION_ROWS {
            return Err(exhausted("segment publication row cap exceeded"));
        }
        budget
            .charge(
                row_count as u64 + 1,
                members.len() as u64 * size_of::<SegMember>() as u64 * 2
                    + nodes.len() as u64 * size_of::<SegNode>() as u64 * 2
                    + cohorts.len() as u64 * size_of::<SegCohort>() as u64 * 2
                    + 1024,
            )
            .map_err(budget_error)?;
        let mut members: Vec<_> = members
            .into_iter()
            .map(|m| SegMember {
                segment_ordinal: manifest.ordinal,
                representation_id: m.representation_id,
                identity_digest: m.identity_digest,
                source: m.source,
                event_digest: m.event_digest,
                commit: m.commit,
                ordinal: m.ordinal,
                span: m.span,
                policy_domain: m.policy_domain,
                profile_digest: m.profile_digest,
                vector_digest: m.vector_digest,
                segment_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            })
            .collect();
        let mut cohorts: Vec<_> = cohorts
            .into_iter()
            .map(|c| SegCohort {
                segment_ordinal: manifest.ordinal,
                policy_domain: c.policy_domain,
                policies: c.policies,
                partition: c.partition,
                segment_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            })
            .collect();
        let mut nodes: Vec<_> = nodes
            .into_iter()
            .map(|n| SegNode {
                segment_ordinal: manifest.ordinal,
                representation_id: n.representation_id,
                policy_domain: n.policy_domain,
                canonical_node: n.canonical_node,
                segment_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            })
            .collect();
        let mut final_manifest = manifest.clone();
        final_manifest.cohorts = summaries;
        final_manifest.content_digest = self.segment_final_digest(
            workspace,
            &final_manifest,
            &members,
            &cohorts,
            &nodes,
            budget,
        )?;
        final_manifest.validate()?;

        let mut rows = SegmentRows::new();
        for row in &mut members {
            row.segment_digest = final_manifest.content_digest;
            self.sign_segment_member(workspace, &final_manifest, row, budget)?;
            budget.charge(1, KEY_BYTES + 2048).map_err(budget_error)?;
            let key = segment_member_key(
                workspace,
                generation.number,
                final_manifest.ordinal,
                row.representation_id,
            )?;
            let value = metered_encode(row, budget, ROW_BYTES)?;
            if rows.insert(key, value).is_some() {
                return Err(integrity("segment member key collision"));
            }
        }
        for row in &mut cohorts {
            row.segment_digest = final_manifest.content_digest;
            self.sign_segment_cohort(workspace, &final_manifest, row, budget)?;
            budget.charge(1, KEY_BYTES + 2048).map_err(budget_error)?;
            let key = segment_cohort_key(
                workspace,
                generation.number,
                final_manifest.ordinal,
                &row.policy_domain,
            )?;
            let value = metered_encode(row, budget, ROW_BYTES)?;
            if rows.insert(key, value).is_some() {
                return Err(integrity("segment cohort key collision"));
            }
        }
        for row in &mut nodes {
            row.segment_digest = final_manifest.content_digest;
            self.sign_segment_node(workspace, &final_manifest, row, budget)?;
            budget.charge(1, KEY_BYTES + 2048).map_err(budget_error)?;
            let key = segment_node_key(
                workspace,
                generation.number,
                final_manifest.ordinal,
                row.representation_id,
            )?;
            let value = metered_encode(row, budget, ROW_BYTES)?;
            if rows.insert(key, value).is_some() {
                return Err(integrity("segment node key collision"));
            }
        }
        *manifest = final_manifest;
        Ok(rows)
    }
}
