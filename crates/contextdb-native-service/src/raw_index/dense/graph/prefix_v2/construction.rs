//! Finite topology from complete admitted prefix plans. No writer or source reader.

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

type PrefixRows = BTreeMap<Vec<u8>, Vec<u8>>;

impl NativeService {
    /// The caller supplies the opaque accepted interval and every admitted source
    /// plan. Structural counters here cannot substitute for that native proof.
    pub(in crate::raw_index::dense::graph) fn construct_prefix_base(
        &self,
        workspace: &str,
        generation: &Generation,
        manifest: &mut DensePrefixBaseManifestV2,
        inputs: &[GraphInput],
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixRows> {
        parent.check().map_err(budget_error)?;
        if inputs.is_empty()
            || inputs.len() > MAX_NODES as usize
            || manifest.nodes != inputs.len() as u64
        {
            return Err(exhausted("prefix whole-source node cap differs"));
        }
        let bytes = metered_json_len(manifest, parent, ROW_BYTES)?;
        parent
            .charge(1, bytes as u64 * 16 + 8192)
            .map_err(budget_error)?;
        manifest.raw.validate()?;
        manifest.target.validate()?;
        manifest.prefix.validate(generation.through)?;
        if !valid_hex(workspace)
            || manifest.revision != 2
            || !manifest.raw.matches_generation(generation)
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || generation.dense.as_ref() != Some(&manifest.prefix)
            || manifest.admitted_known_at < generation.through
            || generation
                .removal_through
                .is_some_and(|at| at > manifest.admitted_known_at)
            || manifest.admitted_global_commit < manifest.admitted_known_at
            || manifest.target.global_commit > manifest.admitted_global_commit
            || !(1..=MAX_WORK).contains(&manifest.interval.work_items)
            || u64::from(manifest.interval.work_items) > manifest.prefix.through
            || manifest.prefix.sources > u64::from(manifest.interval.work_items)
            || manifest.prefix.sources > generation.projected_sources
            || (manifest.prefix.through == generation.through
                && manifest.prefix.sources != generation.projected_sources)
            || manifest.nodes != manifest.prefix.spans
            || manifest.interval.digest.as_bytes() == &[0; 32]
            || manifest.prefix.commitment.as_bytes() == &[0; 32]
            || manifest.builder_revision != contextdb_index::ANN_PARTITION_BUILD_REVISION_V2
        {
            return Err(integrity("prefix construction real admission differs"));
        }

        // These three monotonic trees never delete/reinsert nodes. Reserve their
        // complete finite storage before any insertion, including split roots.
        parent
            .charge(inputs.len() as u64 + 1, (inputs.len() as u64 + 1) * 6144)
            .map_err(budget_error)?;
        let mut documents = BTreeMap::<ObservationId, (&GraphInput, u64, u32)>::new();
        let mut ordinals = BTreeSet::new();
        let mut domains = BTreeSet::new();
        for input in inputs {
            parent.check().map_err(budget_error)?;
            let v = &input.vector;
            if input.policies.is_empty()
                || input.policies.len() > 128
                || v.values_bits.len() != manifest.prefix.profile.dimensions as usize
                || input.values.len() != v.values_bits.len()
                || v.ordinal >= 64
                || v.profile_digest != manifest.prefix.profile_digest
                || v.commit == 0
                || v.commit > manifest.prefix.through
                || v.event_digest.as_bytes() == &[0; 32]
                || v.input_digest.as_bytes() == &[0; 32]
                || v.tokens_digest.as_bytes() == &[0; 32]
                || v.token_count == 0
                || v.token_count > manifest.prefix.profile.max_input_tokens
                || !valid_hex(&v.policy_domain)
                || !v.source.independent_source
                || v.source.omission.is_some()
                || v.span.event_id != v.source.event_id
                || Some(v.span.payload_digest) != v.source.payload_digest
                || v.span.payload_digest.as_bytes() == &[0; 32]
                || v.span.span_digest.as_bytes() == &[0; 32]
                || v.span.start >= v.span.end
                || v.source.byte_length.is_none_or(|end| v.span.end > end)
            {
                return Err(integrity("prefix source/vector shape differs"));
            }
            let bytes = metered_json_len(&(v, &input.policies), parent, ROW_BYTES)?;
            metered_json_len(&input.policies, parent, ROW_BYTES / 2)?;
            // Covers exact native vector checking and topology's variable clones
            // before either operation allocates or encodes them.
            parent
                .charge(v.values_bits.len() as u64 + 1, bytes as u64 * 16 + 8192)
                .map_err(budget_error)?;
            self.check_dense_vector_token(v)?;
            let mut hash = blake3::Hasher::new();
            let mut norm = 0_f64;
            for (value, bits) in input.values.iter().zip(&v.values_bits) {
                parent.charge(1, 4).map_err(budget_error)?;
                if !value.is_finite() || value.to_bits() != *bits {
                    return Err(integrity("prefix vector values differ"));
                }
                norm += f64::from(*value).powi(2);
                hash.update(&value.to_le_bytes());
            }
            if (norm - 1.0).abs() > 0.001
                || ContentDigest::from_bytes(*hash.finalize().as_bytes()) != v.vector_digest
            {
                return Err(integrity("prefix vector digest or normalization differs"));
            }
            if !ordinals.insert((v.source.event_id, v.ordinal)) {
                return Err(integrity("prefix repeats a source ordinal"));
            }
            domains.insert(v.policy_domain.as_str());
            if domains.len() > MAX_COHORTS {
                return Err(exhausted("prefix whole-policy cohort cap exceeded"));
            }
            match documents.entry(v.source.event_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((input, 1, v.ordinal));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (first, count, maximum) = entry.get_mut();
                    if first.vector.source != v.source
                        || first.vector.event_digest != v.event_digest
                        || first.vector.commit != v.commit
                        || first.vector.profile_digest != v.profile_digest
                        || first.vector.policy_domain != v.policy_domain
                        || first.policies != input.policies
                    {
                        return Err(integrity("prefix source bundle immutable metadata differs"));
                    }
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| exhausted("prefix span counter overflow"))?;
                    *maximum = (*maximum).max(v.ordinal);
                }
            }
        }
        if documents.len() as u64 != manifest.prefix.embedded_sources
            || documents
                .values()
                .any(|(_, count, maximum)| *count != u64::from(*maximum) + 1)
        {
            return Err(integrity(
                "prefix construction lacks complete encoded source bundles",
            ));
        }

        // Only unsigned payloads are reused. No v1 manifest/receipt or altered
        // raw census enters the builder or the new owner encoding.
        let GraphTopology {
            members,
            cohorts,
            nodes,
            summaries,
        } =
            self.construct_graph_topology(workspace, generation, &manifest.prefix, inputs, parent)?;
        let rows_count = members
            .len()
            .checked_add(cohorts.len())
            .and_then(|n| n.checked_add(nodes.len()))
            .ok_or_else(|| exhausted("prefix publication row count overflow"))?;
        if rows_count + 16 > crate::raw_index::MAX_PROJECTION_ROWS {
            return Err(exhausted("prefix publication row cap exceeded"));
        }
        parent
            .charge(
                rows_count as u64 + 1,
                members.len() as u64 * size_of::<PrefixMemberV2>() as u64
                    + cohorts.len() as u64 * size_of::<PrefixCohortV2>() as u64
                    + nodes.len() as u64 * size_of::<PrefixNodeV2>() as u64
                    + 4096,
            )
            .map_err(budget_error)?;
        let mut members: Vec<_> = members
            .into_iter()
            .map(|m| PrefixMemberV2 {
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
                prefix_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            })
            .collect();
        let mut cohorts: Vec<_> = cohorts
            .into_iter()
            .map(|c| PrefixCohortV2 {
                policy_domain: c.policy_domain,
                policies: c.policies,
                partition: c.partition,
                prefix_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            })
            .collect();
        let mut nodes: Vec<_> = nodes
            .into_iter()
            .map(|n| PrefixNodeV2 {
                representation_id: n.representation_id,
                policy_domain: n.policy_domain,
                canonical_node: n.canonical_node,
                prefix_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            })
            .collect();
        let mut final_manifest = manifest.clone();
        final_manifest.cohorts = summaries;
        final_manifest.content_digest = self.prefix_final_digest(
            workspace,
            &final_manifest,
            &members,
            &cohorts,
            &nodes,
            parent,
        )?;
        final_manifest.validate()?;

        // This final tree is also monotonic: moved Vec buffers need no clone;
        // prepay all possible BTree nodes before the first insertion.
        parent
            .charge(rows_count as u64 + 1, (rows_count as u64 + 1) * 2048)
            .map_err(budget_error)?;
        let mut rows = PrefixRows::new();
        for row in &mut members {
            row.prefix_digest = final_manifest.content_digest;
            self.sign_prefix_member(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = member_key(workspace, generation.number, row.representation_id)?;
            let value = metered_encode(row, parent, ROW_BYTES)?;
            if rows.insert(key, value).is_some() {
                return Err(integrity("prefix member key collision"));
            }
        }
        for row in &mut cohorts {
            row.prefix_digest = final_manifest.content_digest;
            self.sign_prefix_cohort(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = cohort_key(workspace, generation.number, &row.policy_domain)?;
            let value = metered_encode(row, parent, ROW_BYTES)?;
            if rows.insert(key, value).is_some() {
                return Err(integrity("prefix cohort key collision"));
            }
        }
        for row in &mut nodes {
            row.prefix_digest = final_manifest.content_digest;
            self.sign_prefix_node(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = node_key(workspace, generation.number, row.representation_id)?;
            let value = metered_encode(row, parent, ROW_BYTES)?;
            if rows.insert(key, value).is_some() {
                return Err(integrity("prefix node key collision"));
            }
        }
        *manifest = final_manifest;
        Ok(rows)
    }
}
