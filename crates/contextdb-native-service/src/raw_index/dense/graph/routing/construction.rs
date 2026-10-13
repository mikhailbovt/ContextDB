//! Actual mean centroids and bounded routing topology. No reader, writer or encoder.

use super::super::{ann_error, identity, parameters, portable_epoch, publication::GraphInput};
use super::crypto::{metered_encode, metered_json_len, router_hash, router_input_identity};
use super::types::*;
use crate::{
    NativeService, exhausted, integrity,
    raw_index::{Generation, budget_error},
};
use contextdb_core::{ContentDigest, RepresentationId, TimestampMicros};
use contextdb_index::{
    AnnNodeV2, AnnPartitionBuildBudgetV2, AnnPartitionBuildErrorV2, AnnPartitionBuildInputV2,
    AnnPartitionBuildSpecV2, build_ann_partition_v2,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{AccessPolicy, ServiceError, ServiceResult};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::collections::{BTreeMap, BTreeSet};

struct BuildBudget<'a>(&'a mut QueryBudget);
impl AnnPartitionBuildBudgetV2 for BuildBudget<'_> {
    type Error = ServiceError;
    fn charge(&mut self, work: u64, bytes: u64) -> ServiceResult<()> {
        self.0.charge(work, bytes).map_err(budget_error)
    }
}
type Contributor<'a> = (&'a GraphInput, RepresentationId, ContentDigest);
struct Contributors<'a>(&'a [Contributor<'a>]);
impl Serialize for Contributors<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (input, id, full) in self.0 {
            let v = &input.vector;
            // Full source/version/span/profile/vector identity is in `full`;
            // retain actual encoder input/token observations independently too.
            sequence.serialize_element(&(
                id,
                full,
                v.input_digest,
                v.tokens_digest,
                v.token_count,
                v.vector_digest,
            ))?;
        }
        sequence.end()
    }
}
fn sort_fee(count: usize, parent: &mut QueryBudget) -> ServiceResult<()> {
    let height = usize::BITS - count.max(1).leading_zeros();
    parent
        .charge(count as u64 * u64::from(height) * 4 + 1, 0)
        .map_err(budget_error)
}
fn vector_digest(values: &[f32], parent: &mut QueryBudget) -> ServiceResult<ContentDigest> {
    parent
        .charge(1, size_of::<blake3::Hasher>() as u64 + 256)
        .map_err(budget_error)?;
    let mut hash = blake3::Hasher::new();
    for value in values {
        parent.charge(1, 4).map_err(budget_error)?;
        hash.update(&value.to_le_bytes());
    }
    Ok(ContentDigest::from_bytes(*hash.finalize().as_bytes()))
}

impl NativeService {
    /// Derive one real fine-policy cohort's centroid. The collector separately
    /// proves complete path coverage and current contributor access before reads.
    #[allow(
        clippy::too_many_arguments,
        reason = "one genuine fine cohort retains its path, partition, policies and caller budget"
    )]
    pub(super) fn directory_router_input(
        &self,
        workspace: &str,
        generation: &Generation,
        path: DirectoryRouterFinePathV1,
        fine_partition_digest: ContentDigest,
        policies: &[AccessPolicy],
        inputs: &[GraphInput],
        parent: &mut QueryBudget,
    ) -> ServiceResult<DirectoryRouterInputV1> {
        parent.check().map_err(budget_error)?;
        path.validate()?;
        if !valid_hex(workspace)
            || !nonzero(fine_partition_digest)
            || inputs.is_empty()
            || inputs.len() > path.contributor_cap()
            || policies.is_empty()
            || policies.len() > 128
        {
            return Err(integrity("router fine cohort input bound differs"));
        }
        let dense = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("router fine input dense profile absent"))?;
        let metadata = metered_json_len(&(generation, &path, policies), parent, ROW_BYTES * 2)?;
        parent
            .charge(metadata as u64 + 1, metadata as u64 * 16 + 8192)
            .map_err(budget_error)?;
        dense.validate(generation.through)?;
        if generation.number == 0
            || generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != contextdb_index::RAW_ANALYZER
            || generation.bm25.is_none()
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
        {
            return Err(integrity("router fine input real generation differs"));
        }
        generation.bm25.as_ref().expect("checked BM25").validate()?;
        let policy_digest = router_hash(b"", &policies, ROW_BYTES / 2, parent)?;
        parent.charge(1, 128).map_err(budget_error)?;
        let domain = policy_digest.to_string();
        let dimensions = dense.profile.dimensions as usize;
        parent
            .charge(
                inputs.len() as u64 + 1,
                inputs.len() as u64 * size_of::<Contributor<'_>>() as u64 + 256,
            )
            .map_err(budget_error)?;
        let mut ordered = Vec::with_capacity(inputs.len());
        for input in inputs {
            let v = &input.vector;
            if input.policies.as_slice() != policies
                || v.policy_domain != domain
                || v.profile_digest != dense.profile_digest
                || v.values_bits.len() != dimensions
                || input.values.len() != dimensions
                || v.ordinal >= 64
                || v.commit == 0
                || v.commit > dense.through
                || !v.source.independent_source
                || v.source.omission.is_some()
                || !nonzero(v.event_digest)
                || !nonzero(v.input_digest)
                || !nonzero(v.tokens_digest)
                || !nonzero(v.vector_digest)
                || v.token_count == 0
                || v.token_count > dense.profile.max_input_tokens
                || v.span.event_id != v.source.event_id
                || Some(v.span.payload_digest) != v.source.payload_digest
                || !nonzero(v.span.payload_digest)
                || !nonzero(v.span.span_digest)
                || v.span.start >= v.span.end
                || v.source.byte_length.is_none_or(|end| v.span.end > end)
            {
                return Err(integrity("router genuine contributor binding differs"));
            }
            let bytes = metered_json_len(v, parent, ROW_BYTES)?;
            parent
                .charge(dimensions as u64 + 1, bytes as u64 * 16 + 8192)
                .map_err(budget_error)?;
            self.check_dense_vector_token(v)?;
            let mut norm = 0_f64;
            for (value, bits) in input.values.iter().zip(&v.values_bits) {
                parent.charge(1, 4).map_err(budget_error)?;
                if !value.is_finite() || value.to_bits() != *bits {
                    return Err(integrity("router contributor exact values differ"));
                }
                norm += f64::from(*value).powi(2);
            }
            if (norm - 1.0).abs() > 0.001
                || vector_digest(&input.values, parent)? != v.vector_digest
            {
                return Err(integrity("router contributor L2 or digest differs"));
            }
            let (full, id) = identity(&self.database_id, workspace, generation.number, v)?;
            ordered.push((input, id, full));
        }
        sort_fee(ordered.len(), parent)?;
        ordered.sort_unstable_by_key(|(_, id, _)| *id);
        for pair in ordered.windows(2) {
            parent.charge(1, 0).map_err(budget_error)?;
            if pair[0].1 == pair[1].1 {
                return Err(integrity(
                    "router fine contributor compact identity collision",
                ));
            }
        }
        // Check complete contiguous source ordinal bundles independently of ID
        // order. This tree is finite and monotonic; prepay all structural nodes.
        parent
            .charge(inputs.len() as u64 + 1, (inputs.len() as u64 + 1) * 4096)
            .map_err(budget_error)?;
        let mut documents = BTreeMap::new();
        let mut ordinals = BTreeSet::new();
        for (input, _, _) in &ordered {
            parent.charge(1, 0).map_err(budget_error)?;
            let v = &input.vector;
            if !ordinals.insert((v.source.event_id, v.ordinal)) {
                return Err(integrity("router contributor source ordinal repeats"));
            }
            match documents.entry(v.source.event_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((*input, 1_u32, v.ordinal));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let (first, count, maximum) = entry.get_mut();
                    if first.vector.source != v.source
                        || first.vector.event_digest != v.event_digest
                        || first.vector.commit != v.commit
                    {
                        return Err(integrity(
                            "router contributor source version bundle differs",
                        ));
                    }
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| exhausted("router contributor counter overflow"))?;
                    *maximum = (*maximum).max(v.ordinal);
                }
            }
        }
        if documents
            .values()
            .any(|(_, count, maximum)| *count != *maximum + 1)
        {
            return Err(integrity(
                "router fine cohort lacks a whole source span bundle",
            ));
        }
        let cap = ROW_BYTES
            .checked_add(ordered.len() * 4096)
            .ok_or_else(|| exhausted("router contributor stream bound overflow"))?;
        let contributors_digest = router_hash(
            CONTRIBUTORS_DOMAIN,
            &(
                &self.database_id,
                workspace,
                generation.number,
                &path,
                fine_partition_digest,
                &domain,
                dense.profile_digest,
                dense.vector_space_id,
                RECIPE_REVISION,
                QUERY_TRANSFORM,
                Contributors(&ordered),
            ),
            cap,
            parent,
        )?;
        parent
            .charge(dimensions as u64 + 1, dimensions as u64 * 16 + 512)
            .map_err(budget_error)?;
        let mut mean = vec![0_f64; dimensions];
        for (input, _, _) in &ordered {
            for (sum, value) in mean.iter_mut().zip(&input.values) {
                parent.charge(1, 0).map_err(budget_error)?;
                *sum += f64::from(*value);
            }
        }
        let count = ordered.len() as f64;
        let mut norm = 0_f64;
        for coordinate in &mut mean {
            parent.charge(2, 0).map_err(budget_error)?;
            *coordinate /= count;
            norm += *coordinate * *coordinate;
        }
        parent.charge(1, 0).map_err(budget_error)?;
        let norm = norm.sqrt();
        if !norm.is_finite() {
            return Err(integrity("router real centroid norm is nonfinite"));
        }
        let (first, id, full) = ordered[0];
        let mode = if norm == 0.0 {
            DirectoryRouterCentroidModeV1::FirstContributor {
                representation_id: id,
                identity_digest: full,
                vector_digest: first.vector.vector_digest,
            }
        } else {
            DirectoryRouterCentroidModeV1::Mean
        };
        let mut values = Vec::with_capacity(dimensions);
        let mut values_bits = Vec::with_capacity(dimensions);
        let mut result_norm = 0_f64;
        for (i, coordinate) in mean.iter().enumerate() {
            parent.charge(3, 0).map_err(budget_error)?;
            let value = if norm == 0.0 {
                first.values[i]
            } else {
                (*coordinate / norm) as f32
            };
            let value = if value == 0.0 { 0.0 } else { value };
            if !value.is_finite() {
                return Err(integrity("router derived centroid is nonfinite"));
            }
            result_norm += f64::from(value).powi(2);
            values.push(value);
            values_bits.push(value.to_bits());
        }
        if (result_norm - 1.0).abs() > 0.001 {
            return Err(integrity("router derived centroid L2 differs"));
        }
        let vector_digest = vector_digest(&values, parent)?;
        Ok(DirectoryRouterInputV1 {
            path,
            fine_partition_digest,
            policies: policies.to_vec(),
            policy_domain: domain,
            contributors: inputs.len() as u64,
            contributors_digest,
            values,
            values_bits,
            vector_digest,
            mode,
            source_profile_digest: dense.profile_digest,
            source_space_id: dense.vector_space_id,
        })
    }

    /// Build routing-only ANN content from all completely admitted centroids.
    /// Finalize the caller manifest only after every bounded row has succeeded.
    pub(super) fn construct_directory_router(
        &self,
        workspace: &str,
        generation: &Generation,
        manifest: &mut DirectoryRouterManifestV1,
        inputs: &[DirectoryRouterInputV1],
        parent: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        parent.check().map_err(budget_error)?;
        if inputs.is_empty()
            || inputs.len() > MAX_REPRESENTATIVES
            || manifest.representatives != inputs.len() as u64
        {
            return Err(exhausted("router complete representative cap differs"));
        }
        let bytes = metered_json_len(manifest, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 16 + 8192)
            .map_err(budget_error)?;
        let mut final_manifest = manifest.clone();
        let (space_digest, space) =
            self.directory_router_space(&manifest.covered, &manifest.recipe, parent)?;
        final_manifest.coarse_space_digest = space_digest;
        final_manifest.coarse_space_id = space.id;
        final_manifest.validate_header()?;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("router current dense profile absent"))?;
        latest.validate(generation.through)?;
        let base = generation
            .dense_prefix_base
            .as_ref()
            .ok_or_else(|| integrity("router genuine prefix base absent"))?;
        if !valid_hex(workspace)
            || !final_manifest.raw.matches_generation(generation)
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || generation.dense_prefix_segments != final_manifest.coverage.directory
            || base.global_commit != final_manifest.coverage.base.publication.global_commit
            || base.request_digest != final_manifest.coverage.base.publication.request_digest
            || base.response_digest != final_manifest.coverage.base.publication.response_digest
            || base.receipt_digest != final_manifest.coverage.base.receipt_digest
            || base.content_digest != final_manifest.coverage.base.content_digest
            || latest.profile != manifest.covered.profile
            || latest.profile_digest != manifest.covered.profile_digest
            || latest.vector_space_id != manifest.covered.vector_space_id
            || latest.through < manifest.covered.through
            || latest.sources < manifest.covered.sources
            || latest.embedded_sources < manifest.covered.embedded_sources
            || latest.omitted_sources < manifest.covered.omitted_sources
            || latest.spans < manifest.covered.spans
            || (latest.through == manifest.covered.through && latest != &manifest.covered)
        {
            return Err(integrity(
                "router construction real generation/coverage differs",
            ));
        }
        let build = self.directory_router_build_digest(workspace, &final_manifest, parent)?;
        let contributors = inputs
            .iter()
            .try_fold(0_u64, |total, input| total.checked_add(input.contributors));
        if contributors != Some(manifest.covered.spans) {
            return Err(integrity(
                "router representatives do not cover every fine span",
            ));
        }
        parent
            .charge(inputs.len() as u64 + 1, (inputs.len() as u64 + 1) * 6144)
            .map_err(budget_error)?;
        let mut groups =
            BTreeMap::<String, Vec<(DirectoryRouterMemberV1, &DirectoryRouterInputV1)>>::new();
        let mut paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for input in inputs {
            parent.check().map_err(budget_error)?;
            input.path.validate()?;
            input.mode.validate()?;
            if !input.path.admitted_by(&manifest.coverage)
                || input.source_profile_digest != manifest.source_profile_digest
                || input.source_space_id != manifest.source_space_id
                || !nonzero(input.fine_partition_digest)
                || !nonzero(input.contributors_digest)
                || !nonzero(input.vector_digest)
                || input.contributors == 0
                || input.contributors > input.path.contributor_cap() as u64
                || input.policies.is_empty()
                || input.policies.len() > 128
                || !valid_hex(&input.policy_domain)
                || input.values.len() != space.dimensions as usize
                || input.values_bits.len() != input.values.len()
            {
                return Err(integrity("router derived input full shape differs"));
            }
            let bytes = metered_json_len(
                &(&input.path, &input.policies, &input.mode),
                parent,
                ROW_BYTES,
            )?;
            parent
                .charge(
                    input.values.len() as u64 + 1,
                    bytes as u64 * 16 + input.values.len() as u64 * 8 + 8192,
                )
                .map_err(budget_error)?;
            if router_hash(b"", &input.policies, ROW_BYTES / 2, parent)?.to_string()
                != input.policy_domain
                || vector_digest(&input.values, parent)? != input.vector_digest
            {
                return Err(integrity("router input policy or centroid digest differs"));
            }
            let mut norm = 0_f64;
            for (value, bits) in input.values.iter().zip(&input.values_bits) {
                parent.charge(1, 0).map_err(budget_error)?;
                if !value.is_finite() || value.to_bits() != *bits || *bits == 0x8000_0000 {
                    return Err(integrity("router exact derived bits differ"));
                }
                norm += f64::from(*value).powi(2);
            }
            if (norm - 1.0).abs() > 0.001
                || !paths.insert((input.path.ordinal(), input.policy_domain.as_str()))
            {
                return Err(integrity(
                    "router centroid norm or duplicate fine cohort differs",
                ));
            }
            let (full, id) = router_input_identity(build, input, space.id, parent)?;
            let member = DirectoryRouterMemberV1 {
                representation_id: id,
                identity_digest: full,
                path: input.path.clone(),
                fine_partition_digest: input.fine_partition_digest,
                policy_domain: input.policy_domain.clone(),
                contributors: input.contributors,
                contributors_digest: input.contributors_digest,
                mode: input.mode.clone(),
                source_profile_digest: input.source_profile_digest,
                source_space_id: input.source_space_id,
                coarse_space_id: space.id,
                vector_digest: input.vector_digest,
                router_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            };
            if !ids.insert(id) {
                return Err(integrity("router compact representation collision"));
            }
            let group = groups.entry(input.policy_domain.clone()).or_default();
            if group
                .first()
                .is_some_and(|(_, first)| first.policies != input.policies)
            {
                return Err(integrity("router exact policy conjunction collision"));
            }
            group.push((member, input));
            if groups.len() > MAX_COHORTS {
                return Err(exhausted(
                    "router complete exact policy cohort cap exceeded",
                ));
            }
        }
        parent
            .charge(
                inputs.len() as u64 + 1,
                inputs.len() as u64
                    * (size_of::<DirectoryRouterMemberV1>()
                        + size_of::<DirectoryRouterVectorV1>()
                        + size_of::<DirectoryRouterNodeV1>()) as u64
                    + groups.len() as u64
                        * (size_of::<DirectoryRouterCohortV1>()
                            + size_of::<super::super::GraphCohortSummary>())
                            as u64
                    + 4096,
            )
            .map_err(budget_error)?;
        let mut members = Vec::with_capacity(inputs.len());
        let mut vectors = Vec::with_capacity(inputs.len());
        let mut nodes = Vec::with_capacity(inputs.len());
        let mut cohorts = Vec::with_capacity(groups.len());
        let mut summaries = Vec::with_capacity(groups.len());
        for (domain, mut group) in groups {
            sort_fee(group.len(), parent)?;
            group.sort_unstable_by_key(|(m, _)| m.representation_id);
            parent
                .charge(
                    group.len() as u64 + 1,
                    group.len() as u64 * size_of::<AnnPartitionBuildInputV2<'_>>() as u64 + 256,
                )
                .map_err(budget_error)?;
            let args: Vec<_> = group
                .iter()
                .map(|(m, i)| AnnPartitionBuildInputV2 {
                    representation_id: m.representation_id,
                    values: &i.values,
                })
                .collect();
            let policy = *blake3::Hash::from_hex(&domain)
                .map_err(ann_error)?
                .as_bytes();
            let built = build_ann_partition_v2(
                &mut BuildBudget(parent),
                &space,
                AnnPartitionBuildSpecV2 {
                    generation: generation.number,
                    policy_digest: policy,
                    membership_epoch: portable_epoch(generation.authorization_epoch)?,
                    global_leaf_index: cohorts.len() as u64,
                    valid_for_all_from: TimestampMicros(i64::MIN),
                    valid_for_all_until: None,
                    parameters: parameters(),
                },
                &args,
            )
            .map_err(|e| match e {
                AnnPartitionBuildErrorV2::Budget(e) => e,
                other => ann_error(other),
            })?;
            // The public portable object intentionally has no Serialize impl;
            // its codec owns a bounded private wire shape. Prepay that codec's
            // declared output bound before it creates its canonical Vec.
            let cap = contextdb_index::ANN_V2_MAX_PARTITION_MANIFEST_BYTES;
            parent
                .charge(cap as u64 + 1, cap as u64 * 3 + 256)
                .map_err(budget_error)?;
            let partition = built.partition.encode_json().map_err(ann_error)?;
            parent
                .charge(partition.len() as u64 + 1, 128)
                .map_err(budget_error)?;
            summaries.push(super::super::GraphCohortSummary {
                policy_domain: domain.clone(),
                partition_digest: ContentDigest::from_bytes(*blake3::hash(&partition).as_bytes()),
                nodes: group.len() as u64,
            });
            let policy_bytes = metered_json_len(&group[0].1.policies, parent, ROW_BYTES / 2)?;
            parent
                .charge(1, policy_bytes as u64 * 16 + 4096)
                .map_err(budget_error)?;
            cohorts.push(DirectoryRouterCohortV1 {
                policy_domain: domain.clone(),
                policies: group[0].1.policies.clone(),
                partition,
                router_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            });
            for object in built.nodes {
                parent
                    .charge(
                        object.value().len() as u64 + 1,
                        object.value().len() as u64 * 4 + 8192,
                    )
                    .map_err(budget_error)?;
                let node = AnnNodeV2::decode_canonical(object.value()).map_err(ann_error)?;
                nodes.push(DirectoryRouterNodeV1 {
                    representation_id: node.representation_id,
                    policy_domain: domain.clone(),
                    canonical_node: object.value().to_vec(),
                    router_digest: ContentDigest::from_bytes([0; 32]),
                    token: String::new(),
                });
            }
            for (member, input) in group {
                parent
                    .charge(
                        input.values_bits.len() as u64 + 1,
                        input.values_bits.len() as u64 * 4 + 256,
                    )
                    .map_err(budget_error)?;
                vectors.push(DirectoryRouterVectorV1 {
                    representation_id: member.representation_id,
                    identity_digest: member.identity_digest,
                    policy_domain: domain.clone(),
                    vector_digest: input.vector_digest,
                    values_bits: input.values_bits.clone(),
                    router_digest: ContentDigest::from_bytes([0; 32]),
                    token: String::new(),
                });
                members.push(member);
            }
        }
        sort_fee(inputs.len() * 3, parent)?;
        members.sort_unstable_by_key(|m| m.representation_id);
        vectors.sort_unstable_by_key(|v| v.representation_id);
        nodes.sort_unstable_by_key(|n| n.representation_id);
        final_manifest.cohorts = summaries;
        final_manifest.content_digest = self.directory_router_final_digest(
            workspace,
            &final_manifest,
            &members,
            &vectors,
            &cohorts,
            &nodes,
            parent,
        )?;
        final_manifest.validate()?;
        let count = members.len() + vectors.len() + cohorts.len() + nodes.len();
        if count + 16 > crate::raw_index::MAX_PROJECTION_ROWS {
            return Err(exhausted("router atomic publication row cap exceeded"));
        }
        parent
            .charge(count as u64 + 1, (count as u64 + 1) * 2048)
            .map_err(budget_error)?;
        let mut rows = BTreeMap::new();
        for row in &mut members {
            row.router_digest = final_manifest.content_digest;
            self.sign_router_member(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = member_key(
                workspace,
                generation.number,
                manifest.serial,
                row.representation_id,
            )?;
            insert_row(&mut rows, key, metered_encode(row, parent, ROW_BYTES)?)?;
        }
        for row in &mut vectors {
            row.router_digest = final_manifest.content_digest;
            self.sign_router_vector(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = vector_key(
                workspace,
                generation.number,
                manifest.serial,
                row.representation_id,
            )?;
            insert_row(&mut rows, key, metered_encode(row, parent, ROW_BYTES)?)?;
        }
        for row in &mut cohorts {
            row.router_digest = final_manifest.content_digest;
            self.sign_router_cohort(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = cohort_key(
                workspace,
                generation.number,
                manifest.serial,
                &row.policy_domain,
            )?;
            insert_row(&mut rows, key, metered_encode(row, parent, ROW_BYTES)?)?;
        }
        for row in &mut nodes {
            row.router_digest = final_manifest.content_digest;
            self.sign_router_node(workspace, &final_manifest, row, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let key = node_key(
                workspace,
                generation.number,
                manifest.serial,
                row.representation_id,
            )?;
            insert_row(&mut rows, key, metered_encode(row, parent, ROW_BYTES)?)?;
        }
        *manifest = final_manifest;
        Ok(rows)
    }
}
fn insert_row(
    rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    key: Vec<u8>,
    value: Vec<u8>,
) -> ServiceResult<()> {
    if rows.insert(key, value).is_some() {
        return Err(integrity("router immutable row key collision"));
    }
    Ok(())
}
