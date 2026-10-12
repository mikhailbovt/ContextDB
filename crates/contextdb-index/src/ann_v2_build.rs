//! Bounded, storage-neutral graph construction for a complete owner-admitted cohort.
//!
//! The owner supplies immutable authorized vectors and exact native policy digest.
//! This component creates no writer, universe, source-body reader or owner seal.

use std::{collections::VecDeque, mem::size_of};

use contextdb_core::{RepresentationId, TimestampMicros};
use thiserror::Error;

use crate::{
    ANN_V2_MAX_PARTITIONS, ANN_V2_MAX_VECTOR_DIMENSIONS, AnnBuildParametersV2, AnnLevelV2,
    AnnMerkleScopeV2, AnnNodeV2, AnnObjectKeyV2, AnnObjectV2, AnnPartitionManifestV2, AnnV2Error,
    IndexError, VectorSpace, ann_v2_merkle_internal, ann_v2_merkle_leaf, ann_v2_merkle_root,
    ann_v2_partition_key,
    vector::{score, validate_values},
};

/// Adapted ID-ordered FIFO construction, score pruning and final base cycle.
/// This revision does not claim byte identity with the persistent runtime builder.
pub const ANN_PARTITION_BUILD_REVISION_V2: &str = "contextdb.ann-v2.owner-memory-fifo-cycle.v1";
/// A whole cohort exceeding this ceiling is refused; inputs are never truncated.
pub const ANN_PARTITION_BUILD_MAX_INPUTS_V2: usize = 4096;

/// Fully authorized immutable input. The native owner binds its ID to a source span.
#[derive(Clone, Copy, Debug)]
pub struct AnnPartitionBuildInputV2<'a> {
    /// Unique nonzero representation ID with a full owner-retained binding.
    pub representation_id: RepresentationId,
    /// Exact full-dimensional finite values in the supplied vector space.
    pub values: &'a [f32],
}

/// Native cohort declaration. It is not synthesized from a lossy `IndexPolicy`.
#[derive(Clone, Copy, Debug)]
pub struct AnnPartitionBuildSpecV2 {
    /// Immutable portable graph generation selected by the owner.
    pub generation: u64,
    /// Exact native compound-policy digest, used verbatim.
    pub policy_digest: [u8; 32],
    /// Positive portable membership epoch; owner binds its native epoch separately.
    pub membership_epoch: u64,
    /// Canonical position assigned by the owner's cohort ordering.
    pub global_leaf_index: u64,
    /// Shared validity lower bound for the complete cohort.
    pub valid_for_all_from: TimestampMicros,
    /// Shared exclusive upper bound, if any.
    pub valid_for_all_until: Option<TimestampMicros>,
    /// Existing portable construction limits; this module has its own revision.
    pub parameters: AnnBuildParametersV2,
}

/// Caller-owned work/allocation/deadline/cancellation admission.
pub trait AnnPartitionBuildBudgetV2 {
    /// Preserve the native budget/cancellation failure without an implicit retry.
    type Error;
    /// Admit work and allocations before creation, checking deadline/cancellation.
    fn charge(&mut self, work: u64, allocation_bytes: u64) -> Result<(), Self::Error>;
}

/// Actual bounded build work, independent of model quality and publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnPartitionBuildTraceV2 {
    /// Input count; all inputs are represented in the final graph.
    pub inputs: u64,
    /// Member visits in bounded FIFO construction searches.
    pub construction_visits: u64,
    /// Exact similarity computations, including reciprocal pruning and cycle repair.
    pub similarity_scores: u64,
}

/// Final portable graph content. The native owner authenticates and publishes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnPartitionBuildResultV2 {
    /// Fixed owned-builder revision; retain it in the native graph receipt.
    pub revision: &'static str,
    /// Exact final node-root, counts, entry and cohort declaration.
    pub partition: AnnPartitionManifestV2,
    /// Canonical node objects in ascending representation-ID/leaf order.
    pub nodes: Vec<AnnObjectV2>,
    /// Actual construction counters.
    pub trace: AnnPartitionBuildTraceV2,
}

/// Invalid graph/vector input and native budget failures remain distinct.
#[derive(Debug, Error)]
pub enum AnnPartitionBuildErrorV2<E> {
    /// Portable format, scalar declaration or input identity refusal.
    #[error(transparent)]
    Contract(AnnV2Error),
    /// Invalid space, dimensions, values or finite similarity.
    #[error(transparent)]
    Vector(IndexError),
    /// Original native budget/deadline/cancellation refusal.
    #[error("ANN partition build allowance refused: {0}")]
    Budget(E),
}

/// Build the complete finite cohort without IO, storage writes or neural forwards.
///
/// Reject scalar limits, all invalid vectors, zero IDs and duplicates before any
/// builder heap allocation. Then sort IDs, adapt the persistent builder's bounded
/// FIFO construction/pruning, enforce its base-cycle reachability and compute the
/// exact duplicate-last portable Merkle root. No partial graph is returned.
pub fn build_ann_partition_v2<B: AnnPartitionBuildBudgetV2>(
    budget: &mut B,
    space: &VectorSpace,
    spec: AnnPartitionBuildSpecV2,
    inputs: &[AnnPartitionBuildInputV2<'_>],
) -> Result<AnnPartitionBuildResultV2, AnnPartitionBuildErrorV2<B::Error>> {
    budget
        .charge(1, 0)
        .map_err(AnnPartitionBuildErrorV2::Budget)?;
    if inputs.is_empty() || inputs.len() > ANN_PARTITION_BUILD_MAX_INPUTS_V2 {
        return Err(contract("whole ANN build cohort exceeds its input bound"));
    }
    spec.parameters
        .validate()
        .map_err(AnnPartitionBuildErrorV2::Contract)?;
    if spec.generation == 0
        || spec.membership_epoch == 0
        || spec.global_leaf_index >= ANN_V2_MAX_PARTITIONS
        || spec
            .valid_for_all_until
            .is_some_and(|until| until <= spec.valid_for_all_from)
    {
        return Err(contract(
            "ANN build generation, epoch, leaf or validity is invalid",
        ));
    }
    let dimensions = space.dimensions as usize;
    if dimensions == 0 || dimensions > ANN_V2_MAX_VECTOR_DIMENSIONS {
        return Err(AnnPartitionBuildErrorV2::Vector(IndexError::Invalid(
            "ANN build dimensions exceed their bound",
        )));
    }
    let validation_work = [
        &space.model_family,
        &space.model_revision,
        &space.preprocessing_revision,
    ]
    .into_iter()
    .try_fold(1_u64, |sum, text| sum.checked_add(text.len() as u64))
    .ok_or_else(|| contract("ANN build validation work overflow"))?;
    budget
        .charge(validation_work, 0)
        .map_err(AnnPartitionBuildErrorV2::Budget)?;
    space.validate().map_err(AnnPartitionBuildErrorV2::Vector)?;
    let partition_key = ann_v2_partition_key(space.id, spec.policy_digest)
        .map_err(AnnPartitionBuildErrorV2::Contract)?;
    for (index, input) in inputs.iter().enumerate() {
        budget
            .charge(dimensions as u64 * 2 + 1, 0)
            .map_err(AnnPartitionBuildErrorV2::Budget)?;
        if input.representation_id.as_uuid().is_nil() {
            return Err(contract("ANN build representation ID is zero"));
        }
        validate_values(space, input.values).map_err(AnnPartitionBuildErrorV2::Vector)?;
        // Allocation-free duplicate validation. Each bounded comparison fragment
        // shares cancellation/deadline; sorting occurs only after full admission.
        for chunk in inputs[..index].chunks(64) {
            budget
                .charge(chunk.len() as u64 + 1, 0)
                .map_err(AnnPartitionBuildErrorV2::Budget)?;
            if chunk
                .iter()
                .any(|previous| previous.representation_id == input.representation_id)
            {
                return Err(contract("ANN build repeats a representation ID"));
            }
        }
    }
    let count = inputs.len();
    let visits = (spec.parameters.construction_max_visits as usize).min(count);
    let scratch = visits.max(usize::from(spec.parameters.neighbours_per_level) + 1);
    let initial_bytes = count as u64
        * (size_of::<usize>() + size_of::<Node>() + size_of::<u32>()) as u64
        + visits as u64 * size_of::<usize>() as u64
        + scratch as u64 * size_of::<Ranked>() as u64;
    budget
        .charge(
            count as u64 * (u64::from(count.ilog2()) + 1) * 2 + 1,
            initial_bytes,
        )
        .map_err(AnnPartitionBuildErrorV2::Budget)?;
    let mut order: Vec<_> = (0..count).collect();
    order.sort_unstable_by_key(|index| inputs[*index].representation_id);
    let mut builder = Builder {
        budget,
        space,
        spec,
        inputs,
        order,
        nodes: Vec::with_capacity(count),
        queue: VecDeque::with_capacity(visits),
        marks: vec![0; count],
        mark: 0,
        ranked: Vec::with_capacity(scratch),
        scores: 0,
        visits: 0,
    };
    let mut entry = 0;
    let mut highest = 0;
    for index in 0..count {
        builder.charge(17, 0)?;
        let digest = blake3::hash(builder.id(index).as_uuid().as_bytes());
        let level = ((digest.as_bytes()[0].leading_zeros() / 2).min(4) as u8)
            .min(spec.parameters.max_level);
        builder.insert(index, level, (index != 0).then_some(entry), highest)?;
        if index == 0 || level > highest {
            entry = index;
            highest = level;
        }
    }
    if count > 1 {
        for owner in 0..count {
            builder.charge(1, 0)?;
            let successor = (owner + 1) % count;
            let mut candidates = [0; 65];
            let old = &builder.nodes[owner].levels[0];
            candidates[..old.len()].copy_from_slice(old);
            candidates[old.len()] = successor;
            let length = old.len() + 1;
            let replacement = builder.prune(owner, &candidates[..length], Some(successor))?;
            builder.nodes[owner].levels[0] = replacement;
        }
    }
    builder.finish(partition_key, entry, highest)
}

fn contract<E>(reason: &'static str) -> AnnPartitionBuildErrorV2<E> {
    AnnPartitionBuildErrorV2::Contract(AnnV2Error::Invalid(reason))
}
struct Node {
    levels: Vec<Vec<usize>>,
}
#[derive(Clone, Copy)]
struct Ranked {
    similarity: f32,
    index: usize,
}

struct Builder<'a, B: AnnPartitionBuildBudgetV2> {
    budget: &'a mut B,
    space: &'a VectorSpace,
    spec: AnnPartitionBuildSpecV2,
    inputs: &'a [AnnPartitionBuildInputV2<'a>],
    order: Vec<usize>,
    nodes: Vec<Node>,
    queue: VecDeque<usize>,
    marks: Vec<u32>,
    mark: u32,
    ranked: Vec<Ranked>,
    scores: u64,
    visits: u64,
}

impl<B: AnnPartitionBuildBudgetV2> Builder<'_, B> {
    fn charge(&mut self, work: u64, bytes: u64) -> Result<(), AnnPartitionBuildErrorV2<B::Error>> {
        self.budget
            .charge(work, bytes)
            .map_err(AnnPartitionBuildErrorV2::Budget)
    }
    fn id(&self, index: usize) -> RepresentationId {
        self.inputs[self.order[index]].representation_id
    }
    fn similarity(
        &mut self,
        left: usize,
        right: usize,
    ) -> Result<f32, AnnPartitionBuildErrorV2<B::Error>> {
        self.charge(self.space.dimensions as u64 * 3 + 1, 0)?;
        self.scores = self
            .scores
            .checked_add(1)
            .ok_or_else(|| contract("ANN build similarity counter overflow"))?;
        score(
            self.space.metric,
            self.inputs[self.order[left]].values,
            self.inputs[self.order[right]].values,
        )
        .map_err(AnnPartitionBuildErrorV2::Vector)
    }
    fn sort_ranked(&mut self) -> Result<(), AnnPartitionBuildErrorV2<B::Error>> {
        let length = self.ranked.len().max(1);
        self.charge(length as u64 * (u64::from(length.ilog2()) + 1) * 2 + 1, 0)?;
        self.ranked.sort_unstable_by(|left, right| {
            right
                .similarity
                .total_cmp(&left.similarity)
                .then_with(|| left.index.cmp(&right.index))
        });
        Ok(())
    }
    fn construction(
        &mut self,
        owner: usize,
        start: usize,
        level: usize,
    ) -> Result<(), AnnPartitionBuildErrorV2<B::Error>> {
        self.charge(1, 0)?;
        self.queue.clear();
        self.ranked.clear();
        self.mark = self
            .mark
            .checked_add(1)
            .ok_or_else(|| contract("ANN build visitation marker overflow"))?;
        self.marks[start] = self.mark;
        self.queue.push_back(start);
        let mut queued = 1_usize;
        let maximum =
            (self.spec.parameters.construction_max_visits as usize).min(self.inputs.len());
        while let Some(index) = self.queue.pop_front() {
            self.charge(1, 0)?;
            if self.ranked.len() == maximum {
                break;
            }
            let similarity = self.similarity(owner, index)?;
            self.ranked.push(Ranked { similarity, index });
            self.visits = self
                .visits
                .checked_add(1)
                .ok_or_else(|| contract("ANN build construction counter overflow"))?;
            if let Some(row) = self.nodes[index].levels.get(level) {
                // Bound is fixed at <=64, so a stack copy avoids allocation and
                // releases the graph borrow before cooperative callback checks.
                let mut neighbors = [0; 64];
                let length = row.len();
                neighbors[..length].copy_from_slice(row);
                for neighbor in &neighbors[..length] {
                    self.charge(1, 0)?;
                    if queued < maximum && self.marks[*neighbor] != self.mark {
                        self.marks[*neighbor] = self.mark;
                        queued = queued
                            .checked_add(1)
                            .ok_or_else(|| contract("ANN build queued count overflow"))?;
                        self.queue.push_back(*neighbor);
                    }
                }
            }
        }
        self.sort_ranked()
    }
    fn selected(&mut self) -> Result<Vec<usize>, AnnPartitionBuildErrorV2<B::Error>> {
        let count = self
            .ranked
            .len()
            .min(usize::from(self.spec.parameters.neighbours_per_level));
        self.charge(
            count as u64 * 8 + 1,
            count as u64 * size_of::<usize>() as u64,
        )?;
        let mut selected: Vec<_> = self
            .ranked
            .iter()
            .take(count)
            .map(|item| item.index)
            .collect();
        selected.sort_unstable();
        Ok(selected)
    }
    fn prune(
        &mut self,
        owner: usize,
        candidates: &[usize],
        required: Option<usize>,
    ) -> Result<Vec<usize>, AnnPartitionBuildErrorV2<B::Error>> {
        self.ranked.clear();
        for index in candidates {
            self.charge(self.ranked.len() as u64 + 1, 0)?;
            if *index != owner && !self.ranked.iter().any(|item| item.index == *index) {
                let similarity = self.similarity(owner, *index)?;
                self.ranked.push(Ranked {
                    similarity,
                    index: *index,
                });
            }
        }
        self.sort_ranked()?;
        let mut selected = self.selected()?;
        if let Some(required) = required {
            self.charge(candidates.len() as u64 + selected.len() as u64 + 1, 0)?;
            if required == owner || !candidates.contains(&required) {
                return Err(contract("ANN build required neighbor is absent"));
            }
            if !selected.contains(&required) {
                // Adapt the persistent builder exactly here: its ID-ordered set
                // removes the largest ID, not the lowest similarity, to admit a
                // required predecessor/successor. Capacity cannot grow.
                if selected.len() == usize::from(self.spec.parameters.neighbours_per_level) {
                    selected.pop();
                }
                selected.push(required);
                selected.sort_unstable();
            }
        }
        Ok(selected)
    }
    fn insert(
        &mut self,
        index: usize,
        level: u8,
        entry: Option<usize>,
        highest: u8,
    ) -> Result<(), AnnPartitionBuildErrorV2<B::Error>> {
        self.charge(
            1,
            (usize::from(level) + 1) as u64 * size_of::<Vec<usize>>() as u64,
        )?;
        let mut levels = Vec::with_capacity(usize::from(level) + 1);
        for current_level in 0..=level {
            self.charge(1, 0)?;
            let mut neighbors = if let Some(start) = entry.filter(|_| current_level <= highest) {
                self.construction(index, start, usize::from(current_level))?;
                self.selected()?
            } else {
                Vec::new()
            };
            if current_level == 0 && index != 0 && !neighbors.contains(&(index - 1)) {
                let mut candidates = [0; 65];
                let length = neighbors.len();
                candidates[..length].copy_from_slice(&neighbors);
                candidates[length] = index - 1;
                neighbors = self.prune(index, &candidates[..length + 1], Some(index - 1))?;
            }
            levels.push(neighbors);
        }
        self.charge(1, 0)?;
        self.nodes.push(Node { levels });
        for current_level in 0..=level {
            let row = &self.nodes[index].levels[usize::from(current_level)];
            let mut neighbors = [0; 64];
            let length = row.len();
            neighbors[..length].copy_from_slice(row);
            for neighbor in &neighbors[..length] {
                self.charge(1, 0)?;
                let old = self.nodes[*neighbor]
                    .levels
                    .get(usize::from(current_level))
                    .ok_or_else(|| contract("ANN build reciprocal neighbor lacks its level"))?;
                let mut candidates = [0; 65];
                let count = old.len();
                candidates[..count].copy_from_slice(old);
                candidates[count] = index;
                let required = (current_level == 0 && *neighbor + 1 == index).then_some(index);
                let replacement = self.prune(*neighbor, &candidates[..count + 1], required)?;
                self.nodes[*neighbor].levels[usize::from(current_level)] = replacement;
            }
        }
        Ok(())
    }
    fn finish(
        mut self,
        partition_key: [u8; 32],
        entry: usize,
        max_level: u8,
    ) -> Result<AnnPartitionBuildResultV2, AnnPartitionBuildErrorV2<B::Error>> {
        let count = self.nodes.len();
        self.charge(
            1,
            count as u64 * (size_of::<AnnObjectV2>() + size_of::<[u8; 32]>()) as u64,
        )?;
        let mut objects = Vec::with_capacity(count);
        let mut hashes = Vec::with_capacity(count);
        let mut level_count = 0_u64;
        let mut neighbor_count = 0_u64;
        let mut node_bytes = 0_u64;
        for index in 0..count {
            self.charge(
                1,
                self.nodes[index].levels.len() as u64 * size_of::<AnnLevelV2>() as u64,
            )?;
            let mut levels = Vec::with_capacity(self.nodes[index].levels.len());
            for level in 0..self.nodes[index].levels.len() {
                let length = self.nodes[index].levels[level].len();
                self.charge(
                    length as u64 + 1,
                    length as u64 * size_of::<RepresentationId>() as u64,
                )?;
                let neighbors = self.nodes[index].levels[level]
                    .iter()
                    .map(|neighbor| self.id(*neighbor))
                    .collect();
                levels.push(AnnLevelV2 {
                    level: level as u8,
                    neighbours: neighbors,
                });
                level_count = level_count
                    .checked_add(1)
                    .ok_or_else(|| contract("ANN build level count overflow"))?;
                neighbor_count = neighbor_count
                    .checked_add(length as u64)
                    .ok_or_else(|| contract("ANN build neighbor count overflow"))?;
            }
            let node = AnnNodeV2 {
                generation: self.spec.generation,
                partition_key,
                representation_id: self.id(index),
                leaf_index: index as u64,
                levels,
            };
            let length = node
                .canonical_wire_len()
                .map_err(AnnPartitionBuildErrorV2::Contract)?;
            // Canonical encode plus the two object validations below each
            // decode, allocate level/neighbor arrays and re-encode the value.
            // Five value-sized allocations plus bounded level/key overhead
            // cover those actual codec allocations before any are created.
            self.charge(length as u64 * 16 + 1, length as u64 * 5 + 1024)?;
            let key =
                AnnObjectKeyV2::node(self.spec.generation, partition_key, node.representation_id)
                    .map_err(AnnPartitionBuildErrorV2::Contract)?;
            let bytes = node
                .encode_canonical()
                .map_err(AnnPartitionBuildErrorV2::Contract)?;
            let object =
                AnnObjectV2::new(key, bytes).map_err(AnnPartitionBuildErrorV2::Contract)?;
            node_bytes = node_bytes
                .checked_add(
                    object
                        .encoded_len()
                        .map_err(AnnPartitionBuildErrorV2::Contract)? as u64,
                )
                .ok_or_else(|| contract("ANN build node bytes overflow"))?;
            let hash = ann_v2_merkle_leaf(&object).map_err(AnnPartitionBuildErrorV2::Contract)?;
            hashes.push(hash);
            objects.push(object);
        }
        let mut level = 1_u16;
        while hashes.len() > 1 {
            let length = hashes.len();
            for pair in 0..length.div_ceil(2) {
                self.charge(65, 0)?;
                let left = hashes[pair * 2];
                let right = hashes[(pair * 2 + 1).min(length - 1)];
                hashes[pair] = ann_v2_merkle_internal(level, left, right)
                    .map_err(AnnPartitionBuildErrorV2::Contract)?;
            }
            hashes.truncate(length.div_ceil(2));
            level = level
                .checked_add(1)
                .ok_or_else(|| contract("ANN build Merkle level overflow"))?;
        }
        self.charge(1, 0)?;
        let root = ann_v2_merkle_root(
            AnnMerkleScopeV2::PartitionNodes {
                generation: self.spec.generation,
                partition_key,
            },
            count as u64,
            Some(hashes[0]),
        )
        .map_err(AnnPartitionBuildErrorV2::Contract)?;
        let partition = AnnPartitionManifestV2 {
            format_version: crate::ANN_V2_FORMAT_VERSION,
            generation: self.spec.generation,
            partition_key,
            policy_digest: self.spec.policy_digest,
            vector_space_id: self.space.id,
            entry: self.id(entry),
            max_level,
            global_leaf_index: self.spec.global_leaf_index,
            node_count: count as u64,
            level_row_count: level_count,
            neighbour_count: neighbor_count,
            node_bytes,
            node_tree_root: root,
            valid_for_all_from: self.spec.valid_for_all_from,
            valid_for_all_until: self.spec.valid_for_all_until,
            membership_epoch: self.spec.membership_epoch,
            manifest_digest: [0; 32],
        }
        .seal()
        .map_err(AnnPartitionBuildErrorV2::Contract)?;
        self.charge(1, 0)?;
        Ok(AnnPartitionBuildResultV2 {
            revision: ANN_PARTITION_BUILD_REVISION_V2,
            partition,
            nodes: objects,
            trace: AnnPartitionBuildTraceV2 {
                inputs: count as u64,
                construction_visits: self.visits,
                similarity_scores: self.scores,
            },
        })
    }
}

#[cfg(test)]
#[path = "ann_v2_build_tests.rs"]
mod tests;
