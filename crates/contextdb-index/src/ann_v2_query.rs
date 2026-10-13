//! Point-only traversal of one owner-admitted immutable ANN-v2 partition.
//!
//! This module publishes no universe and scans no corpus. The reader establishes
//! the accepted graph seal and current membership; format validity alone never
//! establishes permission or graph-root membership. Results are approximate
//! discovery observations, with exact finite scores for the visited vectors.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
    mem::size_of,
};

use contextdb_core::RepresentationId;
use serde::Serialize;
use thiserror::Error;

use crate::{
    ANN_V2_MAX_NODE_BYTES, ANN_V2_MAX_VECTOR_DIMENSIONS, AnnNodeV2, AnnObjectKeyV2,
    AnnObjectReadRequestV2, AnnObjectReadResponseV2, AnnPartitionManifestV2, AnnV2Error,
    IndexError, VectorSpace,
    vector::{score, validate_values},
};

/// Distinct from the existing persistent runtime's FIFO traversal revision.
pub const ANN_PARTITION_QUERY_REVISION_V2: &str = "contextdb.ann-v2.owner-point-best-first.v1";
/// Hard bound for each query's node reads, vector reads and distinct discoveries.
pub const ANN_PARTITION_QUERY_MAX_READS_V2: usize = 65_536;

/// Point-only owner facade. No method can enumerate or publish a corpus.
///
/// Every method must share the calling operation's absolute deadline,
/// cancellation, work and byte allowance. `charge` admits kernel allocations
/// before creation. Point reads additionally pre-admit their actual bounded IO,
/// response construction and backend decoding; they must not allocate an
/// oversized response and check its size afterward.
pub trait AnnPartitionQueryReaderV2 {
    /// Native failures remain typed, including stale permissions and cancellation.
    type Error;
    /// Check current deadline/cancellation and admit work and allocation bytes.
    fn charge(&mut self, work: u64, allocation_bytes: u64) -> Result<(), Self::Error>;
    /// Establish the accepted published graph seal, exact vector-space semantics,
    /// supported source cutoff and fully admitted policy cohort. Recheck the
    /// current owner epoch on the final acknowledgement too. This is not a
    /// request to count all members, rebuild, or perform unbounded verification.
    fn acknowledge_partition(
        &mut self,
        partition: &AnnPartitionManifestV2,
        space: &VectorSpace,
    ) -> Result<(), Self::Error>;
    /// Establish current custody and the immutable base member's binding to this
    /// exact partition/space/cutoff before either a node or vector is read. A
    /// denied or missing member refuses the query, rather than crossing it as a
    /// routing shortcut. No permission is inferred from a graph neighbor ID.
    fn admit_member(
        &mut self,
        partition: &AnnPartitionManifestV2,
        id: RepresentationId,
    ) -> Result<(), Self::Error>;
    /// Read only the exact admitted node, bound to this request and byte cap.
    /// The owner also establishes its membership in the accepted graph seal.
    fn read_node(
        &mut self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> Result<AnnObjectReadResponseV2, Self::Error>;
    /// Read exactly this admitted immutable vector. `max_bytes` bounds returned
    /// f32 values; the owner separately bounds and charges physical encoding/IO.
    fn read_vector(
        &mut self,
        id: RepresentationId,
        dimensions: usize,
        max_bytes: usize,
    ) -> Result<Vec<f32>, Self::Error>;
    /// Observe each newly materialized vector's validated finite score once,
    /// including observations that do not survive the local result beam. Cached
    /// reuse does not repeat this callback. An owner that retains observations
    /// must admit its own allocations against the same parent allowance; a
    /// refusal discards the query result. The default adds no work or allocation.
    fn observe_score(&mut self, _id: RepresentationId, _score: f32) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Separate finite bounds. They do not reset or replace the parent allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnPartitionQueryLimitsV2 {
    /// Includes repeated upper-layer reads of the same node.
    pub max_node_reads: usize,
    /// Maximum distinct vectors materialized and scored.
    pub max_vector_reads: usize,
    /// Maximum distinct IDs retained in the score cache or discovered queue.
    pub max_discovered: usize,
    /// Best-first candidate beam; must cover the requested result count.
    pub ef_search: usize,
}

/// Values in the exact supplied space. Targets and source bodies stay outside.
#[derive(Clone, Copy, Debug)]
pub struct AnnPartitionQueryV2<'a> {
    /// Full-dimensional query values; no inferred space or normalization.
    pub values: &'a [f32],
    /// Maximum returned representation IDs, from one through `ef_search`.
    pub limit: usize,
}

/// Completion of this approximate traversal, never exhaustive source recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnPartitionQueryCompletionV2 {
    /// Queue/beam stopping condition reached within all local bounds.
    Complete,
    /// A further node read was refused before invoking the reader.
    NodeLimit,
    /// A further vector read was refused before invoking the reader.
    VectorLimit,
    /// A further cache/queue identity was refused before allocation or reading.
    DiscoveryLimit,
}

/// Exact finite similarity for one currently admitted immutable representation.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct AnnPartitionHitV2 {
    /// Owner resolves this to authenticated source spans after bounded fusion.
    pub representation_id: RepresentationId,
    /// Exact score under the supplied space's declared metric.
    pub score: f32,
}

/// Actual kernel read counts; reader-specific IO belongs to the parent trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AnnPartitionQueryTraceV2 {
    /// Fixed new traversal revision, independent of graph-builder revision.
    pub revision: &'static str,
    /// Exact node point-reader invocations.
    pub node_reads: u64,
    /// Exact vector point-reader invocations.
    pub vector_reads: u64,
    /// Distinct validated and scored representations in the bounded cache.
    pub discovered: u64,
    /// Highest simultaneous best-first queue length.
    pub peak_queue: u64,
}

/// A bounded discovery observation; it grants no disclosure or publication rights.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AnnPartitionQueryResultV2 {
    /// Descending exact score, with ascending representation-ID ties.
    pub hits: Vec<AnnPartitionHitV2>,
    /// Local limit status. Native budget/authorization errors remain errors.
    pub completion: AnnPartitionQueryCompletionV2,
    /// Actual traversal counters.
    pub trace: AnnPartitionQueryTraceV2,
}

/// Preserve native failures without relabeling them as a generic budget error.
#[derive(Debug, Error)]
pub enum AnnPartitionQueryErrorV2<E> {
    /// Invalid portable manifest, node or request binding.
    #[error(transparent)]
    Contract(AnnV2Error),
    /// Invalid space, vector or finite-score computation.
    #[error(transparent)]
    Vector(IndexError),
    /// Original owner error, including current denial/deadline/cancellation.
    #[error("ANN partition owner refused: {0}")]
    Reader(E),
}

/// Search one acknowledged partition without writes, scans or target reads.
///
/// The new fixed method uses greedy upper-layer descent and a best-first bounded
/// level-zero beam. Scores from all visited vectors may enter the final beam.
/// Local caps return only already admitted/scored hits with explicit completion;
/// any owner error discards the result. Real-encoder recall is a separate gate.
pub fn search_ann_partition_v2<R: AnnPartitionQueryReaderV2>(
    reader: &mut R,
    partition: &AnnPartitionManifestV2,
    space: &VectorSpace,
    query: AnnPartitionQueryV2<'_>,
    limits: AnnPartitionQueryLimitsV2,
) -> Result<AnnPartitionQueryResultV2, AnnPartitionQueryErrorV2<R::Error>> {
    reader
        .charge(1, 0)
        .map_err(AnnPartitionQueryErrorV2::Reader)?;
    for bound in [
        limits.max_node_reads,
        limits.max_vector_reads,
        limits.max_discovered,
        limits.ef_search,
    ] {
        if bound == 0 || bound > ANN_PARTITION_QUERY_MAX_READS_V2 {
            return Err(AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "partition query limit is invalid",
            )));
        }
    }
    if query.limit == 0
        || query.limit > limits.ef_search
        || limits.ef_search > limits.max_discovered
    {
        return Err(AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
            "partition query beam or result limit is invalid",
        )));
    }
    let dimensions = space.dimensions as usize;
    if dimensions == 0 || dimensions > ANN_V2_MAX_VECTOR_DIMENSIONS {
        return Err(AnnPartitionQueryErrorV2::Vector(IndexError::Invalid(
            "partition vector dimensions exceed their bound",
        )));
    }
    let validation_work = [
        &space.model_family,
        &space.model_revision,
        &space.preprocessing_revision,
    ]
    .into_iter()
    .try_fold(dimensions as u64 * 2 + 1, |work, label| {
        work.checked_add(label.len() as u64)
    })
    .ok_or_else(|| {
        AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
            "partition validation work overflow",
        ))
    })?;
    reader
        .charge(validation_work, 0)
        .map_err(AnnPartitionQueryErrorV2::Reader)?;
    partition
        .validate()
        .map_err(AnnPartitionQueryErrorV2::Contract)?;
    space.validate().map_err(AnnPartitionQueryErrorV2::Vector)?;
    if partition.vector_space_id != space.id {
        return Err(AnnPartitionQueryErrorV2::Vector(
            IndexError::IncompatibleVectorSpace,
        ));
    }
    validate_values(space, query.values).map_err(AnnPartitionQueryErrorV2::Vector)?;
    reader
        .acknowledge_partition(partition, space)
        .map_err(AnnPartitionQueryErrorV2::Reader)?;
    let capacity = limits
        .max_discovered
        .min(limits.max_vector_reads)
        .min(partition.node_count as usize);
    let beam = limits.ef_search.min(capacity);
    reader
        .charge(
            1,
            (capacity as u64 + beam as u64) * size_of::<Ranked>() as u64,
        )
        .map_err(AnnPartitionQueryErrorV2::Reader)?;
    let mut search = Search {
        reader,
        partition,
        space,
        values: query.values,
        limits,
        dimensions,
        cache: BTreeMap::new(),
        frontier: BinaryHeap::with_capacity(capacity),
        retained: Vec::with_capacity(beam),
        beam,
        node_reads: 0,
        vector_reads: 0,
        peak_queue: 0,
        completion: AnnPartitionQueryCompletionV2::Complete,
    };
    search.traverse()?;
    search.finish(query.limit)
}

#[derive(Clone, Copy, Debug)]
struct Ranked {
    id: RepresentationId,
    score: f32,
}
impl PartialEq for Ranked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Ranked {}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.id.cmp(&self.id))
    }
}
struct Cached {
    candidate: Ranked,
    level_zero_seen: bool,
}

struct Search<'a, R: AnnPartitionQueryReaderV2> {
    reader: &'a mut R,
    partition: &'a AnnPartitionManifestV2,
    space: &'a VectorSpace,
    values: &'a [f32],
    limits: AnnPartitionQueryLimitsV2,
    dimensions: usize,
    cache: BTreeMap<RepresentationId, Cached>,
    frontier: BinaryHeap<Ranked>,
    retained: Vec<Ranked>,
    beam: usize,
    node_reads: u64,
    vector_reads: u64,
    peak_queue: u64,
    completion: AnnPartitionQueryCompletionV2,
}

impl<R: AnnPartitionQueryReaderV2> Search<'_, R> {
    fn charge(&mut self, work: u64, bytes: u64) -> Result<(), AnnPartitionQueryErrorV2<R::Error>> {
        self.reader
            .charge(work, bytes)
            .map_err(AnnPartitionQueryErrorV2::Reader)
    }

    fn candidate(
        &mut self,
        id: RepresentationId,
    ) -> Result<Option<Ranked>, AnnPartitionQueryErrorV2<R::Error>> {
        self.charge(1 + u64::from(self.cache.len().max(1).ilog2()), 0)?;
        if let Some(cached) = self.cache.get(&id) {
            return Ok(Some(cached.candidate));
        }
        if self.cache.len() == self.limits.max_discovered {
            self.completion = AnnPartitionQueryCompletionV2::DiscoveryLimit;
            return Ok(None);
        }
        if self.vector_reads == self.limits.max_vector_reads as u64 {
            self.completion = AnnPartitionQueryCompletionV2::VectorLimit;
            return Ok(None);
        }
        if self.cache.len() as u64 >= self.partition.node_count {
            return Err(AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "partition discovered more members than its seal",
            )));
        }
        // Reserve a full BTree node before its first insertion; duplicates never
        // pay a second node reservation. The vector allocation is admitted too.
        let vector_bytes = self.dimensions * size_of::<f32>();
        self.charge(self.dimensions as u64 * 5 + 1, vector_bytes as u64 + 1024)?;
        self.reader
            .admit_member(self.partition, id)
            .map_err(AnnPartitionQueryErrorV2::Reader)?;
        self.vector_reads = self.vector_reads.checked_add(1).ok_or_else(|| {
            AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "partition vector counter overflow",
            ))
        })?;
        let values = self
            .reader
            .read_vector(id, self.dimensions, vector_bytes)
            .map_err(AnnPartitionQueryErrorV2::Reader)?;
        validate_values(self.space, &values).map_err(AnnPartitionQueryErrorV2::Vector)?;
        let candidate = Ranked {
            id,
            score: score(self.space.metric, self.values, &values)
                .map_err(AnnPartitionQueryErrorV2::Vector)?,
        };
        self.charge(1, 0)?;
        self.reader
            .observe_score(id, candidate.score)
            .map_err(AnnPartitionQueryErrorV2::Reader)?;
        self.cache.insert(
            id,
            Cached {
                candidate,
                level_zero_seen: false,
            },
        );
        self.charge(2 * (self.retained.len() as u64 + 1), 0)?;
        let position = self.retained.partition_point(|old| *old >= candidate);
        if position < self.beam {
            if self.retained.len() == self.beam {
                self.retained.pop();
            }
            self.retained.insert(position, candidate);
        }
        Ok(Some(candidate))
    }

    fn node(
        &mut self,
        id: RepresentationId,
    ) -> Result<Option<AnnNodeV2>, AnnPartitionQueryErrorV2<R::Error>> {
        self.charge(1, 0)?;
        if self.node_reads == self.limits.max_node_reads as u64 {
            self.completion = AnnPartitionQueryCompletionV2::NodeLimit;
            return Ok(None);
        }
        self.reader
            .admit_member(self.partition, id)
            .map_err(AnnPartitionQueryErrorV2::Reader)?;
        self.charge(1, 128)?;
        let key = AnnObjectKeyV2::node(self.partition.generation, self.partition.partition_key, id)
            .map_err(AnnPartitionQueryErrorV2::Contract)?;
        let request = AnnObjectReadRequestV2 {
            key: &key,
            max_bytes: ANN_V2_MAX_NODE_BYTES,
        };
        self.node_reads = self.node_reads.checked_add(1).ok_or_else(|| {
            AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "partition node counter overflow",
            ))
        })?;
        let response = self
            .reader
            .read_node(request)
            .map_err(AnnPartitionQueryErrorV2::Reader)?;
        let length = response.object().map_or(0, |object| object.value().len());
        // Response revalidation and canonical node decode are bounded by the
        // exact admitted payload. Backend response allocations belong to reader.
        self.charge(length as u64 * 4 + 1, length as u64 * 4 + 1024)?;
        response
            .validate_for(request)
            .map_err(AnnPartitionQueryErrorV2::Contract)?;
        let object = response.into_object().ok_or_else(|| {
            AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "admitted partition node is absent",
            ))
        })?;
        let node = AnnNodeV2::decode_canonical(object.value())
            .map_err(AnnPartitionQueryErrorV2::Contract)?;
        if node.leaf_index >= self.partition.node_count
            || node.levels.len() > self.partition.max_level as usize + 1
        {
            return Err(AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "partition node leaf or level exceeds its manifest",
            )));
        }
        Ok(Some(node))
    }

    fn enqueue(&mut self, candidate: Ranked) -> Result<(), AnnPartitionQueryErrorV2<R::Error>> {
        self.charge(1 + u64::from(self.cache.len().max(1).ilog2()), 0)?;
        let cached = self.cache.get_mut(&candidate.id).ok_or_else(|| {
            AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                "queued partition candidate is not cached",
            ))
        })?;
        if cached.level_zero_seen {
            return Ok(());
        }
        cached.level_zero_seen = true;
        if self
            .retained
            .last()
            .is_some_and(|worst| self.retained.len() == self.beam && candidate < *worst)
        {
            return Ok(());
        }
        // Every ID is queued at most once. Capacity was admitted for all distinct
        // possible discoveries, so pushing cannot trigger a larger allocation.
        self.frontier.push(candidate);
        self.peak_queue = self.peak_queue.max(self.frontier.len() as u64);
        Ok(())
    }

    fn traverse(&mut self) -> Result<(), AnnPartitionQueryErrorV2<R::Error>> {
        let Some(mut current) = self.candidate(self.partition.entry)? else {
            return Ok(());
        };
        for level in (1..=self.partition.max_level).rev() {
            loop {
                self.charge(1, 0)?;
                let Some(node) = self.node(current.id)? else {
                    return Ok(());
                };
                let row = node.levels.get(level as usize).ok_or_else(|| {
                    AnnPartitionQueryErrorV2::Contract(AnnV2Error::Invalid(
                        "partition routing node lacks its requested level",
                    ))
                })?;
                let mut best = current;
                for id in &row.neighbours {
                    self.charge(1, 0)?;
                    let Some(candidate) = self.candidate(*id)? else {
                        return Ok(());
                    };
                    if candidate > best {
                        best = candidate;
                    }
                }
                if best.id == current.id {
                    break;
                }
                current = best;
            }
        }
        self.enqueue(current)?;
        while let Some(candidate) = self.frontier.peek().copied() {
            self.charge(1 + u64::from(self.frontier.len().max(1).ilog2()), 0)?;
            if self
                .retained
                .last()
                .is_some_and(|worst| self.retained.len() == self.beam && candidate < *worst)
            {
                break;
            }
            self.frontier.pop();
            let Some(node) = self.node(candidate.id)? else {
                return Ok(());
            };
            for id in &node.levels[0].neighbours {
                self.charge(1, 0)?;
                let Some(neighbor) = self.candidate(*id)? else {
                    return Ok(());
                };
                self.enqueue(neighbor)?;
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        limit: usize,
    ) -> Result<AnnPartitionQueryResultV2, AnnPartitionQueryErrorV2<R::Error>> {
        let count = self.retained.len().min(limit);
        self.charge(
            count as u64 + 1,
            count as u64 * size_of::<AnnPartitionHitV2>() as u64,
        )?;
        self.reader
            .acknowledge_partition(self.partition, self.space)
            .map_err(AnnPartitionQueryErrorV2::Reader)?;
        self.charge(1, 0)?;
        let hits = self
            .retained
            .iter()
            .take(count)
            .map(|candidate| AnnPartitionHitV2 {
                representation_id: candidate.id,
                score: candidate.score,
            })
            .collect();
        Ok(AnnPartitionQueryResultV2 {
            hits,
            completion: self.completion,
            trace: AnnPartitionQueryTraceV2 {
                revision: ANN_PARTITION_QUERY_REVISION_V2,
                node_reads: self.node_reads,
                vector_reads: self.vector_reads,
                discovered: self.cache.len() as u64,
                peak_queue: self.peak_queue,
            },
        })
    }
}

#[cfg(test)]
#[path = "ann_v2_query_tests.rs"]
mod tests;
