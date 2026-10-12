//! Synthetic vectors prove the point-reader contract, never encoder recall.

use contextdb_core::{Modality, TimestampMicros, VectorSpaceId};
use std::{collections::BTreeSet, str::FromStr};

use super::*;
use crate::{ANN_V2_FORMAT_VERSION, AnnLevelV2, AnnObjectV2, VectorMetric, ann_v2_partition_key};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Refusal {
    Allowance,
    Denied,
    Stale,
    Missing,
    NotAdmitted,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

struct Reader {
    objects: BTreeMap<Vec<u8>, (RepresentationId, AnnObjectV2)>,
    vectors: BTreeMap<RepresentationId, Vec<f32>>,
    admitted: BTreeSet<RepresentationId>,
    denied: Option<RepresentationId>,
    acknowledgements: usize,
    fail_acknowledgement: Option<usize>,
    cancelled: bool,
    cancel_after_node: bool,
    wrong_node_response: bool,
    remaining_work: u64,
    remaining_bytes: u64,
    node_reads: Vec<RepresentationId>,
    vector_reads: Vec<RepresentationId>,
}
impl AnnPartitionQueryReaderV2 for Reader {
    type Error = Refusal;
    fn charge(&mut self, work: u64, bytes: u64) -> Result<(), Refusal> {
        if self.cancelled || work > self.remaining_work || bytes > self.remaining_bytes {
            return Err(Refusal::Allowance);
        }
        self.remaining_work -= work;
        self.remaining_bytes -= bytes;
        Ok(())
    }
    fn acknowledge_partition(
        &mut self,
        _: &AnnPartitionManifestV2,
        _: &VectorSpace,
    ) -> Result<(), Refusal> {
        self.charge(1, 0)?;
        self.acknowledgements += 1;
        if self.fail_acknowledgement == Some(self.acknowledgements) {
            return Err(Refusal::Stale);
        }
        Ok(())
    }
    fn admit_member(
        &mut self,
        _: &AnnPartitionManifestV2,
        id: RepresentationId,
    ) -> Result<(), Refusal> {
        self.charge(1, 0)?;
        if self.acknowledgements == 0 {
            return Err(Refusal::NotAdmitted);
        }
        if self.denied == Some(id) {
            return Err(Refusal::Denied);
        }
        if !self.vectors.contains_key(&id) {
            return Err(Refusal::Missing);
        }
        self.admitted.insert(id);
        Ok(())
    }
    fn read_node(
        &mut self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> Result<AnnObjectReadResponseV2, Refusal> {
        let (id, object) = if self.wrong_node_response {
            self.objects
                .values()
                .find(|(_, object)| object.key() != request.key)
        } else {
            self.objects.get(request.key.as_bytes())
        }
        .ok_or(Refusal::Missing)?;
        let id = *id;
        let bytes = object.encoded_len().map_err(|_| Refusal::Missing)? as u64;
        if !self.admitted.contains(&id) && !self.wrong_node_response {
            return Err(Refusal::NotAdmitted);
        }
        self.charge(1, bytes * 4)?;
        let object = if self.wrong_node_response {
            self.objects
                .values()
                .find(|(_, object)| object.key() != request.key)
                .expect("alternate fixture")
                .1
                .clone()
        } else {
            self.objects
                .get(request.key.as_bytes())
                .expect("fixture node")
                .1
                .clone()
        };
        self.node_reads.push(id);
        let response_request = AnnObjectReadRequestV2 {
            key: object.key(),
            max_bytes: request.max_bytes,
        };
        let response = AnnObjectReadResponseV2::new(response_request, Some(object.clone()))
            .map_err(|_| Refusal::Missing)?;
        if self.cancel_after_node {
            self.cancelled = true;
        }
        Ok(response)
    }
    fn read_vector(
        &mut self,
        id: RepresentationId,
        dimensions: usize,
        max_bytes: usize,
    ) -> Result<Vec<f32>, Refusal> {
        if !self.admitted.contains(&id) {
            return Err(Refusal::NotAdmitted);
        }
        let bytes = self.vectors.get(&id).ok_or(Refusal::Missing)?.len() * size_of::<f32>();
        assert!(bytes <= max_bytes && dimensions > 0, "bounded fixture read");
        self.charge(1, bytes as u64)?;
        self.vector_reads.push(id);
        Ok(self.vectors[&id].clone())
    }
}

fn id<T: FromStr>(number: u32) -> T
where
    T::Err: std::fmt::Debug,
{
    format!("00000000-0000-4000-8000-{number:012x}")
        .parse()
        .expect("fixed fixture ID")
}
fn space(metric: VectorMetric) -> VectorSpace {
    VectorSpace {
        id: id::<VectorSpaceId>(100),
        dimensions: 2,
        metric,
        model_family: "supplied-vector-contract-fixture".into(),
        model_revision: "1".into(),
        preprocessing_revision: "exact-f32-v1".into(),
        modality: Modality::Text,
    }
}
type FixtureRow = (u32, [f32; 2], Vec<Vec<u32>>);

fn fixture(
    rows: &[FixtureRow],
    metric: VectorMetric,
) -> (Reader, AnnPartitionManifestV2, VectorSpace) {
    let space = space(metric);
    let policy_digest = [7; 32];
    let partition_key = ann_v2_partition_key(space.id, policy_digest).expect("partition key");
    let mut objects = BTreeMap::new();
    let mut vectors = BTreeMap::new();
    let mut level_rows = 0;
    let mut neighbors = 0;
    let mut node_bytes = 0;
    let mut max_level = 0;
    for (leaf, (number, values, levels)) in rows.iter().enumerate() {
        let representation_id = id(*number);
        let node = AnnNodeV2 {
            generation: 11,
            partition_key,
            representation_id,
            leaf_index: leaf as u64,
            levels: levels
                .iter()
                .enumerate()
                .map(|(level, ids)| AnnLevelV2 {
                    level: level as u8,
                    neighbours: ids.iter().map(|number| id(*number)).collect(),
                })
                .collect(),
        };
        level_rows += levels.len() as u64;
        neighbors += levels.iter().map(|ids| ids.len() as u64).sum::<u64>();
        max_level = max_level.max((levels.len() - 1) as u8);
        let key = AnnObjectKeyV2::node(11, partition_key, representation_id).expect("node key");
        let bytes = node.encode_canonical().expect("canonical node");
        node_bytes += bytes.len() as u64;
        let object = AnnObjectV2::new(key, bytes).expect("fixture object");
        objects.insert(
            object.key().as_bytes().to_vec(),
            (representation_id, object),
        );
        vectors.insert(representation_id, values.to_vec());
    }
    // This fixture explicitly acknowledges its supplied graph. It proves no
    // native publication seal, Merkle membership, encoder or quality result.
    let partition = AnnPartitionManifestV2 {
        format_version: ANN_V2_FORMAT_VERSION,
        generation: 11,
        partition_key,
        policy_digest,
        vector_space_id: space.id,
        entry: id(rows[0].0),
        max_level,
        global_leaf_index: 0,
        node_count: rows.len() as u64,
        level_row_count: level_rows,
        neighbour_count: neighbors,
        node_bytes,
        node_tree_root: [9; 32],
        valid_for_all_from: TimestampMicros(0),
        valid_for_all_until: None,
        membership_epoch: 3,
        manifest_digest: [0; 32],
    }
    .seal()
    .expect("fixture manifest");
    let reader = Reader {
        objects,
        vectors,
        admitted: BTreeSet::new(),
        denied: None,
        acknowledgements: 0,
        fail_acknowledgement: None,
        cancelled: false,
        cancel_after_node: false,
        wrong_node_response: false,
        remaining_work: 1_000_000,
        remaining_bytes: 16 * 1024 * 1024,
        node_reads: vec![],
        vector_reads: vec![],
    };
    (reader, partition, space)
}
fn limits() -> AnnPartitionQueryLimitsV2 {
    AnnPartitionQueryLimitsV2 {
        max_node_reads: 32,
        max_vector_reads: 32,
        max_discovered: 32,
        ef_search: 8,
    }
}
fn search(
    reader: &mut Reader,
    partition: &AnnPartitionManifestV2,
    space: &VectorSpace,
    limits: AnnPartitionQueryLimitsV2,
) -> Result<AnnPartitionQueryResultV2, AnnPartitionQueryErrorV2<Refusal>> {
    search_ann_partition_v2(
        reader,
        partition,
        space,
        AnnPartitionQueryV2 {
            values: &[1.0, 0.0],
            limit: 3,
        },
        limits,
    )
}

#[test]
fn best_first_reads_better_frontier_before_lower_id_and_returns_stable_exact_scores() {
    let (mut reader, partition, space) = fixture(
        &[
            (1, [0.0, 1.0], vec![vec![2, 3]]),
            (2, [0.0, 1.0], vec![vec![1]]),
            (3, [1.0, 0.0], vec![vec![1, 4]]),
            (4, [1.0, 0.0], vec![vec![3]]),
        ],
        VectorMetric::Cosine,
    );
    let result = search(
        &mut reader,
        &partition,
        &space,
        AnnPartitionQueryLimitsV2 {
            max_node_reads: 2,
            ..limits()
        },
    )
    .expect("bounded traversal");
    assert_eq!(reader.node_reads, [id(1), id(3)]);
    assert_eq!(result.completion, AnnPartitionQueryCompletionV2::NodeLimit);
    assert_eq!(
        result
            .hits
            .iter()
            .map(|hit| hit.representation_id)
            .collect::<Vec<_>>(),
        [id(3), id(4), id(1)]
    );
    assert_eq!(
        result.hits.iter().map(|hit| hit.score).collect::<Vec<_>>(),
        [1.0, 1.0, 0.0]
    );
    assert_eq!(result.trace.node_reads, 2);
    assert_eq!(result.trace.vector_reads, 4);
    assert_eq!(result.trace.discovered, 4);
    assert_eq!(reader.acknowledgements, 2);
}

#[test]
fn complete_traversal_reuses_scores_and_respects_the_declared_metric() {
    let (mut reader, partition, space) = fixture(
        &[
            (1, [2.0, 1.0], vec![vec![2]]),
            (2, [1.0, 0.0], vec![vec![1]]),
        ],
        VectorMetric::DotProduct,
    );
    let result = search(&mut reader, &partition, &space, limits()).expect("declared metric");
    assert_eq!(result.completion, AnnPartitionQueryCompletionV2::Complete);
    assert_eq!(result.hits[0].score, 2.0, "no guessed cosine normalization");
    assert_eq!(
        reader.vector_reads,
        [id(1), id(2)],
        "duplicate edge scores stay cached"
    );
}

#[test]
fn upper_layer_node_cap_is_checked_before_the_next_physical_read() {
    let (mut reader, partition, space) = fixture(
        &[
            (1, [0.0, 1.0], vec![vec![2], vec![2]]),
            (2, [1.0, 0.0], vec![vec![1], vec![1]]),
        ],
        VectorMetric::Cosine,
    );
    let result = search(
        &mut reader,
        &partition,
        &space,
        AnnPartitionQueryLimitsV2 {
            max_node_reads: 1,
            ..limits()
        },
    )
    .expect("upper layer limit");
    assert_eq!(result.completion, AnnPartitionQueryCompletionV2::NodeLimit);
    assert_eq!(reader.node_reads, [id(1)], "no hidden second read");
    assert_eq!(result.trace.node_reads, 1);
    assert_eq!(result.hits[0].representation_id, id(2));
}

#[test]
fn vector_and_discovery_caps_refuse_before_vector_cache_or_queue_growth() {
    for (vector_cap, discovery_cap, expected) in [
        (1, 8, AnnPartitionQueryCompletionV2::VectorLimit),
        (8, 1, AnnPartitionQueryCompletionV2::DiscoveryLimit),
    ] {
        let (mut reader, partition, space) = fixture(
            &[
                (1, [0.0, 1.0], vec![vec![2]]),
                (2, [1.0, 0.0], vec![vec![1]]),
            ],
            VectorMetric::Cosine,
        );
        let result = search_ann_partition_v2(
            &mut reader,
            &partition,
            &space,
            AnnPartitionQueryV2 {
                values: &[1.0, 0.0],
                limit: 1,
            },
            AnnPartitionQueryLimitsV2 {
                max_vector_reads: vector_cap,
                max_discovered: discovery_cap,
                ef_search: 1,
                ..limits()
            },
        )
        .expect("explicit cap");
        assert_eq!(result.completion, expected);
        assert_eq!(reader.vector_reads, [id(1)]);
        assert_eq!(result.trace.discovered, 1);
        assert!(result.trace.peak_queue <= 1);
    }
}

#[test]
fn current_denial_and_final_epoch_failure_preserve_native_errors_and_return_no_hits() {
    let rows = [
        (1, [0.0, 1.0], vec![vec![2]]),
        (2, [1.0, 0.0], vec![vec![1]]),
    ];
    let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
    reader.denied = Some(id(2));
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Reader(Refusal::Denied))
    ));
    assert_eq!(
        reader.vector_reads,
        [id(1)],
        "denied neighbor is never materialized"
    );
    let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
    reader.fail_acknowledgement = Some(2);
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Reader(Refusal::Stale))
    ));
    assert_eq!(reader.acknowledgements, 2);
}

#[test]
fn cancellation_and_allocation_refusal_are_observed_before_more_reads() {
    let rows = [
        (1, [0.0, 1.0], vec![vec![2]]),
        (2, [1.0, 0.0], vec![vec![1]]),
    ];
    let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
    reader.cancel_after_node = true;
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Reader(Refusal::Allowance))
    ));
    assert_eq!(reader.node_reads, [id(1)]);
    assert_eq!(reader.vector_reads, [id(1)]);
    let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
    reader.remaining_bytes = 0;
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Reader(Refusal::Allowance))
    ));
    assert!(reader.node_reads.is_empty() && reader.vector_reads.is_empty());
}

#[test]
fn wrong_key_nonfinite_vector_and_incompatible_space_are_rejected() {
    let rows = [
        (1, [0.0, 1.0], vec![vec![2]]),
        (2, [1.0, 0.0], vec![vec![1]]),
    ];
    let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
    reader.wrong_node_response = true;
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Contract(_))
    ));
    let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
    reader.vectors.get_mut(&id(1)).expect("fixture vector")[0] = f32::NAN;
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Vector(_))
    ));
    for invalid in [vec![1.0], vec![0.0, 0.0]] {
        let (mut reader, partition, space) = fixture(&rows, VectorMetric::Cosine);
        reader.vectors.insert(id(1), invalid);
        assert!(matches!(
            search(&mut reader, &partition, &space, limits()),
            Err(AnnPartitionQueryErrorV2::Vector(_))
        ));
    }
    let (mut reader, partition, mut space) = fixture(&rows, VectorMetric::Cosine);
    space.id = id(101);
    assert!(matches!(
        search(&mut reader, &partition, &space, limits()),
        Err(AnnPartitionQueryErrorV2::Vector(
            IndexError::IncompatibleVectorSpace
        ))
    ));
    assert_eq!(reader.acknowledgements, 0);
    assert!(reader.node_reads.is_empty() && reader.vector_reads.is_empty());
}
