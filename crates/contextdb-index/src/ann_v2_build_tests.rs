//! Supplied vectors establish graph structure and traversal, never encoder recall.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use contextdb_core::{Modality, VectorSpaceId};

use super::*;
use crate::{
    AnnAlgorithmV2, AnnObjectReadRequestV2, AnnObjectReadResponseV2, AnnPartitionQueryCompletionV2,
    AnnPartitionQueryLimitsV2, AnnPartitionQueryReaderV2, AnnPartitionQueryV2,
    AnnPartitionSchemeV2, VectorMetric, search_ann_partition_v2,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Refusal {
    Work,
    Allocation,
    Cancelled,
    Missing,
    NotAdmitted,
    Stale,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

struct Budget {
    remaining_work: u64,
    remaining_bytes: u64,
    allocated: u64,
    calls: usize,
    cancel_on_call: Option<usize>,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            remaining_work: 10_000_000,
            remaining_bytes: 16 * 1024 * 1024,
            allocated: 0,
            calls: 0,
            cancel_on_call: None,
        }
    }
}
impl AnnPartitionBuildBudgetV2 for Budget {
    type Error = Refusal;
    fn charge(&mut self, work: u64, bytes: u64) -> Result<(), Refusal> {
        self.calls += 1;
        if self.cancel_on_call == Some(self.calls) {
            return Err(Refusal::Cancelled);
        }
        if work > self.remaining_work {
            return Err(Refusal::Work);
        }
        if bytes > self.remaining_bytes {
            return Err(Refusal::Allocation);
        }
        self.remaining_work -= work;
        self.remaining_bytes -= bytes;
        self.allocated += bytes;
        Ok(())
    }
}

fn id<T: FromStr>(number: u32) -> T
where
    T::Err: std::fmt::Debug,
{
    format!("00000000-0000-4000-8000-{number:012x}")
        .parse()
        .expect("fixture ID")
}
fn space(metric: VectorMetric) -> VectorSpace {
    VectorSpace {
        id: id::<VectorSpaceId>(100),
        dimensions: 2,
        metric,
        model_family: "supplied-builder-contract-fixture".into(),
        model_revision: "1".into(),
        preprocessing_revision: "exact-f32-v1".into(),
        modality: Modality::Text,
    }
}
fn spec() -> AnnPartitionBuildSpecV2 {
    AnnPartitionBuildSpecV2 {
        generation: 7,
        policy_digest: [13; 32],
        membership_epoch: 2,
        global_leaf_index: 3,
        valid_for_all_from: TimestampMicros(20),
        valid_for_all_until: Some(TimestampMicros(40)),
        parameters: AnnBuildParametersV2 {
            algorithm: AnnAlgorithmV2::DeterministicHnswV1,
            partition_scheme: AnnPartitionSchemeV2::ExactPolicyV1,
            max_level: 4,
            neighbours_per_level: 2,
            construction_max_visits: 64,
        },
    }
}
fn rows(count: u32) -> Vec<(RepresentationId, [f32; 2])> {
    (1..=count)
        .map(|number| (id(number), [number as f32, 1.0]))
        .collect()
}
fn inputs(rows: &[(RepresentationId, [f32; 2])]) -> Vec<AnnPartitionBuildInputV2<'_>> {
    rows.iter()
        .map(|(representation_id, values)| AnnPartitionBuildInputV2 {
            representation_id: *representation_id,
            values,
        })
        .collect()
}
fn build(
    rows: &[(RepresentationId, [f32; 2])],
    spec: AnnPartitionBuildSpecV2,
) -> AnnPartitionBuildResultV2 {
    build_ann_partition_v2(
        &mut Budget::default(),
        &space(VectorMetric::DotProduct),
        spec,
        &inputs(rows),
    )
    .expect("finite complete build")
}
fn nodes(result: &AnnPartitionBuildResultV2) -> Vec<AnnNodeV2> {
    result
        .nodes
        .iter()
        .map(|object| AnnNodeV2::decode_canonical(object.value()).expect("canonical built node"))
        .collect()
}

#[test]
fn shuffled_inputs_have_identical_canonical_objects_root_counts_and_entry() {
    let rows = rows(19);
    let ordered = build(&rows, spec());
    let mut shuffled = rows.clone();
    shuffled.rotate_left(7);
    shuffled.reverse();
    let reordered = build(&shuffled, spec());
    assert_eq!(
        ordered, reordered,
        "input order does not affect content or trace"
    );
    assert_eq!(ordered.revision, ANN_PARTITION_BUILD_REVISION_V2);
    assert_eq!(ordered.trace.inputs, 19);
    assert!(ordered.trace.similarity_scores >= ordered.trace.construction_visits);
    let nodes = nodes(&ordered);
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.representation_id)
            .collect::<Vec<_>>(),
        rows.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    );
    for (index, node) in nodes.iter().enumerate() {
        assert_eq!(node.leaf_index, index as u64);
    }
    assert_eq!(ordered.partition.node_count, nodes.len() as u64);
    assert_eq!(
        ordered.partition.level_row_count,
        nodes
            .iter()
            .map(|node| node.levels.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(
        ordered.partition.neighbour_count,
        nodes
            .iter()
            .flat_map(|node| &node.levels)
            .map(|level| level.neighbours.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(
        ordered.partition.node_bytes,
        ordered
            .nodes
            .iter()
            .map(|object| object.encoded_len().expect("bounded object") as u64)
            .sum::<u64>()
    );
    let expected_entry = nodes
        .iter()
        .max_by(|left, right| {
            left.levels
                .len()
                .cmp(&right.levels.len())
                .then_with(|| right.representation_id.cmp(&left.representation_id))
        })
        .expect("nonempty");
    assert_eq!(ordered.partition.entry, expected_entry.representation_id);
    assert_eq!(
        ordered.partition.max_level as usize + 1,
        expected_entry.levels.len()
    );
    let mut level = ordered
        .nodes
        .iter()
        .map(|object| ann_v2_merkle_leaf(object).expect("portable leaf"))
        .collect::<Vec<_>>();
    let mut height = 1;
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                ann_v2_merkle_internal(height, pair[0], *pair.get(1).unwrap_or(&pair[0]))
                    .expect("duplicate-last parent")
            })
            .collect();
        height += 1;
    }
    assert_eq!(
        ordered.partition.node_tree_root,
        ann_v2_merkle_root(
            AnnMerkleScopeV2::PartitionNodes {
                generation: spec().generation,
                partition_key: ordered.partition.partition_key
            },
            rows.len() as u64,
            Some(level[0])
        )
        .expect("portable root")
    );
    ordered.partition.validate().expect("sealed manifest");
}

#[test]
fn base_successor_cycle_is_reachable_with_one_slot_and_all_local_caps_hold() {
    let rows = rows(33);
    let spec = AnnPartitionBuildSpecV2 {
        parameters: AnnBuildParametersV2 {
            neighbours_per_level: 1,
            ..spec().parameters
        },
        ..spec()
    };
    let result = build(&rows, spec);
    let nodes = nodes(&result);
    let graph: BTreeMap<_, _> = nodes
        .iter()
        .map(|node| (node.representation_id, node))
        .collect();
    for (index, node) in nodes.iter().enumerate() {
        assert_eq!(
            node.levels[0].neighbours,
            [nodes[(index + 1) % nodes.len()].representation_id]
        );
        for (level, row) in node.levels.iter().enumerate() {
            assert_eq!(row.level as usize, level);
            assert!(row.neighbours.len() <= 1);
            for neighbor in &row.neighbours {
                assert!(
                    graph[neighbor].levels.len() > level,
                    "no edge crosses to a missing level"
                );
            }
        }
    }
    for start in graph.keys() {
        let mut visited = BTreeSet::new();
        let mut current = *start;
        while visited.insert(current) {
            current = graph[&current].levels[0].neighbours[0];
        }
        assert_eq!(visited.len(), rows.len());
        assert_eq!(current, *start);
    }
}

#[test]
fn singleton_has_one_canonical_leaf_and_no_self_edge() {
    let result = build(&rows(1), spec());
    let node = nodes(&result).pop().expect("singleton");
    assert_eq!(result.partition.node_count, 1);
    assert_eq!(result.partition.neighbour_count, 0);
    assert!(node.levels.iter().all(|level| level.neighbours.is_empty()));
    assert_eq!(
        result.partition.node_tree_root,
        ann_v2_merkle_root(
            AnnMerkleScopeV2::PartitionNodes {
                generation: spec().generation,
                partition_key: result.partition.partition_key
            },
            1,
            Some(ann_v2_merkle_leaf(&result.nodes[0]).expect("single leaf"))
        )
        .expect("single root")
    );
}

#[test]
fn invalid_whole_inputs_are_refused_before_any_builder_allocation() {
    let space = space(VectorMetric::Cosine);
    for values in [
        vec![1.0],
        vec![f32::NAN, 1.0],
        vec![f32::INFINITY, 1.0],
        vec![0.0, 0.0],
    ] {
        let mut budget = Budget::default();
        let input = AnnPartitionBuildInputV2 {
            representation_id: id(1),
            values: &values,
        };
        assert!(matches!(
            build_ann_partition_v2(&mut budget, &space, spec(), &[input]),
            Err(AnnPartitionBuildErrorV2::Vector(_))
        ));
        assert_eq!(budget.allocated, 0);
    }
    let values = [1.0, 1.0];
    let valid = AnnPartitionBuildInputV2 {
        representation_id: id(1),
        values: &values,
    };
    let too_many = vec![valid; ANN_PARTITION_BUILD_MAX_INPUTS_V2 + 1];
    for inputs in [&[][..], &[valid, valid][..], &too_many[..]] {
        let mut budget = Budget::default();
        assert!(matches!(
            build_ann_partition_v2(&mut budget, &space, spec(), inputs),
            Err(AnnPartitionBuildErrorV2::Contract(_))
        ));
        assert_eq!(budget.allocated, 0);
    }
    for invalid in [
        AnnPartitionBuildSpecV2 {
            generation: 0,
            ..spec()
        },
        AnnPartitionBuildSpecV2 {
            membership_epoch: 0,
            ..spec()
        },
        AnnPartitionBuildSpecV2 {
            policy_digest: [0; 32],
            ..spec()
        },
        AnnPartitionBuildSpecV2 {
            global_leaf_index: ANN_V2_MAX_PARTITIONS,
            ..spec()
        },
        AnnPartitionBuildSpecV2 {
            valid_for_all_until: Some(spec().valid_for_all_from),
            ..spec()
        },
        AnnPartitionBuildSpecV2 {
            parameters: AnnBuildParametersV2 {
                neighbours_per_level: 0,
                ..spec().parameters
            },
            ..spec()
        },
    ] {
        let mut budget = Budget::default();
        assert!(matches!(
            build_ann_partition_v2(&mut budget, &space, invalid, &[valid]),
            Err(AnnPartitionBuildErrorV2::Contract(_))
        ));
        assert_eq!(budget.allocated, 0);
    }
    let mut budget = Budget::default();
    let oversized_space = VectorSpace {
        dimensions: ANN_V2_MAX_VECTOR_DIMENSIONS as u32 + 1,
        ..space
    };
    assert!(matches!(
        build_ann_partition_v2(&mut budget, &oversized_space, spec(), &[valid]),
        Err(AnnPartitionBuildErrorV2::Vector(_))
    ));
    assert_eq!(budget.allocated, 0);
}

#[test]
fn native_allocation_work_and_mid_construction_cancellation_remain_typed() {
    let rows = rows(3);
    let inputs = inputs(&rows);
    for (mut budget, expected) in [
        (
            Budget {
                remaining_bytes: 0,
                ..Budget::default()
            },
            Refusal::Allocation,
        ),
        (
            Budget {
                remaining_work: 0,
                ..Budget::default()
            },
            Refusal::Work,
        ),
        (
            Budget {
                cancel_on_call: Some(18),
                ..Budget::default()
            },
            Refusal::Cancelled,
        ),
    ] {
        assert!(
            matches!(build_ann_partition_v2(&mut budget, &space(VectorMetric::DotProduct), spec(), &inputs),
            Err(AnnPartitionBuildErrorV2::Budget(error)) if error == expected)
        );
        if expected == Refusal::Cancelled {
            assert_eq!(budget.calls, 18, "no callback follows the refusal");
            assert!(
                budget.allocated > 0,
                "cancellation interrupts an actual staged build"
            );
        } else {
            assert_eq!(budget.allocated, 0);
        }
    }
}

struct Reader {
    budget: Budget,
    manifest: AnnPartitionManifestV2,
    space: VectorSpace,
    objects: BTreeMap<Vec<u8>, (RepresentationId, AnnObjectV2)>,
    vectors: BTreeMap<RepresentationId, Vec<f32>>,
    admitted: BTreeSet<RepresentationId>,
    node_reads: usize,
    vector_reads: usize,
    acknowledgements: usize,
}
impl AnnPartitionQueryReaderV2 for Reader {
    type Error = Refusal;
    fn charge(&mut self, work: u64, bytes: u64) -> Result<(), Refusal> {
        self.budget.charge(work, bytes)
    }
    fn acknowledge_partition(
        &mut self,
        partition: &AnnPartitionManifestV2,
        space: &VectorSpace,
    ) -> Result<(), Refusal> {
        self.charge(1, 0)?;
        if partition != &self.manifest || space != &self.space {
            return Err(Refusal::Stale);
        }
        self.acknowledgements += 1;
        Ok(())
    }
    fn admit_member(
        &mut self,
        _: &AnnPartitionManifestV2,
        id: RepresentationId,
    ) -> Result<(), Refusal> {
        self.charge(1, 0)?;
        if self.acknowledgements == 0 || !self.vectors.contains_key(&id) {
            return Err(Refusal::Missing);
        }
        self.admitted.insert(id);
        Ok(())
    }
    fn read_node(
        &mut self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> Result<AnnObjectReadResponseV2, Refusal> {
        let (id, object) = self
            .objects
            .get(request.key.as_bytes())
            .ok_or(Refusal::Missing)?;
        if !self.admitted.contains(id) {
            return Err(Refusal::NotAdmitted);
        }
        let bytes = object.encoded_len().map_err(|_| Refusal::Missing)? as u64;
        self.charge(1, bytes * 4)?;
        self.node_reads += 1;
        let object = self.objects[request.key.as_bytes()].1.clone();
        AnnObjectReadResponseV2::new(request, Some(object)).map_err(|_| Refusal::Missing)
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
        let values = self.vectors.get(&id).ok_or(Refusal::Missing)?;
        assert_eq!(values.len(), dimensions);
        let bytes = values.len() * size_of::<f32>();
        assert!(bytes <= max_bytes);
        self.charge(1, bytes as u64)?;
        self.vector_reads += 1;
        Ok(self.vectors[&id].clone())
    }
}

#[test]
fn built_graph_is_searchable_through_the_actual_bounded_point_kernel() {
    let rows = rows(17);
    let space = space(VectorMetric::DotProduct);
    let result = build(&rows, spec());
    let objects = result
        .nodes
        .iter()
        .map(|object| {
            let node = AnnNodeV2::decode_canonical(object.value()).expect("built node");
            (
                object.key().as_bytes().to_vec(),
                (node.representation_id, object.clone()),
            )
        })
        .collect();
    let mut reader = Reader {
        budget: Budget::default(),
        manifest: result.partition.clone(),
        space: space.clone(),
        objects,
        vectors: rows
            .iter()
            .map(|(id, values)| (*id, values.to_vec()))
            .collect(),
        admitted: BTreeSet::new(),
        node_reads: 0,
        vector_reads: 0,
        acknowledgements: 0,
    };
    let output = search_ann_partition_v2(
        &mut reader,
        &result.partition,
        &space,
        AnnPartitionQueryV2 {
            values: &[1.0, 0.0],
            limit: 3,
        },
        AnnPartitionQueryLimitsV2 {
            max_node_reads: 128,
            max_vector_reads: 17,
            max_discovered: 17,
            ef_search: 17,
        },
    )
    .expect("bounded built-graph traversal");
    assert_eq!(output.completion, AnnPartitionQueryCompletionV2::Complete);
    assert_eq!(
        output
            .hits
            .iter()
            .map(|hit| hit.representation_id)
            .collect::<Vec<_>>(),
        [id(17), id(16), id(15)]
    );
    assert_eq!(
        output.hits.iter().map(|hit| hit.score).collect::<Vec<_>>(),
        [17.0, 16.0, 15.0]
    );
    assert_eq!(output.trace.discovered, rows.len() as u64);
    assert_eq!(output.trace.vector_reads, reader.vector_reads as u64);
    assert_eq!(output.trace.node_reads, reader.node_reads as u64);
    assert!(reader.node_reads <= 128);
    assert_eq!(reader.vector_reads, rows.len());
    assert_eq!(
        reader.acknowledgements, 2,
        "final owner epoch is acknowledged again"
    );
}
