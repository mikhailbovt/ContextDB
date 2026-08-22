use std::collections::BTreeMap;

use contextdb_core::{CommitSeq, RepresentationId, TimestampMicros, VectorSpaceId};

use crate::{
    ANN_V2_FORMAT_VERSION, ANN_V2_MAX_NODE_BYTES, ANN_V2_MAX_NODES, ANN_V2_MAX_PAGE_ENTRIES,
    AnnAlgorithmV2, AnnBuildParametersV2, AnnGenerationManifestV2, AnnLevelV2, AnnMerkleGeometryV2,
    AnnMerkleProofV2, AnnMerkleScopeV2, AnnNodeV2, AnnObjectKeyV2, AnnObjectPageRequestV2,
    AnnObjectPageV2, AnnObjectReadRequestV2, AnnObjectReadResponseV2, AnnObjectReaderV2,
    AnnObjectV2, AnnPartitionManifestV2, AnnPartitionSchemeV2, AnnSourceSealV2, AnnV2Error,
    AnnV2Result, ann_v2_empty_partition_root, ann_v2_generation_prefix, ann_v2_merkle_internal,
    ann_v2_merkle_leaf, ann_v2_merkle_root, ann_v2_partition_key, ann_v2_verify_merkle_proof,
    verify_ann_generation_v2,
};

#[derive(Clone, Debug)]
struct MemoryObjectReader {
    objects: BTreeMap<Vec<u8>, AnnObjectV2>,
    page_entries: usize,
}

impl MemoryObjectReader {
    fn new(objects: impl IntoIterator<Item = AnnObjectV2>, page_entries: usize) -> Self {
        let objects = objects
            .into_iter()
            .map(|object| (object.key().as_bytes().to_vec(), object))
            .collect();
        Self {
            objects,
            page_entries,
        }
    }

    fn replace(&mut self, object: AnnObjectV2) {
        self.objects
            .insert(object.key().as_bytes().to_vec(), object);
    }
}

impl AnnObjectReaderV2 for MemoryObjectReader {
    fn get_bounded(
        &self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> AnnV2Result<AnnObjectReadResponseV2> {
        request.validate()?;
        AnnObjectReadResponseV2::new(request, self.objects.get(request.key.as_bytes()).cloned())
    }

    fn scan_page(&self, request: AnnObjectPageRequestV2<'_>) -> AnnV2Result<AnnObjectPageV2> {
        request.validate()?;
        let limit = request.max_entries.min(self.page_entries);
        let mut objects = Vec::new();
        let mut bytes = 0_usize;
        let mut has_more = false;
        for object in self.objects.values().filter(|object| {
            object.key().as_bytes().starts_with(request.prefix)
                && request
                    .start_after
                    .is_none_or(|cursor| object.key().as_bytes() > cursor)
        }) {
            let next_bytes = bytes
                .checked_add(object.encoded_len()?)
                .ok_or(AnnV2Error::Invalid("test page byte counter overflowed"))?;
            if objects.len() == limit || next_bytes > request.max_bytes {
                has_more = true;
                break;
            }
            bytes = next_bytes;
            objects.push(object.clone());
        }
        let continuation = has_more
            .then(|| objects.last().map(|object| object.key().clone()))
            .flatten();
        AnnObjectPageV2::new(request, objects, continuation)
    }
}

fn build_parameters() -> AnnBuildParametersV2 {
    AnnBuildParametersV2 {
        algorithm: AnnAlgorithmV2::DeterministicHnswV1,
        partition_scheme: AnnPartitionSchemeV2::ExactPolicyV1,
        max_level: 4,
        neighbours_per_level: 16,
        construction_max_visits: 256,
    }
}

fn source_seal() -> AnnSourceSealV2 {
    AnnSourceSealV2 {
        vector_store_generation: 7,
        vector_store_root: [1; 32],
        route_generation: 9,
        route_root: [2; 32],
        vector_space_registry_digest: [3; 32],
    }
}

fn generation_manifest() -> AnnGenerationManifestV2 {
    AnnGenerationManifestV2 {
        format_version: ANN_V2_FORMAT_VERSION,
        generation: 11,
        watermark: CommitSeq::new(42),
        source: source_seal(),
        build: build_parameters(),
        partition_count: 1,
        node_count: 2,
        level_row_count: 3,
        neighbour_count: 2,
        object_bytes: 1_024,
        partition_tree_root: [4; 32],
        manifest_digest: [0; 32],
    }
    .seal()
    .expect("valid generation manifest")
}

fn partition_manifest(
    vector_space_id: VectorSpaceId,
    entry: RepresentationId,
) -> AnnPartitionManifestV2 {
    let policy_digest = [6; 32];
    AnnPartitionManifestV2 {
        format_version: ANN_V2_FORMAT_VERSION,
        generation: 11,
        partition_key: ann_v2_partition_key(vector_space_id, policy_digest)
            .expect("canonical partition key"),
        policy_digest,
        vector_space_id,
        entry,
        max_level: 1,
        global_leaf_index: 0,
        node_count: 2,
        level_row_count: 3,
        neighbour_count: 2,
        node_bytes: 512,
        node_tree_root: [7; 32],
        valid_for_all_from: TimestampMicros(10),
        valid_for_all_until: Some(TimestampMicros(20)),
        membership_epoch: 3,
        manifest_digest: [0; 32],
    }
    .seal()
    .expect("valid partition manifest")
}

fn node_with_neighbour(
    representation_id: RepresentationId,
    neighbour: RepresentationId,
) -> AnnNodeV2 {
    AnnNodeV2 {
        generation: 11,
        partition_key: [5; 32],
        representation_id,
        leaf_index: 0,
        levels: vec![AnnLevelV2 {
            level: 0,
            neighbours: vec![neighbour],
        }],
    }
}

fn tree_key(scope: AnnMerkleScopeV2, leaf_count: u64, level: u16, index: u64) -> AnnObjectKeyV2 {
    match scope {
        AnnMerkleScopeV2::PartitionNodes {
            generation,
            partition_key,
        } => AnnObjectKeyV2::partition_tree(generation, partition_key, leaf_count, level, index)
            .expect("partition tree key"),
        AnnMerkleScopeV2::GenerationPartitions { generation } => {
            AnnObjectKeyV2::global_tree(generation, leaf_count, level, index)
                .expect("global tree key")
        }
    }
}

fn physical_tree(scope: AnnMerkleScopeV2, leaves: Vec<[u8; 32]>) -> (Vec<AnnObjectV2>, [u8; 32]) {
    let leaf_count = u64::try_from(leaves.len()).expect("leaf count");
    let mut objects = Vec::new();
    for (index, leaf) in leaves.iter().enumerate() {
        objects.push(
            AnnObjectV2::new(
                tree_key(
                    scope,
                    leaf_count,
                    0,
                    u64::try_from(index).expect("leaf index"),
                ),
                leaf.to_vec(),
            )
            .expect("leaf object"),
        );
    }

    let mut level = 0_u16;
    let mut current = leaves;
    while current.len() > 1 {
        level += 1;
        let mut next = Vec::new();
        for children in current.chunks(2) {
            let left = children[0];
            let right = children.get(1).copied().unwrap_or(left);
            let parent = ann_v2_merkle_internal(level, left, right).expect("internal hash");
            let index = u64::try_from(next.len()).expect("parent index");
            objects.push(
                AnnObjectV2::new(tree_key(scope, leaf_count, level, index), parent.to_vec())
                    .expect("internal object"),
            );
            next.push(parent);
        }
        current = next;
    }
    let top = current.first().copied();
    let root = ann_v2_merkle_root(scope, leaf_count, top).expect("bound tree root");
    (objects, root)
}

fn verified_generation_fixture() -> (
    AnnGenerationManifestV2,
    MemoryObjectReader,
    AnnPartitionManifestV2,
    [RepresentationId; 2],
) {
    let generation = 11;
    let vector_space_id = VectorSpaceId::new();
    let policy_digest = [6; 32];
    let partition_key =
        ann_v2_partition_key(vector_space_id, policy_digest).expect("partition key");
    let mut ids = [RepresentationId::new(), RepresentationId::new()];
    ids.sort_unstable();
    let nodes = [
        AnnNodeV2 {
            generation,
            partition_key,
            representation_id: ids[0],
            leaf_index: 0,
            levels: vec![AnnLevelV2 {
                level: 0,
                neighbours: vec![ids[1]],
            }],
        },
        AnnNodeV2 {
            generation,
            partition_key,
            representation_id: ids[1],
            leaf_index: 1,
            levels: vec![AnnLevelV2 {
                level: 0,
                neighbours: vec![ids[0]],
            }],
        },
    ];
    let node_objects: Vec<_> = nodes
        .iter()
        .map(|node| {
            AnnObjectV2::new(
                AnnObjectKeyV2::node(generation, partition_key, node.representation_id)
                    .expect("node key"),
                node.encode_canonical().expect("node value"),
            )
            .expect("node object")
        })
        .collect();
    let node_bytes = node_objects
        .iter()
        .try_fold(0_u64, |total, object| {
            total
                .checked_add(u64::try_from(object.encoded_len()?).expect("object bytes"))
                .ok_or(AnnV2Error::Invalid("fixture byte overflow"))
        })
        .expect("node byte total");
    let node_leaves = node_objects
        .iter()
        .map(|object| ann_v2_merkle_leaf(object).expect("node leaf"))
        .collect();
    let partition_scope = AnnMerkleScopeV2::PartitionNodes {
        generation,
        partition_key,
    };
    let (partition_tree, node_tree_root) = physical_tree(partition_scope, node_leaves);
    let partition = AnnPartitionManifestV2 {
        format_version: ANN_V2_FORMAT_VERSION,
        generation,
        partition_key,
        policy_digest,
        vector_space_id,
        entry: ids[0],
        max_level: 0,
        global_leaf_index: 0,
        node_count: 2,
        level_row_count: 2,
        neighbour_count: 2,
        node_bytes,
        node_tree_root,
        valid_for_all_from: TimestampMicros(10),
        valid_for_all_until: Some(TimestampMicros(20)),
        membership_epoch: 3,
        manifest_digest: [0; 32],
    }
    .seal()
    .expect("partition manifest");
    let partition_object = AnnObjectV2::new(
        AnnObjectKeyV2::partition_manifest(generation, partition_key)
            .expect("partition manifest key"),
        partition.encode_json().expect("partition manifest value"),
    )
    .expect("partition manifest object");
    let global_scope = AnnMerkleScopeV2::GenerationPartitions { generation };
    let (global_tree, partition_tree_root) = physical_tree(
        global_scope,
        vec![ann_v2_merkle_leaf(&partition_object).expect("partition leaf")],
    );

    let mut objects = Vec::new();
    objects.extend(node_objects);
    objects.push(partition_object);
    objects.extend(partition_tree);
    objects.extend(global_tree);
    let object_bytes = objects
        .iter()
        .try_fold(0_u64, |total, object| {
            total
                .checked_add(u64::try_from(object.encoded_len()?).expect("object bytes"))
                .ok_or(AnnV2Error::Invalid("fixture byte overflow"))
        })
        .expect("generation byte total");
    let manifest = AnnGenerationManifestV2 {
        format_version: ANN_V2_FORMAT_VERSION,
        generation,
        watermark: CommitSeq::new(42),
        source: source_seal(),
        build: AnnBuildParametersV2 {
            max_level: 0,
            neighbours_per_level: 1,
            ..build_parameters()
        },
        partition_count: 1,
        node_count: 2,
        level_row_count: 2,
        neighbour_count: 2,
        object_bytes,
        partition_tree_root,
        manifest_digest: [0; 32],
    }
    .seal()
    .expect("generation manifest");
    (
        manifest,
        MemoryObjectReader::new(objects, 1),
        partition,
        ids,
    )
}

#[test]
fn generation_manifest_digest_is_manual_stable_and_fail_closed() {
    let manifest = generation_manifest();
    let digest = manifest.computed_digest();
    assert_eq!(manifest.manifest_digest, digest);

    let bytes = manifest.encode_json().expect("encode generation");
    let decoded = AnnGenerationManifestV2::decode_json(&bytes).expect("decode generation");
    assert_eq!(decoded, manifest);

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&bytes);
    assert_eq!(
        AnnGenerationManifestV2::decode_json(&noncanonical),
        Err(AnnV2Error::NonCanonical)
    );

    let mut tampered = manifest;
    tampered.node_count += 1;
    assert_eq!(
        tampered.validate(),
        Err(AnnV2Error::DigestMismatch("generation manifest"))
    );
}

#[test]
fn manifests_reject_unknown_fields_versions_placeholders_and_caps() {
    let manifest = generation_manifest();
    let mut value: serde_json::Value =
        serde_json::from_slice(&manifest.encode_json().expect("generation JSON"))
            .expect("generation JSON value");
    value
        .as_object_mut()
        .expect("generation object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    assert!(matches!(
        AnnGenerationManifestV2::decode_json(
            &serde_json::to_vec(&value).expect("unknown-field JSON")
        ),
        Err(AnnV2Error::Invalid("generation manifest JSON is invalid"))
    ));

    let mut wrong_version = generation_manifest();
    wrong_version.format_version = 3;
    assert!(matches!(
        wrong_version.validate(),
        Err(AnnV2Error::UnsupportedFormat {
            actual: 3,
            expected: ANN_V2_FORMAT_VERSION
        })
    ));

    let mut placeholder = generation_manifest();
    placeholder.source.route_root = [0; 32];
    assert_eq!(
        placeholder.validate(),
        Err(AnnV2Error::Invalid("source seal contains a zero digest"))
    );

    let mut over_limit = generation_manifest();
    over_limit.node_count = ANN_V2_MAX_NODES + 1;
    assert!(matches!(
        over_limit.seal(),
        Err(AnnV2Error::ResourceExhausted {
            resource: "generation_nodes",
            ..
        })
    ));

    let empty = AnnGenerationManifestV2 {
        partition_count: 0,
        node_count: 0,
        level_row_count: 0,
        neighbour_count: 0,
        object_bytes: 0,
        partition_tree_root: ann_v2_empty_partition_root(11).expect("empty tree root"),
        ..generation_manifest()
    }
    .seal()
    .expect("canonical empty generation");
    assert!(empty.validate().is_ok());
}

#[test]
fn partition_manifest_binds_identity_counts_time_and_json_shape() {
    let vector_space = VectorSpaceId::new();
    let entry = RepresentationId::new();
    let manifest = partition_manifest(vector_space, entry);
    let bytes = manifest.encode_json().expect("partition encode");
    assert_eq!(
        AnnPartitionManifestV2::decode_json(&bytes).expect("partition decode"),
        manifest
    );

    let mut invalid_time = manifest.clone();
    invalid_time.valid_for_all_until = Some(invalid_time.valid_for_all_from);
    assert_eq!(
        invalid_time.seal(),
        Err(AnnV2Error::Invalid(
            "partition shared validity interval is empty"
        ))
    );

    let mut invalid_count = manifest.clone();
    invalid_count.neighbour_count = invalid_count.level_row_count * 65;
    assert_eq!(
        invalid_count.seal(),
        Err(AnnV2Error::Invalid(
            "partition neighbour count is inconsistent"
        ))
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).expect("partition JSON");
    unknown
        .as_object_mut()
        .expect("partition object")
        .insert("unknown".to_owned(), serde_json::json!(1));
    assert!(
        AnnPartitionManifestV2::decode_json(
            &serde_json::to_vec(&unknown).expect("unknown partition JSON")
        )
        .is_err()
    );
}

#[test]
fn node_codec_is_deterministic_authenticated_and_canonical() {
    let representation = RepresentationId::new();
    let mut neighbours = [RepresentationId::new(), RepresentationId::new()];
    neighbours.sort_unstable();
    let node = AnnNodeV2 {
        generation: 11,
        partition_key: [5; 32],
        representation_id: representation,
        leaf_index: 3,
        levels: vec![
            AnnLevelV2 {
                level: 0,
                neighbours: neighbours.to_vec(),
            },
            AnnLevelV2 {
                level: 1,
                neighbours: vec![neighbours[0]],
            },
        ],
    };
    let first = node.encode_canonical().expect("first encode");
    let second = node.encode_canonical().expect("second encode");
    assert_eq!(first, second);
    assert!(first.len() <= ANN_V2_MAX_NODE_BYTES);
    assert_eq!(AnnNodeV2::decode_canonical(&first).expect("decode"), node);

    let mut corrupt = first.clone();
    corrupt[20] ^= 1;
    assert_eq!(
        AnnNodeV2::decode_canonical(&corrupt),
        Err(AnnV2Error::DigestMismatch("node object"))
    );

    let mut trailing = first;
    trailing.extend_from_slice(&[0]);
    assert!(AnnNodeV2::decode_canonical(&trailing).is_err());
}

#[test]
fn node_codec_rejects_unsafe_rows_before_unbounded_allocation() {
    let representation = RepresentationId::new();
    let neighbour = RepresentationId::new();
    let duplicate = AnnNodeV2 {
        generation: 11,
        partition_key: [5; 32],
        representation_id: representation,
        leaf_index: 0,
        levels: vec![AnnLevelV2 {
            level: 0,
            neighbours: vec![neighbour, neighbour],
        }],
    };
    assert_eq!(
        duplicate.validate(),
        Err(AnnV2Error::Invalid(
            "node neighbours are not unique canonical IDs"
        ))
    );

    let self_link = node_with_neighbour(representation, representation);
    assert!(self_link.validate().is_err());

    let wrong_level = AnnNodeV2 {
        levels: vec![AnnLevelV2 {
            level: 1,
            neighbours: vec![neighbour],
        }],
        ..node_with_neighbour(representation, neighbour)
    };
    assert_eq!(
        wrong_level.validate(),
        Err(AnnV2Error::Invalid("node levels are not contiguous"))
    );

    let oversized = vec![0_u8; ANN_V2_MAX_NODE_BYTES + 1];
    assert!(matches!(
        AnnNodeV2::decode_canonical(&oversized),
        Err(AnnV2Error::ResourceExhausted {
            resource: "node_bytes",
            ..
        })
    ));
}

#[test]
fn object_keys_are_fixed_ordered_and_bounded() {
    let partition = [5; 32];
    let representation = RepresentationId::new();
    let manifest = AnnObjectKeyV2::partition_manifest(11, partition).expect("manifest key");
    let node = AnnObjectKeyV2::node(11, partition, representation).expect("node key");
    let tree = AnnObjectKeyV2::partition_tree(11, partition, 5, 2, 1).expect("tree key");
    let global = AnnObjectKeyV2::global_tree(11, 2, 1, 0).expect("global key");
    for key in [&manifest, &node, &tree, &global] {
        assert_eq!(key.generation(), 11);
        assert!(
            key.as_bytes()
                .starts_with(&ann_v2_generation_prefix(11).expect("prefix"))
        );
    }
    assert!(node < manifest);
    assert!(AnnObjectKeyV2::from_bytes(vec![b'g'; 10]).is_err());
    assert!(AnnObjectKeyV2::partition_manifest(11, [0; 32]).is_err());
    assert!(AnnObjectKeyV2::global_tree(0, 1, 0, 0).is_err());
    assert!(AnnObjectKeyV2::global_tree(11, 1, 65, 0).is_err());
    assert!(AnnObjectKeyV2::global_tree(11, 3, 2, 1).is_err());

    assert!(
        AnnObjectReadRequestV2 {
            key: &node,
            max_bytes: ANN_V2_MAX_NODE_BYTES,
        }
        .validate()
        .is_ok()
    );
    assert!(
        AnnObjectReadRequestV2 {
            key: &node,
            max_bytes: ANN_V2_MAX_NODE_BYTES + 1,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn objects_bind_key_value_identity_and_digest() {
    let vector_space = VectorSpaceId::new();
    let entry = RepresentationId::new();
    let partition = partition_manifest(vector_space, entry);
    let key =
        AnnObjectKeyV2::partition_manifest(11, partition.partition_key).expect("partition key");
    let object = AnnObjectV2::new(key, partition.encode_json().expect("partition bytes"))
        .expect("partition object");
    assert!(object.validate().is_ok());

    let wrong_key = AnnObjectKeyV2::partition_manifest(12, partition.partition_key)
        .expect("wrong generation key");
    assert!(AnnObjectV2::new(wrong_key, object.value().to_vec()).is_err());

    let representation = RepresentationId::new();
    let neighbour = RepresentationId::new();
    let mut ids = [representation, neighbour];
    ids.sort_unstable();
    let representation = ids[0];
    let neighbour = ids[1];
    let node_value = node_with_neighbour(representation, neighbour)
        .encode_canonical()
        .expect("node bytes");
    let node_key = AnnObjectKeyV2::node(11, [5; 32], representation).expect("node key");
    let node_object = AnnObjectV2::new(node_key, node_value).expect("node object");
    let mut digest = node_object.digest();
    digest[0] ^= 1;
    assert_eq!(
        AnnObjectV2::from_parts(
            node_object.key().clone(),
            node_object.value().to_vec(),
            digest
        ),
        Err(AnnV2Error::DigestMismatch("portable object"))
    );

    let tree = AnnObjectKeyV2::global_tree(11, 1, 0, 0).expect("tree key");
    assert!(AnnObjectV2::new(tree.clone(), vec![1; 32]).is_ok());
    assert!(AnnObjectV2::new(tree, vec![0; 32]).is_err());
}

#[test]
fn object_pages_enforce_exclusive_progress_order_and_byte_caps() {
    let partition = [5; 32];
    let key_a = AnnObjectKeyV2::global_tree(11, 2, 0, 0).expect("key a");
    let key_b = AnnObjectKeyV2::global_tree(11, 2, 0, 1).expect("key b");
    let object_a = AnnObjectV2::new(key_a.clone(), vec![1; 32]).expect("object a");
    let object_b = AnnObjectV2::new(key_b.clone(), vec![2; 32]).expect("object b");
    let prefix = ann_v2_generation_prefix(11).expect("prefix");
    let request = AnnObjectPageRequestV2 {
        prefix: &prefix,
        start_after: None,
        max_entries: 2,
        max_bytes: 1_024,
    };
    let page = AnnObjectPageV2::new(
        request,
        vec![object_a.clone(), object_b.clone()],
        Some(key_b.clone()),
    )
    .expect("valid page");
    assert_eq!(page.objects().len(), 2);
    assert_eq!(page.continuation(), Some(&key_b));

    assert!(
        AnnObjectPageV2::new(
            request,
            vec![object_b.clone(), object_a.clone()],
            Some(key_a.clone())
        )
        .is_err()
    );
    assert!(AnnObjectPageV2::new(request, Vec::new(), Some(key_a.clone())).is_err());
    assert!(AnnObjectPageV2::new(request, vec![object_a.clone()], Some(key_b)).is_err());

    let exclusive = AnnObjectPageRequestV2 {
        prefix: &prefix,
        start_after: Some(key_a.as_bytes()),
        max_entries: 1,
        max_bytes: 1_024,
    };
    assert!(AnnObjectPageV2::new(exclusive, vec![object_a], None).is_err());

    let tiny = AnnObjectPageRequestV2 {
        prefix: &prefix,
        start_after: None,
        max_entries: 1,
        max_bytes: 1,
    };
    assert!(AnnObjectPageV2::new(tiny, vec![object_b], None).is_err());

    assert!(
        AnnObjectPageRequestV2 {
            prefix: &partition,
            start_after: None,
            max_entries: ANN_V2_MAX_PAGE_ENTRIES + 1,
            max_bytes: 1,
        }
        .validate()
        .is_err()
    );

    let oversized_cursor = vec![b'g'; 65];
    assert!(
        AnnObjectPageRequestV2 {
            prefix: &prefix,
            start_after: Some(&oversized_cursor),
            max_entries: 1,
            max_bytes: 1,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn manifest_decoders_require_exact_canonical_json_and_validated_identity() {
    let generation = generation_manifest();
    let bytes = generation.encode_json().expect("generation JSON");
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    assert_eq!(
        AnnGenerationManifestV2::decode_json(&trailing),
        Err(AnnV2Error::NonCanonical)
    );

    let vector_space = VectorSpaceId::new();
    let entry = RepresentationId::new();
    let partition = partition_manifest(vector_space, entry);
    let partition_bytes = partition.encode_json().expect("partition JSON");
    let mut value: serde_json::Value =
        serde_json::from_slice(&partition_bytes).expect("partition value");
    value["partition_key"] = serde_json::to_value([9_u8; 32]).expect("digest JSON");
    assert_eq!(
        AnnPartitionManifestV2::decode_json(
            &serde_json::to_vec(&value).expect("tampered partition JSON")
        ),
        Err(AnnV2Error::Invalid(
            "partition key disagrees with vector space and policy digest"
        ))
    );

    let mut reordered = serde_json::Map::new();
    let object =
        serde_json::from_slice::<serde_json::Value>(&partition_bytes).expect("partition value");
    for (key, value) in object.as_object().expect("partition object").iter().rev() {
        reordered.insert(key.clone(), value.clone());
    }
    let reordered = serde_json::to_vec(&reordered).expect("reordered partition JSON");
    if reordered != partition_bytes {
        assert_eq!(
            AnnPartitionManifestV2::decode_json(&reordered),
            Err(AnnV2Error::NonCanonical)
        );
    }
}

#[test]
fn partition_key_is_domain_separated_stable_and_manifest_enforced() {
    let vector_space = VectorSpaceId::new();
    let policy = [7; 32];
    let first = ann_v2_partition_key(vector_space, policy).expect("partition key");
    let second = ann_v2_partition_key(vector_space, policy).expect("partition key");
    assert_eq!(first, second);
    assert_ne!(
        first,
        ann_v2_partition_key(vector_space, [8; 32]).expect("different partition key")
    );
    assert!(ann_v2_partition_key(vector_space, [0; 32]).is_err());

    let mut partition = partition_manifest(vector_space, RepresentationId::new());
    partition.partition_key[0] ^= 1;
    assert_eq!(
        partition.seal(),
        Err(AnnV2Error::Invalid(
            "partition key disagrees with vector space and policy digest"
        ))
    );
}

#[test]
fn merkle_rules_bind_scope_geometry_and_odd_node_proofs() {
    let scope = AnnMerkleScopeV2::GenerationPartitions { generation: 11 };
    let leaves = [[1; 32], [2; 32], [3; 32]];
    let left = ann_v2_merkle_internal(1, leaves[0], leaves[1]).expect("left parent");
    let odd = ann_v2_merkle_internal(1, leaves[2], leaves[2]).expect("odd parent");
    let top = ann_v2_merkle_internal(2, left, odd).expect("manual top");
    let root = ann_v2_merkle_root(scope, 3, Some(top)).expect("manual root");

    let geometry = AnnMerkleGeometryV2::new(scope, 3).expect("geometry");
    assert_eq!(geometry.root_level(), 2);
    assert_eq!(geometry.object_count(), 6);
    assert_eq!(geometry.width_at(0).expect("leaf width"), 3);
    assert_eq!(geometry.width_at(1).expect("parent width"), 2);
    assert_eq!(geometry.width_at(2).expect("root width"), 1);

    let proof = AnnMerkleProofV2::new(scope, 2, 3, vec![leaves[2], left]).expect("odd-node proof");
    assert!(ann_v2_verify_merkle_proof(scope, leaves[2], &proof, root).is_ok());

    let bad_odd =
        AnnMerkleProofV2::new(scope, 2, 3, vec![[4; 32], left]).expect("shape-valid bad odd proof");
    assert_eq!(
        ann_v2_verify_merkle_proof(scope, leaves[2], &bad_odd, root),
        Err(AnnV2Error::Invalid(
            "Merkle odd-node proof does not duplicate its final child"
        ))
    );
    let tampered = AnnMerkleProofV2::new(scope, 2, 3, vec![leaves[2], [9; 32]])
        .expect("shape-valid tampered proof");
    assert_eq!(
        ann_v2_verify_merkle_proof(scope, leaves[2], &tampered, root),
        Err(AnnV2Error::DigestMismatch("Merkle proof root"))
    );
    assert_eq!(
        ann_v2_verify_merkle_proof(
            AnnMerkleScopeV2::GenerationPartitions { generation: 12 },
            leaves[2],
            &AnnMerkleProofV2::new(
                AnnMerkleScopeV2::GenerationPartitions { generation: 12 },
                2,
                3,
                vec![leaves[2], left],
            )
            .expect("other-scope proof"),
            root,
        ),
        Err(AnnV2Error::DigestMismatch("Merkle proof root"))
    );
    assert_ne!(
        ann_v2_empty_partition_root(11).expect("empty root"),
        ann_v2_empty_partition_root(12).expect("other empty root")
    );
    assert!(ann_v2_merkle_internal(0, leaves[0], leaves[1]).is_err());
}

#[test]
fn tree_keys_require_contextual_exact_geometry() {
    let scope = AnnMerkleScopeV2::GenerationPartitions { generation: 11 };
    let key = AnnObjectKeyV2::global_tree(11, 3, 1, 1).expect("three-leaf key");
    assert!(key.validate_merkle_geometry(scope, 3).is_ok());
    assert_eq!(
        key.validate_merkle_geometry(scope, 2),
        Err(AnnV2Error::Invalid(
            "Merkle key is outside the exact tree geometry"
        ))
    );

    let raw = AnnObjectKeyV2::from_bytes(key.as_bytes().to_vec())
        .expect("structurally valid raw tree key");
    assert!(raw.validate_merkle_geometry(scope, 2).is_err());
    assert!(AnnObjectKeyV2::global_tree(11, 3, 2, 1).is_err());
    assert!(AnnMerkleGeometryV2::new(scope, crate::ANN_V2_MAX_PARTITIONS + 1).is_err());
}

#[test]
fn point_read_responses_bind_key_limit_and_validated_object() {
    let key_a = AnnObjectKeyV2::global_tree(11, 2, 0, 0).expect("key a");
    let key_b = AnnObjectKeyV2::global_tree(11, 2, 0, 1).expect("key b");
    let object_a = AnnObjectV2::new(key_a.clone(), vec![1; 32]).expect("object a");
    let request_a = AnnObjectReadRequestV2 {
        key: &key_a,
        max_bytes: 32,
    };
    let response =
        AnnObjectReadResponseV2::new(request_a, Some(object_a.clone())).expect("bound response");
    assert_eq!(response.object(), Some(&object_a));

    let request_b = AnnObjectReadRequestV2 {
        key: &key_b,
        max_bytes: 32,
    };
    assert!(response.validate_for(request_b).is_err());
    assert!(AnnObjectReadResponseV2::new(request_b, Some(object_a.clone())).is_err());
    assert!(
        AnnObjectReadResponseV2::new(
            AnnObjectReadRequestV2 {
                key: &key_a,
                max_bytes: 31,
            },
            Some(object_a),
        )
        .is_err()
    );
}

#[test]
fn aggregate_gate_streams_and_closes_every_generation_layer() {
    let (manifest, reader, partition, _) = verified_generation_fixture();
    let report = verify_ann_generation_v2(&reader, &manifest).expect("verified generation");
    assert_eq!(report.generation(), manifest.generation);
    assert_eq!(report.manifest_digest(), manifest.manifest_digest);
    assert_eq!(report.partition_count(), 1);
    assert_eq!(report.node_count(), 2);
    assert_eq!(report.level_row_count(), 2);
    assert_eq!(report.neighbour_count(), 2);
    assert_eq!(report.object_count(), 7);
    assert_eq!(report.object_bytes(), manifest.object_bytes);

    let mut bad_leaf_reader = reader.clone();
    let leaf_key = AnnObjectKeyV2::partition_tree(
        manifest.generation,
        partition.partition_key,
        partition.node_count,
        0,
        0,
    )
    .expect("partition leaf key");
    bad_leaf_reader
        .replace(AnnObjectV2::new(leaf_key, vec![9; 32]).expect("tampered authenticated object"));
    assert_eq!(
        verify_ann_generation_v2(&bad_leaf_reader, &manifest),
        Err(AnnV2Error::DigestMismatch("partition node-tree leaf"))
    );

    let mut bad_root = manifest.clone();
    bad_root.partition_tree_root[0] ^= 1;
    let bad_root = bad_root.seal().expect("resealed wrong root");
    assert_eq!(
        verify_ann_generation_v2(&reader, &bad_root),
        Err(AnnV2Error::DigestMismatch("scope-bound Merkle root"))
    );

    let mut bad_bytes = manifest.clone();
    bad_bytes.object_bytes += 1;
    let bad_bytes = bad_bytes.seal().expect("resealed wrong byte count");
    assert_eq!(
        verify_ann_generation_v2(&reader, &bad_bytes),
        Err(AnnV2Error::Invalid(
            "generation object count or bytes are incomplete"
        ))
    );
}

#[test]
fn aggregate_gate_accepts_only_the_scope_bound_empty_generation() {
    let manifest = AnnGenerationManifestV2 {
        format_version: ANN_V2_FORMAT_VERSION,
        generation: 11,
        watermark: CommitSeq::new(42),
        source: source_seal(),
        build: build_parameters(),
        partition_count: 0,
        node_count: 0,
        level_row_count: 0,
        neighbour_count: 0,
        object_bytes: 0,
        partition_tree_root: ann_v2_empty_partition_root(11).expect("empty root"),
        manifest_digest: [0; 32],
    }
    .seal()
    .expect("empty manifest");
    let reader = MemoryObjectReader::new(Vec::<AnnObjectV2>::new(), 1);
    let report = verify_ann_generation_v2(&reader, &manifest).expect("empty generation gate");
    assert_eq!(report.object_count(), 0);
    assert_eq!(report.object_bytes(), 0);

    let mut wrong_scope = manifest;
    wrong_scope.partition_tree_root = ann_v2_empty_partition_root(12).expect("other root");
    assert_eq!(
        wrong_scope.seal(),
        Err(AnnV2Error::Invalid(
            "empty generation counters or root are not canonical"
        ))
    );
}

#[test]
fn aggregate_gate_rejects_degree_locality_leaf_index_and_extra_tree_objects() {
    let (manifest, reader, partition, ids) = verified_generation_fixture();
    let mut foreign = [RepresentationId::new(), RepresentationId::new()];
    foreign.sort_unstable();
    let excessive_degree = AnnNodeV2 {
        generation: manifest.generation,
        partition_key: partition.partition_key,
        representation_id: ids[0],
        leaf_index: 0,
        levels: vec![AnnLevelV2 {
            level: 0,
            neighbours: foreign.to_vec(),
        }],
    };
    let excessive_key = AnnObjectKeyV2::node(
        manifest.generation,
        partition.partition_key,
        excessive_degree.representation_id,
    )
    .expect("node key");
    let mut excessive_reader = reader.clone();
    excessive_reader.replace(
        AnnObjectV2::new(
            excessive_key,
            excessive_degree.encode_canonical().expect("node value"),
        )
        .expect("node object"),
    );
    assert_eq!(
        verify_ann_generation_v2(&excessive_reader, &manifest),
        Err(AnnV2Error::Invalid(
            "node degree exceeds generation build parameters"
        ))
    );

    let missing_neighbour = AnnLevelV2 {
        neighbours: vec![foreign[0]],
        ..node_with_neighbour(ids[0], ids[1]).levels[0].clone()
    };
    let nonlocal_node = AnnNodeV2 {
        generation: manifest.generation,
        partition_key: partition.partition_key,
        representation_id: ids[0],
        leaf_index: 0,
        levels: vec![missing_neighbour],
    };
    let mut nonlocal_reader = reader.clone();
    nonlocal_reader.replace(
        AnnObjectV2::new(
            AnnObjectKeyV2::node(manifest.generation, partition.partition_key, ids[0])
                .expect("node key"),
            nonlocal_node.encode_canonical().expect("node value"),
        )
        .expect("node object"),
    );
    assert_eq!(
        verify_ann_generation_v2(&nonlocal_reader, &manifest),
        Err(AnnV2Error::Invalid("required ANN object is absent"))
    );

    let wrong_index = AnnNodeV2 {
        generation: manifest.generation,
        partition_key: partition.partition_key,
        representation_id: ids[0],
        leaf_index: 1,
        levels: vec![AnnLevelV2 {
            level: 0,
            neighbours: vec![ids[1]],
        }],
    };
    let mut wrong_index_reader = reader.clone();
    wrong_index_reader.replace(
        AnnObjectV2::new(
            AnnObjectKeyV2::node(manifest.generation, partition.partition_key, ids[0])
                .expect("node key"),
            wrong_index.encode_canonical().expect("node value"),
        )
        .expect("node object"),
    );
    assert_eq!(
        verify_ann_generation_v2(&wrong_index_reader, &manifest),
        Err(AnnV2Error::Invalid(
            "node leaf indices are not unique and contiguous"
        ))
    );

    let valid_global_leaf =
        AnnObjectKeyV2::global_tree(manifest.generation, 1, 0, 0).expect("global leaf");
    let mut extra_raw = valid_global_leaf.as_bytes().to_vec();
    extra_raw[10..12].copy_from_slice(&1_u16.to_be_bytes());
    let extra_key = AnnObjectKeyV2::from_bytes(extra_raw).expect("structural extra key");
    assert!(
        extra_key
            .validate_merkle_geometry(
                AnnMerkleScopeV2::GenerationPartitions {
                    generation: manifest.generation,
                },
                1,
            )
            .is_err()
    );
    let mut extra_reader = reader;
    extra_reader.replace(AnnObjectV2::new(extra_key, vec![8; 32]).expect("extra object"));
    assert_eq!(
        verify_ann_generation_v2(&extra_reader, &manifest),
        Err(AnnV2Error::ResourceExhausted {
            resource: "verified Merkle objects",
            limit: 1,
            required: 2,
        })
    );
}
