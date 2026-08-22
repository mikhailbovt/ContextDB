use std::collections::BTreeSet;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use contextdb_core::{
    CommitSeq, LineageNode, MemorySpaceId, MemorySubjectId, Modality, Purpose, RepresentationId,
    ScopeId, SecurityClassification, TimeRange, TimestampMicros, VectorSpaceId, WorkspaceId,
};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
    WriteTransaction,
};
use contextdb_storage_memory::MemoryStorage;
use contextdb_storage_redb::RedbStorage;

use super::*;
use crate::{AnnAlgorithmV2, AnnPartitionSchemeV2, VectorMetric, VectorQuery, VectorRecord};

#[derive(Clone)]
struct TestIdentity {
    workspace: WorkspaceId,
    memory_space: MemorySpaceId,
    owner: MemorySubjectId,
    scope: ScopeId,
}

impl TestIdentity {
    fn numbered(number: u128) -> Self {
        Self {
            workspace: stable_id(number + 1),
            memory_space: stable_id(number + 2),
            owner: stable_id(number + 3),
            scope: stable_id(number + 4),
        }
    }

    fn policy(&self) -> IndexPolicy {
        IndexPolicy {
            workspace_id: self.workspace,
            memory_spaces: BTreeSet::from([self.memory_space]),
            subjects: BTreeSet::from([self.owner]),
            owners: BTreeSet::from([self.owner]),
            scopes: BTreeSet::from([self.scope]),
            purposes: BTreeSet::from([Purpose::KnowledgeRecall]),
            classification: SecurityClassification::Confidential,
            security_labels: BTreeSet::from(["ann-v2-test".to_owned()]),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
            retrieve_allowed: true,
            deleted_at: None,
        }
    }

    fn principal(&self) -> IndexPrincipal {
        IndexPrincipal {
            workspace_id: self.workspace,
            memory_spaces: BTreeSet::from([self.memory_space]),
            subjects: BTreeSet::from([self.owner]),
            owner_identities: BTreeSet::from([self.owner]),
            scopes: BTreeSet::from([self.scope]),
            purpose: Purpose::KnowledgeRecall,
        }
    }
}

fn stable_id<T: FromStr>(number: u128) -> T
where
    T::Err: std::fmt::Debug,
{
    let value = format!("{number:032x}");
    let value = format!(
        "{}-{}-4{}-8{}-{}",
        &value[0..8],
        &value[8..12],
        &value[13..16],
        &value[17..20],
        &value[20..32]
    );
    value.parse().expect("stable test ID")
}

fn vector_space(id: VectorSpaceId) -> VectorSpace {
    VectorSpace {
        id,
        dimensions: 4,
        metric: VectorMetric::Cosine,
        model_family: "ann-v2-test".to_owned(),
        model_revision: "1".to_owned(),
        preprocessing_revision: "1".to_owned(),
        modality: Modality::Text,
    }
}

fn record(
    id: RepresentationId,
    identity: &TestIdentity,
    space: VectorSpaceId,
    values: Vec<f32>,
) -> VectorRecord {
    VectorRecord {
        id,
        target: LineageNode::External {
            namespace: "ann-v2-test".to_owned(),
            identifier: id.to_string(),
        },
        vector_space_id: space,
        values,
        policy: identity.policy(),
        valid_time: TimeRange::open_ended(TimestampMicros(0)),
        projected_at: CommitSeq::new(7),
        lineage: Vec::new(),
        tombstone_at: None,
    }
}

fn populated_index() -> (
    VectorIndex,
    TestIdentity,
    TestIdentity,
    VectorSpaceId,
    BTreeSet<RepresentationId>,
) {
    let allowed = TestIdentity::numbered(0x100);
    let denied = TestIdentity::numbered(0x200);
    let space = stable_id(0x300);
    let mut index = VectorIndex::new();
    index.register_space(vector_space(space)).expect("space");
    let mut denied_ids = BTreeSet::new();
    for offset in 0_u128..48 {
        let angle = (offset as f32) * 0.173;
        let identity = if offset < 40 { &allowed } else { &denied };
        let id = stable_id(0x1000 + offset);
        if offset >= 40 {
            denied_ids.insert(id);
        }
        index
            .insert(record(
                id,
                identity,
                space,
                vec![angle.cos(), angle.sin(), 0.25, 0.5],
            ))
            .expect("vector");
    }
    (index, allowed, denied, space, denied_ids)
}

fn build_parameters() -> AnnBuildParametersV2 {
    AnnBuildParametersV2 {
        algorithm: AnnAlgorithmV2::DeterministicHnswV1,
        partition_scheme: AnnPartitionSchemeV2::ExactPolicyV1,
        max_level: 4,
        neighbours_per_level: 8,
        construction_max_visits: 64,
    }
}

#[test]
fn live_generation_matches_exact_oracle_and_is_policy_first() {
    let (index, allowed, _, space, denied_ids) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 1, 1).expect("source");
    let spy = SpySource::new(source, denied_ids.clone());
    let runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("runtime");
    let publication = runtime
        .rebuild_and_publish(
            &spy,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("published generation");
    assert_eq!(publication.verification.node_count(), 48);
    assert_eq!(publication.verification.partition_count(), 2);
    spy.clear_reads();

    let universe = runtime
        .authorize(&spy, &allowed.principal(), CommitSeq::new(7))
        .expect("authorized universe");
    assert!(
        spy.vector_reads().is_empty(),
        "authorization touched vectors"
    );
    assert_eq!(spy.route_pages.load(Ordering::Relaxed), 0);

    for query in [
        [1.0, 0.0, 0.25, 0.5],
        [0.0, 1.0, 0.25, 0.5],
        [-1.0, 0.0, 0.25, 0.5],
    ] {
        spy.clear_reads();
        let live = runtime
            .search(
                &spy,
                &universe,
                AnnQueryV2 {
                    vector_space_id: space,
                    values: &query,
                    valid_at: None,
                    limit: 8,
                },
                AnnQueryBudgetV2 {
                    max_ann_visits: 128,
                    ef_search: 64,
                    max_exact_scores: 64,
                },
            )
            .expect("live ANN search");
        let exact_universe = index
            .authorize(&allowed.principal(), CommitSeq::new(7))
            .expect("exact universe");
        let exact = index
            .search_exact(
                &exact_universe,
                VectorQuery {
                    vector_space_id: space,
                    values: &query,
                    valid_at: None,
                    limit: 8,
                },
                64,
            )
            .expect("exact search");
        assert_eq!(
            live.hits
                .iter()
                .map(|hit| hit.representation_id)
                .collect::<Vec<_>>(),
            exact
                .hits
                .iter()
                .map(|hit| hit.representation_id)
                .collect::<Vec<_>>()
        );
        assert!(
            live.hits
                .iter()
                .zip(exact.hits.iter())
                .all(|(left, right)| left.score.to_bits() == right.score.to_bits())
        );
        assert!(spy.vector_reads().iter().all(|id| !denied_ids.contains(id)));
        assert_eq!(live.trace.exact_fallback_scores, 0);
    }
}

#[test]
fn delta_and_current_use_tombstone_match_exact_without_reauthorizing_old_universe() {
    let (base, allowed, _, space, _) = populated_index();
    let (mut exact, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&base, 41, 43).expect("source");
    let runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("base publication");
    let old_universe = runtime
        .authorize(&source, &allowed.principal(), CommitSeq::new(7))
        .expect("old universe");

    let delta_id = stable_id(0x9_000);
    let mut delta = record(delta_id, &allowed, space, vec![1.0, 0.0, 0.25, 0.5]);
    delta.projected_at = CommitSeq::new(8);
    let first_delta = runtime
        .publish_delta(&source, delta.clone(), Durability::Sync)
        .expect("delta publication");
    assert!(!first_delta.idempotent);
    assert!(
        runtime
            .publish_delta(&source, delta.clone(), Durability::Sync)
            .expect("idempotent delta")
            .idempotent
    );
    exact.insert(delta).expect("exact delta");
    let current_universe = runtime
        .authorize(&source, &allowed.principal(), CommitSeq::new(8))
        .expect("current universe");

    let removed_id = stable_id(0x1_000);
    let first_tombstone = runtime
        .publish_tombstone(removed_id, CommitSeq::new(8), Durability::Sync)
        .expect("tombstone publication");
    assert!(!first_tombstone.idempotent);
    assert!(
        runtime
            .publish_tombstone(removed_id, CommitSeq::new(8), Durability::Sync)
            .expect("idempotent tombstone")
            .idempotent
    );
    exact
        .tombstone(removed_id, CommitSeq::new(8))
        .expect("exact tombstone");

    let query = [1.0, 0.0, 0.25, 0.5];
    let old = runtime
        .search(
            &source,
            &old_universe,
            AnnQueryV2 {
                vector_space_id: space,
                values: &query,
                valid_at: None,
                limit: 8,
            },
            AnnQueryBudgetV2 {
                max_ann_visits: 128,
                ef_search: 64,
                max_exact_scores: 128,
            },
        )
        .expect("old-universe current-use query");
    assert!(
        old.hits
            .iter()
            .all(|hit| hit.representation_id != removed_id),
        "a current-use tombstone leaked through an older semantic universe"
    );

    let live = runtime
        .search(
            &source,
            &current_universe,
            AnnQueryV2 {
                vector_space_id: space,
                values: &query,
                valid_at: None,
                limit: 8,
            },
            AnnQueryBudgetV2 {
                max_ann_visits: 128,
                ef_search: 64,
                max_exact_scores: 128,
            },
        )
        .expect("delta/tombstone query");
    let exact_universe = exact
        .authorize(&allowed.principal(), CommitSeq::new(8))
        .expect("exact universe");
    let expected = exact
        .search_exact(
            &exact_universe,
            VectorQuery {
                vector_space_id: space,
                values: &query,
                valid_at: None,
                limit: 8,
            },
            128,
        )
        .expect("exact delta/tombstone query");
    assert_eq!(
        live.hits
            .iter()
            .map(|hit| (hit.representation_id, hit.score.to_bits()))
            .collect::<Vec<_>>(),
        expected
            .hits
            .iter()
            .map(|hit| (hit.representation_id, hit.score.to_bits()))
            .collect::<Vec<_>>()
    );
    assert!(
        live.hits
            .iter()
            .any(|hit| hit.representation_id == delta_id)
    );
    runtime
        .release_universe(old_universe, Durability::Sync)
        .expect("release old universe");
    runtime
        .release_universe(current_universe, Durability::Sync)
        .expect("release current universe");
}

#[test]
fn delta_policy_is_admitted_before_full_vector_point_read_and_corruption_fails_closed() {
    let (index, allowed, _, space, denied_ids) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 107, 109).expect("source");
    let spy = SpySource::new(source, denied_ids);
    let runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("runtime");
    runtime
        .rebuild_and_publish(
            &spy,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("base publication");
    let delta_id = stable_id(0xe_000);
    let mut delta = record(delta_id, &allowed, space, vec![1.0, 0.0, 0.25, 0.5]);
    delta.projected_at = CommitSeq::new(8);
    runtime
        .publish_delta(&spy, delta, Durability::Sync)
        .expect("delta publication");
    let mut write = runtime.engine.begin_write().expect("corrupt delta point");
    let mut bytes = write
        .get(&runtime.overlay, &overlay_delta_id_key(delta_id))
        .expect("delta point read")
        .expect("delta point");
    bytes[0] ^= 0xff;
    write
        .put(&runtime.overlay, overlay_delta_id_key(delta_id), bytes)
        .expect("corrupt delta point");
    write
        .commit(Durability::Sync)
        .expect("commit delta corruption");
    spy.clear_reads();

    let universe = runtime
        .authorize(&spy, &allowed.principal(), CommitSeq::new(8))
        .expect("routing-only authorization");
    assert_eq!(spy.route_pages.load(Ordering::Relaxed), 0);
    assert!(spy.vector_reads().is_empty());
    assert!(
        runtime
            .search(
                &spy,
                &universe,
                AnnQueryV2 {
                    vector_space_id: space,
                    values: &[1.0, 0.0, 0.25, 0.5],
                    valid_at: None,
                    limit: 8,
                },
                AnnQueryBudgetV2 {
                    max_ann_visits: 128,
                    ef_search: 64,
                    max_exact_scores: 128,
                },
            )
            .is_err(),
        "corrupt full-precision delta must fail before returning hits"
    );
    runtime
        .release_universe(universe, Durability::Sync)
        .expect("release corrupt-delta universe");
}

#[test]
fn large_partition_retains_complete_base_layer_reachability() {
    let identity = TestIdentity::numbered(0x500);
    let space = stable_id(0x600);
    let mut index = VectorIndex::new();
    index.register_space(vector_space(space)).expect("space");
    for offset in 0_u128..160 {
        let angle = (offset as f32) * 0.113;
        let id = stable_id(0x10_000 + offset);
        index
            .insert(record(
                id,
                &identity,
                space,
                vec![angle.cos(), angle.sin(), 0.25, 0.5],
            ))
            .expect("vector");
    }
    let source = VectorIndexAnnSourceV2::new(&index, 31, 37).expect("source");
    let runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("runtime");
    let publication = runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("large connected publication");
    assert_eq!(publication.verification.node_count(), 160);
    assert_eq!(publication.verification.partition_count(), 1);
    assert_eq!(
        runtime
            .verify_active()
            .expect("complete verification")
            .expect("active generation")
            .node_count(),
        160
    );

    let partition_key = ann_v2_partition_key(
        space,
        canonical_policy_digest(&identity.policy()).expect("policy digest"),
    )
    .expect("partition key");
    let read = runtime
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("read active generation");
    let reader = StorageAnnReaderV2 {
        snapshot: &read,
        keyspace: &runtime.objects,
    };
    let partition_object = reader
        .get_bounded(AnnObjectReadRequestV2 {
            key: &AnnObjectKeyV2::partition_manifest(1, partition_key)
                .expect("partition manifest key"),
            max_bytes: crate::ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
        })
        .expect("read partition manifest")
        .into_object()
        .expect("partition manifest");
    let partition = AnnPartitionManifestV2::decode_json(partition_object.value())
        .expect("decode partition manifest");
    let prefix = node_prefix(1, partition_key).expect("node prefix");
    let mut cursor = None;
    let mut nodes = Vec::new();
    loop {
        let page = reader
            .scan_page(AnnObjectPageRequestV2 {
                prefix: &prefix,
                start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            })
            .expect("node page");
        nodes.extend(
            page.objects()
                .iter()
                .map(|object| AnnNodeV2::decode_canonical(object.value()).expect("decode node")),
        );
        let Some(next) = page.continuation().cloned() else {
            break;
        };
        cursor = Some(next);
    }
    nodes.sort_by_key(|node| node.leaf_index);
    assert_eq!(nodes.len(), 160);
    for (index, node) in nodes.iter().enumerate() {
        let successor = nodes[(index + 1) % nodes.len()].representation_id;
        assert!(node.levels[0].neighbours.contains(&successor));
        assert!(
            node.levels[0].neighbours.len() <= usize::from(build_parameters().neighbours_per_level)
        );
    }

    let disconnected_storage = MemoryStorage::new();
    let disconnected_objects = Keyspace::new(OBJECT_KEYSPACE).expect("object keyspace");
    let mut transaction = disconnected_storage.begin_write().expect("write");
    for node in nodes.iter().take(2) {
        let mut disconnected = node.clone();
        disconnected.levels[0].neighbours.clear();
        let object = AnnObjectV2::new(
            AnnObjectKeyV2::node(1, partition_key, disconnected.representation_id)
                .expect("node key"),
            disconnected.encode_canonical().expect("node bytes"),
        )
        .expect("node object");
        transaction
            .put(
                &disconnected_objects,
                object.key().as_bytes().to_vec(),
                object.value().to_vec(),
            )
            .expect("put disconnected node");
    }
    transaction.commit(Durability::Sync).expect("commit");
    let disconnected_read = disconnected_storage
        .begin_read(SnapshotSelector::Latest)
        .expect("read disconnected graph");
    let disconnected_reader = StorageAnnReaderV2 {
        snapshot: &disconnected_read,
        keyspace: &disconnected_objects,
    };
    let mut disconnected_partition = partition.clone();
    disconnected_partition.entry = nodes[0].representation_id;
    disconnected_partition.node_count = 2;
    assert!(matches!(
        verify_partition_connectivity(&disconnected_reader, &disconnected_partition),
        Err(AnnRuntimeErrorV2::Invariant(
            "ANN base layer is disconnected"
        ))
    ));
    drop(read);

    let universe = runtime
        .authorize(&source, &identity.principal(), CommitSeq::new(7))
        .expect("authorized universe");
    let result = runtime
        .search(
            &source,
            &universe,
            AnnQueryV2 {
                vector_space_id: space,
                values: &[1.0, 0.0, 0.25, 0.5],
                valid_at: None,
                limit: 8,
            },
            AnnQueryBudgetV2 {
                max_ann_visits: 256,
                ef_search: 160,
                max_exact_scores: 160,
            },
        )
        .expect("connected query");
    assert_eq!(result.hits.len(), 8);
}

#[test]
fn authorization_universe_spans_bounded_storage_pages_without_source_rescan() {
    let identity = TestIdentity::numbered(0xc00);
    let space = stable_id(0xd00);
    let mut index = VectorIndex::new();
    index.register_space(vector_space(space)).expect("space");
    for offset in 0_u128..1_050 {
        let angle = (offset as f32) * 0.031;
        index
            .insert(record(
                stable_id(0x20_000 + offset),
                &identity,
                space,
                vec![angle.cos(), angle.sin(), 0.25, 0.5],
            ))
            .expect("vector");
    }
    let source = VectorIndexAnnSourceV2::new(&index, 101, 103).expect("source");
    let spy = SpySource::new(source, BTreeSet::new());
    let runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("runtime");
    runtime
        .rebuild_and_publish(
            &spy,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("publication");
    spy.clear_reads();
    let universe = runtime
        .authorize(&spy, &identity.principal(), CommitSeq::new(7))
        .expect("paged universe");
    assert_eq!(universe.authorized_count(), 1_050);
    assert_eq!(spy.route_pages.load(Ordering::Relaxed), 0);
    assert!(spy.vector_reads().is_empty());

    let read = runtime
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("universe read");
    let prefix = universe_route_id_prefix(universe.universe_id);
    let first = read
        .scan_prefix_page(
            &runtime.universes,
            ScanPageRequest {
                prefix: &prefix,
                start_after: None,
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("first universe page");
    assert_eq!(first.entries.len(), ANN_V2_MAX_PAGE_ENTRIES);
    let continuation = first.continuation.expect("second universe page");
    let second = read
        .scan_prefix_page(
            &runtime.universes,
            ScanPageRequest {
                prefix: &prefix,
                start_after: Some(&continuation),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("second universe page");
    assert_eq!(second.entries.len(), 26);
    assert!(second.continuation.is_none());
    drop(read);
    runtime
        .release_universe(universe, Durability::Sync)
        .expect("release paged universe");
}

#[test]
fn redb_reopen_verifies_and_interrupted_generation_recovers_old_active() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ann-v2.redb");
    let (index, allowed, _, space, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 11, 13).expect("source");
    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("redb")).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("first publication");
    drop(runtime);

    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("reopen redb"))
        .expect("reopen runtime");
    let verified = runtime
        .verify_active()
        .expect("reopen verification")
        .expect("active generation");
    assert_eq!(verified.generation(), 1);
    let failing = FailingSource::new(&source, 5);
    assert!(
        runtime
            .rebuild_and_publish(
                &failing,
                2,
                CommitSeq::new(7),
                build_parameters(),
                Durability::Sync,
            )
            .is_err()
    );
    assert_eq!(
        runtime
            .active_manifest()
            .expect("active")
            .expect("active manifest")
            .generation,
        1
    );
    drop(runtime);

    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("second reopen"))
        .expect("second runtime");
    let recovery = runtime.recover(Durability::Sync).expect("recovery");
    assert_eq!(recovery.active_generation, 1);
    assert_eq!(recovery.abandoned_generation, Some(2));
    assert!(recovery.objects_deleted > 0);
    assert_eq!(
        runtime
            .verify_active()
            .expect("post-recovery verification")
            .expect("verified active generation")
            .generation(),
        1
    );
    let universe = runtime
        .authorize(&source, &allowed.principal(), CommitSeq::new(7))
        .expect("post-recovery universe");
    assert!(
        !runtime
            .search(
                &source,
                &universe,
                AnnQueryV2 {
                    vector_space_id: space,
                    values: &[1.0, 0.0, 0.25, 0.5],
                    valid_at: None,
                    limit: 1,
                },
                AnnQueryBudgetV2 {
                    max_ann_visits: 64,
                    ef_search: 32,
                    max_exact_scores: 64,
                },
            )
            .expect("post-recovery search")
            .hits
            .is_empty()
    );
}

#[test]
fn redb_reopen_recovers_delta_and_tombstone_overlay_exactly() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ann-v2-overlay.redb");
    let (base, allowed, _, space, _) = populated_index();
    let (mut exact, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&base, 51, 53).expect("source");
    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("redb")).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("base publication");
    let delta_id = stable_id(0xa_000);
    let mut delta = record(delta_id, &allowed, space, vec![0.0, 1.0, 0.25, 0.5]);
    delta.projected_at = CommitSeq::new(8);
    runtime
        .publish_delta(&source, delta.clone(), Durability::Sync)
        .expect("delta");
    let removed_id = stable_id(0x1_001);
    runtime
        .publish_tombstone(removed_id, CommitSeq::new(8), Durability::Sync)
        .expect("tombstone");
    exact.insert(delta.clone()).expect("exact delta");
    exact
        .tombstone(removed_id, CommitSeq::new(8))
        .expect("exact tombstone");
    drop(runtime);

    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("reopen redb"))
        .expect("reopen runtime");
    let recovery = runtime.recover(Durability::Sync).expect("overlay recovery");
    assert_eq!(recovery.active_generation, 1);
    assert!(
        runtime
            .publish_delta(&source, delta, Durability::Sync)
            .expect("reopened idempotent delta")
            .idempotent
    );
    assert!(
        runtime
            .publish_tombstone(removed_id, CommitSeq::new(8), Durability::Sync)
            .expect("reopened idempotent tombstone")
            .idempotent
    );
    let universe = runtime
        .authorize(&source, &allowed.principal(), CommitSeq::new(8))
        .expect("reopened universe");
    let query = [0.0, 1.0, 0.25, 0.5];
    let live = runtime
        .search(
            &source,
            &universe,
            AnnQueryV2 {
                vector_space_id: space,
                values: &query,
                valid_at: None,
                limit: 8,
            },
            AnnQueryBudgetV2 {
                max_ann_visits: 128,
                ef_search: 64,
                max_exact_scores: 128,
            },
        )
        .expect("reopened overlay query");
    let exact_universe = exact
        .authorize(&allowed.principal(), CommitSeq::new(8))
        .expect("exact universe");
    let expected = exact
        .search_exact(
            &exact_universe,
            VectorQuery {
                vector_space_id: space,
                values: &query,
                valid_at: None,
                limit: 8,
            },
            128,
        )
        .expect("exact overlay query");
    assert_eq!(
        live.hits
            .iter()
            .map(|hit| (hit.representation_id, hit.score.to_bits()))
            .collect::<Vec<_>>(),
        expected
            .hits
            .iter()
            .map(|hit| (hit.representation_id, hit.score.to_bits()))
            .collect::<Vec<_>>()
    );
    runtime
        .release_universe(universe, Durability::Sync)
        .expect("release reopened universe");
}

#[test]
fn lost_active_pointer_is_restored_only_from_verified_rotation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ann-v2-lost-activation.redb");
    let (index, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 61, 67).expect("source");
    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("redb")).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("publication");
    let engine = runtime.into_engine();
    let control = Keyspace::new(CONTROL_KEYSPACE).expect("control keyspace");
    let mut write = engine.begin_write().expect("delete active pointer");
    write
        .delete(&control, ACTIVE_MANIFEST_KEY.to_vec())
        .expect("delete active pointer");
    write.commit(Durability::Sync).expect("commit lost pointer");
    drop(engine);

    let runtime =
        PersistentAnnV2::open(RedbStorage::open(&path).expect("reopen")).expect("reopen runtime");
    assert!(runtime.active_manifest().expect("active read").is_none());
    let recovery = runtime
        .recover(Durability::Sync)
        .expect("lost activation recovery");
    assert_eq!(recovery.active_generation, 1);
    assert_eq!(
        runtime
            .active_manifest()
            .expect("restored active")
            .expect("restored manifest")
            .generation,
        1
    );
}

#[test]
fn concurrent_generation_lease_blocks_pruning_until_universe_release() {
    let (index, allowed, _, space, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 71, 73).expect("source");
    let runtime = Arc::new(PersistentAnnV2::open(MemoryStorage::new()).expect("runtime"));
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("first generation");
    let leased = runtime
        .authorize(&source, &allowed.principal(), CommitSeq::new(7))
        .expect("generation-one lease");
    runtime
        .rebuild_and_publish(
            &source,
            2,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("atomic rotation");

    let pruning_runtime = Arc::clone(&runtime);
    let retained =
        std::thread::spawn(move || pruning_runtime.prune_generations_before(2, Durability::Sync))
            .join()
            .expect("prune thread")
            .expect("leased prune report");
    assert_eq!(retained.active_generation, 2);
    assert_eq!(retained.retained_generations, 2);
    assert_eq!(retained.leased_generations, 1);
    assert_eq!(retained.pruned_generations, 0);

    let old_result = runtime
        .search(
            &source,
            &leased,
            AnnQueryV2 {
                vector_space_id: space,
                values: &[1.0, 0.0, 0.25, 0.5],
                valid_at: None,
                limit: 4,
            },
            AnnQueryBudgetV2 {
                max_ann_visits: 128,
                ef_search: 64,
                max_exact_scores: 128,
            },
        )
        .expect("leased generation-one query");
    assert_eq!(old_result.trace.generation, 1);
    assert_eq!(old_result.hits.len(), 4);

    runtime
        .release_universe(leased, Durability::Sync)
        .expect("release generation-one lease");
    let pruned = runtime
        .prune_generations_before(2, Durability::Sync)
        .expect("unleased prune");
    assert_eq!(pruned.retained_generations, 1);
    assert_eq!(pruned.leased_generations, 0);
    assert_eq!(pruned.pruned_generations, 1);
    let read = runtime
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("retention read");
    assert!(
        read_manifest(&read, &runtime.control, &manifest_key(1))
            .expect("generation-one manifest read")
            .is_none()
    );
    drop(read);
    assert_eq!(
        runtime
            .prune_generations_before(2, Durability::Sync)
            .expect("idempotent prune")
            .pruned_generations,
        0
    );
}

#[test]
fn reopen_resumes_a_fenced_partial_generation_prune() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ann-v2-prune-recovery.redb");
    let (index, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 89, 97).expect("source");
    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("redb")).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("first generation");
    runtime
        .rebuild_and_publish(
            &source,
            2,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("second generation");
    let engine = runtime.into_engine();
    let control = Keyspace::new(CONTROL_KEYSPACE).expect("control keyspace");
    let objects = Keyspace::new(OBJECT_KEYSPACE).expect("object keyspace");
    let fence = PruneFenceV2 {
        format_version: RUNTIME_FORMAT_VERSION,
        generation: 1,
    };
    let mut write = engine.begin_write().expect("prune fence write");
    write
        .put(
            &control,
            PRUNE_FENCE_KEY.to_vec(),
            serde_json::to_vec(&fence).expect("prune fence bytes"),
        )
        .expect("prune fence put");
    write.commit(Durability::Sync).expect("prune fence commit");
    let read = engine
        .begin_read(SnapshotSelector::Latest)
        .expect("partial prune read");
    let object = read
        .scan_prefix_page(
            &objects,
            ScanPageRequest {
                prefix: &ann_v2_generation_prefix(1).expect("generation prefix"),
                start_after: None,
                max_entries: 1,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("generation-one object page")
        .entries
        .into_iter()
        .next()
        .expect("generation-one object");
    drop(read);
    let mut write = engine.begin_write().expect("partial prune write");
    write
        .delete(&objects, object.key)
        .expect("partial object delete");
    write
        .commit(Durability::Sync)
        .expect("partial prune commit");
    drop(engine);

    let runtime =
        PersistentAnnV2::open(RedbStorage::open(&path).expect("reopen")).expect("reopen runtime");
    let recovery = runtime.recover(Durability::Sync).expect("prune recovery");
    assert_eq!(recovery.active_generation, 2);
    let read = runtime
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("post-prune read");
    assert!(
        read_prune_fence(&read, &runtime.control)
            .expect("prune fence read")
            .is_none()
    );
    assert!(
        read_manifest(&read, &runtime.control, &manifest_key(1))
            .expect("generation-one manifest")
            .is_none()
    );
    assert!(
        read.scan_prefix_page(
            &runtime.objects,
            ScanPageRequest {
                prefix: &ann_v2_generation_prefix(1).expect("generation prefix"),
                start_after: None,
                max_entries: 1,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("generation-one objects")
        .entries
        .is_empty()
    );
}

#[test]
fn active_corruption_is_detected_after_reopen() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ann-v2-corrupt.redb");
    let (index, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 21, 22).expect("source");
    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("redb")).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("publication");
    let engine = runtime.into_engine();
    let objects = Keyspace::new(OBJECT_KEYSPACE).expect("object keyspace");
    let prefix = ann_v2_generation_prefix(1).expect("generation prefix");
    let read = engine.begin_read(SnapshotSelector::Latest).expect("read");
    let page = read
        .scan_prefix_page(
            &objects,
            ScanPageRequest {
                prefix: &prefix,
                start_after: None,
                max_entries: 64,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("object page");
    let node = page
        .entries
        .into_iter()
        .find(|entry| entry.key.get(9) == Some(&b'n'))
        .expect("node object");
    drop(read);
    let mut corrupted = node.value;
    corrupted[0] ^= 0xff;
    let mut write = engine.begin_write().expect("write");
    write.put(&objects, node.key, corrupted).expect("tamper");
    write.commit(Durability::Sync).expect("tamper commit");
    drop(engine);

    let reopened =
        PersistentAnnV2::open(RedbStorage::open(&path).expect("reopen")).expect("runtime");
    assert!(matches!(
        reopened.verify_active(),
        Err(AnnRuntimeErrorV2::Contract(_))
    ));
}

#[test]
fn route_overlay_and_universe_index_divergence_fail_closed() {
    let (index, allowed, _, space, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 79, 83).expect("source");

    let route_runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("route runtime");
    route_runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("route publication");
    let route_engine = route_runtime.into_engine();
    let routes = Keyspace::new(ROUTE_KEYSPACE).expect("route keyspace");
    let read = route_engine
        .begin_read(SnapshotSelector::Latest)
        .expect("route read");
    let route = read
        .scan_prefix_page(
            &routes,
            ScanPageRequest {
                prefix: &persistent_route_generation_prefix(1),
                start_after: None,
                max_entries: 1,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("route page")
        .entries
        .into_iter()
        .next()
        .expect("route row");
    drop(read);
    let mut corrupted = route.value;
    corrupted[0] ^= 0xff;
    let mut write = route_engine.begin_write().expect("route corruption write");
    write
        .put(&routes, route.key, corrupted)
        .expect("route corruption");
    write
        .commit(Durability::Sync)
        .expect("route corruption commit");
    let route_runtime = PersistentAnnV2::open(route_engine).expect("reopen route runtime");
    assert!(route_runtime.verify_active().is_err());

    let overlay_runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("overlay runtime");
    overlay_runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("overlay base publication");
    let delta_id = stable_id(0xb_000);
    let mut delta = record(delta_id, &allowed, space, vec![1.0, 0.0, 0.25, 0.5]);
    delta.projected_at = CommitSeq::new(8);
    overlay_runtime
        .publish_delta(&source, delta, Durability::Sync)
        .expect("overlay delta");
    let overlay_engine = overlay_runtime.into_engine();
    let overlay = Keyspace::new(OVERLAY_KEYSPACE).expect("overlay keyspace");
    let read = overlay_engine
        .begin_read(SnapshotSelector::Latest)
        .expect("overlay read");
    let route = read
        .scan_prefix_page(
            &overlay,
            ScanPageRequest {
                prefix: b"p",
                start_after: None,
                max_entries: 1,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("overlay route page")
        .entries
        .into_iter()
        .next()
        .expect("overlay route row");
    drop(read);
    let mut corrupted = route.value;
    corrupted[0] ^= 0xff;
    let mut write = overlay_engine
        .begin_write()
        .expect("overlay corruption write");
    write
        .put(&overlay, route.key, corrupted)
        .expect("overlay corruption");
    write
        .commit(Durability::Sync)
        .expect("overlay corruption commit");
    let overlay_runtime = PersistentAnnV2::open(overlay_engine).expect("reopen overlay runtime");
    assert!(overlay_runtime.verify_active().is_err());

    let universe_runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("universe runtime");
    universe_runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("universe publication");
    let universe = universe_runtime
        .authorize(&source, &allowed.principal(), CommitSeq::new(7))
        .expect("persistent universe");
    let universe_engine = universe_runtime.into_engine();
    let universes = Keyspace::new(UNIVERSE_KEYSPACE).expect("universe keyspace");
    let read = universe_engine
        .begin_read(SnapshotSelector::Latest)
        .expect("universe read");
    let row = read
        .scan_prefix_page(
            &universes,
            ScanPageRequest {
                prefix: &universe_route_id_prefix(universe.universe_id),
                start_after: None,
                max_entries: 1,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )
        .expect("universe route page")
        .entries
        .into_iter()
        .next()
        .expect("universe route row");
    drop(read);
    let mut corrupted = row.value;
    corrupted[0] ^= 0xff;
    let mut write = universe_engine
        .begin_write()
        .expect("universe corruption write");
    write
        .put(&universes, row.key, corrupted)
        .expect("universe corruption");
    write
        .commit(Durability::Sync)
        .expect("universe corruption commit");
    let universe_runtime = PersistentAnnV2::open(universe_engine).expect("reopen universe runtime");
    universe_runtime
        .verify_active()
        .expect("active verification")
        .expect("active generation");
    assert!(
        universe_runtime
            .search(
                &source,
                &universe,
                AnnQueryV2 {
                    vector_space_id: space,
                    values: &[1.0, 0.0, 0.25, 0.5],
                    valid_at: None,
                    limit: 4,
                },
                AnnQueryBudgetV2 {
                    max_ann_visits: 128,
                    ef_search: 64,
                    max_exact_scores: 128,
                },
            )
            .is_err()
    );
}

#[test]
fn process_kill_recovery_keeps_the_verified_active_generation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ann-v2-kill.redb");
    let (index, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 31, 37).expect("source");
    let runtime = PersistentAnnV2::open(RedbStorage::open(&path).expect("redb")).expect("runtime");
    runtime
        .rebuild_and_publish(
            &source,
            1,
            CommitSeq::new(7),
            build_parameters(),
            Durability::Sync,
        )
        .expect("first publication");
    drop(runtime);

    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("ann_v2_runtime::tests::process_kill_child")
        .arg("--nocapture")
        .env("CONTEXTDB_ANN_V2_KILL_DB", &path)
        .status()
        .expect("kill child");
    assert!(
        !status.success(),
        "kill child unexpectedly returned normally"
    );

    let runtime =
        PersistentAnnV2::open(RedbStorage::open(&path).expect("reopen")).expect("runtime");
    let recovery = runtime.recover(Durability::Sync).expect("kill recovery");
    assert_eq!(recovery.active_generation, 1);
    assert_eq!(recovery.abandoned_generation, Some(2));
    assert!(recovery.objects_deleted > 0);
    assert_eq!(
        runtime
            .active_manifest()
            .expect("active")
            .expect("active manifest")
            .generation,
        1
    );
}

#[test]
fn process_kill_child() {
    let Ok(path) = std::env::var("CONTEXTDB_ANN_V2_KILL_DB") else {
        return;
    };
    let (index, _, _, _, _) = populated_index();
    let source = VectorIndexAnnSourceV2::new(&index, 31, 37).expect("source");
    let runtime =
        PersistentAnnV2::open(RedbStorage::open(path).expect("child redb")).expect("child runtime");
    runtime
        .verify_active()
        .expect("child active verification")
        .expect("child active generation");
    let killing = KillingSource::new(&source, 5);
    let _ = runtime.rebuild_and_publish(
        &killing,
        2,
        CommitSeq::new(7),
        build_parameters(),
        Durability::Sync,
    );
    panic!("kill source failed to terminate the process");
}

struct SpySource<'a> {
    inner: VectorIndexAnnSourceV2<'a>,
    reads: Mutex<Vec<RepresentationId>>,
    route_pages: AtomicUsize,
}

impl<'a> SpySource<'a> {
    fn new(inner: VectorIndexAnnSourceV2<'a>, _denied: BTreeSet<RepresentationId>) -> Self {
        Self {
            inner,
            reads: Mutex::new(Vec::new()),
            route_pages: AtomicUsize::new(0),
        }
    }

    fn clear_reads(&self) {
        self.reads.lock().expect("reads lock").clear();
        self.route_pages.store(0, Ordering::Relaxed);
    }

    fn vector_reads(&self) -> Vec<RepresentationId> {
        self.reads.lock().expect("reads lock").clone()
    }
}

impl AnnVectorSourceV2 for SpySource<'_> {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2> {
        self.inner.source_seal()
    }

    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace> {
        self.inner.vector_space(id)
    }

    fn scan_routes_page(
        &self,
        start_after: Option<RepresentationId>,
        max_entries: usize,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<AnnVectorRoutePageV2> {
        self.route_pages.fetch_add(1, Ordering::Relaxed);
        self.inner
            .scan_routes_page(start_after, max_entries, max_bytes)
    }

    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>> {
        self.reads.lock().expect("reads lock").push(id);
        self.inner.read_vector(id, dimensions)
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        self.inner.read_target(id, max_bytes)
    }
}

struct FailingSource<'a> {
    inner: &'a VectorIndexAnnSourceV2<'a>,
    calls: AtomicUsize,
    fail_at: usize,
}

impl<'a> FailingSource<'a> {
    fn new(inner: &'a VectorIndexAnnSourceV2<'a>, fail_at: usize) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            fail_at,
        }
    }
}

impl AnnVectorSourceV2 for FailingSource<'_> {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2> {
        self.inner.source_seal()
    }

    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace> {
        self.inner.vector_space(id)
    }

    fn scan_routes_page(
        &self,
        start_after: Option<RepresentationId>,
        max_entries: usize,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<AnnVectorRoutePageV2> {
        self.inner
            .scan_routes_page(start_after, max_entries, max_bytes)
    }

    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>> {
        if self.calls.fetch_add(1, Ordering::Relaxed) >= self.fail_at {
            return Err(AnnRuntimeErrorV2::Source("injected vector read failure"));
        }
        self.inner.read_vector(id, dimensions)
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        self.inner.read_target(id, max_bytes)
    }
}

struct KillingSource<'a> {
    inner: &'a VectorIndexAnnSourceV2<'a>,
    calls: AtomicUsize,
    kill_at: usize,
}

impl<'a> KillingSource<'a> {
    fn new(inner: &'a VectorIndexAnnSourceV2<'a>, kill_at: usize) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            kill_at,
        }
    }
}

impl AnnVectorSourceV2 for KillingSource<'_> {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2> {
        self.inner.source_seal()
    }

    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace> {
        self.inner.vector_space(id)
    }

    fn scan_routes_page(
        &self,
        start_after: Option<RepresentationId>,
        max_entries: usize,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<AnnVectorRoutePageV2> {
        self.inner
            .scan_routes_page(start_after, max_entries, max_bytes)
    }

    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>> {
        if self.calls.fetch_add(1, Ordering::Relaxed) >= self.kill_at {
            std::process::abort();
        }
        self.inner.read_vector(id, dimensions)
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        self.inner.read_target(id, max_bytes)
    }
}
