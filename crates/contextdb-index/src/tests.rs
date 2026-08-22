use std::collections::BTreeSet;
#[cfg(feature = "ann-hnsw")]
use std::str::FromStr;

use contextdb_core::{
    AccessCapability, ActorId, Artifact, ArtifactId, Audience, AudienceGrant, BlobLocator,
    CommitSeq, Compression, ConsentPolicy, ContentBlock, ContentBlockId, ContentDigest,
    ContentEncoding, DerivationId, DerivationKind, DerivationRef, EpistemicRole, EvidenceSelector,
    LineageNode, MemorySpaceId, MemorySubjectId, MemoryUsePolicy, Modality, ModificationPolicy,
    NonEmptyVec, OwnershipPolicy, Perspective, PipelineIdentity, PolicyDecision, Purpose,
    RepresentationId, RetentionPolicy, ScopeId, ScopeInheritance, ScopeKind, ScopeRef,
    SecurityClassification, SecurityPolicy, SemanticEnvelope, SourceId, TimeRange, TimestampMicros,
    VectorSpaceId, WorkspaceId,
};
use proptest::prelude::*;

use super::*;

#[derive(Clone)]
struct Fixture {
    workspace: WorkspaceId,
    space: MemorySpaceId,
    owner: MemorySubjectId,
    scope: ScopeId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            workspace: WorkspaceId::new(),
            space: MemorySpaceId::new(),
            owner: MemorySubjectId::new(),
            scope: ScopeId::new(),
        }
    }

    fn policy(&self) -> IndexPolicy {
        IndexPolicy {
            workspace_id: self.workspace,
            memory_spaces: BTreeSet::from([self.space]),
            subjects: BTreeSet::from([self.owner]),
            owners: BTreeSet::from([self.owner]),
            scopes: BTreeSet::from([self.scope]),
            purposes: BTreeSet::from([Purpose::KnowledgeRecall]),
            classification: SecurityClassification::Confidential,
            security_labels: BTreeSet::from(["personal".into()]),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
            retrieve_allowed: true,
            deleted_at: None,
        }
    }

    fn principal(&self) -> IndexPrincipal {
        IndexPrincipal {
            workspace_id: self.workspace,
            memory_spaces: BTreeSet::from([self.space]),
            subjects: BTreeSet::from([self.owner]),
            owner_identities: BTreeSet::from([self.owner]),
            scopes: BTreeSet::from([self.scope]),
            purpose: Purpose::KnowledgeRecall,
        }
    }

    fn envelope(&self, artifact: ArtifactId) -> SemanticEnvelope {
        SemanticEnvelope {
            scopes: NonEmptyVec::new(ScopeRef {
                kind: ScopeKind::Workspace,
                id: self.scope,
                inheritance: ScopeInheritance::Descendants,
            }),
            perspective: Perspective {
                knower: self.owner,
                experiencer: Some(self.owner),
                narrator: ActorId::new(),
                role: EpistemicRole::Asserter,
            },
            ownership: OwnershipPolicy {
                owners: NonEmptyVec::new(self.owner),
                audience_grants: vec![AudienceGrant {
                    audience: Audience::Subject { id: self.owner },
                    purposes: BTreeSet::from([Purpose::KnowledgeRecall]),
                    capabilities: BTreeSet::from([AccessCapability::Retrieve]),
                }],
                allowed_purposes: BTreeSet::from([Purpose::KnowledgeRecall]),
                modification: ModificationPolicy {
                    owners_may_modify: true,
                    delegates_may_modify: false,
                    system_may_derive: true,
                },
            },
            consent: ConsentPolicy {
                required: false,
                decisions: Vec::new(),
            },
            use_policy: MemoryUsePolicy {
                retrieve: PolicyDecision::Allow,
                influence_response: PolicyDecision::Allow,
                mention_explicitly: PolicyDecision::Conditional,
                external_model_use: PolicyDecision::Deny,
                retention: RetentionPolicy::Indefinite,
            },
            security: SecurityPolicy {
                classification: SecurityClassification::Confidential,
                labels: BTreeSet::from(["personal".into()]),
                required_compartments: BTreeSet::new(),
                allow_external_processing: false,
            },
            derivation: DerivationRef {
                id: DerivationId::new(),
                kind: DerivationKind::Import,
                actor: None,
                model_call: None,
                pipeline: PipelineIdentity {
                    name: "artifact-import".into(),
                    version: "1".into(),
                    schema_version: "1".into(),
                },
                inputs: vec![LineageNode::Artifact { id: artifact }],
            },
        }
    }
}

fn interval() -> TimeRange {
    TimeRange::open_ended(TimestampMicros(0))
}

fn lexical_document(fixture: &Fixture, text: &str, projected_at: u64) -> LexicalDocument {
    LexicalDocument {
        id: RepresentationId::new(),
        target: LineageNode::External {
            namespace: "test".into(),
            identifier: text.into(),
        },
        text: text.into(),
        aliases: Vec::new(),
        policy: fixture.policy(),
        valid_time: interval(),
        projected_at: CommitSeq::new(projected_at),
        lineage: Vec::new(),
        tombstone_at: None,
    }
}

#[test]
fn exact_lexical_search_is_always_available() {
    let fixture = Fixture::new();
    let mut index = LexicalIndex::new();
    let document = lexical_document(&fixture, "always available exact lexical", 1);
    let expected = document.id;
    index.upsert(document).expect("document");
    index
        .publish_generation(1, CommitSeq::new(1))
        .expect("publication");
    let universe = index
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("universe");
    let result = index
        .search_exact(&universe, "available", None, 1)
        .expect("exact search");
    assert_eq!(result.hits[0].representation_id, expected);
}

#[test]
#[cfg(not(feature = "lexical-tantivy"))]
fn disabled_tantivy_fails_before_query_validation() {
    let fixture = Fixture::new();
    let index = LexicalIndex::new();
    let universe = index
        .authorize(&fixture.principal(), CommitSeq::GENESIS)
        .expect("empty exact universe");
    assert_eq!(
        index.search_tantivy(&universe, "", None, 0),
        Err(IndexError::CapabilityUnavailable {
            capability: "lexical-tantivy"
        })
    );
}

#[test]
#[cfg(feature = "lexical-tantivy")]
fn lexical_tantivy_is_policy_first_and_delta_survives_partial_publish() {
    let visible = Fixture::new();
    let denied = Fixture::new();
    let mut index = LexicalIndex::new();
    let visible_id = lexical_document(&visible, "japan neighbourhood bar", 1).id;
    let mut first = lexical_document(&visible, "japan neighbourhood bar", 1);
    first.id = visible_id;
    index.upsert(first).expect("visible document");
    index
        .upsert(lexical_document(&visible, "future searchable delta", 3))
        .expect("future delta");
    index
        .upsert(lexical_document(
            &denied,
            "japan japan japan forbidden super score",
            1,
        ))
        .expect("denied document");
    index
        .publish_generation(1, CommitSeq::new(1))
        .expect("partial publication");

    let universe = index
        .authorize(&visible.principal(), CommitSeq::new(1))
        .expect("authorized universe");
    let result = index
        .search_tantivy(&universe, "japan", None, 10)
        .expect("search");
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].representation_id, visible_id);
    assert_eq!(result.trace.authorized_examined, 1);
    let bundle = index.export_generation().expect("lexical bundle");
    let mut restored = LexicalIndex::new();
    restored.import_generation(bundle).expect("lexical restore");
    let restored_universe = restored
        .authorize(&visible.principal(), CommitSeq::new(1))
        .expect("restored universe");
    assert_eq!(
        restored
            .search_tantivy(&restored_universe, "japan", None, 10)
            .expect("restored search")
            .hits,
        result.hits
    );

    index
        .publish_generation(2, CommitSeq::new(3))
        .expect("publish retained delta");
    let future = index
        .authorize(&visible.principal(), CommitSeq::new(3))
        .expect("future universe");
    assert_eq!(
        index
            .search_exact(&future, "future", None, 10)
            .expect("future search")
            .hits
            .len(),
        1
    );
}

fn vector_space(id: VectorSpaceId, modality: Modality) -> VectorSpace {
    VectorSpace {
        id,
        dimensions: 3,
        metric: VectorMetric::Cosine,
        model_family: "reference-embedder".into(),
        model_revision: "1".into(),
        preprocessing_revision: "1".into(),
        modality,
    }
}

fn vector_record(
    fixture: &Fixture,
    space: VectorSpaceId,
    values: Vec<f32>,
    seq: u64,
) -> VectorRecord {
    VectorRecord {
        id: RepresentationId::new(),
        target: LineageNode::External {
            namespace: "vector".into(),
            identifier: format!("{values:?}"),
        },
        vector_space_id: space,
        values,
        policy: fixture.policy(),
        valid_time: interval(),
        projected_at: CommitSeq::new(seq),
        lineage: Vec::new(),
        tombstone_at: None,
    }
}

#[test]
fn exact_vector_search_is_always_available_without_an_ann_claim() {
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    let record = vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 1);
    let expected = record.id;
    index.insert(record).expect("vector");
    let snapshot = CommitSeq::new(1);
    let universe = index
        .authorize(&fixture.principal(), snapshot)
        .expect("universe");
    let result = index
        .search_exact(
            &universe,
            VectorQuery {
                vector_space_id: space,
                values: &[1.0, 0.0, 0.0],
                valid_at: None,
                limit: 1,
            },
            1,
        )
        .expect("exact search");
    assert_eq!(result.hits[0].representation_id, expected);
    assert_eq!(result.trace.generation, 0);
    assert_eq!(result.trace.watermark, snapshot);
    assert_eq!(result.trace.ann_visits, 0);
}

#[test]
#[cfg(not(feature = "ann-hnsw"))]
fn disabled_ann_operations_fail_without_inspecting_inputs() {
    let fixture = Fixture::new();
    let mut index = VectorIndex::new();
    let universe = index
        .authorize(&fixture.principal(), CommitSeq::GENESIS)
        .expect("empty exact universe");
    let unavailable = || IndexError::CapabilityUnavailable {
        capability: "ann-hnsw",
    };
    assert_eq!(
        index.stage_rebuild(0, CommitSeq::GENESIS, 0),
        Err(unavailable())
    );
    assert_eq!(index.publish_staged(0), Err(unavailable()));
    assert_eq!(index.export_generation(0), Err(unavailable()));
    assert_eq!(
        index.prune_ann_generations(CommitSeq::GENESIS),
        Err(unavailable())
    );
    assert_eq!(
        index.import_staged(PersistentAnnGeneration {
            schema_version: 0,
            generation: 0,
            watermark: CommitSeq::GENESIS,
            payload_digest: [0; 32],
            payload: Vec::new(),
        }),
        Err(unavailable())
    );
    assert_eq!(
        index.search_ann(
            &universe,
            VectorQuery {
                vector_space_id: VectorSpaceId::new(),
                values: &[],
                valid_at: None,
                limit: 0,
            },
            AnnBudget {
                max_visits: 0,
                ef_search: 0,
            },
        ),
        Err(unavailable())
    );
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn ann_never_traverses_denied_partition_and_matches_exact_top_hit() {
    let visible = Fixture::new();
    let denied = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    let expected = vector_record(&visible, space, vec![1.0, 0.0, 0.0], 1);
    let expected_id = expected.id;
    index.insert(expected).expect("visible vector");
    index
        .insert(vector_record(&visible, space, vec![0.9, 0.1, 0.0], 1))
        .expect("second visible vector");
    for _ in 0..12 {
        index
            .insert(vector_record(&denied, space, vec![1.0, 0.0, 0.0], 1))
            .expect("denied vector");
    }
    index.stage_rebuild(1, CommitSeq::new(1), 4).expect("stage");
    index.publish_staged(1).expect("publish");
    let universe = index
        .authorize(&visible.principal(), CommitSeq::new(1))
        .expect("universe");
    let exact = index
        .search_exact(
            &universe,
            VectorQuery {
                vector_space_id: space,
                values: &[1.0, 0.0, 0.0],
                valid_at: None,
                limit: 2,
            },
            20,
        )
        .expect("exact");
    let ann = index
        .search_ann(
            &universe,
            VectorQuery {
                vector_space_id: space,
                values: &[1.0, 0.0, 0.0],
                valid_at: None,
                limit: 2,
            },
            AnnBudget {
                max_visits: 20,
                ef_search: 20,
            },
        )
        .expect("ann");
    assert_eq!(exact.hits[0].representation_id, expected_id);
    assert_eq!(ann.hits[0].representation_id, expected_id);
    assert!(ann.trace.ann_visits <= 20);
    assert!(ann.trace.authorized_scored <= 2);
    assert_eq!(ann.trace.exact_fallback_scored, 0);
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn ann_search_rejects_unbounded_visit_and_candidate_budgets() {
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    index
        .insert(vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 1))
        .expect("vector");
    index.stage_rebuild(1, CommitSeq::new(1), 2).expect("stage");
    index.publish_staged(1).expect("publish");
    let universe = index
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("universe");
    let query = VectorQuery {
        vector_space_id: space,
        values: &[1.0, 0.0, 0.0],
        valid_at: None,
        limit: 1,
    };
    assert_eq!(
        index.search_ann(
            &universe,
            query,
            AnnBudget {
                max_visits: MAX_ANN_SEARCH_VISITS + 1,
                ef_search: 1,
            },
        ),
        Err(IndexError::InvalidBudget)
    );
    assert_eq!(
        index.search_ann(
            &universe,
            query,
            AnnBudget {
                max_visits: 4,
                ef_search: 5,
            },
        ),
        Err(IndexError::InvalidBudget)
    );
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn vector_spaces_are_immutable_and_generation_bundle_is_self_verifying() {
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    let mut rebound = vector_space(space, Modality::Image);
    rebound.model_revision = "2".into();
    assert_eq!(
        index.register_space(rebound),
        Err(IndexError::IncompatibleVectorSpace)
    );
    index
        .insert(vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 1))
        .expect("vector");
    index.stage_rebuild(1, CommitSeq::new(1), 2).expect("stage");
    index.publish_staged(1).expect("publish");
    let store = index.export_store(CommitSeq::new(1)).expect("store");
    let generation = index.export_generation(1).expect("generation");
    let mut restored = VectorIndex::new();
    restored.import_store(store).expect("store restore");
    restored
        .import_staged(generation)
        .expect("generation restore");
    restored.publish_staged(1).expect("generation switch");
    let universe = restored
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("restored universe");
    assert_eq!(
        restored
            .search_ann(
                &universe,
                VectorQuery {
                    vector_space_id: space,
                    values: &[1.0, 0.0, 0.0],
                    valid_at: None,
                    limit: 1,
                },
                AnnBudget {
                    max_visits: 4,
                    ef_search: 4,
                },
            )
            .expect("restored search")
            .hits
            .len(),
        1
    );
    let mut bundle = index.export_generation(1).expect("bundle");
    bundle.payload[0] ^= 1;
    let mut restored = VectorIndex::new();
    assert!(restored.import_staged(bundle).is_err());
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn incremental_ann_rebuild_is_deterministic_and_neighbour_bounded() {
    const RECORDS: usize = 192;
    const NEIGHBOURS: usize = 8;

    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut left = VectorIndex::new();
    left.register_space(vector_space(space, Modality::Text))
        .expect("space");
    for value in 0..RECORDS {
        let angle = (value as f32) / (RECORDS as f32) * std::f32::consts::TAU;
        left.insert(vector_record(
            &fixture,
            space,
            vec![angle.cos(), angle.sin(), 0.25],
            1,
        ))
        .expect("vector");
    }
    assert_eq!(
        left.stage_rebuild(1, CommitSeq::new(1), 65),
        Err(IndexError::Invalid(
            "HNSW neighbours exceed bounded construction limit"
        ))
    );

    let mut right = left.clone();
    left.stage_rebuild(1, CommitSeq::new(1), NEIGHBOURS)
        .expect("left stage");
    right
        .stage_rebuild(1, CommitSeq::new(1), NEIGHBOURS)
        .expect("right stage");
    left.publish_staged(1).expect("left publish");
    right.publish_staged(1).expect("right publish");
    let left_generation = left.export_generation(1).expect("left generation");
    let right_generation = right.export_generation(1).expect("right generation");
    assert_eq!(left_generation, right_generation);

    let payload: serde_json::Value =
        serde_json::from_slice(&left_generation.payload).expect("ANN payload JSON");
    let partitions = payload["partitions"]
        .as_object()
        .expect("ANN partitions object");
    for partition in partitions.values() {
        let nodes = partition["nodes"].as_object().expect("ANN nodes object");
        for node in nodes.values() {
            let levels = node["levels"].as_array().expect("ANN levels array");
            assert!(levels.iter().all(|level| {
                level
                    .as_array()
                    .is_some_and(|neighbours| neighbours.len() <= NEIGHBOURS)
            }));
        }
    }

    let mut disconnected: serde_json::Value =
        serde_json::from_slice(&left_generation.payload).expect("disconnect payload JSON");
    for partition in disconnected["partitions"]
        .as_object_mut()
        .expect("disconnect partitions")
        .values_mut()
    {
        for node in partition["nodes"]
            .as_object_mut()
            .expect("disconnect nodes")
            .values_mut()
        {
            node["levels"]
                .as_array_mut()
                .and_then(|levels| levels.first_mut())
                .and_then(serde_json::Value::as_array_mut)
                .expect("disconnect base level")
                .clear();
        }
    }
    let mut disconnected_bundle = left_generation.clone();
    disconnected_bundle.payload =
        serde_json::to_vec(&disconnected).expect("disconnected payload bytes");
    disconnected_bundle.payload_digest = *blake3::hash(&disconnected_bundle.payload).as_bytes();
    let mut restored = VectorIndex::new();
    assert_eq!(
        restored.import_staged(disconnected_bundle),
        Err(IndexError::Invalid("ANN base layer is disconnected"))
    );

    let mut reordered: serde_json::Value =
        serde_json::from_slice(&left_generation.payload).expect("reorder payload JSON");
    let reordered_neighbours = reordered["partitions"]
        .as_object_mut()
        .and_then(|partitions| partitions.values_mut().next())
        .and_then(|partition| partition["nodes"].as_object_mut())
        .and_then(|nodes| {
            nodes.values_mut().find_map(|node| {
                node["levels"]
                    .as_array_mut()
                    .and_then(|levels| levels.first_mut())
                    .and_then(serde_json::Value::as_array_mut)
                    .filter(|neighbours| neighbours.len() >= 2)
            })
        })
        .expect("reorder base neighbours");
    reordered_neighbours.reverse();
    let mut reordered_bundle = left_generation.clone();
    reordered_bundle.payload = serde_json::to_vec(&reordered).expect("reordered payload bytes");
    reordered_bundle.payload_digest = *blake3::hash(&reordered_bundle.payload).as_bytes();
    let store = left.export_store(CommitSeq::new(1)).expect("vector store");
    let mut restored = VectorIndex::new();
    restored.import_store(store).expect("vector store restore");
    assert_eq!(
        restored.import_staged(reordered_bundle),
        Err(IndexError::Invalid("ANN neighbour order is non-canonical"))
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&left_generation.payload).expect("tamper payload JSON");
    let first_partition = tampered["partitions"]
        .as_object_mut()
        .and_then(|partitions| partitions.values_mut().next())
        .expect("tamper partition");
    let (self_id, first_node) = first_partition["nodes"]
        .as_object_mut()
        .and_then(|nodes| {
            nodes
                .iter_mut()
                .next()
                .map(|(id, node)| (serde_json::Value::String(id.clone()), node))
        })
        .expect("tamper node");
    first_node["levels"]
        .as_array_mut()
        .and_then(|levels| levels.first_mut())
        .and_then(serde_json::Value::as_array_mut)
        .expect("tamper base level")
        .push(self_id);
    let mut malformed = left_generation;
    malformed.payload = serde_json::to_vec(&tampered).expect("tampered payload bytes");
    malformed.payload_digest = *blake3::hash(&malformed.payload).as_bytes();
    let mut restored = VectorIndex::new();
    assert_eq!(
        restored.import_staged(malformed),
        Err(IndexError::Invalid("ANN neighbour linkage is invalid"))
    );
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn ann_import_is_atomic_and_generation_watermarks_never_regress() {
    let new_space =
        VectorSpaceId::from_str("00000000-0000-4000-8000-000000000001").expect("new space ID");
    let existing_space =
        VectorSpaceId::from_str("ffffffff-ffff-4fff-8fff-ffffffffffff").expect("existing space ID");

    let mut target = VectorIndex::new();
    target
        .register_space(vector_space(existing_space, Modality::Text))
        .expect("target space");

    let mut source = VectorIndex::new();
    source
        .register_space(vector_space(new_space, Modality::Text))
        .expect("new source space");
    source
        .register_space(vector_space(existing_space, Modality::Image))
        .expect("incompatible source space");
    source
        .stage_rebuild(1, CommitSeq::new(1), 2)
        .expect("source stage");
    source.publish_staged(1).expect("source publish");
    let bundle = source.export_generation(1).expect("source bundle");
    assert_eq!(
        target.import_staged(bundle),
        Err(IndexError::IncompatibleVectorSpace)
    );
    assert_eq!(
        target.registry().get(new_space),
        Err(IndexError::UnknownVectorSpace(new_space))
    );

    let fixture = Fixture::new();
    target
        .insert(vector_record(
            &fixture,
            existing_space,
            vec![1.0, 0.0, 0.0],
            1,
        ))
        .expect("target vector");
    target
        .stage_rebuild(1, CommitSeq::new(2), 2)
        .expect("fresh stage");
    target.publish_staged(1).expect("fresh publish");
    assert_eq!(
        target.stage_rebuild(2, CommitSeq::new(1), 2),
        Err(IndexError::StaleGeneration)
    );
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn ann_publish_validation_failure_preserves_staged_generation_for_retry() {
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    let record = vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 1);
    let record_id = record.id;
    index.insert(record).expect("vector");
    index.stage_rebuild(1, CommitSeq::new(2), 2).expect("stage");

    index
        .tombstone(record_id, CommitSeq::new(1))
        .expect("conflicting tombstone");
    assert_eq!(
        index.publish_staged(1),
        Err(IndexError::Invalid(
            "ANN generation disagrees with full-precision records"
        ))
    );
    assert_eq!(
        index.export_generation(1),
        Err(IndexError::GenerationNotReady(1))
    );

    // Moving the logical deletion beyond the staged watermark removes the
    // validation drift. The same preserved staged generation can now publish.
    index
        .tombstone(record_id, CommitSeq::new(3))
        .expect("post-watermark tombstone");
    index.publish_staged(1).expect("retry publish");
    assert_eq!(index.export_generation(1).expect("published").generation, 1);
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn ann_generation_prune_is_explicit_idempotent_and_snapshot_safe() {
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    index
        .insert(vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 1))
        .expect("vector");
    for generation in 1..=3 {
        index
            .stage_rebuild(generation, CommitSeq::new(generation), 2)
            .expect("stage generation");
        index
            .publish_staged(generation)
            .expect("publish generation");
    }

    let query = VectorQuery {
        vector_space_id: space,
        values: &[1.0, 0.0, 0.0],
        valid_at: None,
        limit: 1,
    };
    let expired_before_prune = index
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("historical universe before prune");
    let exact_before_prune = index
        .search_exact(&expired_before_prune, query, 4)
        .expect("exact historical search before prune");
    assert_eq!(exact_before_prune.trace.generation, 0);
    assert_eq!(exact_before_prune.trace.watermark, CommitSeq::new(1));
    let before = index
        .authorize(&fixture.principal(), CommitSeq::new(2))
        .expect("retained universe");
    assert_eq!(
        index
            .search_ann(
                &before,
                query,
                AnnBudget {
                    max_visits: 4,
                    ef_search: 4,
                },
            )
            .expect("retained search")
            .trace
            .generation,
        2
    );

    let report = index
        .prune_ann_generations(CommitSeq::new(2))
        .expect("prune");
    assert_eq!(report.previous_oldest_retained_snapshot, CommitSeq::GENESIS);
    assert_eq!(report.oldest_retained_snapshot, CommitSeq::new(2));
    assert_eq!(report.baseline_generation, 2);
    assert_eq!(report.active_generation, 3);
    assert_eq!(report.generations_deleted, 1);
    assert!(report.payload_bytes_deleted > 0);
    assert!(!report.staged_generation_discarded);
    assert_eq!(
        index.export_generation(1),
        Err(IndexError::GenerationNotReady(1))
    );
    let expired = index
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("exact historical universe remains available");
    let exact_from_pre_prune_universe = index
        .search_exact(&expired_before_prune, query, 4)
        .expect("pre-prune universe remains exact-readable");
    let exact_from_post_prune_universe = index
        .search_exact(&expired, query, 4)
        .expect("post-prune exact historical search");
    assert_eq!(exact_from_pre_prune_universe, exact_before_prune);
    assert_eq!(exact_from_post_prune_universe, exact_before_prune);
    assert_eq!(exact_from_post_prune_universe.hits.len(), 1);
    assert_eq!(
        index.search_ann(
            &expired_before_prune,
            query,
            AnnBudget {
                max_visits: 4,
                ef_search: 4,
            },
        ),
        Err(IndexError::Invalid(
            "ANN snapshot precedes the explicit retention floor"
        ))
    );
    assert_eq!(
        index.search_ann(
            &expired,
            query,
            AnnBudget {
                max_visits: 4,
                ef_search: 4,
            },
        ),
        Err(IndexError::Invalid(
            "ANN snapshot precedes the explicit retention floor"
        ))
    );
    let retained = index
        .authorize(&fixture.principal(), CommitSeq::new(2))
        .expect("baseline universe");
    assert_eq!(
        index
            .search_ann(
                &retained,
                query,
                AnnBudget {
                    max_visits: 4,
                    ef_search: 4,
                },
            )
            .expect("baseline search")
            .trace
            .generation,
        2
    );

    let repeated = index
        .prune_ann_generations(CommitSeq::new(2))
        .expect("repeat prune");
    assert_eq!(repeated.generations_deleted, 0);
    assert_eq!(repeated.payload_bytes_deleted, 0);

    index
        .stage_rebuild(4, CommitSeq::new(3), 2)
        .expect("stale-at-next-floor stage");
    let advanced = index
        .prune_ann_generations(CommitSeq::new(4))
        .expect("advance prune floor");
    assert_eq!(advanced.baseline_generation, 3);
    assert_eq!(advanced.generations_deleted, 1);
    assert!(advanced.staged_generation_discarded);
    assert_eq!(
        index.publish_staged(4),
        Err(IndexError::GenerationNotReady(4))
    );
    assert_eq!(
        index.prune_ann_generations(CommitSeq::new(3)),
        Err(IndexError::StaleGeneration)
    );
    let active = index
        .authorize(&fixture.principal(), CommitSeq::new(4))
        .expect("active retained universe");
    assert_eq!(
        index
            .search_ann(
                &active,
                query,
                AnnBudget {
                    max_visits: 4,
                    ef_search: 4,
                },
            )
            .expect("active retained search")
            .trace
            .generation,
        3
    );
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn ann_delta_tombstone_temporal_snapshot_and_rebuild_match_exact() {
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    index
        .register_space(vector_space(space, Modality::Text))
        .expect("space");
    let old = vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 1);
    let old_id = old.id;
    index.insert(old).expect("old vector");
    index
        .insert(vector_record(&fixture, space, vec![0.0, 1.0, 0.0], 1))
        .expect("other vector");
    index.stage_rebuild(1, CommitSeq::new(1), 2).expect("stage");
    index.publish_staged(1).expect("publish");

    index
        .tombstone(old_id, CommitSeq::new(2))
        .expect("tombstone");
    let mut delta = vector_record(&fixture, space, vec![1.0, 0.0, 0.0], 2);
    delta.valid_time =
        TimeRange::new(TimestampMicros(10), Some(TimestampMicros(20))).expect("valid time");
    let delta_id = delta.id;
    index.insert(delta).expect("delta");

    let old_universe = index
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("old universe");
    assert_eq!(
        index
            .search_ann(
                &old_universe,
                VectorQuery {
                    vector_space_id: space,
                    values: &[1.0, 0.0, 0.0],
                    valid_at: Some(TimestampMicros(0)),
                    limit: 1,
                },
                AnnBudget {
                    max_visits: 4,
                    ef_search: 4,
                },
            )
            .expect("old search")
            .hits[0]
            .representation_id,
        old_id
    );
    let current_universe = index
        .authorize(&fixture.principal(), CommitSeq::new(2))
        .expect("current universe");
    let current_query = VectorQuery {
        vector_space_id: space,
        values: &[1.0, 0.0, 0.0],
        valid_at: Some(TimestampMicros(15)),
        limit: 1,
    };
    let exact = index
        .search_exact(&current_universe, current_query, 4)
        .expect("exact delta");
    let before_rebuild = index
        .search_ann(
            &current_universe,
            current_query,
            AnnBudget {
                max_visits: 4,
                ef_search: 4,
            },
        )
        .expect("delta fallback");
    assert_eq!(exact.hits[0].representation_id, delta_id);
    assert_eq!(before_rebuild.hits, exact.hits);

    index.stage_rebuild(2, CommitSeq::new(2), 2).expect("stage");
    index.publish_staged(2).expect("publish");
    let rebuilt_universe = index
        .authorize(&fixture.principal(), CommitSeq::new(2))
        .expect("rebuilt universe");
    assert_eq!(
        index
            .search_ann(
                &rebuilt_universe,
                current_query,
                AnnBudget {
                    max_visits: 4,
                    ef_search: 4,
                },
            )
            .expect("rebuilt search")
            .hits,
        exact.hits
    );
}

fn block(id: ContentBlockId, locator: &str, digest: u8) -> ContentBlock {
    ContentBlock {
        id,
        media_type: "text/plain".into(),
        encoding: ContentEncoding::Utf8,
        compression: Compression::None,
        byte_length: 10,
        blob_locator: BlobLocator(locator.into()),
        content_hash: ContentDigest::from_bytes([digest; 32]),
    }
}

fn artifact_projection(fixture: &Fixture) -> ArtifactProjection {
    let artifact_id = ArtifactId::new();
    let content_block_id = ContentBlockId::new();
    ArtifactProjection {
        artifact: Artifact {
            id: artifact_id,
            source_id: SourceId::new(),
            modality: Modality::Image,
            media_type: "image/png".into(),
            native_locator: Some("camera:frame-1".into()),
            content_blocks: NonEmptyVec::new(content_block_id),
            content_hash: ContentDigest::from_bytes([1; 32]),
            created_at: Some(TimestampMicros(1)),
            ingested_at: TimestampMicros(2),
            envelope: fixture.envelope(artifact_id),
        },
        content_blocks: vec![block(content_block_id, "cas-v1:original", 2)],
        blob_locator_schema_version: 1,
        policy: fixture.policy(),
        projected_at: CommitSeq::new(1),
        tombstone_at: None,
    }
}

#[test]
fn artifact_derived_lineage_policy_and_deletion_closure_are_enforced() {
    let fixture = Fixture::new();
    let mut index = ArtifactIndex::new();
    let source = artifact_projection(&fixture);
    let artifact_id = source.artifact.id;
    let source_block = source.content_blocks[0].clone();
    index.insert_artifact(source).expect("artifact");
    let representation_id = RepresentationId::new();
    index
        .insert_representation(ArtifactRepresentation {
            id: representation_id,
            artifact_id,
            source_content_block_id: source_block.id,
            source_selector: EvidenceSelector::ImageRegion {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            source_content_hash: source_block.content_hash,
            kind: RepresentationKind::Caption,
            modality: Modality::Text,
            content_block: block(ContentBlockId::new(), "cas-v1:caption", 3),
            confidence_millionths: 900_000,
            compatibility: None,
            envelope: SemanticEnvelope {
                derivation: DerivationRef {
                    id: DerivationId::new(),
                    kind: DerivationKind::DeterministicProjector,
                    actor: None,
                    model_call: None,
                    pipeline: PipelineIdentity {
                        name: "captioner".into(),
                        version: "1".into(),
                        schema_version: "1".into(),
                    },
                    inputs: vec![LineageNode::Artifact { id: artifact_id }],
                },
                ..fixture.envelope(artifact_id)
            },
            policy: fixture.policy(),
            projected_at: CommitSeq::new(1),
            tombstone_at: None,
        })
        .expect("caption");
    index
        .publish_generation(1, CommitSeq::new(1))
        .expect("generation");
    let bundle = index.export_generation(1).expect("artifact bundle");
    let mut restored = ArtifactIndex::new();
    restored
        .import_generation(bundle)
        .expect("artifact restore");
    let restored_universe = restored.authorize(&fixture.principal(), CommitSeq::new(1));
    assert_eq!(
        restored
            .representation(&restored_universe, representation_id)
            .expect("restored representation")
            .source_content_hash,
        source_block.content_hash
    );
    let universe = index.authorize(&fixture.principal(), CommitSeq::new(1));
    assert_eq!(
        index
            .representation(&universe, representation_id)
            .expect("representation")
            .source_selector,
        EvidenceSelector::ImageRegion {
            x: 1,
            y: 2,
            width: 3,
            height: 4
        }
    );
    let closure = index
        .tombstone_artifact(artifact_id, CommitSeq::new(2))
        .expect("closure");
    assert_eq!(closure.representation_ids, vec![representation_id]);
    assert_eq!(closure.blob_locators.len(), 2);
    let after = index.authorize(&fixture.principal(), CommitSeq::new(2));
    assert!(index.artifact(&after, artifact_id).is_err());
    assert!(index.representation(&after, representation_id).is_err());
}

#[test]
fn incompatible_cross_modal_space_is_rejected() {
    let fixture = Fixture::new();
    let mut index = ArtifactIndex::new();
    let source = artifact_projection(&fixture);
    let artifact_id = source.artifact.id;
    let source_block = source.content_blocks[0].clone();
    index.insert_artifact(source).expect("artifact");
    let native = VectorSpaceId::new();
    let incompatible = VectorSpaceId::new();
    let result = index.insert_representation(ArtifactRepresentation {
        id: RepresentationId::new(),
        artifact_id,
        source_content_block_id: source_block.id,
        source_selector: EvidenceSelector::Whole,
        source_content_hash: source_block.content_hash,
        kind: RepresentationKind::Embedding,
        modality: Modality::Image,
        content_block: block(ContentBlockId::new(), "cas-v1:embedding", 4),
        confidence_millionths: 1_000_000,
        compatibility: Some(RepresentationCompatibility {
            family: "clip".into(),
            revision: "1".into(),
            native_vector_space: Some(native),
            compatible_vector_spaces: BTreeSet::from([incompatible]),
        }),
        envelope: SemanticEnvelope {
            derivation: DerivationRef {
                id: DerivationId::new(),
                kind: DerivationKind::DeterministicProjector,
                actor: None,
                model_call: None,
                pipeline: PipelineIdentity {
                    name: "embedder".into(),
                    version: "1".into(),
                    schema_version: "1".into(),
                },
                inputs: vec![LineageNode::Artifact { id: artifact_id }],
            },
            ..fixture.envelope(artifact_id)
        },
        policy: fixture.policy(),
        projected_at: CommitSeq::new(1),
        tombstone_at: None,
    });
    assert_eq!(
        result,
        Err(IndexError::Invalid(
            "native vector space must be included in compatibility set"
        ))
    );
}

proptest! {
    #[test]
    fn denied_lexical_payload_never_changes_visible_result(secret in ".{0,128}") {
        let visible = Fixture::new();
        let denied = Fixture::new();
        let mut baseline = LexicalIndex::new();
        baseline.upsert(lexical_document(&visible, "stable visible memory", 1)).expect("visible");
        baseline.publish_generation(1, CommitSeq::new(1)).expect("publish");
        let baseline_universe = baseline.authorize(&visible.principal(), CommitSeq::new(1)).expect("universe");
        let expected = baseline.search_exact(&baseline_universe, "stable", None, 5).expect("search");

        let mut with_secret = LexicalIndex::new();
        with_secret.upsert(lexical_document(&visible, "stable visible memory", 1)).expect("visible");
        let secret = if secret.trim().is_empty() { "stable secret".to_owned() } else { format!("stable {secret}") };
        with_secret.upsert(lexical_document(&denied, &secret, 1)).expect("secret");
        with_secret.publish_generation(1, CommitSeq::new(1)).expect("publish");
        let universe = with_secret.authorize(&visible.principal(), CommitSeq::new(1)).expect("universe");
        let actual = with_secret.search_exact(&universe, "stable", None, 5).expect("search");
        prop_assert_eq!(actual.hits.len(), expected.hits.len());
        prop_assert_eq!(actual.trace.authorized_examined, expected.trace.authorized_examined);
        prop_assert_eq!(actual.hits[0].score, expected.hits[0].score);
    }
}

#[test]
#[cfg(feature = "ann-hnsw")]
fn deterministic_ann_recall_floor_against_exact_oracle() {
    const DOCUMENTS: usize = 256;
    const DIMENSIONS: usize = 12;
    const K: usize = 10;
    const MAX_VISITS: usize = 128;
    let fixture = Fixture::new();
    let space = VectorSpaceId::new();
    let mut index = VectorIndex::new();
    let mut definition = vector_space(space, Modality::Text);
    definition.dimensions = DIMENSIONS as u32;
    index.register_space(definition).expect("space");
    let mut vectors = Vec::new();
    for ordinal in 0..DOCUMENTS {
        let values = deterministic_vector(ordinal as u64 + 1, DIMENSIONS);
        let id = RepresentationId::from_str(&format!("00000000-0000-4000-8000-{ordinal:012x}"))
            .expect("stable representation ID");
        vectors.push((id, values.clone()));
        let mut record = vector_record(&fixture, space, values, 1);
        record.id = id;
        index.insert(record).expect("vector");
    }
    index
        .stage_rebuild(1, CommitSeq::new(1), 12)
        .expect("stage");
    index.publish_staged(1).expect("publish");
    let universe = index
        .authorize(&fixture.principal(), CommitSeq::new(1))
        .expect("universe");
    let mut overlap = 0_usize;
    let mut possible = 0_usize;
    let mut queries = 0_usize;
    for (_, values) in vectors.iter().step_by(8) {
        let query = VectorQuery {
            vector_space_id: space,
            values,
            valid_at: None,
            limit: K,
        };
        let exact = index
            .search_exact(&universe, query, DOCUMENTS)
            .expect("exact");
        let ann = index
            .search_ann(
                &universe,
                query,
                AnnBudget {
                    max_visits: MAX_VISITS,
                    ef_search: 64,
                },
            )
            .expect("ann");
        assert_eq!(ann.trace.exact_fallback_scored, 0);
        assert!(ann.trace.ann_visits <= MAX_VISITS as u64);
        assert!(ann.trace.authorized_scored <= 64);
        let exact_ids = exact
            .hits
            .iter()
            .map(|hit| hit.representation_id)
            .collect::<BTreeSet<_>>();
        overlap += ann
            .hits
            .iter()
            .filter(|hit| exact_ids.contains(&hit.representation_id))
            .count();
        possible += exact.hits.len();
        queries += 1;
    }
    let recall = overlap as f64 / possible as f64;
    println!(
        "M7_ANN_QUALITY documents={DOCUMENTS} dimensions={DIMENSIONS} queries={queries} k={K} max_visits={MAX_VISITS} overlap={overlap} possible={possible} recall={recall:.6}"
    );
    assert!(recall >= 0.90, "ANN recall {recall:.6} is below 0.90");
}

#[cfg(feature = "ann-hnsw")]
fn deterministic_vector(seed: u64, dimensions: usize) -> Vec<f32> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut values = Vec::with_capacity(dimensions);
    for _ in 0..dimensions {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let fraction = ((state >> 40) as f32) / ((1_u32 << 24) as f32);
        values.push(fraction.mul_add(2.0, -1.0));
    }
    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    for value in &mut values {
        *value /= norm;
    }
    values
}
