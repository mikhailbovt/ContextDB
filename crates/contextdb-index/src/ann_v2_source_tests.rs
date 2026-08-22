use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Mutex;

use contextdb_core::{
    CommitSeq, LineageNode, MemorySpaceId, MemorySubjectId, Modality, Purpose, RepresentationId,
    ScopeId, SecurityClassification, TimeRange, TimestampMicros, VectorSpaceId, WorkspaceId,
};
use contextdb_storage::{Durability, Keyspace, StorageEngine, WriteTransaction};
use contextdb_storage_memory::MemoryStorage;
use contextdb_storage_redb::RedbStorage;

use super::*;

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
            security_labels: BTreeSet::from(["durable-source-test".to_owned()]),
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
        metric: VectorMetric::DotProduct,
        model_family: "durable-source-test".to_owned(),
        model_revision: "1".to_owned(),
        preprocessing_revision: "1".to_owned(),
        modality: Modality::Structured,
    }
}

fn record(number: u128, identity: &TestIdentity, space: VectorSpaceId) -> VectorRecord {
    let id = stable_id(number);
    VectorRecord {
        id,
        target: LineageNode::External {
            namespace: "durable-source-test".to_owned(),
            identifier: id.to_string(),
        },
        vector_space_id: space,
        values: vec![number as f32, 0.25, 0.5, 1.0],
        policy: identity.policy(),
        valid_time: TimeRange::open_ended(TimestampMicros(0)),
        projected_at: CommitSeq::new(7),
        lineage: Vec::new(),
        tombstone_at: None,
    }
}

fn plan(records: u64) -> AnnSourceImportPlanV2 {
    AnnSourceImportPlanV2 {
        vector_store_generation: 11,
        route_generation: 13,
        expected_vector_spaces: 1,
        expected_records: records,
    }
}

#[test]
fn import_resumes_idempotently_reopens_and_rejects_divergence() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("source.redb");
    let identity = TestIdentity::numbered(0x100);
    let space_id = stable_id(0x200);
    let first = record(0x300, &identity, space_id);
    let second = record(0x301, &identity, space_id);
    let third = record(0x302, &identity, space_id);

    let importer = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(&path).expect("redb"),
        plan(3),
        Durability::Sync,
    )
    .expect("begin import");
    importer
        .put_vector_space(&vector_space(space_id))
        .expect("space");
    importer
        .put_records_page(std::slice::from_ref(&first))
        .expect("first page");
    drop(importer);

    let importer = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(&path).expect("reopen redb"),
        plan(3),
        Durability::Sync,
    )
    .expect("resume import");
    importer
        .put_vector_space(&vector_space(space_id))
        .expect("idempotent space");
    importer
        .put_records_page(std::slice::from_ref(&first))
        .expect("idempotent first row");
    let mut divergent = first.clone();
    divergent.values[0] += 1.0;
    importer
        .put_records_page(&[divergent])
        .expect_err("same ID cannot be rebound");
    importer
        .put_records_page(&[second, third])
        .expect("remaining page");
    let source = importer.finish().expect("publish source");
    assert_eq!(source.verification().record_count, 3);
    let seal = source.source_seal().expect("seal");
    drop(source);

    let reopened =
        PersistentAnnVectorSourceV2::open(RedbStorage::open(&path).expect("second redb reopen"))
            .expect("verified reopen");
    assert_eq!(reopened.source_seal().expect("reopened seal"), seal);
    drop(reopened);
    let sealed_retry = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(&path).expect("sealed redb reopen"),
        plan(3),
        Durability::Sync,
    )
    .expect("sealed retry");
    sealed_retry
        .put_vector_space(&vector_space(space_id))
        .expect("sealed identical space");
    sealed_retry
        .put_records_page(std::slice::from_ref(&first))
        .expect("sealed identical row");
    let mut changed = first;
    changed.values[1] += 1.0;
    sealed_retry
        .put_records_page(&[changed])
        .expect_err("sealed row is immutable");
}

#[test]
fn computed_roots_match_the_exact_in_memory_bridge() {
    let directory = tempfile::tempdir().expect("tempdir");
    let identity = TestIdentity::numbered(0x400);
    let space_id = stable_id(0x500);
    let space = vector_space(space_id);
    let records = (0_u128..8)
        .map(|offset| record(0x600 + offset, &identity, space_id))
        .collect::<Vec<_>>();
    let mut exact = VectorIndex::new();
    exact.register_space(space.clone()).expect("exact space");
    for row in &records {
        exact.insert(row.clone()).expect("exact row");
    }
    let expected = VectorIndexAnnSourceV2::new(&exact, 11, 13)
        .expect("exact bridge")
        .source_seal()
        .expect("exact seal");

    let importer = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(directory.path().join("roots.redb")).expect("redb"),
        plan(8),
        Durability::Sync,
    )
    .expect("importer");
    importer.put_vector_space(&space).expect("space");
    importer.put_records_page(&records).expect("records");
    let durable = importer.finish().expect("durable source");
    assert_eq!(durable.source_seal().expect("durable seal"), expected);
}

#[test]
fn verification_uses_multiple_bounded_pages_without_collecting_the_source() {
    let directory = tempfile::tempdir().expect("tempdir");
    let identity = TestIdentity::numbered(0x700);
    let space_id = stable_id(0x800);
    let importer = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(directory.path().join("paged.redb")).expect("redb"),
        plan(2_050),
        Durability::Sync,
    )
    .expect("importer");
    importer
        .put_vector_space(&vector_space(space_id))
        .expect("space");
    for page_index in 0_u128..3 {
        let start = page_index * 1_024;
        let count = if page_index < 2 { 1_024 } else { 2 };
        let rows = (0_u128..count)
            .map(|offset| record(0x10_000 + start + offset, &identity, space_id))
            .collect::<Vec<_>>();
        importer.put_records_page(&rows).expect("bounded page");
    }
    let source = importer.finish().expect("source");
    let verification = source.verification();
    assert_eq!(verification.record_count, 2_050);
    assert_eq!(verification.route_pages, 3);
    assert_eq!(verification.vector_key_pages, 3);
    assert_eq!(verification.target_key_pages, 3);

    let mut cursor = None;
    let mut seen = 0_usize;
    loop {
        let page = source
            .scan_routes_page(cursor, 17, 64 * 1024)
            .expect("route page");
        assert!(page.routes.len() <= 17);
        seen += page.routes.len();
        let Some(next) = page.continuation else {
            break;
        };
        assert!(cursor.is_none_or(|previous| next > previous));
        cursor = Some(next);
    }
    assert_eq!(seen, 2_050);
}

#[test]
fn reopen_fails_closed_after_published_row_corruption() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("corrupt.redb");
    let storage = RedbStorage::open(&path).expect("redb");
    let raw = storage.clone();
    let identity = TestIdentity::numbered(0x900);
    let space_id = stable_id(0xa00);
    let row = record(0xb00, &identity, space_id);
    let importer = PersistentAnnVectorSourceV2::begin_import(storage, plan(1), Durability::Sync)
        .expect("importer");
    importer
        .put_vector_space(&vector_space(space_id))
        .expect("space");
    importer
        .put_records_page(std::slice::from_ref(&row))
        .expect("row");
    drop(importer.finish().expect("source"));

    let mut write = raw.begin_write().expect("raw writer");
    write
        .put(
            &Keyspace::new("ann_source_vectors").expect("keyspace"),
            row.id.to_string().into_bytes(),
            b"{not-canonical-or-valid".to_vec(),
        )
        .expect("corrupt row");
    write.commit(Durability::Sync).expect("commit corruption");
    drop(raw);
    PersistentAnnVectorSourceV2::open(RedbStorage::open(&path).expect("reopen redb"))
        .expect_err("root verification must reject corruption");
}

#[derive(Debug, Default)]
struct SourceAudit {
    route_pages: u64,
    vector_reads: Vec<RepresentationId>,
    target_reads: Vec<RepresentationId>,
}

#[derive(Debug)]
struct AuditedSource<'a> {
    inner: &'a PersistentAnnVectorSourceV2<RedbStorage>,
    audit: Mutex<SourceAudit>,
}

impl AuditedSource<'_> {
    fn clear(&self) {
        *self.audit.lock().expect("audit lock") = SourceAudit::default();
    }
}

impl AnnVectorSourceV2 for AuditedSource<'_> {
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
        self.audit.lock().expect("audit lock").route_pages += 1;
        self.inner
            .scan_routes_page(start_after, max_entries, max_bytes)
    }

    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>> {
        self.audit.lock().expect("audit lock").vector_reads.push(id);
        self.inner.read_vector(id, dimensions)
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        self.audit.lock().expect("audit lock").target_reads.push(id);
        self.inner.read_target(id, max_bytes)
    }
}

#[test]
fn authorization_reads_policies_before_any_durable_vector_or_target() {
    let directory = tempfile::tempdir().expect("tempdir");
    let allowed = TestIdentity::numbered(0xc00);
    let denied = TestIdentity::numbered(0xd00);
    let space_id = stable_id(0xe00);
    let rows = (0_u128..16)
        .map(|offset| {
            record(
                0xf00 + offset,
                if offset < 12 { &allowed } else { &denied },
                space_id,
            )
        })
        .collect::<Vec<_>>();
    let importer = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(directory.path().join("policy-source.redb")).expect("redb"),
        plan(16),
        Durability::Sync,
    )
    .expect("importer");
    importer
        .put_vector_space(&vector_space(space_id))
        .expect("space");
    importer.put_records_page(&rows).expect("rows");
    let source = importer.finish().expect("source");
    let audited = AuditedSource {
        inner: &source,
        audit: Mutex::new(SourceAudit::default()),
    };
    let runtime = PersistentAnnV2::open(MemoryStorage::new()).expect("runtime");
    runtime
        .rebuild_and_publish(
            &audited,
            1,
            CommitSeq::new(7),
            AnnBuildParametersV2 {
                algorithm: AnnAlgorithmV2::DeterministicHnswV1,
                partition_scheme: AnnPartitionSchemeV2::ExactPolicyV1,
                max_level: 4,
                neighbours_per_level: 8,
                construction_max_visits: 64,
            },
            Durability::Sync,
        )
        .expect("ANN publication");
    audited.clear();
    let universe = runtime
        .authorize(&audited, &allowed.principal(), CommitSeq::new(7))
        .expect("authorized universe");
    let audit = audited.audit.lock().expect("audit lock");
    assert_eq!(universe.authorized_count(), 12);
    assert_eq!(
        audit.route_pages, 0,
        "authorization must use persisted routes"
    );
    assert!(audit.vector_reads.is_empty());
    assert!(audit.target_reads.is_empty());
}
