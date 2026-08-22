//! Live, storage-backed ANN-v2 generation build, publication, recovery and query.
//!
//! The runtime deliberately remains a rebuildable development component. Base
//! full-precision vectors stay authoritative behind [`AnnVectorSourceV2`];
//! post-generation deltas live in a separate bounded overlay until a later
//! source generation incorporates them.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use contextdb_core::{
    CommitSeq, LineageNode, RepresentationId, TimestampMicros, Validate, VectorSpaceId,
};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ANN_V2_FORMAT_VERSION, ANN_V2_MAX_GENERATION_BYTES, ANN_V2_MAX_NODES, ANN_V2_MAX_OBJECT_BYTES,
    ANN_V2_MAX_PAGE_BYTES, ANN_V2_MAX_PAGE_ENTRIES, AnnBuildParametersV2, AnnGenerationManifestV2,
    AnnGenerationVerificationV2, AnnLevelV2, AnnMerkleGeometryV2, AnnMerkleScopeV2, AnnNodeV2,
    AnnObjectKeyV2, AnnObjectPageRequestV2, AnnObjectPageV2, AnnObjectReadRequestV2,
    AnnObjectReadResponseV2, AnnObjectReaderV2, AnnObjectV2, AnnPartitionManifestV2,
    AnnSourceSealV2, AnnV2Error, IndexPolicy, IndexPrincipal, VectorIndex, VectorRecord,
    VectorSpace, ann_v2_generation_prefix, ann_v2_merkle_internal, ann_v2_merkle_leaf,
    ann_v2_merkle_root, ann_v2_partition_key, score, validate_values, verify_ann_generation_v2,
};

const OBJECT_KEYSPACE: &str = "ann_v2_objects";
const CONTROL_KEYSPACE: &str = "ann_v2_control";
const BUILD_KEYSPACE: &str = "ann_v2_build";
const ROUTE_KEYSPACE: &str = "ann_v2_routes";
const OVERLAY_KEYSPACE: &str = "ann_v2_overlay";
const UNIVERSE_KEYSPACE: &str = "ann_v2_universes";
const LEASE_KEYSPACE: &str = "ann_v2_leases";
const ACTIVE_MANIFEST_KEY: &[u8] = b"active_manifest";
const BUILD_FENCE_KEY: &[u8] = b"build_fence";
const ACTIVE_ROTATION_KEY: &[u8] = b"active_rotation";
const UNIVERSE_FENCE_KEY: &[u8] = b"universe_fence";
const PRUNE_FENCE_KEY: &[u8] = b"prune_fence";
const OVERLAY_EPOCH_KEY: &[u8] = b"overlay_epoch";
const MANIFEST_PREFIX: &[u8] = b"manifest/";
const ROUTE_MANIFEST_PREFIX: &[u8] = b"route_manifest/";
const RUNTIME_FORMAT_VERSION: u16 = 1;
const CLEAN_PAGE_ENTRIES: usize = 1_024;
const CLEAN_PAGE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_BUILD_BATCH_OBJECTS: usize = 512;
const MAX_QUERY_VISITS: usize = 65_536;
const MAX_QUERY_EXACT_SCORES: usize = 1_000_000;
pub(crate) const MAX_TARGET_BYTES: usize = 64 * 1024;
/// Maximum full-precision dimensions materialized by one runtime point read.
pub const ANN_V2_MAX_VECTOR_DIMENSIONS: usize = 65_536;
const UNIVERSE_ID_DOMAIN: &[u8] = b"contextdb.ann-v2.universe-id/v1\0";
const LEASE_ID_DOMAIN: &[u8] = b"contextdb.ann-v2.lease-id/v1\0";
const ROUTE_GENERATION_DOMAIN: &[u8] = b"contextdb.ann-v2.persistent-routes/v1\0";
static NEXT_LOCAL_ID: AtomicU64 = AtomicU64::new(1);
type VerifiedGenerationDigestsV2 = ([u8; 32], [u8; 32]);

const POLICY_DIGEST_DOMAIN: &[u8] = b"contextdb.ann-v2.policy/v1\0";
pub(crate) const REGISTRY_DIGEST_DOMAIN: &[u8] = b"contextdb.ann-v2.registry/v1\0";
pub(crate) const VECTOR_ROOT_DOMAIN: &[u8] = b"contextdb.ann-v2.vector-source/v1\0";
pub(crate) const ROUTE_ROOT_DOMAIN: &[u8] = b"contextdb.ann-v2.route-source/v1\0";

/// Live ANN-v2 runtime error with storage failures kept explicit.
#[derive(Debug, Error)]
pub enum AnnRuntimeErrorV2 {
    #[error(transparent)]
    Contract(#[from] AnnV2Error),
    #[error("ANN-v2 storage failure: {0}")]
    Storage(#[from] contextdb_storage::StorageError),
    #[error("ANN-v2 source failure: {0}")]
    Source(&'static str),
    #[error("ANN-v2 runtime invariant failed: {0}")]
    Invariant(&'static str),
    #[error("ANN-v2 build for generation {0} is already active")]
    BuildInProgress(u64),
    #[error("ANN-v2 generation {0} is not active")]
    GenerationUnavailable(u64),
    #[error("ANN-v2 query budget is invalid")]
    InvalidBudget,
}

/// Runtime result.
pub type AnnRuntimeResultV2<T> = Result<T, AnnRuntimeErrorV2>;

/// Routing-only record read before vector materialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnVectorRouteV2 {
    pub representation_id: RepresentationId,
    pub vector_space_id: VectorSpaceId,
    pub policy: IndexPolicy,
    pub valid_from: TimestampMicros,
    pub valid_until: Option<TimestampMicros>,
    pub projected_at: CommitSeq,
    pub tombstone_at: Option<CommitSeq>,
    pub membership_epoch: u64,
}

impl AnnVectorRouteV2 {
    fn visible_at(&self, snapshot: CommitSeq, valid_at: Option<TimestampMicros>) -> bool {
        self.projected_at <= snapshot
            && self.tombstone_at.is_none_or(|deleted| deleted > snapshot)
            && valid_at.is_none_or(|instant| {
                instant >= self.valid_from && self.valid_until.is_none_or(|until| instant < until)
            })
    }
}

/// Strictly ordered bounded routing page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnVectorRoutePageV2 {
    pub routes: Vec<AnnVectorRouteV2>,
    pub continuation: Option<RepresentationId>,
}

/// Full-precision source boundary used by build, exact oracle and reranking.
///
/// Implementations must keep `scan_routes_page` content-free. `read_vector`
/// must return at most `dimensions` finite values for the exact requested ID.
pub trait AnnVectorSourceV2 {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2>;
    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace>;
    fn scan_routes_page(
        &self,
        start_after: Option<RepresentationId>,
        max_entries: usize,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<AnnVectorRoutePageV2>;
    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>>;
    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode>;
}

/// Read-only adapter from the exact in-memory oracle to the live ANN-v2 runtime.
///
/// This bridge is useful for the M17 development runner and differential tests.
/// It does not turn the in-memory vector store into a production persistence
/// layer; the returned source seal authenticates the exact immutable snapshot.
#[derive(Debug)]
pub struct VectorIndexAnnSourceV2<'a> {
    index: &'a VectorIndex,
    seal: AnnSourceSealV2,
}

impl<'a> VectorIndexAnnSourceV2<'a> {
    pub fn new(
        index: &'a VectorIndex,
        vector_store_generation: u64,
        route_generation: u64,
    ) -> AnnRuntimeResultV2<Self> {
        if vector_store_generation == 0 || route_generation == 0 {
            return Err(AnnRuntimeErrorV2::Source("source generation is zero"));
        }
        let mut registry = blake3::Hasher::new();
        registry.update(REGISTRY_DIGEST_DOMAIN);
        for (id, space) in index.ann_v2_spaces().ann_v2_iter() {
            registry.update(id.as_uuid().as_bytes());
            let bytes = serde_json::to_vec(space)
                .map_err(|_| AnnRuntimeErrorV2::Source("vector space encode failed"))?;
            registry.update(&(bytes.len() as u64).to_be_bytes());
            registry.update(&bytes);
        }
        let registry_digest = *registry.finalize().as_bytes();

        let mut vectors = blake3::Hasher::new();
        vectors.update(VECTOR_ROOT_DOMAIN);
        vectors.update(&vector_store_generation.to_be_bytes());
        let mut routes = blake3::Hasher::new();
        routes.update(ROUTE_ROOT_DOMAIN);
        routes.update(&route_generation.to_be_bytes());
        for (id, record) in index.ann_v2_records() {
            vectors.update(id.as_uuid().as_bytes());
            vectors.update(record.vector_space_id.as_uuid().as_bytes());
            vectors.update(&(record.values.len() as u64).to_be_bytes());
            for value in &record.values {
                vectors.update(&value.to_bits().to_be_bytes());
            }
            let target = serde_json::to_vec(&record.target)
                .map_err(|_| AnnRuntimeErrorV2::Source("target encode failed"))?;
            vectors.update(&(target.len() as u64).to_be_bytes());
            vectors.update(&target);
            let route = route_from_record(record);
            let bytes = serde_json::to_vec(&route)
                .map_err(|_| AnnRuntimeErrorV2::Source("route encode failed"))?;
            routes.update(&(bytes.len() as u64).to_be_bytes());
            routes.update(&bytes);
        }
        let seal = AnnSourceSealV2 {
            vector_store_generation,
            vector_store_root: *vectors.finalize().as_bytes(),
            route_generation,
            route_root: *routes.finalize().as_bytes(),
            vector_space_registry_digest: registry_digest,
        };
        seal.validate()?;
        Ok(Self { index, seal })
    }
}

impl AnnVectorSourceV2 for VectorIndexAnnSourceV2<'_> {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2> {
        Ok(self.seal)
    }

    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace> {
        self.index
            .ann_v2_spaces()
            .get(id)
            .cloned()
            .map_err(|_| AnnRuntimeErrorV2::Source("unknown vector space"))
    }

    fn scan_routes_page(
        &self,
        start_after: Option<RepresentationId>,
        max_entries: usize,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<AnnVectorRoutePageV2> {
        if max_entries == 0
            || max_entries > ANN_V2_MAX_PAGE_ENTRIES
            || max_bytes == 0
            || max_bytes > ANN_V2_MAX_PAGE_BYTES
        {
            return Err(AnnRuntimeErrorV2::Source("route page limit is invalid"));
        }
        let matching = self
            .index
            .ann_v2_records()
            .iter()
            .filter(|(id, _)| start_after.is_none_or(|cursor| **id > cursor));
        let mut routes = Vec::new();
        let mut used_bytes = 0_usize;
        let mut has_more = false;
        for (_, record) in matching {
            if routes.len() == max_entries {
                has_more = true;
                break;
            }
            let route = route_from_record(record);
            let route_bytes = serde_json::to_vec(&route)
                .map_err(|_| AnnRuntimeErrorV2::Source("route encode failed"))?
                .len();
            if route_bytes > max_bytes && routes.is_empty() {
                return Err(AnnRuntimeErrorV2::Source(
                    "one route exceeds the bounded page byte limit",
                ));
            }
            if used_bytes
                .checked_add(route_bytes)
                .is_none_or(|next| next > max_bytes)
            {
                has_more = true;
                break;
            }
            used_bytes += route_bytes;
            routes.push(route);
        }
        let continuation = has_more
            .then(|| routes.last().map(|route| route.representation_id))
            .flatten();
        Ok(AnnVectorRoutePageV2 {
            routes,
            continuation,
        })
    }

    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>> {
        if dimensions == 0 || dimensions > ANN_V2_MAX_VECTOR_DIMENSIONS {
            return Err(AnnRuntimeErrorV2::Source(
                "vector dimensions exceed the point-read limit",
            ));
        }
        let record = self
            .index
            .ann_v2_records()
            .get(&id)
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector representation"))?;
        if record.values.len() != dimensions {
            return Err(AnnRuntimeErrorV2::Source("vector dimension mismatch"));
        }
        Ok(record.values.clone())
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        if max_bytes == 0 || max_bytes > MAX_TARGET_BYTES {
            return Err(AnnRuntimeErrorV2::Source("target byte limit is invalid"));
        }
        let target = self
            .index
            .ann_v2_records()
            .get(&id)
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector representation"))?
            .target
            .clone();
        let required = serde_json::to_vec(&target)
            .map_err(|_| AnnRuntimeErrorV2::Source("target encode failed"))?
            .len();
        if required > max_bytes {
            return Err(AnnRuntimeErrorV2::Source(
                "target exceeds the point-read byte limit",
            ));
        }
        Ok(target)
    }
}

pub(crate) fn route_from_record(record: &VectorRecord) -> AnnVectorRouteV2 {
    AnnVectorRouteV2 {
        representation_id: record.id,
        vector_space_id: record.vector_space_id,
        policy: record.policy.clone(),
        valid_from: record.valid_time.start,
        valid_until: record.valid_time.end,
        projected_at: record.projected_at,
        tombstone_at: record.tombstone_at,
        membership_epoch: 1,
    }
}

/// Handle to a storage-backed authorized route universe and generation lease.
#[derive(Debug, Eq, PartialEq)]
pub struct AnnAuthorizedUniverseV2 {
    snapshot: CommitSeq,
    generation: u64,
    universe_id: [u8; 32],
    lease_id: [u8; 32],
    route_count: u64,
}

impl AnnAuthorizedUniverseV2 {
    #[must_use]
    pub const fn snapshot(&self) -> CommitSeq {
        self.snapshot
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn authorized_count(&self) -> u64 {
        self.route_count
    }
}

/// Report for one immutable delta representation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnDeltaPublicationV2 {
    pub representation_id: RepresentationId,
    pub overlay_epoch: u64,
    pub storage_sequence: u64,
    pub idempotent: bool,
}

/// Report for one current-use tombstone publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnTombstonePublicationV2 {
    pub representation_id: RepresentationId,
    pub overlay_epoch: u64,
    pub storage_sequence: u64,
    pub idempotent: bool,
}

/// Bounded generation-retention outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnRetentionReportV2 {
    pub active_generation: u64,
    pub retained_generations: u64,
    pub leased_generations: u64,
    pub pruned_generations: u64,
    pub deleted_objects: u64,
    pub deleted_routes: u64,
}

/// Explicit finite query budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnQueryBudgetV2 {
    pub max_ann_visits: usize,
    pub ef_search: usize,
    pub max_exact_scores: usize,
}

impl AnnQueryBudgetV2 {
    fn validate(self) -> AnnRuntimeResultV2<()> {
        if self.max_ann_visits == 0
            || self.max_ann_visits > MAX_QUERY_VISITS
            || self.ef_search == 0
            || self.ef_search > self.max_ann_visits
            || self.max_exact_scores == 0
            || self.max_exact_scores > MAX_QUERY_EXACT_SCORES
        {
            return Err(AnnRuntimeErrorV2::InvalidBudget);
        }
        Ok(())
    }
}

/// Query accepted only after authorization created an opaque universe.
#[derive(Clone, Copy, Debug)]
pub struct AnnQueryV2<'a> {
    pub vector_space_id: VectorSpaceId,
    pub values: &'a [f32],
    pub valid_at: Option<TimestampMicros>,
    pub limit: usize,
}

/// Privacy-safe runtime counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnQueryTraceV2 {
    pub generation: u64,
    pub watermark: CommitSeq,
    pub ann_node_reads: u64,
    pub authorized_vector_reads: u64,
    pub exact_fallback_scores: u64,
    pub returned: u64,
}

/// Full-precision reranked ANN response.
#[derive(Clone, Debug, PartialEq)]
pub struct AnnQueryResultV2 {
    pub hits: Vec<AnnHitV2>,
    pub trace: AnnQueryTraceV2,
}

/// One exact full-precision reranked result.
#[derive(Clone, Debug, PartialEq)]
pub struct AnnHitV2 {
    pub representation_id: RepresentationId,
    pub target: LineageNode,
    pub score: f32,
}

/// Outcome of one fully verified generation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnPublicationV2 {
    pub generation: u64,
    pub storage_sequence: u64,
    pub verification: AnnGenerationVerificationV2,
}

/// Recovery result for an interrupted inactive-generation build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnRecoveryV2 {
    pub active_generation: u64,
    pub abandoned_generation: Option<u64>,
    pub objects_deleted: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildFenceV2 {
    format_version: u16,
    generation: u64,
    source: AnnSourceSealWireV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveRotationV2 {
    format_version: u16,
    active_generation: u64,
    previous_generation: Option<u64>,
    manifest_digest: [u8; 32],
    route_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteGenerationManifestV2 {
    format_version: u16,
    generation: u64,
    route_count: u64,
    route_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UniverseRouteOriginV2 {
    Base,
    Delta,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UniverseRouteRowV2 {
    route: AnnVectorRouteV2,
    partition: [u8; 32],
    origin: UniverseRouteOriginV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UniversePartitionV2 {
    partition: [u8; 32],
    base_total: u64,
    authorized_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UniverseHeaderV2 {
    format_version: u16,
    universe_id: [u8; 32],
    generation: u64,
    snapshot: CommitSeq,
    overlay_epoch: u64,
    route_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UniverseFenceV2 {
    format_version: u16,
    universe_id: [u8; 32],
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PruneFenceV2 {
    format_version: u16,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationLeaseV2 {
    format_version: u16,
    lease_id: [u8; 32],
    universe_id: [u8; 32],
    generation: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayDeltaV2 {
    format_version: u16,
    record: VectorRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayTombstoneV2 {
    format_version: u16,
    representation_id: RepresentationId,
    applied_at: CommitSeq,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnSourceSealWireV2 {
    vector_store_generation: u64,
    vector_store_root: [u8; 32],
    route_generation: u64,
    route_root: [u8; 32],
    vector_space_registry_digest: [u8; 32],
}

impl From<AnnSourceSealV2> for AnnSourceSealWireV2 {
    fn from(value: AnnSourceSealV2) -> Self {
        Self {
            vector_store_generation: value.vector_store_generation,
            vector_store_root: value.vector_store_root,
            route_generation: value.route_generation,
            route_root: value.route_root,
            vector_space_registry_digest: value.vector_space_registry_digest,
        }
    }
}

impl From<AnnSourceSealWireV2> for AnnSourceSealV2 {
    fn from(value: AnnSourceSealWireV2) -> Self {
        Self {
            vector_store_generation: value.vector_store_generation,
            vector_store_root: value.vector_store_root,
            route_generation: value.route_generation,
            route_root: value.route_root,
            vector_space_registry_digest: value.vector_space_registry_digest,
        }
    }
}

/// Storage-backed ANN-v2 graph runtime.
pub struct PersistentAnnV2<E: StorageEngine> {
    engine: E,
    objects: Keyspace,
    control: Keyspace,
    build: Keyspace,
    routes: Keyspace,
    overlay: Keyspace,
    universes: Keyspace,
    leases: Keyspace,
    maintenance: Mutex<()>,
    verified_generations: Mutex<BTreeMap<u64, VerifiedGenerationDigestsV2>>,
}

impl<E: StorageEngine> std::fmt::Debug for PersistentAnnV2<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistentAnnV2")
            .finish_non_exhaustive()
    }
}

impl<E: StorageEngine> PersistentAnnV2<E> {
    /// Opens the portable runtime keyspaces without adopting staged state.
    pub fn open(engine: E) -> AnnRuntimeResultV2<Self> {
        Ok(Self {
            engine,
            objects: Keyspace::new(OBJECT_KEYSPACE)?,
            control: Keyspace::new(CONTROL_KEYSPACE)?,
            build: Keyspace::new(BUILD_KEYSPACE)?,
            routes: Keyspace::new(ROUTE_KEYSPACE)?,
            overlay: Keyspace::new(OVERLAY_KEYSPACE)?,
            universes: Keyspace::new(UNIVERSE_KEYSPACE)?,
            leases: Keyspace::new(LEASE_KEYSPACE)?,
            maintenance: Mutex::new(()),
            verified_generations: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the backend while preserving all bytes.
    pub fn into_engine(self) -> E {
        self.engine
    }

    /// Reads and validates the active control manifest, if one is published.
    pub fn active_manifest(&self) -> AnnRuntimeResultV2<Option<AnnGenerationManifestV2>> {
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        read_manifest(&read, &self.control, ACTIVE_MANIFEST_KEY)
    }

    /// Re-verifies every active object through bounded pages after reopen or
    /// suspected media corruption. A missing active generation returns `None`.
    pub fn verify_active(&self) -> AnnRuntimeResultV2<Option<AnnGenerationVerificationV2>> {
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let Some(manifest) = read_manifest(&read, &self.control, ACTIVE_MANIFEST_KEY)? else {
            self.verified_generations
                .lock()
                .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?
                .clear();
            return Ok(None);
        };
        let activation = read_active_rotation(&read, &self.control)?.ok_or(
            AnnRuntimeErrorV2::Invariant("active rotation record is absent"),
        )?;
        if activation.active_generation != manifest.generation
            || activation.manifest_digest != manifest.manifest_digest
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "active rotation record disagrees with its manifest",
            ));
        }
        if read_manifest(&read, &self.control, &manifest_key(manifest.generation))?.as_ref()
            != Some(&manifest)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "active and archived manifests diverge",
            ));
        }
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        let verification = verify_runtime_generation(&reader, &manifest)?;
        let route_manifest = verify_route_generation(
            &read,
            &self.control,
            &self.routes,
            manifest.generation,
            manifest.node_count,
        )?;
        if activation.route_digest != route_manifest.route_digest {
            return Err(AnnRuntimeErrorV2::Invariant(
                "active rotation route digest diverges",
            ));
        }
        verify_overlay_state(&read, &self.overlay)?;
        self.verified_generations
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?
            .insert(
                manifest.generation,
                (manifest.manifest_digest, route_manifest.route_digest),
            );
        Ok(Some(verification))
    }

    /// Builds, verifies and atomically publishes one inactive generation.
    pub fn rebuild_and_publish<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        watermark: CommitSeq,
        build: AnnBuildParametersV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnPublicationV2> {
        build.validate()?;
        let source_seal = source.source_seal()?;
        source_seal.validate()?;
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let active = self.active_manifest()?;
        if let Some(active) = &active {
            self.ensure_verified(active)?;
        }
        if generation == 0
            || active
                .as_ref()
                .is_some_and(|manifest| generation <= manifest.generation)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "inactive generation does not advance the active generation",
            ));
        }
        self.acquire_fence(generation, source_seal, durability)?;
        let result = (|| {
            self.delete_generation(generation, durability)?;
            self.delete_build_generation(generation, durability)?;
            self.delete_route_generation(generation, durability)?;
            self.delete_route_manifest(generation, durability)?;
            self.stage_routes(source, generation, watermark, durability)?;
            let manifest = self.build_generation(
                source,
                generation,
                watermark,
                source_seal,
                build,
                durability,
            )?;
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let reader = StorageAnnReaderV2 {
                snapshot: &read,
                keyspace: &self.objects,
            };
            let verification = verify_runtime_generation(&reader, &manifest)?;
            drop(read);
            self.delete_build_generation(generation, durability)?;
            let storage_sequence =
                self.publish_manifest(active.as_ref(), source_seal, &manifest, durability)?;
            let route_manifest = read_route_manifest_for_generation(
                &self.engine.begin_read(SnapshotSelector::Latest)?,
                &self.control,
                generation,
            )?
            .ok_or(AnnRuntimeErrorV2::Invariant(
                "published route manifest is absent",
            ))?;
            self.verified_generations
                .lock()
                .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?
                .insert(
                    manifest.generation,
                    (manifest.manifest_digest, route_manifest.route_digest),
                );
            Ok(AnnPublicationV2 {
                generation,
                storage_sequence,
                verification,
            })
        })();
        if result.is_err() {
            // Keep the fence durable on failure. Recovery can then distinguish
            // an abandoned generation from an independently injected key range.
        }
        result
    }

    /// Removes only the fenced, unpublished generation after a crash/reopen.
    pub fn recover(&self, durability: Durability) -> AnnRuntimeResultV2<AnnRecoveryV2> {
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let mut active = read_manifest(&read, &self.control, ACTIVE_MANIFEST_KEY)?;
        let activation = read_active_rotation(&read, &self.control)?;
        let fence = read_fence(&read, &self.control)?;
        let universe_fence = read_universe_fence(&read, &self.control)?;
        let prune_fence = read_prune_fence(&read, &self.control)?;
        drop(read);

        if let Some(universe_fence) = universe_fence {
            self.delete_universe_rows(universe_fence.universe_id, durability)?;
            let mut write = self.engine.begin_write()?;
            if read_universe_fence(&write, &self.control)?.as_ref() != Some(&universe_fence) {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "universe fence changed during recovery",
                ));
            }
            write.delete(&self.control, UNIVERSE_FENCE_KEY.to_vec())?;
            write.commit(durability)?;
        }

        match (active.as_ref(), activation) {
            (None, Some(rotation)) => {
                let read = self.engine.begin_read(SnapshotSelector::Latest)?;
                let archived = read_manifest(
                    &read,
                    &self.control,
                    &manifest_key(rotation.active_generation),
                )?
                .ok_or(AnnRuntimeErrorV2::Invariant(
                    "lost activation has no archived manifest",
                ))?;
                if archived.manifest_digest != rotation.manifest_digest {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "lost activation archive digest diverges",
                    ));
                }
                let reader = StorageAnnReaderV2 {
                    snapshot: &read,
                    keyspace: &self.objects,
                };
                verify_runtime_generation(&reader, &archived)?;
                let routes = verify_route_generation(
                    &read,
                    &self.control,
                    &self.routes,
                    archived.generation,
                    archived.node_count,
                )?;
                if routes.route_digest != rotation.route_digest {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "lost activation route digest diverges",
                    ));
                }
                drop(read);
                let mut write = self.engine.begin_write()?;
                if read_manifest(&write, &self.control, ACTIVE_MANIFEST_KEY)?.is_some()
                    || read_active_rotation(&write, &self.control)? != Some(rotation)
                {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "lost activation state changed during recovery",
                    ));
                }
                write.put(
                    &self.control,
                    ACTIVE_MANIFEST_KEY.to_vec(),
                    archived.encode_json()?,
                )?;
                write.commit(durability)?;
                active = Some(archived);
            }
            (Some(manifest), Some(rotation))
                if rotation.active_generation == manifest.generation
                    && rotation.manifest_digest == manifest.manifest_digest => {}
            (None, None) => {}
            _ => {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "active manifest and rotation record diverge",
                ));
            }
        }
        if let Some(prune_fence) = prune_fence {
            if active
                .as_ref()
                .is_some_and(|manifest| manifest.generation == prune_fence.generation)
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "prune fence targets the active generation",
                ));
            }
            let lease_read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let lease_page = lease_read.scan_prefix_page(
                &self.leases,
                ScanPageRequest {
                    prefix: &lease_generation_prefix(prune_fence.generation),
                    start_after: None,
                    max_entries: 1,
                    max_bytes: CLEAN_PAGE_BYTES,
                },
            )?;
            if !lease_page.entries.is_empty() {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "prune fence targets a leased generation",
                ));
            }
            drop(lease_read);
            self.finish_prune_generation(prune_fence, durability)?;
        }
        let active_generation = active.as_ref().map_or(0, |manifest| manifest.generation);
        let Some(fence) = fence else {
            self.verify_active()?;
            return Ok(AnnRecoveryV2 {
                active_generation,
                abandoned_generation: None,
                objects_deleted: 0,
            });
        };
        if active_generation == fence.generation {
            return Err(AnnRuntimeErrorV2::Invariant(
                "active generation is still protected by a build fence",
            ));
        }
        let objects_deleted = self.delete_generation(fence.generation, durability)?;
        self.delete_build_generation(fence.generation, durability)?;
        self.delete_route_generation(fence.generation, durability)?;
        self.delete_route_manifest(fence.generation, durability)?;
        let mut transaction = self.engine.begin_write()?;
        let actual = read_fence(&transaction, &self.control)?;
        if actual.as_ref() != Some(&fence) {
            return Err(AnnRuntimeErrorV2::Invariant(
                "build fence changed during recovery",
            ));
        }
        transaction.delete(&self.control, BUILD_FENCE_KEY.to_vec())?;
        transaction.commit(durability)?;
        self.verify_active()?;
        Ok(AnnRecoveryV2 {
            active_generation,
            abandoned_generation: Some(fence.generation),
            objects_deleted,
        })
    }

    /// Creates an opaque policy universe before query/vector materialization.
    pub fn authorize<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        principal: &IndexPrincipal,
        snapshot: CommitSeq,
    ) -> AnnRuntimeResultV2<AnnAuthorizedUniverseV2> {
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let manifest = self
            .active_manifest()?
            .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(0))?;
        self.ensure_verified(&manifest)?;
        if manifest.watermark > snapshot || source.source_seal()? != manifest.source {
            return Err(AnnRuntimeErrorV2::Invariant(
                "active generation source or watermark is stale",
            ));
        }
        let sequence = self.engine.head_sequence()?;
        let local = NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed);
        let universe_id = runtime_id(
            UNIVERSE_ID_DOMAIN,
            sequence,
            manifest.generation,
            snapshot,
            local,
        );
        let lease_id = runtime_id(
            LEASE_ID_DOMAIN,
            sequence,
            manifest.generation,
            snapshot,
            local,
        );
        let fence = UniverseFenceV2 {
            format_version: RUNTIME_FORMAT_VERSION,
            universe_id,
            generation: manifest.generation,
        };
        let mut fence_write = self.engine.begin_write()?;
        if read_universe_fence(&fence_write, &self.control)?.is_some() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "an interrupted authorization universe requires recovery",
            ));
        }
        fence_write.put(
            &self.control,
            UNIVERSE_FENCE_KEY.to_vec(),
            serde_json::to_vec(&fence)
                .map_err(|_| AnnRuntimeErrorV2::Invariant("universe fence encode failed"))?,
        )?;
        fence_write.commit(Durability::Sync)?;

        let result = (|| {
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let overlay_epoch = read_overlay_epoch(&read, &self.overlay)?;
            let route_prefix = persistent_route_generation_prefix(manifest.generation);
            let mut cursor = None;
            let mut current_partition = None;
            let mut base_total = 0_u64;
            let mut authorized_base = 0_u64;
            let mut route_count = 0_u64;
            loop {
                let page = read.scan_prefix_page(
                    &self.routes,
                    ScanPageRequest {
                        prefix: &route_prefix,
                        start_after: cursor.as_deref(),
                        max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                        max_bytes: ANN_V2_MAX_PAGE_BYTES,
                    },
                )?;
                if page.continuation.is_some() && page.entries.is_empty() {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorization route page made no progress",
                    ));
                }
                let mut write = self.engine.begin_write()?;
                for entry in &page.entries {
                    let (generation, partition, id) = parse_persistent_route_key(&entry.key)?;
                    if generation != manifest.generation {
                        return Err(AnnRuntimeErrorV2::Invariant(
                            "authorization route generation diverged",
                        ));
                    }
                    if current_partition.is_some_and(|current| current != partition) {
                        let completed = current_partition.ok_or(AnnRuntimeErrorV2::Invariant(
                            "authorization partition state disappeared",
                        ))?;
                        put_universe_partition(
                            &mut write,
                            &self.universes,
                            universe_id,
                            completed,
                            base_total,
                            authorized_base,
                        )?;
                        base_total = 0;
                        authorized_base = 0;
                    }
                    current_partition = Some(partition);
                    base_total = checked_add("authorized base routes", base_total, 1)?;
                    let route: AnnVectorRouteV2 = decode_canonical_json(
                        &entry.value,
                        "persistent authorization route is invalid",
                    )?;
                    if route.representation_id != id {
                        return Err(AnnRuntimeErrorV2::Invariant(
                            "persistent authorization route ID diverges",
                        ));
                    }
                    if ann_v2_partition_key(
                        route.vector_space_id,
                        canonical_policy_digest(&route.policy)?,
                    )? != partition
                    {
                        return Err(AnnRuntimeErrorV2::Invariant(
                            "persistent authorization route partition diverges",
                        ));
                    }
                    let tombstoned = read
                        .get(&self.overlay, &overlay_tombstone_key(id))?
                        .is_some();
                    if !tombstoned
                        && route.visible_at(snapshot, None)
                        && route.policy.authorizes(principal, snapshot)
                    {
                        put_universe_route(
                            &mut write,
                            &self.universes,
                            universe_id,
                            UniverseRouteRowV2 {
                                route,
                                partition,
                                origin: UniverseRouteOriginV2::Base,
                            },
                        )?;
                        authorized_base =
                            checked_add("authorized base routes", authorized_base, 1)?;
                        route_count = checked_add("authorized universe routes", route_count, 1)?;
                    }
                }
                write.commit(Durability::Sync)?;
                let Some(next) = page.continuation else {
                    break;
                };
                if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorization route cursor did not advance",
                    ));
                }
                cursor = Some(next);
            }
            if let Some(partition) = current_partition {
                let mut write = self.engine.begin_write()?;
                put_universe_partition(
                    &mut write,
                    &self.universes,
                    universe_id,
                    partition,
                    base_total,
                    authorized_base,
                )?;
                write.commit(Durability::Sync)?;
            }

            let delta_prefix = overlay_delta_partition_prefix(None);
            let mut delta_cursor = None;
            loop {
                let page = read.scan_prefix_page(
                    &self.overlay,
                    ScanPageRequest {
                        prefix: &delta_prefix,
                        start_after: delta_cursor.as_deref(),
                        max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                        max_bytes: ANN_V2_MAX_PAGE_BYTES,
                    },
                )?;
                if page.continuation.is_some() && page.entries.is_empty() {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorization delta page made no progress",
                    ));
                }
                let mut write = self.engine.begin_write()?;
                for entry in &page.entries {
                    let (partition, id) = parse_overlay_partition_key(&entry.key)?;
                    let route: AnnVectorRouteV2 = decode_canonical_json(
                        &entry.value,
                        "delta authorization route is invalid",
                    )?;
                    if route.representation_id != id {
                        return Err(AnnRuntimeErrorV2::Invariant(
                            "delta authorization route ID diverges",
                        ));
                    }
                    if ann_v2_partition_key(
                        route.vector_space_id,
                        canonical_policy_digest(&route.policy)?,
                    )? != partition
                    {
                        return Err(AnnRuntimeErrorV2::Invariant(
                            "delta authorization route partition diverges",
                        ));
                    }
                    let incorporated = read
                        .get(
                            &self.routes,
                            &persistent_route_id_key(manifest.generation, id),
                        )?
                        .is_some();
                    let tombstoned = read
                        .get(&self.overlay, &overlay_tombstone_key(id))?
                        .is_some();
                    if !incorporated
                        && !tombstoned
                        && route.visible_at(snapshot, None)
                        && route.policy.authorizes(principal, snapshot)
                    {
                        put_universe_route(
                            &mut write,
                            &self.universes,
                            universe_id,
                            UniverseRouteRowV2 {
                                route,
                                partition,
                                origin: UniverseRouteOriginV2::Delta,
                            },
                        )?;
                        route_count = checked_add("authorized universe routes", route_count, 1)?;
                    }
                }
                write.commit(Durability::Sync)?;
                let Some(next) = page.continuation else {
                    break;
                };
                if delta_cursor
                    .as_ref()
                    .is_some_and(|previous| next <= *previous)
                {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorization delta cursor did not advance",
                    ));
                }
                delta_cursor = Some(next);
            }
            if route_count > ANN_V2_MAX_NODES {
                return Err(AnnV2Error::ResourceExhausted {
                    resource: "authorized_routes",
                    limit: ANN_V2_MAX_NODES,
                    required: route_count,
                }
                .into());
            }
            drop(read);

            let header = UniverseHeaderV2 {
                format_version: RUNTIME_FORMAT_VERSION,
                universe_id,
                generation: manifest.generation,
                snapshot,
                overlay_epoch,
                route_count,
            };
            let lease = GenerationLeaseV2 {
                format_version: RUNTIME_FORMAT_VERSION,
                lease_id,
                universe_id,
                generation: manifest.generation,
            };
            let mut write = self.engine.begin_write()?;
            if read_universe_fence(&write, &self.control)?.as_ref() != Some(&fence)
                || read_manifest(&write, &self.control, ACTIVE_MANIFEST_KEY)?.as_ref()
                    != Some(&manifest)
                || source.source_seal()? != manifest.source
                || read_overlay_epoch(&write, &self.overlay)? != overlay_epoch
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorization inputs changed before universe activation",
                ));
            }
            write.put(
                &self.universes,
                universe_header_key(universe_id),
                serde_json::to_vec(&header)
                    .map_err(|_| AnnRuntimeErrorV2::Invariant("universe header encode failed"))?,
            )?;
            write.put(
                &self.leases,
                lease_key(manifest.generation, lease_id),
                serde_json::to_vec(&lease)
                    .map_err(|_| AnnRuntimeErrorV2::Invariant("lease encode failed"))?,
            )?;
            write.delete(&self.control, UNIVERSE_FENCE_KEY.to_vec())?;
            write.commit(Durability::Sync)?;
            Ok(AnnAuthorizedUniverseV2 {
                snapshot,
                generation: manifest.generation,
                universe_id,
                lease_id,
                route_count,
            })
        })();
        // The fence deliberately remains durable on error; recovery reclaims
        // only this unpublished universe and never changes the active ANN.
        result
    }

    /// Searches only fully authorized partitions, then full-precision reranks.
    /// Partial partitions use a bounded exact authorized fallback.
    pub fn search<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        universe: &AnnAuthorizedUniverseV2,
        query: AnnQueryV2<'_>,
        budget: AnnQueryBudgetV2,
    ) -> AnnRuntimeResultV2<AnnQueryResultV2> {
        budget.validate()?;
        if query.limit == 0 {
            return Err(AnnRuntimeErrorV2::InvalidBudget);
        }
        let control_read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let header = read_universe_header(&control_read, &self.universes, universe.universe_id)?
            .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(
                universe.generation,
            ))?;
        let lease = read_generation_lease(
            &control_read,
            &self.leases,
            universe.generation,
            universe.lease_id,
        )?
        .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(
            universe.generation,
        ))?;
        if header.generation != universe.generation
            || header.snapshot != universe.snapshot
            || header.route_count != universe.route_count
            || lease.universe_id != universe.universe_id
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "authorized universe handle diverges from persistent state",
            ));
        }
        let manifest = read_manifest(
            &control_read,
            &self.control,
            &manifest_key(universe.generation),
        )?
        .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(
            universe.generation,
        ))?;
        if manifest.watermark > universe.snapshot || source.source_seal()? != manifest.source {
            return Err(AnnRuntimeErrorV2::GenerationUnavailable(
                universe.generation,
            ));
        }
        drop(control_read);
        self.ensure_generation_verified(&manifest)?;
        let space = source.vector_space(query.vector_space_id)?;
        validate_values(&space, query.values)
            .map_err(|_| AnnRuntimeErrorV2::Source("invalid query vector"))?;

        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let overlay_epoch = read_overlay_epoch(&read, &self.overlay)?;
        if header.overlay_epoch > overlay_epoch {
            return Err(AnnRuntimeErrorV2::Invariant(
                "authorized universe overlay epoch is from the future",
            ));
        }
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        let universe_reader = PersistentUniverseReaderV2 {
            snapshot: &read,
            universes: &self.universes,
            overlay: &self.overlay,
            universe_id: universe.universe_id,
        };
        let mut candidates = BTreeSet::new();
        let mut ann_reads = 0_usize;
        let mut ann_vector_reads = 0_u64;
        let mut exact_scores = 0_usize;
        let mut traversed_partitions = BTreeSet::new();

        let partition_prefix = universe_partition_prefix(universe.universe_id);
        let mut partition_cursor = None;
        loop {
            let page = read.scan_prefix_page(
                &self.universes,
                ScanPageRequest {
                    prefix: &partition_prefix,
                    start_after: partition_cursor.as_deref(),
                    max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                    max_bytes: ANN_V2_MAX_PAGE_BYTES,
                },
            )?;
            for entry in &page.entries {
                let (status_universe, status_partition) = parse_universe_partition_key(&entry.key)?;
                let status: UniversePartitionV2 =
                    decode_canonical_json(&entry.value, "authorized partition status is invalid")?;
                if status_universe != universe.universe_id
                    || status.partition != status_partition
                    || status.authorized_base > status.base_total
                    || status.base_total > ANN_V2_MAX_NODES
                {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorized partition key and status diverge",
                    ));
                }
                if status.base_total != status.authorized_base {
                    continue;
                }
                let key =
                    AnnObjectKeyV2::partition_manifest(manifest.generation, status.partition)?;
                let object = reader
                    .get_bounded(AnnObjectReadRequestV2 {
                        key: &key,
                        max_bytes: crate::ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
                    })?
                    .into_object()
                    .ok_or(AnnRuntimeErrorV2::Invariant(
                        "authorized partition manifest is absent",
                    ))?;
                let partition = AnnPartitionManifestV2::decode_json(object.value())?;
                if partition.partition_key != status.partition
                    || partition.generation != manifest.generation
                    || partition.vector_space_id != query.vector_space_id
                {
                    continue;
                }
                let eligible = universe_reader.count_visible_base_routes(
                    status.partition,
                    universe.snapshot,
                    query.valid_at,
                )?;
                if eligible != partition.node_count {
                    continue;
                }
                let remaining = budget.max_ann_visits.saturating_sub(ann_reads);
                if remaining == 0 {
                    break;
                }
                let (ids, reads, vector_reads) = traverse_persistent_partition(
                    &reader,
                    source,
                    &partition,
                    &space,
                    query.values,
                    &universe_reader,
                    remaining,
                    budget.ef_search,
                )?;
                ann_reads += reads;
                ann_vector_reads = ann_vector_reads.saturating_add(vector_reads);
                candidates.extend(ids);
                traversed_partitions.insert(partition.partition_key);
            }
            let Some(next) = page.continuation else {
                break;
            };
            if partition_cursor
                .as_ref()
                .is_some_and(|previous| next <= *previous)
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized partition cursor did not advance",
                ));
            }
            partition_cursor = Some(next);
        }

        let route_prefix = universe_route_id_prefix(universe.universe_id);
        let mut route_cursor = None;
        let mut scanned_routes = 0_u64;
        loop {
            let page = read.scan_prefix_page(
                &self.universes,
                ScanPageRequest {
                    prefix: &route_prefix,
                    start_after: route_cursor.as_deref(),
                    max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                    max_bytes: ANN_V2_MAX_PAGE_BYTES,
                },
            )?;
            for entry in &page.entries {
                let (route_universe, route_id) = parse_universe_route_id_key(&entry.key)?;
                let row: UniverseRouteRowV2 =
                    decode_canonical_json(&entry.value, "authorized route is invalid")?;
                validate_universe_route_row(&row, route_id)?;
                let partition_copy: Option<UniverseRouteRowV2> = read_canonical_json(
                    &read,
                    &self.universes,
                    &universe_route_partition_key(universe.universe_id, row.partition, route_id),
                    "authorized partition route is invalid",
                )?;
                if route_universe != universe.universe_id || partition_copy.as_ref() != Some(&row) {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorized universe route indexes diverge",
                    ));
                }
                scanned_routes = checked_add("authorized universe route scan", scanned_routes, 1)?;
                if scanned_routes > header.route_count {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorized universe contains extraneous routes",
                    ));
                }
                if universe_reader.is_tombstoned(row.route.representation_id)?
                    || row.route.vector_space_id != query.vector_space_id
                    || !row.route.visible_at(universe.snapshot, query.valid_at)
                    || (row.origin == UniverseRouteOriginV2::Base
                        && traversed_partitions.contains(&row.partition))
                {
                    continue;
                }
                if exact_scores == budget.max_exact_scores {
                    return Err(AnnRuntimeErrorV2::InvalidBudget);
                }
                exact_scores += 1;
                candidates.insert(row.route.representation_id);
            }
            let Some(next) = page.continuation else {
                break;
            };
            if route_cursor
                .as_ref()
                .is_some_and(|previous| next <= *previous)
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized route cursor did not advance",
                ));
            }
            route_cursor = Some(next);
        }
        if scanned_routes != header.route_count {
            return Err(AnnRuntimeErrorV2::Invariant(
                "authorized universe route count is incomplete",
            ));
        }

        let mut ranked = Vec::new();
        let mut rerank_reads = 0_u64;
        for id in candidates {
            let Some(row) = universe_reader.route(id)? else {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "ANN traversal produced an unauthorized representation",
                ));
            };
            if !row.route.visible_at(universe.snapshot, query.valid_at) {
                continue;
            }
            let values = read_authorized_vector(
                source,
                &read,
                &self.overlay,
                &row,
                bounded_dimensions(&space)?,
            )?;
            rerank_reads = rerank_reads.saturating_add(1);
            validate_values(&space, &values)
                .map_err(|_| AnnRuntimeErrorV2::Source("stored vector is invalid"))?;
            ranked.push((
                score(space.metric, query.values, &values)
                    .map_err(|_| AnnRuntimeErrorV2::Source("vector score is invalid"))?,
                id,
            ));
        }
        ranked.sort_by(|left, right| {
            right
                .0
                .total_cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
        });
        ranked.truncate(query.limit);
        let mut hits = Vec::with_capacity(ranked.len());
        for (score, representation_id) in ranked {
            let row =
                universe_reader
                    .route(representation_id)?
                    .ok_or(AnnRuntimeErrorV2::Invariant(
                        "ranked route disappeared from its universe",
                    ))?;
            hits.push(AnnHitV2 {
                representation_id,
                target: read_authorized_target(
                    source,
                    &read,
                    &self.overlay,
                    &row,
                    MAX_TARGET_BYTES,
                )?,
                score,
            });
        }
        let latest = self.engine.begin_read(SnapshotSelector::Latest)?;
        if read_overlay_epoch(&latest, &self.overlay)? != overlay_epoch {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay changed during query; retry authorization",
            ));
        }
        Ok(AnnQueryResultV2 {
            trace: AnnQueryTraceV2 {
                generation: manifest.generation,
                watermark: manifest.watermark,
                ann_node_reads: u64::try_from(ann_reads).unwrap_or(u64::MAX),
                authorized_vector_reads: ann_vector_reads.saturating_add(rerank_reads),
                exact_fallback_scores: u64::try_from(exact_scores).unwrap_or(u64::MAX),
                returned: u64::try_from(hits.len()).unwrap_or(u64::MAX),
            },
            hits,
        })
    }

    /// Publishes one immutable post-generation vector into the exact delta
    /// overlay. Authorization sees only its routing copy; vector and target
    /// bytes remain behind point reads until after policy admission.
    pub fn publish_delta<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        record: VectorRecord,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnDeltaPublicationV2> {
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let manifest = self
            .active_manifest()?
            .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(0))?;
        self.ensure_verified(&manifest)?;
        if source.source_seal()? != manifest.source
            || record.projected_at <= manifest.watermark
            || record.tombstone_at.is_some()
        {
            return Err(AnnRuntimeErrorV2::Source(
                "delta source, watermark, or tombstone is invalid",
            ));
        }
        record
            .policy
            .validate()
            .map_err(|_| AnnRuntimeErrorV2::Source("delta policy is invalid"))?;
        record
            .target
            .validate()
            .map_err(|_| AnnRuntimeErrorV2::Source("delta target is invalid"))?;
        let space = source.vector_space(record.vector_space_id)?;
        validate_values(&space, &record.values)
            .map_err(|_| AnnRuntimeErrorV2::Source("delta vector is invalid"))?;
        let route = route_from_record(&record);
        validate_route(&route)?;
        let partition = ann_v2_partition_key(
            route.vector_space_id,
            canonical_policy_digest(&route.policy)?,
        )?;
        let delta = OverlayDeltaV2 {
            format_version: RUNTIME_FORMAT_VERSION,
            record,
        };
        let bytes = crate::ann_v2_source::canonical_encode_bounded(
            &delta,
            ANN_V2_MAX_PAGE_BYTES,
            "delta record exceeds its bounded encoding",
        )?;
        let mut write = self.engine.begin_write()?;
        if let Some(existing) = write.get(
            &self.overlay,
            &overlay_delta_id_key(route.representation_id),
        )? {
            let route_bytes = serde_json::to_vec(&route)
                .map_err(|_| AnnRuntimeErrorV2::Source("delta route encode failed"))?;
            if existing != bytes
                || write
                    .get(
                        &self.overlay,
                        &overlay_delta_partition_key(partition, route.representation_id),
                    )?
                    .as_deref()
                    != Some(route_bytes.as_slice())
            {
                return Err(AnnRuntimeErrorV2::Source(
                    "delta representation identifier is immutable",
                ));
            }
            let epoch = read_overlay_epoch(&write, &self.overlay)?;
            let sequence = write.sequence();
            write.rollback()?;
            return Ok(AnnDeltaPublicationV2 {
                representation_id: route.representation_id,
                overlay_epoch: epoch,
                storage_sequence: sequence,
                idempotent: true,
            });
        }
        if write
            .get(
                &self.routes,
                &persistent_route_id_key(manifest.generation, route.representation_id),
            )?
            .is_some()
        {
            return Err(AnnRuntimeErrorV2::Source(
                "delta representation is already part of the active base generation",
            ));
        }
        if write
            .get(
                &self.overlay,
                &overlay_tombstone_key(route.representation_id),
            )?
            .is_some()
        {
            return Err(AnnRuntimeErrorV2::Source(
                "tombstoned representation cannot be republished as delta",
            ));
        }
        let epoch = read_overlay_epoch(&write, &self.overlay)?
            .checked_add(1)
            .ok_or(AnnRuntimeErrorV2::Invariant("overlay epoch overflowed"))?;
        write.put(
            &self.overlay,
            overlay_delta_id_key(route.representation_id),
            bytes,
        )?;
        write.put(
            &self.overlay,
            overlay_delta_partition_key(partition, route.representation_id),
            serde_json::to_vec(&route)
                .map_err(|_| AnnRuntimeErrorV2::Source("delta route encode failed"))?,
        )?;
        write.put(
            &self.overlay,
            OVERLAY_EPOCH_KEY.to_vec(),
            epoch.to_be_bytes().to_vec(),
        )?;
        let receipt = write.commit(durability)?;
        Ok(AnnDeltaPublicationV2 {
            representation_id: route.representation_id,
            overlay_epoch: epoch,
            storage_sequence: receipt.sequence,
            idempotent: false,
        })
    }

    /// Publishes an irreversible current-use tombstone. Once present, the ID
    /// is excluded even from an older semantic snapshot or universe created
    /// before the tombstone; an in-flight query fails if the overlay changes.
    pub fn publish_tombstone(
        &self,
        representation_id: RepresentationId,
        applied_at: CommitSeq,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnTombstonePublicationV2> {
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let manifest = self
            .active_manifest()?
            .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(0))?;
        self.ensure_verified(&manifest)?;
        let mut write = self.engine.begin_write()?;
        let tombstone = OverlayTombstoneV2 {
            format_version: RUNTIME_FORMAT_VERSION,
            representation_id,
            applied_at,
        };
        let bytes = serde_json::to_vec(&tombstone)
            .map_err(|_| AnnRuntimeErrorV2::Invariant("tombstone encode failed"))?;
        if let Some(existing) =
            write.get(&self.overlay, &overlay_tombstone_key(representation_id))?
        {
            if existing != bytes {
                return Err(AnnRuntimeErrorV2::Source(
                    "current-use tombstone is immutable",
                ));
            }
            let epoch = read_overlay_epoch(&write, &self.overlay)?;
            let sequence = write.sequence();
            write.rollback()?;
            return Ok(AnnTombstonePublicationV2 {
                representation_id,
                overlay_epoch: epoch,
                storage_sequence: sequence,
                idempotent: true,
            });
        }
        let base_route: Option<AnnVectorRouteV2> = read_canonical_json(
            &write,
            &self.routes,
            &persistent_route_id_key(manifest.generation, representation_id),
            "tombstone base route is invalid",
        )?;
        let delta = read_overlay_delta(&write, &self.overlay, representation_id)?;
        let projected_at = match (base_route, delta) {
            (Some(route), _) => {
                validate_route(&route)?;
                if route.representation_id != representation_id {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "tombstone base route ID diverges",
                    ));
                }
                route.projected_at
            }
            (None, Some(delta)) => delta.record.projected_at,
            (None, None) => {
                return Err(AnnRuntimeErrorV2::Source(
                    "cannot tombstone an unknown ANN representation",
                ));
            }
        };
        if applied_at < projected_at {
            return Err(AnnRuntimeErrorV2::Source(
                "current-use tombstone precedes vector projection",
            ));
        }
        let epoch = read_overlay_epoch(&write, &self.overlay)?
            .checked_add(1)
            .ok_or(AnnRuntimeErrorV2::Invariant("overlay epoch overflowed"))?;
        write.put(
            &self.overlay,
            overlay_tombstone_key(representation_id),
            bytes,
        )?;
        write.put(
            &self.overlay,
            OVERLAY_EPOCH_KEY.to_vec(),
            epoch.to_be_bytes().to_vec(),
        )?;
        let receipt = write.commit(durability)?;
        Ok(AnnTombstonePublicationV2 {
            representation_id,
            overlay_epoch: epoch,
            storage_sequence: receipt.sequence,
            idempotent: false,
        })
    }

    /// Releases one persistent authorization universe and its generation
    /// lease. The lease remains present until every universe row is reclaimed.
    pub fn release_universe(
        &self,
        universe: AnnAuthorizedUniverseV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<()> {
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let lease =
            read_generation_lease(&read, &self.leases, universe.generation, universe.lease_id)?
                .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(
                    universe.generation,
                ))?;
        if lease.universe_id != universe.universe_id {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation lease and universe diverge",
            ));
        }
        drop(read);
        self.delete_universe_rows(universe.universe_id, durability)?;
        let mut write = self.engine.begin_write()?;
        write.delete(
            &self.leases,
            lease_key(universe.generation, universe.lease_id),
        )?;
        write.commit(durability)?;
        Ok(())
    }

    /// Prunes archived generations below `retain_from_generation`. The active
    /// generation and every generation with a persistent lease are skipped.
    pub fn prune_generations_before(
        &self,
        retain_from_generation: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnRetentionReportV2> {
        let _guard = self
            .maintenance
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("maintenance lock poisoned"))?;
        let active = self
            .active_manifest()?
            .ok_or(AnnRuntimeErrorV2::GenerationUnavailable(0))?;
        self.ensure_verified(&active)?;
        let fence_read = self.engine.begin_read(SnapshotSelector::Latest)?;
        if read_prune_fence(&fence_read, &self.control)?.is_some() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "an interrupted generation prune requires recovery",
            ));
        }
        drop(fence_read);
        let mut cursor = None;
        let mut retained = 0_u64;
        let mut leased = 0_u64;
        let mut pruned = 0_u64;
        let mut deleted_objects = 0_u64;
        let mut deleted_routes = 0_u64;
        loop {
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let page = read.scan_prefix_page(
                &self.control,
                ScanPageRequest {
                    prefix: MANIFEST_PREFIX,
                    start_after: cursor.as_deref(),
                    max_entries: CLEAN_PAGE_ENTRIES,
                    max_bytes: CLEAN_PAGE_BYTES,
                },
            )?;
            if page.continuation.is_some() && page.entries.is_empty() {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "generation retention page made no progress",
                ));
            }
            let mut candidates = Vec::with_capacity(page.entries.len());
            for entry in &page.entries {
                let manifest = AnnGenerationManifestV2::decode_json(&entry.value)?;
                if entry.key != manifest_key(manifest.generation) {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "archived generation manifest key diverges",
                    ));
                }
                if manifest.generation == active.generation
                    || manifest.generation >= retain_from_generation
                {
                    retained = retained.saturating_add(1);
                    continue;
                }
                let lease_page = read.scan_prefix_page(
                    &self.leases,
                    ScanPageRequest {
                        prefix: &lease_generation_prefix(manifest.generation),
                        start_after: None,
                        max_entries: 1,
                        max_bytes: CLEAN_PAGE_BYTES,
                    },
                )?;
                if !lease_page.entries.is_empty() {
                    leased = leased.saturating_add(1);
                    retained = retained.saturating_add(1);
                } else {
                    candidates.push(manifest.generation);
                }
            }
            let next_cursor = page.continuation;
            drop(read);
            for generation in candidates {
                let lease_read = self.engine.begin_read(SnapshotSelector::Latest)?;
                let lease_page = lease_read.scan_prefix_page(
                    &self.leases,
                    ScanPageRequest {
                        prefix: &lease_generation_prefix(generation),
                        start_after: None,
                        max_entries: 1,
                        max_bytes: CLEAN_PAGE_BYTES,
                    },
                )?;
                if !lease_page.entries.is_empty() {
                    leased = leased.saturating_add(1);
                    retained = retained.saturating_add(1);
                    continue;
                }
                drop(lease_read);
                let fence = PruneFenceV2 {
                    format_version: RUNTIME_FORMAT_VERSION,
                    generation,
                };
                let mut control = self.engine.begin_write()?;
                if read_prune_fence(&control, &self.control)?.is_some() {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "generation prune fence changed concurrently",
                    ));
                }
                if read_manifest(&control, &self.control, ACTIVE_MANIFEST_KEY)?
                    .is_some_and(|manifest| manifest.generation == generation)
                {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "retention attempted to prune the active generation",
                    ));
                }
                let final_lease_page = control.scan_prefix_page(
                    &self.leases,
                    ScanPageRequest {
                        prefix: &lease_generation_prefix(generation),
                        start_after: None,
                        max_entries: 1,
                        max_bytes: CLEAN_PAGE_BYTES,
                    },
                )?;
                if !final_lease_page.entries.is_empty() {
                    control.rollback()?;
                    leased = leased.saturating_add(1);
                    retained = retained.saturating_add(1);
                    continue;
                }
                control.put(
                    &self.control,
                    PRUNE_FENCE_KEY.to_vec(),
                    serde_json::to_vec(&fence).map_err(|_| {
                        AnnRuntimeErrorV2::Invariant("generation prune fence encode failed")
                    })?,
                )?;
                control.commit(durability)?;
                let (objects, routes) = self.finish_prune_generation(fence, durability)?;
                deleted_objects = deleted_objects.saturating_add(objects);
                deleted_routes = deleted_routes.saturating_add(routes);
                pruned = pruned.saturating_add(1);
            }
            let Some(next) = next_cursor else {
                break;
            };
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "generation retention cursor did not advance",
                ));
            }
            cursor = Some(next);
        }
        Ok(AnnRetentionReportV2 {
            active_generation: active.generation,
            retained_generations: retained,
            leased_generations: leased,
            pruned_generations: pruned,
            deleted_objects,
            deleted_routes,
        })
    }

    fn ensure_verified(&self, manifest: &AnnGenerationManifestV2) -> AnnRuntimeResultV2<()> {
        let verified = self
            .verified_generations
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?;
        if verified
            .get(&manifest.generation)
            .is_none_or(|(digest, _)| *digest != manifest.manifest_digest)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation has not passed this process recovery gate",
            ));
        }
        Ok(())
    }

    fn ensure_generation_verified(
        &self,
        manifest: &AnnGenerationManifestV2,
    ) -> AnnRuntimeResultV2<()> {
        if self
            .verified_generations
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?
            .get(&manifest.generation)
            .is_some_and(|(digest, _)| *digest == manifest.manifest_digest)
        {
            return Ok(());
        }
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        verify_runtime_generation(&reader, manifest)?;
        let routes = verify_route_generation(
            &read,
            &self.control,
            &self.routes,
            manifest.generation,
            manifest.node_count,
        )?;
        self.verified_generations
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?
            .insert(
                manifest.generation,
                (manifest.manifest_digest, routes.route_digest),
            );
        Ok(())
    }

    fn stage_routes<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        watermark: CommitSeq,
        durability: Durability,
    ) -> AnnRuntimeResultV2<u64> {
        let expected_seal = source.source_seal()?;
        let mut cursor = None;
        let mut count = 0_u64;
        loop {
            let page =
                source.scan_routes_page(cursor, ANN_V2_MAX_PAGE_ENTRIES, ANN_V2_MAX_PAGE_BYTES)?;
            validate_route_page(
                cursor,
                ANN_V2_MAX_PAGE_ENTRIES,
                ANN_V2_MAX_PAGE_BYTES,
                &page,
            )?;
            let mut transaction = self.engine.begin_write()?;
            for route in &page.routes {
                if route.projected_at > watermark
                    || route
                        .tombstone_at
                        .is_some_and(|deleted| deleted <= watermark)
                {
                    continue;
                }
                validate_route(route)?;
                count = checked_add("generation nodes", count, 1)?;
                if count > ANN_V2_MAX_NODES {
                    return Err(AnnV2Error::ResourceExhausted {
                        resource: "generation_nodes",
                        limit: ANN_V2_MAX_NODES,
                        required: count,
                    }
                    .into());
                }
                let partition = ann_v2_partition_key(
                    route.vector_space_id,
                    canonical_policy_digest(&route.policy)?,
                )?;
                let value = serde_json::to_vec(route)
                    .map_err(|_| AnnRuntimeErrorV2::Source("route encode failed"))?;
                if value.len() > ANN_V2_MAX_OBJECT_BYTES {
                    return Err(AnnV2Error::ResourceExhausted {
                        resource: "route_bytes",
                        limit: ANN_V2_MAX_OBJECT_BYTES as u64,
                        required: value.len() as u64,
                    }
                    .into());
                }
                transaction.put(
                    &self.build,
                    build_route_key(generation, partition, route.representation_id),
                    value.clone(),
                )?;
                transaction.put(
                    &self.routes,
                    persistent_route_key(generation, partition, route.representation_id),
                    value.clone(),
                )?;
                transaction.put(
                    &self.routes,
                    persistent_route_id_key(generation, route.representation_id),
                    value,
                )?;
            }
            transaction.commit(durability)?;
            let Some(next) = page.continuation else {
                break;
            };
            cursor = Some(next);
        }
        if source.source_seal()? != expected_seal {
            return Err(AnnRuntimeErrorV2::Source(
                "vector source changed while staging routes",
            ));
        }
        self.seal_route_generation(generation, count, durability)?;
        Ok(count)
    }

    fn build_generation<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        watermark: CommitSeq,
        source_seal: AnnSourceSealV2,
        build: AnnBuildParametersV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnGenerationManifestV2> {
        let partitions = self.discover_build_partitions(generation)?;
        let mut node_count = 0_u64;
        let mut level_rows = 0_u64;
        let mut neighbours = 0_u64;
        for (global_leaf_index, partition_key) in partitions.iter().enumerate() {
            let partition = self.build_partition(
                source,
                generation,
                *partition_key,
                global_leaf_index as u64,
                build,
                durability,
            )?;
            node_count = checked_add("generation nodes", node_count, partition.node_count)?;
            level_rows = checked_add(
                "generation level rows",
                level_rows,
                partition.level_row_count,
            )?;
            neighbours = checked_add(
                "generation neighbours",
                neighbours,
                partition.neighbour_count,
            )?;
        }
        let partition_tree_root =
            self.build_global_tree(generation, partitions.len() as u64, durability)?;
        let object_bytes = self.generation_object_bytes(generation)?;
        let manifest = AnnGenerationManifestV2 {
            format_version: ANN_V2_FORMAT_VERSION,
            generation,
            watermark,
            source: source_seal,
            build,
            partition_count: partitions.len() as u64,
            node_count,
            level_row_count: level_rows,
            neighbour_count: neighbours,
            object_bytes,
            partition_tree_root,
            manifest_digest: [0; 32],
        }
        .seal()?;
        if source.source_seal()? != source_seal {
            return Err(AnnRuntimeErrorV2::Source(
                "vector source changed while building generation",
            ));
        }
        Ok(manifest)
    }

    fn discover_build_partitions(&self, generation: u64) -> AnnRuntimeResultV2<Vec<[u8; 32]>> {
        let prefix = build_generation_prefix(generation);
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let mut cursor = None;
        let mut partitions = BTreeSet::new();
        loop {
            let page = read.scan_prefix_page(
                &self.build,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: cursor.as_deref(),
                    max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                    max_bytes: ANN_V2_MAX_PAGE_BYTES,
                },
            )?;
            for entry in &page.entries {
                let (actual_generation, partition, _) = parse_build_route_key(&entry.key)?;
                if actual_generation != generation {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "staged route belongs to another generation",
                    ));
                }
                partitions.insert(partition);
                if partitions.len() as u64 > crate::ANN_V2_MAX_PARTITIONS {
                    return Err(AnnV2Error::ResourceExhausted {
                        resource: "generation_partitions",
                        limit: crate::ANN_V2_MAX_PARTITIONS,
                        required: partitions.len() as u64,
                    }
                    .into());
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "build partition cursor did not advance",
                ));
            }
            cursor = Some(next);
        }
        Ok(partitions.into_iter().collect())
    }

    fn build_partition<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        partition_key: [u8; 32],
        global_leaf_index: u64,
        build: AnnBuildParametersV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnPartitionManifestV2> {
        let prefix = build_partition_prefix(generation, partition_key);
        let mut cursor = None;
        let mut entry = None;
        let mut max_level = 0_u8;
        let mut previous = None;
        let mut next_leaf = 0_u64;
        let mut policy_digest = None;
        let mut vector_space_id = None;
        let mut valid_from = None;
        let mut valid_until: Option<TimestampMicros> = None;
        let mut membership_epoch = None;

        loop {
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let page = read.scan_prefix_page(
                &self.build,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: cursor.as_deref(),
                    max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                    max_bytes: ANN_V2_MAX_PAGE_BYTES,
                },
            )?;
            drop(read);
            for item in &page.entries {
                let route: AnnVectorRouteV2 = serde_json::from_slice(&item.value)
                    .map_err(|_| AnnRuntimeErrorV2::Invariant("staged route decode failed"))?;
                validate_route(&route)?;
                let (_, actual_partition, id) = parse_build_route_key(&item.key)?;
                if actual_partition != partition_key || id != route.representation_id {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "staged route key disagrees with its value",
                    ));
                }
                let digest = canonical_policy_digest(&route.policy)?;
                if ann_v2_partition_key(route.vector_space_id, digest)? != partition_key {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "staged route disagrees with its partition",
                    ));
                }
                if policy_digest.is_some_and(|existing| existing != digest)
                    || vector_space_id.is_some_and(|existing| existing != route.vector_space_id)
                    || membership_epoch.is_some_and(|existing| existing != route.membership_epoch)
                {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "partition routes do not share immutable routing identity",
                    ));
                }
                policy_digest = Some(digest);
                vector_space_id = Some(route.vector_space_id);
                membership_epoch = Some(route.membership_epoch);
                valid_from = Some(
                    valid_from.map_or(route.valid_from, |current: TimestampMicros| {
                        current.max(route.valid_from)
                    }),
                );
                valid_until = intersect_until(valid_until, route.valid_until);
                if valid_until.is_some_and(|until| valid_from.is_some_and(|from| until <= from)) {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "partition routes have no shared validity interval",
                    ));
                }

                let node = self.insert_node(
                    source,
                    generation,
                    partition_key,
                    &route,
                    next_leaf,
                    entry,
                    max_level,
                    previous,
                    build,
                    durability,
                )?;
                let node_level = u8::try_from(node.levels.len() - 1)
                    .map_err(|_| AnnRuntimeErrorV2::Invariant("node level overflowed"))?;
                if entry.is_none() || node_level > max_level {
                    entry = Some(node.representation_id);
                    max_level = node_level;
                }
                previous = Some(node.representation_id);
                next_leaf = checked_add("partition nodes", next_leaf, 1)?;
            }
            let Some(next) = page.continuation else {
                break;
            };
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "partition build cursor did not advance",
                ));
            }
            cursor = Some(next);
        }
        self.enforce_base_cycle(
            source,
            generation,
            partition_key,
            build.neighbours_per_level,
            durability,
        )?;
        let entry = entry.ok_or(AnnRuntimeErrorV2::Invariant("empty staged partition"))?;
        let (node_count, level_row_count, neighbour_count, node_bytes) =
            self.partition_node_totals(generation, partition_key)?;
        let node_tree_root =
            self.build_partition_tree(generation, partition_key, node_count, durability)?;
        let manifest = AnnPartitionManifestV2 {
            format_version: ANN_V2_FORMAT_VERSION,
            generation,
            partition_key,
            policy_digest: policy_digest
                .ok_or(AnnRuntimeErrorV2::Invariant("missing policy digest"))?,
            vector_space_id: vector_space_id
                .ok_or(AnnRuntimeErrorV2::Invariant("missing vector space"))?,
            entry,
            max_level,
            global_leaf_index,
            node_count,
            level_row_count,
            neighbour_count,
            node_bytes,
            node_tree_root,
            valid_for_all_from: valid_from
                .ok_or(AnnRuntimeErrorV2::Invariant("missing validity start"))?,
            valid_for_all_until: valid_until,
            membership_epoch: membership_epoch
                .ok_or(AnnRuntimeErrorV2::Invariant("missing membership epoch"))?,
            manifest_digest: [0; 32],
        }
        .seal()?;
        self.put_object(
            AnnObjectV2::new(
                AnnObjectKeyV2::partition_manifest(generation, partition_key)?,
                manifest.encode_json()?,
            )?,
            durability,
        )?;
        Ok(manifest)
    }

    /// Reserves one base-layer edge for a deterministic leaf-order cycle.
    ///
    /// HNSW neighbour pruning is local: a later reciprocal update can otherwise
    /// evict an older bridge and split a large partition. The immutable leaf
    /// order is already authenticated, so retaining each node's successor (and
    /// closing the final edge back to the first node) guarantees complete
    /// directed reachability from any valid entry while consuming only one
    /// configured neighbour slot.
    fn enforce_base_cycle<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        partition_key: [u8; 32],
        neighbours_per_level: u16,
        durability: Durability,
    ) -> AnnRuntimeResultV2<()> {
        let prefix = node_prefix(generation, partition_key)?;
        let mut cursor = None;
        let mut first = None;
        let mut previous = None;
        let mut expected_leaf = 0_u64;
        loop {
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let reader = StorageAnnReaderV2 {
                snapshot: &read,
                keyspace: &self.objects,
            };
            let request = AnnObjectPageRequestV2 {
                prefix: &prefix,
                start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
                max_entries: DEFAULT_BUILD_BATCH_OBJECTS,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            };
            let page = reader.scan_page(request)?;
            let nodes = page
                .objects()
                .iter()
                .map(|object| AnnNodeV2::decode_canonical(object.value()))
                .collect::<Result<Vec<_>, _>>()?;
            let continuation = page.continuation().cloned();
            drop(read);
            for node in nodes {
                if node.leaf_index != expected_leaf {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "base-cycle leaf order is not contiguous",
                    ));
                }
                first.get_or_insert(node.representation_id);
                if let Some(owner) = previous {
                    self.retain_base_successor(
                        source,
                        generation,
                        partition_key,
                        owner,
                        node.representation_id,
                        usize::from(neighbours_per_level),
                        durability,
                    )?;
                }
                previous = Some(node.representation_id);
                expected_leaf = checked_add("base-cycle nodes", expected_leaf, 1)?;
            }
            let Some(next) = continuation else {
                break;
            };
            cursor = Some(next);
        }
        if expected_leaf > 1 {
            self.retain_base_successor(
                source,
                generation,
                partition_key,
                previous.ok_or(AnnRuntimeErrorV2::Invariant(
                    "base-cycle final node is absent",
                ))?,
                first.ok_or(AnnRuntimeErrorV2::Invariant(
                    "base-cycle first node is absent",
                ))?,
                usize::from(neighbours_per_level),
                durability,
            )?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the source, immutable generation identity, successor, and durability stay explicit"
    )]
    fn retain_base_successor<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        partition_key: [u8; 32],
        owner_id: RepresentationId,
        successor: RepresentationId,
        maximum: usize,
        durability: Durability,
    ) -> AnnRuntimeResultV2<()> {
        let mut owner = self.read_node(generation, partition_key, owner_id)?;
        let space = source.vector_space(
            self.read_staged_route(generation, partition_key, owner_id)?
                .vector_space_id,
        )?;
        let mut candidates = owner.levels[0].neighbours.clone();
        candidates.push(successor);
        owner.levels[0].neighbours = self.prune_neighbours(
            source,
            &space,
            owner_id,
            candidates,
            maximum,
            Some(successor),
        )?;
        owner.validate()?;
        self.put_object(
            AnnObjectV2::new(
                AnnObjectKeyV2::node(generation, partition_key, owner_id)?,
                owner.encode_canonical()?,
            )?,
            durability,
        )
    }

    fn read_staged_route(
        &self,
        generation: u64,
        partition_key: [u8; 32],
        id: RepresentationId,
    ) -> AnnRuntimeResultV2<AnnVectorRouteV2> {
        let key = build_route_key(generation, partition_key, id);
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let value = read
            .get(&self.build, &key)?
            .ok_or(AnnRuntimeErrorV2::Invariant(
                "base-cycle staged route is absent",
            ))?;
        serde_json::from_slice(&value)
            .map_err(|_| AnnRuntimeErrorV2::Invariant("staged route decode failed"))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the inactive-generation node identity and finite build controls stay explicit"
    )]
    fn insert_node<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        partition_key: [u8; 32],
        route: &AnnVectorRouteV2,
        leaf_index: u64,
        entry: Option<RepresentationId>,
        current_max_level: u8,
        previous: Option<RepresentationId>,
        build: AnnBuildParametersV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnNodeV2> {
        let space = source.vector_space(route.vector_space_id)?;
        let dimensions = bounded_dimensions(&space)?;
        let query = source.read_vector(route.representation_id, dimensions)?;
        validate_values(&space, &query)
            .map_err(|_| AnnRuntimeErrorV2::Source("stored vector is invalid"))?;
        let level = deterministic_level_v2(route.representation_id).min(build.max_level);
        let mut levels = Vec::with_capacity(usize::from(level) + 1);
        for current_level in 0..=level {
            let mut neighbours = if let Some(start) = entry
                && current_level <= current_max_level
            {
                self.construction_candidates(
                    source,
                    generation,
                    partition_key,
                    start,
                    current_level,
                    &space,
                    &query,
                    build.construction_max_visits as usize,
                )?
                .into_iter()
                .take(usize::from(build.neighbours_per_level))
                .map(|(_, id)| id)
                .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            if current_level == 0
                && let Some(previous) = previous
                && !neighbours.contains(&previous)
            {
                neighbours.push(previous);
                neighbours = self.prune_neighbours(
                    source,
                    &space,
                    route.representation_id,
                    neighbours,
                    usize::from(build.neighbours_per_level),
                    Some(previous),
                )?;
            }
            neighbours.sort_unstable();
            neighbours.dedup();
            levels.push(AnnLevelV2 {
                level: current_level,
                neighbours,
            });
        }
        let node = AnnNodeV2 {
            generation,
            partition_key,
            representation_id: route.representation_id,
            leaf_index,
            levels,
        };
        node.validate()?;

        let mut updates = BTreeMap::<RepresentationId, AnnNodeV2>::new();
        for row in &node.levels {
            for neighbour in &row.neighbours {
                let owner = match updates.remove(neighbour) {
                    Some(node) => node,
                    None => self.read_node(generation, partition_key, *neighbour)?,
                };
                if usize::from(row.level) >= owner.levels.len() {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "construction neighbour lacks reciprocal level",
                    ));
                }
                let required = (row.level == 0 && Some(*neighbour) == previous)
                    .then_some(route.representation_id);
                let mut owner = owner;
                let mut candidates = owner.levels[usize::from(row.level)].neighbours.clone();
                candidates.push(route.representation_id);
                owner.levels[usize::from(row.level)].neighbours = self.prune_neighbours(
                    source,
                    &space,
                    owner.representation_id,
                    candidates,
                    usize::from(build.neighbours_per_level),
                    required,
                )?;
                owner.validate()?;
                updates.insert(owner.representation_id, owner);
            }
        }

        let mut transaction = self.engine.begin_write()?;
        let object = AnnObjectV2::new(
            AnnObjectKeyV2::node(generation, partition_key, node.representation_id)?,
            node.encode_canonical()?,
        )?;
        transaction.put(
            &self.objects,
            object.key().as_bytes().to_vec(),
            object.value().to_vec(),
        )?;
        for update in updates.values() {
            let object = AnnObjectV2::new(
                AnnObjectKeyV2::node(generation, partition_key, update.representation_id)?,
                update.encode_canonical()?,
            )?;
            transaction.put(
                &self.objects,
                object.key().as_bytes().to_vec(),
                object.value().to_vec(),
            )?;
        }
        transaction.commit(durability)?;
        Ok(node)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "storage scope, query geometry, and hard visit limit are independent inputs"
    )]
    fn construction_candidates<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        generation: u64,
        partition_key: [u8; 32],
        start: RepresentationId,
        level: u8,
        space: &VectorSpace,
        query: &[f32],
        max_visits: usize,
    ) -> AnnRuntimeResultV2<Vec<(f32, RepresentationId)>> {
        let dimensions = bounded_dimensions(space)?;
        let mut queue = VecDeque::from([start]);
        let mut queued = BTreeSet::from([start]);
        let mut ranked = Vec::new();
        while let Some(id) = queue.pop_front() {
            if ranked.len() == max_visits {
                break;
            }
            let values = source.read_vector(id, dimensions)?;
            validate_values(space, &values)
                .map_err(|_| AnnRuntimeErrorV2::Source("stored vector is invalid"))?;
            ranked.push((
                score(space.metric, query, &values)
                    .map_err(|_| AnnRuntimeErrorV2::Source("vector score is invalid"))?,
                id,
            ));
            let node = self.read_node(generation, partition_key, id)?;
            if let Some(row) = node.levels.get(usize::from(level)) {
                for neighbour in &row.neighbours {
                    if queued.len() < max_visits && queued.insert(*neighbour) {
                        queue.push_back(*neighbour);
                    }
                }
            }
        }
        ranked.sort_by(|left, right| {
            right
                .0
                .total_cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
        });
        Ok(ranked)
    }

    fn prune_neighbours<S: AnnVectorSourceV2>(
        &self,
        source: &S,
        space: &VectorSpace,
        owner: RepresentationId,
        candidates: Vec<RepresentationId>,
        maximum: usize,
        required: Option<RepresentationId>,
    ) -> AnnRuntimeResultV2<Vec<RepresentationId>> {
        let dimensions = bounded_dimensions(space)?;
        let owner_values = source.read_vector(owner, dimensions)?;
        validate_values(space, &owner_values)
            .map_err(|_| AnnRuntimeErrorV2::Source("stored vector is invalid"))?;
        let mut unique = candidates
            .into_iter()
            .filter(|id| *id != owner)
            .collect::<BTreeSet<_>>();
        let mut ranked = Vec::with_capacity(unique.len());
        for candidate in &unique {
            let values = source.read_vector(*candidate, dimensions)?;
            validate_values(space, &values)
                .map_err(|_| AnnRuntimeErrorV2::Source("stored vector is invalid"))?;
            ranked.push((
                score(space.metric, &owner_values, &values)
                    .map_err(|_| AnnRuntimeErrorV2::Source("vector score is invalid"))?,
                *candidate,
            ));
        }
        ranked.sort_by(|left, right| {
            right
                .0
                .total_cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
        });
        unique = ranked.into_iter().take(maximum).map(|(_, id)| id).collect();
        if let Some(required) = required
            && !unique.contains(&required)
        {
            if unique.len() == maximum {
                unique.pop_last();
            }
            unique.insert(required);
        }
        Ok(unique.into_iter().collect())
    }

    fn read_node(
        &self,
        generation: u64,
        partition_key: [u8; 32],
        id: RepresentationId,
    ) -> AnnRuntimeResultV2<AnnNodeV2> {
        let key = AnnObjectKeyV2::node(generation, partition_key, id)?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let value = read
            .get(&self.objects, key.as_bytes())?
            .ok_or(AnnRuntimeErrorV2::Invariant("required node is absent"))?;
        Ok(AnnNodeV2::decode_canonical(&value)?)
    }

    fn partition_node_totals(
        &self,
        generation: u64,
        partition_key: [u8; 32],
    ) -> AnnRuntimeResultV2<(u64, u64, u64, u64)> {
        let prefix = node_prefix(generation, partition_key)?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        let mut cursor = None;
        let mut nodes = 0_u64;
        let mut rows = 0_u64;
        let mut neighbours = 0_u64;
        let mut bytes = 0_u64;
        loop {
            let request = AnnObjectPageRequestV2 {
                prefix: &prefix,
                start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            };
            let page = reader.scan_page(request)?;
            for object in page.objects() {
                let node = AnnNodeV2::decode_canonical(object.value())?;
                if node.leaf_index != nodes {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "node leaf indices are not contiguous",
                    ));
                }
                nodes = checked_add("partition nodes", nodes, 1)?;
                rows = checked_add("partition rows", rows, node.levels.len() as u64)?;
                for row in node.levels {
                    neighbours = checked_add(
                        "partition neighbours",
                        neighbours,
                        row.neighbours.len() as u64,
                    )?;
                }
                bytes = checked_add("partition node bytes", bytes, object.encoded_len()? as u64)?;
            }
            let Some(next) = page.continuation().cloned() else {
                break;
            };
            cursor = Some(next);
        }
        Ok((nodes, rows, neighbours, bytes))
    }

    fn build_partition_tree(
        &self,
        generation: u64,
        partition_key: [u8; 32],
        leaf_count: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<[u8; 32]> {
        let scope = AnnMerkleScopeV2::PartitionNodes {
            generation,
            partition_key,
        };
        let prefix = node_prefix(generation, partition_key)?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        let mut cursor = None;
        let mut leaves = Vec::new();
        let mut next_index = 0_u64;
        loop {
            let request = AnnObjectPageRequestV2 {
                prefix: &prefix,
                start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
                max_entries: DEFAULT_BUILD_BATCH_OBJECTS,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            };
            let page = reader.scan_page(request)?;
            for object in page.objects() {
                leaves.push(AnnObjectV2::new(
                    AnnObjectKeyV2::partition_tree(
                        generation,
                        partition_key,
                        leaf_count,
                        0,
                        next_index,
                    )?,
                    ann_v2_merkle_leaf(object)?.to_vec(),
                )?);
                next_index = checked_add("partition tree leaves", next_index, 1)?;
            }
            self.put_objects(&leaves, durability)?;
            leaves.clear();
            let Some(next) = page.continuation().cloned() else {
                break;
            };
            cursor = Some(next);
        }
        drop(read);
        if next_index != leaf_count {
            return Err(AnnRuntimeErrorV2::Invariant(
                "partition tree leaf count changed during build",
            ));
        }
        self.build_internal_tree(scope, leaf_count, durability)
    }

    fn build_global_tree(
        &self,
        generation: u64,
        leaf_count: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<[u8; 32]> {
        let scope = AnnMerkleScopeV2::GenerationPartitions { generation };
        if leaf_count == 0 {
            return Ok(ann_v2_merkle_root(scope, 0, None)?);
        }
        let prefix = partition_manifest_prefix(generation)?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        let mut cursor = None;
        let mut leaves = Vec::new();
        let mut next_index = 0_u64;
        loop {
            let request = AnnObjectPageRequestV2 {
                prefix: &prefix,
                start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
                max_entries: DEFAULT_BUILD_BATCH_OBJECTS,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            };
            let page = reader.scan_page(request)?;
            for object in page.objects() {
                leaves.push(AnnObjectV2::new(
                    AnnObjectKeyV2::global_tree(generation, leaf_count, 0, next_index)?,
                    ann_v2_merkle_leaf(object)?.to_vec(),
                )?);
                next_index = checked_add("global tree leaves", next_index, 1)?;
            }
            self.put_objects(&leaves, durability)?;
            leaves.clear();
            let Some(next) = page.continuation().cloned() else {
                break;
            };
            cursor = Some(next);
        }
        drop(read);
        if next_index != leaf_count {
            return Err(AnnRuntimeErrorV2::Invariant(
                "global tree leaf count changed during build",
            ));
        }
        self.build_internal_tree(scope, leaf_count, durability)
    }

    fn build_internal_tree(
        &self,
        scope: AnnMerkleScopeV2,
        leaf_count: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<[u8; 32]> {
        let geometry = AnnMerkleGeometryV2::new(scope, leaf_count)?;
        for level in 1..=geometry.root_level() {
            let width = geometry.width_at(level)?;
            let child_width = geometry.width_at(level - 1)?;
            let mut batch = Vec::new();
            for index in 0..width {
                let left_index = index.checked_mul(2).ok_or(AnnRuntimeErrorV2::Invariant(
                    "Merkle child index overflowed",
                ))?;
                let left = self.read_tree_hash(scope, leaf_count, level - 1, left_index)?;
                let right = if left_index + 1 < child_width {
                    self.read_tree_hash(scope, leaf_count, level - 1, left_index + 1)?
                } else {
                    left
                };
                batch.push(AnnObjectV2::new(
                    tree_key(scope, leaf_count, level, index)?,
                    ann_v2_merkle_internal(level, left, right)?.to_vec(),
                )?);
                if batch.len() == DEFAULT_BUILD_BATCH_OBJECTS {
                    self.put_objects(&batch, durability)?;
                    batch.clear();
                }
            }
            self.put_objects(&batch, durability)?;
        }
        let top = self.read_tree_hash(scope, leaf_count, geometry.root_level(), 0)?;
        Ok(ann_v2_merkle_root(scope, leaf_count, Some(top))?)
    }

    fn read_tree_hash(
        &self,
        scope: AnnMerkleScopeV2,
        leaf_count: u64,
        level: u16,
        index: u64,
    ) -> AnnRuntimeResultV2<[u8; 32]> {
        let key = tree_key(scope, leaf_count, level, index)?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let value = read
            .get(&self.objects, key.as_bytes())?
            .ok_or(AnnRuntimeErrorV2::Invariant("Merkle object is absent"))?;
        value
            .as_slice()
            .try_into()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("Merkle object length is invalid"))
    }

    fn put_object(&self, object: AnnObjectV2, durability: Durability) -> AnnRuntimeResultV2<()> {
        self.put_objects(&[object], durability)
    }

    fn put_objects(
        &self,
        objects: &[AnnObjectV2],
        durability: Durability,
    ) -> AnnRuntimeResultV2<()> {
        if objects.is_empty() {
            return Ok(());
        }
        let mut transaction = self.engine.begin_write()?;
        for object in objects {
            object.validate()?;
            transaction.put(
                &self.objects,
                object.key().as_bytes().to_vec(),
                object.value().to_vec(),
            )?;
        }
        transaction.commit(durability)?;
        Ok(())
    }

    fn generation_object_bytes(&self, generation: u64) -> AnnRuntimeResultV2<u64> {
        let prefix = ann_v2_generation_prefix(generation)?;
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let reader = StorageAnnReaderV2 {
            snapshot: &read,
            keyspace: &self.objects,
        };
        let mut cursor = None;
        let mut bytes = 0_u64;
        loop {
            let request = AnnObjectPageRequestV2 {
                prefix: &prefix,
                start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            };
            let page = reader.scan_page(request)?;
            for object in page.objects() {
                bytes = checked_add(
                    "generation object bytes",
                    bytes,
                    object.encoded_len()? as u64,
                )?;
                if bytes > ANN_V2_MAX_GENERATION_BYTES {
                    return Err(AnnV2Error::ResourceExhausted {
                        resource: "generation_object_bytes",
                        limit: ANN_V2_MAX_GENERATION_BYTES,
                        required: bytes,
                    }
                    .into());
                }
            }
            let Some(next) = page.continuation().cloned() else {
                break;
            };
            cursor = Some(next);
        }
        Ok(bytes)
    }

    fn acquire_fence(
        &self,
        generation: u64,
        source: AnnSourceSealV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<()> {
        let mut transaction = self.engine.begin_write()?;
        if let Some(existing) = read_fence(&transaction, &self.control)? {
            return Err(AnnRuntimeErrorV2::BuildInProgress(existing.generation));
        }
        let fence = BuildFenceV2 {
            format_version: RUNTIME_FORMAT_VERSION,
            generation,
            source: source.into(),
        };
        transaction.put(
            &self.control,
            BUILD_FENCE_KEY.to_vec(),
            serde_json::to_vec(&fence)
                .map_err(|_| AnnRuntimeErrorV2::Invariant("fence encode failed"))?,
        )?;
        transaction.commit(durability)?;
        Ok(())
    }

    fn publish_manifest(
        &self,
        expected_active: Option<&AnnGenerationManifestV2>,
        source: AnnSourceSealV2,
        manifest: &AnnGenerationManifestV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<u64> {
        let mut transaction = self.engine.begin_write()?;
        if read_manifest(&transaction, &self.control, ACTIVE_MANIFEST_KEY)?.as_ref()
            != expected_active
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "active manifest changed during inactive build",
            ));
        }
        let fence = read_fence(&transaction, &self.control)?
            .ok_or(AnnRuntimeErrorV2::Invariant("build fence disappeared"))?;
        if fence.generation != manifest.generation || AnnSourceSealV2::from(fence.source) != source
        {
            return Err(AnnRuntimeErrorV2::Invariant("build fence identity changed"));
        }
        let route_manifest =
            read_route_manifest_for_generation(&transaction, &self.control, manifest.generation)?
                .ok_or(AnnRuntimeErrorV2::Invariant(
                "route generation manifest disappeared",
            ))?;
        if route_manifest.route_count != manifest.node_count {
            return Err(AnnRuntimeErrorV2::Invariant(
                "route generation count disagrees with ANN manifest",
            ));
        }
        let bytes = manifest.encode_json()?;
        transaction.put(&self.control, ACTIVE_MANIFEST_KEY.to_vec(), bytes.clone())?;
        transaction.put(&self.control, manifest_key(manifest.generation), bytes)?;
        transaction.put(
            &self.control,
            ACTIVE_ROTATION_KEY.to_vec(),
            serde_json::to_vec(&ActiveRotationV2 {
                format_version: RUNTIME_FORMAT_VERSION,
                active_generation: manifest.generation,
                previous_generation: expected_active.map(|value| value.generation),
                manifest_digest: manifest.manifest_digest,
                route_digest: route_manifest.route_digest,
            })
            .map_err(|_| AnnRuntimeErrorV2::Invariant("rotation encode failed"))?,
        )?;
        transaction.delete(&self.control, BUILD_FENCE_KEY.to_vec())?;
        Ok(transaction.commit(durability)?.sequence)
    }

    fn delete_generation(
        &self,
        generation: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<u64> {
        let prefix = ann_v2_generation_prefix(generation)?;
        let mut deleted = 0_u64;
        loop {
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let page = read.scan_prefix_page(
                &self.objects,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: None,
                    max_entries: CLEAN_PAGE_ENTRIES,
                    max_bytes: CLEAN_PAGE_BYTES,
                },
            )?;
            drop(read);
            if page.entries.is_empty() {
                return Ok(deleted);
            }
            let mut transaction = self.engine.begin_write()?;
            for entry in page.entries {
                transaction.delete(&self.objects, entry.key)?;
                deleted = deleted.saturating_add(1);
            }
            transaction.commit(durability)?;
        }
    }

    fn delete_build_generation(
        &self,
        generation: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<u64> {
        let prefix = build_generation_prefix(generation);
        let mut deleted = 0_u64;
        loop {
            let read = self.engine.begin_read(SnapshotSelector::Latest)?;
            let page = read.scan_prefix_page(
                &self.build,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: None,
                    max_entries: CLEAN_PAGE_ENTRIES,
                    max_bytes: CLEAN_PAGE_BYTES,
                },
            )?;
            drop(read);
            if page.entries.is_empty() {
                return Ok(deleted);
            }
            let mut transaction = self.engine.begin_write()?;
            for entry in page.entries {
                transaction.delete(&self.build, entry.key)?;
                deleted = deleted.saturating_add(1);
            }
            transaction.commit(durability)?;
        }
    }

    fn seal_route_generation(
        &self,
        generation: u64,
        expected_count: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<RouteGenerationManifestV2> {
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        let manifest = compute_route_generation(&read, &self.routes, generation)?;
        if manifest.route_count != expected_count {
            return Err(AnnRuntimeErrorV2::Invariant(
                "persistent route count disagrees with staged routes",
            ));
        }
        drop(read);
        let mut transaction = self.engine.begin_write()?;
        transaction.put(
            &self.control,
            route_manifest_key(generation),
            serde_json::to_vec(&manifest)
                .map_err(|_| AnnRuntimeErrorV2::Invariant("route manifest encode failed"))?,
        )?;
        transaction.commit(durability)?;
        Ok(manifest)
    }

    fn delete_route_generation(
        &self,
        generation: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<u64> {
        let mut deleted = delete_prefix_pages(
            &self.engine,
            &self.routes,
            &persistent_route_generation_prefix(generation),
            durability,
        )?;
        deleted = deleted.saturating_add(delete_prefix_pages(
            &self.engine,
            &self.routes,
            &persistent_route_id_prefix(generation),
            durability,
        )?);
        Ok(deleted)
    }

    fn delete_route_manifest(
        &self,
        generation: u64,
        durability: Durability,
    ) -> AnnRuntimeResultV2<()> {
        let mut transaction = self.engine.begin_write()?;
        transaction.delete(&self.control, route_manifest_key(generation))?;
        transaction.commit(durability)?;
        Ok(())
    }

    fn finish_prune_generation(
        &self,
        fence: PruneFenceV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<(u64, u64)> {
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        if read_prune_fence(&read, &self.control)?.as_ref() != Some(&fence) {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation prune fence changed during cleanup",
            ));
        }
        if read_manifest(&read, &self.control, ACTIVE_MANIFEST_KEY)?
            .is_some_and(|manifest| manifest.generation == fence.generation)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation prune cleanup targets the active generation",
            ));
        }
        let lease_page = read.scan_prefix_page(
            &self.leases,
            ScanPageRequest {
                prefix: &lease_generation_prefix(fence.generation),
                start_after: None,
                max_entries: 1,
                max_bytes: CLEAN_PAGE_BYTES,
            },
        )?;
        if !lease_page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation prune cleanup targets a leased generation",
            ));
        }
        drop(read);

        let objects = self.delete_generation(fence.generation, durability)?;
        let routes = self.delete_route_generation(fence.generation, durability)?;
        let mut control = self.engine.begin_write()?;
        if read_prune_fence(&control, &self.control)?.as_ref() != Some(&fence) {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation prune fence changed before completion",
            ));
        }
        if read_manifest(&control, &self.control, ACTIVE_MANIFEST_KEY)?
            .is_some_and(|manifest| manifest.generation == fence.generation)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation became active during prune cleanup",
            ));
        }
        let final_lease_page = control.scan_prefix_page(
            &self.leases,
            ScanPageRequest {
                prefix: &lease_generation_prefix(fence.generation),
                start_after: None,
                max_entries: 1,
                max_bytes: CLEAN_PAGE_BYTES,
            },
        )?;
        if !final_lease_page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "generation acquired a lease during prune cleanup",
            ));
        }
        control.delete(&self.control, manifest_key(fence.generation))?;
        control.delete(&self.control, route_manifest_key(fence.generation))?;
        control.delete(&self.control, PRUNE_FENCE_KEY.to_vec())?;
        control.commit(durability)?;
        self.verified_generations
            .lock()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("verification lock poisoned"))?
            .remove(&fence.generation);
        Ok((objects, routes))
    }

    fn delete_universe_rows(
        &self,
        universe: [u8; 32],
        durability: Durability,
    ) -> AnnRuntimeResultV2<u64> {
        let mut deleted = 0_u64;
        for prefix in [
            universe_route_id_prefix(universe),
            universe_partition_prefix(universe),
            {
                let mut prefix = vec![b'r'];
                prefix.extend_from_slice(&universe);
                prefix
            },
        ] {
            deleted = deleted.saturating_add(delete_prefix_pages(
                &self.engine,
                &self.universes,
                &prefix,
                durability,
            )?);
        }
        let mut write = self.engine.begin_write()?;
        if write
            .get(&self.universes, &universe_header_key(universe))?
            .is_some()
        {
            write.delete(&self.universes, universe_header_key(universe))?;
            deleted = deleted.saturating_add(1);
        }
        write.commit(durability)?;
        Ok(deleted)
    }
}

struct StorageAnnReaderV2<'a, S: ReadSnapshot> {
    snapshot: &'a S,
    keyspace: &'a Keyspace,
}

impl<S: ReadSnapshot> AnnObjectReaderV2 for StorageAnnReaderV2<'_, S> {
    fn get_bounded(
        &self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> Result<AnnObjectReadResponseV2, AnnV2Error> {
        request.validate()?;
        let value = self
            .snapshot
            .get(self.keyspace, request.key.as_bytes())
            .map_err(|_| AnnV2Error::Invalid("ANN storage point read failed"))?;
        let object = value
            .map(|value| {
                if value.len() > request.max_bytes {
                    return Err(AnnV2Error::ResourceExhausted {
                        resource: "object_read_bytes",
                        limit: request.max_bytes as u64,
                        required: value.len() as u64,
                    });
                }
                AnnObjectV2::new(request.key.clone(), value)
            })
            .transpose()?;
        AnnObjectReadResponseV2::new(request, object)
    }

    fn scan_page(
        &self,
        request: AnnObjectPageRequestV2<'_>,
    ) -> Result<AnnObjectPageV2, AnnV2Error> {
        request.validate()?;
        let storage_page = self
            .snapshot
            .scan_prefix_page(
                self.keyspace,
                ScanPageRequest {
                    prefix: request.prefix,
                    start_after: request.start_after,
                    max_entries: request.max_entries,
                    max_bytes: request.max_bytes,
                },
            )
            .map_err(|_| AnnV2Error::Invalid("ANN storage page read failed"))?;
        let storage_has_more = storage_page.continuation.is_some();
        let storage_len = storage_page.entries.len();
        let mut objects = Vec::new();
        let mut used = 0_usize;
        for entry in storage_page.entries {
            let key = AnnObjectKeyV2::from_bytes(entry.key)?;
            let object = AnnObjectV2::new(key, entry.value)?;
            let next =
                used.checked_add(object.encoded_len()?)
                    .ok_or(AnnV2Error::ResourceExhausted {
                        resource: "object_page_bytes",
                        limit: request.max_bytes as u64,
                        required: u64::MAX,
                    })?;
            if next > request.max_bytes {
                if objects.is_empty() {
                    return Err(AnnV2Error::ResourceExhausted {
                        resource: "object_page_bytes",
                        limit: request.max_bytes as u64,
                        required: next as u64,
                    });
                }
                break;
            }
            used = next;
            objects.push(object);
        }
        let truncated = objects.len() < storage_len;
        let continuation = (truncated || storage_has_more)
            .then(|| objects.last().map(|object| object.key().clone()))
            .flatten();
        if (truncated || storage_has_more) && continuation.is_none() {
            return Err(AnnV2Error::Invalid(
                "ANN storage page claimed continuation without progress",
            ));
        }
        AnnObjectPageV2::new(request, objects, continuation)
    }
}

fn read_manifest<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
    key: &[u8],
) -> AnnRuntimeResultV2<Option<AnnGenerationManifestV2>> {
    snapshot
        .get(control, key)?
        .map(|bytes| AnnGenerationManifestV2::decode_json(&bytes).map_err(Into::into))
        .transpose()
}

fn read_fence<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
) -> AnnRuntimeResultV2<Option<BuildFenceV2>> {
    let Some(bytes) = snapshot.get(control, BUILD_FENCE_KEY)? else {
        return Ok(None);
    };
    let fence: BuildFenceV2 = serde_json::from_slice(&bytes)
        .map_err(|_| AnnRuntimeErrorV2::Invariant("build fence decode failed"))?;
    if fence.format_version != RUNTIME_FORMAT_VERSION || fence.generation == 0 {
        return Err(AnnRuntimeErrorV2::Invariant("build fence is invalid"));
    }
    AnnSourceSealV2::from(fence.source).validate()?;
    let canonical = serde_json::to_vec(&fence)
        .map_err(|_| AnnRuntimeErrorV2::Invariant("build fence encode failed"))?;
    if canonical != bytes {
        return Err(AnnRuntimeErrorV2::Invariant(
            "build fence is not canonically encoded",
        ));
    }
    Ok(Some(fence))
}

fn read_active_rotation<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
) -> AnnRuntimeResultV2<Option<ActiveRotationV2>> {
    let rotation: Option<ActiveRotationV2> = read_canonical_json(
        snapshot,
        control,
        ACTIVE_ROTATION_KEY,
        "active rotation record is invalid",
    )?;
    if let Some(value) = rotation
        && (value.format_version != RUNTIME_FORMAT_VERSION
            || value.active_generation == 0
            || value.manifest_digest == [0; 32]
            || value.route_digest == [0; 32]
            || value
                .previous_generation
                .is_some_and(|previous| previous >= value.active_generation))
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "active rotation fields are invalid",
        ));
    }
    Ok(rotation)
}

fn read_universe_fence<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
) -> AnnRuntimeResultV2<Option<UniverseFenceV2>> {
    let fence: Option<UniverseFenceV2> = read_canonical_json(
        snapshot,
        control,
        UNIVERSE_FENCE_KEY,
        "universe fence is invalid",
    )?;
    if let Some(value) = fence
        && (value.format_version != RUNTIME_FORMAT_VERSION
            || value.generation == 0
            || value.universe_id == [0; 32])
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "universe fence fields are invalid",
        ));
    }
    Ok(fence)
}

fn read_prune_fence<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
) -> AnnRuntimeResultV2<Option<PruneFenceV2>> {
    let fence: Option<PruneFenceV2> = read_canonical_json(
        snapshot,
        control,
        PRUNE_FENCE_KEY,
        "generation prune fence is invalid",
    )?;
    if let Some(value) = fence
        && (value.format_version != RUNTIME_FORMAT_VERSION || value.generation == 0)
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "generation prune fence fields are invalid",
        ));
    }
    Ok(fence)
}

fn read_universe_header<S: ReadSnapshot>(
    snapshot: &S,
    universes: &Keyspace,
    universe: [u8; 32],
) -> AnnRuntimeResultV2<Option<UniverseHeaderV2>> {
    let header: Option<UniverseHeaderV2> = read_canonical_json(
        snapshot,
        universes,
        &universe_header_key(universe),
        "authorized universe header is invalid",
    )?;
    if let Some(value) = header
        && (value.format_version != RUNTIME_FORMAT_VERSION
            || value.universe_id != universe
            || value.generation == 0
            || value.route_count > ANN_V2_MAX_NODES)
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "authorized universe header fields are invalid",
        ));
    }
    Ok(header)
}

fn read_generation_lease<S: ReadSnapshot>(
    snapshot: &S,
    leases: &Keyspace,
    generation: u64,
    lease_id: [u8; 32],
) -> AnnRuntimeResultV2<Option<GenerationLeaseV2>> {
    let lease: Option<GenerationLeaseV2> = read_canonical_json(
        snapshot,
        leases,
        &lease_key(generation, lease_id),
        "generation lease is invalid",
    )?;
    if let Some(value) = lease
        && (value.format_version != RUNTIME_FORMAT_VERSION
            || value.generation != generation
            || value.lease_id != lease_id
            || value.universe_id == [0; 32])
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "generation lease fields are invalid",
        ));
    }
    Ok(lease)
}

fn read_overlay_epoch<S: ReadSnapshot>(
    snapshot: &S,
    overlay: &Keyspace,
) -> AnnRuntimeResultV2<u64> {
    match snapshot.get(overlay, OVERLAY_EPOCH_KEY)? {
        None => Ok(0),
        Some(bytes) if bytes.len() == 8 => {
            Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
                AnnRuntimeErrorV2::Invariant("overlay epoch is truncated")
            })?))
        }
        Some(_) => Err(AnnRuntimeErrorV2::Invariant("overlay epoch is invalid")),
    }
}

fn verify_overlay_state<S: ReadSnapshot>(
    snapshot: &S,
    overlay: &Keyspace,
) -> AnnRuntimeResultV2<()> {
    let partition_prefix = overlay_delta_partition_prefix(None);
    let mut partition_cursor = None;
    let mut partition_rows = 0_u64;
    loop {
        let page = snapshot.scan_prefix_page(
            overlay,
            ScanPageRequest {
                prefix: &partition_prefix,
                start_after: partition_cursor.as_deref(),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay partition page made no progress",
            ));
        }
        for entry in &page.entries {
            let (partition, id) = parse_overlay_partition_key(&entry.key)?;
            let route: AnnVectorRouteV2 =
                decode_canonical_json(&entry.value, "overlay route is invalid")?;
            validate_route(&route)?;
            if route.representation_id != id
                || ann_v2_partition_key(
                    route.vector_space_id,
                    canonical_policy_digest(&route.policy)?,
                )? != partition
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "overlay route key and value diverge",
                ));
            }
            let delta = read_overlay_delta(snapshot, overlay, id)?.ok_or(
                AnnRuntimeErrorV2::Invariant("overlay route has no full-precision delta"),
            )?;
            if route_from_record(&delta.record) != route {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "overlay route and full-precision delta diverge",
                ));
            }
            partition_rows = checked_add("overlay partition rows", partition_rows, 1)?;
            if partition_rows > ANN_V2_MAX_NODES {
                return Err(AnnV2Error::ResourceExhausted {
                    resource: "overlay_partition_rows",
                    limit: ANN_V2_MAX_NODES,
                    required: partition_rows,
                }
                .into());
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if partition_cursor
            .as_ref()
            .is_some_and(|previous| next <= *previous)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay partition cursor did not advance",
            ));
        }
        partition_cursor = Some(next);
    }

    let mut delta_cursor = None;
    let mut delta_rows = 0_u64;
    loop {
        let page = snapshot.scan_prefix_page(
            overlay,
            ScanPageRequest {
                prefix: b"d",
                start_after: delta_cursor.as_deref(),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay delta page made no progress",
            ));
        }
        for entry in &page.entries {
            let id = parse_overlay_id_key(&entry.key, b'd')?;
            let delta: OverlayDeltaV2 =
                decode_canonical_json(&entry.value, "overlay delta is invalid")?;
            validate_overlay_delta(&delta, id)?;
            let route = route_from_record(&delta.record);
            let partition = ann_v2_partition_key(
                route.vector_space_id,
                canonical_policy_digest(&route.policy)?,
            )?;
            let route_bytes = serde_json::to_vec(&route)
                .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay route encode failed"))?;
            if snapshot
                .get(overlay, &overlay_delta_partition_key(partition, id))?
                .as_deref()
                != Some(route_bytes.as_slice())
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "overlay delta ID and partition indexes diverge",
                ));
            }
            delta_rows = checked_add("overlay delta rows", delta_rows, 1)?;
            if delta_rows > ANN_V2_MAX_NODES {
                return Err(AnnV2Error::ResourceExhausted {
                    resource: "overlay_delta_rows",
                    limit: ANN_V2_MAX_NODES,
                    required: delta_rows,
                }
                .into());
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if delta_cursor
            .as_ref()
            .is_some_and(|previous| next <= *previous)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay delta cursor did not advance",
            ));
        }
        delta_cursor = Some(next);
    }
    if delta_rows != partition_rows {
        return Err(AnnRuntimeErrorV2::Invariant(
            "overlay delta indexes have different cardinality",
        ));
    }

    let mut tombstone_cursor = None;
    let mut tombstone_rows = 0_u64;
    loop {
        let page = snapshot.scan_prefix_page(
            overlay,
            ScanPageRequest {
                prefix: b"t",
                start_after: tombstone_cursor.as_deref(),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay tombstone page made no progress",
            ));
        }
        for entry in &page.entries {
            let id = parse_overlay_id_key(&entry.key, b't')?;
            let tombstone: OverlayTombstoneV2 =
                decode_canonical_json(&entry.value, "overlay tombstone is invalid")?;
            if tombstone.format_version != RUNTIME_FORMAT_VERSION
                || tombstone.representation_id != id
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "overlay tombstone fields are invalid",
                ));
            }
            tombstone_rows = checked_add("overlay tombstone rows", tombstone_rows, 1)?;
            if tombstone_rows > ANN_V2_MAX_NODES {
                return Err(AnnV2Error::ResourceExhausted {
                    resource: "overlay_tombstone_rows",
                    limit: ANN_V2_MAX_NODES,
                    required: tombstone_rows,
                }
                .into());
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if tombstone_cursor
            .as_ref()
            .is_some_and(|previous| next <= *previous)
        {
            return Err(AnnRuntimeErrorV2::Invariant(
                "overlay tombstone cursor did not advance",
            ));
        }
        tombstone_cursor = Some(next);
    }
    let expected_epoch = checked_add("overlay expected epoch", delta_rows, tombstone_rows)?;
    if read_overlay_epoch(snapshot, overlay)? != expected_epoch {
        return Err(AnnRuntimeErrorV2::Invariant(
            "overlay epoch disagrees with immutable mutations",
        ));
    }
    Ok(())
}

fn validate_overlay_delta(delta: &OverlayDeltaV2, id: RepresentationId) -> AnnRuntimeResultV2<()> {
    if delta.format_version != RUNTIME_FORMAT_VERSION
        || delta.record.id != id
        || delta.record.tombstone_at.is_some()
        || delta.record.values.is_empty()
        || delta.record.values.len() > ANN_V2_MAX_VECTOR_DIMENSIONS
        || delta.record.values.iter().any(|value| !value.is_finite())
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "overlay delta fields are invalid",
        ));
    }
    delta
        .record
        .policy
        .validate()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay delta policy is invalid"))?;
    delta
        .record
        .target
        .validate()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay delta target is invalid"))?;
    validate_route(&route_from_record(&delta.record))?;
    Ok(())
}

fn read_authorized_vector<S: AnnVectorSourceV2, R: ReadSnapshot>(
    source: &S,
    read: &R,
    overlay: &Keyspace,
    row: &UniverseRouteRowV2,
    dimensions: usize,
) -> AnnRuntimeResultV2<Vec<f32>> {
    match row.origin {
        UniverseRouteOriginV2::Base => source.read_vector(row.route.representation_id, dimensions),
        UniverseRouteOriginV2::Delta => {
            let delta = read_overlay_delta(read, overlay, row.route.representation_id)?.ok_or(
                AnnRuntimeErrorV2::Invariant("authorized delta vector disappeared"),
            )?;
            if route_from_record(&delta.record) != row.route
                || delta.record.values.len() != dimensions
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized delta vector diverges from its route",
                ));
            }
            Ok(delta.record.values)
        }
    }
}

fn read_authorized_target<S: AnnVectorSourceV2, R: ReadSnapshot>(
    source: &S,
    read: &R,
    overlay: &Keyspace,
    row: &UniverseRouteRowV2,
    max_bytes: usize,
) -> AnnRuntimeResultV2<LineageNode> {
    match row.origin {
        UniverseRouteOriginV2::Base => source.read_target(row.route.representation_id, max_bytes),
        UniverseRouteOriginV2::Delta => {
            let delta = read_overlay_delta(read, overlay, row.route.representation_id)?.ok_or(
                AnnRuntimeErrorV2::Invariant("authorized delta target disappeared"),
            )?;
            let bytes = serde_json::to_vec(&delta.record.target)
                .map_err(|_| AnnRuntimeErrorV2::Invariant("delta target encode failed"))?;
            if bytes.len() > max_bytes || route_from_record(&delta.record) != row.route {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized delta target exceeds its bound or route",
                ));
            }
            Ok(delta.record.target)
        }
    }
}

fn read_overlay_delta<S: ReadSnapshot>(
    snapshot: &S,
    overlay: &Keyspace,
    id: RepresentationId,
) -> AnnRuntimeResultV2<Option<OverlayDeltaV2>> {
    let delta: Option<OverlayDeltaV2> = read_canonical_json(
        snapshot,
        overlay,
        &overlay_delta_id_key(id),
        "overlay delta is invalid",
    )?;
    if let Some(value) = &delta {
        validate_overlay_delta(value, id)?;
    }
    Ok(delta)
}

fn read_route_manifest_for_generation<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
    generation: u64,
) -> AnnRuntimeResultV2<Option<RouteGenerationManifestV2>> {
    let manifest: Option<RouteGenerationManifestV2> = read_canonical_json(
        snapshot,
        control,
        &route_manifest_key(generation),
        "route generation manifest is invalid",
    )?;
    if let Some(value) = manifest
        && (value.format_version != RUNTIME_FORMAT_VERSION
            || value.generation != generation
            || value.route_count > ANN_V2_MAX_NODES
            || value.route_digest == [0; 32])
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "route generation manifest fields are invalid",
        ));
    }
    Ok(manifest)
}

fn compute_route_generation<S: ReadSnapshot>(
    snapshot: &S,
    routes: &Keyspace,
    generation: u64,
) -> AnnRuntimeResultV2<RouteGenerationManifestV2> {
    let prefix = persistent_route_generation_prefix(generation);
    let mut cursor = None;
    let mut count = 0_u64;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROUTE_GENERATION_DOMAIN);
    hasher.update(&generation.to_be_bytes());
    loop {
        let page = snapshot.scan_prefix_page(
            routes,
            ScanPageRequest {
                prefix: &prefix,
                start_after: cursor.as_deref(),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "persistent route page made no progress",
            ));
        }
        for entry in &page.entries {
            let (actual_generation, partition, id) = parse_persistent_route_key(&entry.key)?;
            if actual_generation != generation {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "persistent route belongs to another generation",
                ));
            }
            let route: AnnVectorRouteV2 =
                decode_canonical_json(&entry.value, "persistent route is not canonical")?;
            validate_route(&route)?;
            if route.representation_id != id
                || ann_v2_partition_key(
                    route.vector_space_id,
                    canonical_policy_digest(&route.policy)?,
                )? != partition
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "persistent route key and value diverge",
                ));
            }
            if snapshot
                .get(routes, &persistent_route_id_key(generation, id))?
                .as_deref()
                != Some(entry.value.as_slice())
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "persistent route ID index diverges",
                ));
            }
            hasher.update(&(entry.key.len() as u64).to_be_bytes());
            hasher.update(&entry.key);
            hasher.update(&(entry.value.len() as u64).to_be_bytes());
            hasher.update(&entry.value);
            count = checked_add("persistent route count", count, 1)?;
            if count > ANN_V2_MAX_NODES {
                return Err(AnnV2Error::ResourceExhausted {
                    resource: "persistent_routes",
                    limit: ANN_V2_MAX_NODES,
                    required: count,
                }
                .into());
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if cursor.as_ref().is_some_and(|previous| next <= *previous) {
            return Err(AnnRuntimeErrorV2::Invariant(
                "persistent route cursor did not advance",
            ));
        }
        cursor = Some(next);
    }
    let id_prefix = persistent_route_id_prefix(generation);
    let mut id_cursor = None;
    let mut id_count = 0_u64;
    loop {
        let page = snapshot.scan_prefix_page(
            routes,
            ScanPageRequest {
                prefix: &id_prefix,
                start_after: id_cursor.as_deref(),
                max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                max_bytes: ANN_V2_MAX_PAGE_BYTES,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Invariant(
                "persistent route ID page made no progress",
            ));
        }
        for entry in &page.entries {
            let (actual_generation, id) = parse_persistent_route_id_key(&entry.key)?;
            if actual_generation != generation {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "persistent route ID belongs to another generation",
                ));
            }
            let route: AnnVectorRouteV2 =
                decode_canonical_json(&entry.value, "persistent route ID is not canonical")?;
            validate_route(&route)?;
            let partition = ann_v2_partition_key(
                route.vector_space_id,
                canonical_policy_digest(&route.policy)?,
            )?;
            if route.representation_id != id
                || snapshot
                    .get(routes, &persistent_route_key(generation, partition, id))?
                    .as_deref()
                    != Some(entry.value.as_slice())
            {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "persistent route partition index diverges",
                ));
            }
            id_count = checked_add("persistent route ID count", id_count, 1)?;
            if id_count > ANN_V2_MAX_NODES {
                return Err(AnnV2Error::ResourceExhausted {
                    resource: "persistent_route_ids",
                    limit: ANN_V2_MAX_NODES,
                    required: id_count,
                }
                .into());
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if id_cursor.as_ref().is_some_and(|previous| next <= *previous) {
            return Err(AnnRuntimeErrorV2::Invariant(
                "persistent route ID cursor did not advance",
            ));
        }
        id_cursor = Some(next);
    }
    if id_count != count {
        return Err(AnnRuntimeErrorV2::Invariant(
            "persistent route indexes have different cardinality",
        ));
    }
    Ok(RouteGenerationManifestV2 {
        format_version: RUNTIME_FORMAT_VERSION,
        generation,
        route_count: count,
        route_digest: *hasher.finalize().as_bytes(),
    })
}

fn verify_route_generation<S: ReadSnapshot>(
    snapshot: &S,
    control: &Keyspace,
    routes: &Keyspace,
    generation: u64,
    expected_count: u64,
) -> AnnRuntimeResultV2<RouteGenerationManifestV2> {
    let expected = read_route_manifest_for_generation(snapshot, control, generation)?.ok_or(
        AnnRuntimeErrorV2::Invariant("route generation manifest is absent"),
    )?;
    let actual = compute_route_generation(snapshot, routes, generation)?;
    if expected != actual || actual.route_count != expected_count {
        return Err(AnnRuntimeErrorV2::Invariant(
            "persistent route generation verification failed",
        ));
    }
    Ok(actual)
}

fn read_canonical_json<T: for<'de> Deserialize<'de> + Serialize, S: ReadSnapshot>(
    snapshot: &S,
    keyspace: &Keyspace,
    key: &[u8],
    error: &'static str,
) -> AnnRuntimeResultV2<Option<T>> {
    snapshot
        .get(keyspace, key)?
        .map(|bytes| decode_canonical_json(&bytes, error))
        .transpose()
}

fn decode_canonical_json<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    error: &'static str,
) -> AnnRuntimeResultV2<T> {
    let value = serde_json::from_slice(bytes).map_err(|_| AnnRuntimeErrorV2::Invariant(error))?;
    if serde_json::to_vec(&value).map_err(|_| AnnRuntimeErrorV2::Invariant(error))? != bytes {
        return Err(AnnRuntimeErrorV2::Invariant(error));
    }
    Ok(value)
}

fn delete_prefix_pages<E: StorageEngine>(
    engine: &E,
    keyspace: &Keyspace,
    prefix: &[u8],
    durability: Durability,
) -> AnnRuntimeResultV2<u64> {
    let mut deleted = 0_u64;
    loop {
        let read = engine.begin_read(SnapshotSelector::Latest)?;
        let page = read.scan_prefix_page(
            keyspace,
            ScanPageRequest {
                prefix,
                start_after: None,
                max_entries: CLEAN_PAGE_ENTRIES,
                max_bytes: CLEAN_PAGE_BYTES,
            },
        )?;
        drop(read);
        if page.entries.is_empty() {
            return Ok(deleted);
        }
        let mut write = engine.begin_write()?;
        for entry in page.entries {
            write.delete(keyspace, entry.key)?;
            deleted = deleted.saturating_add(1);
        }
        write.commit(durability)?;
    }
}

fn manifest_key(generation: u64) -> Vec<u8> {
    let mut key = MANIFEST_PREFIX.to_vec();
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn route_manifest_key(generation: u64) -> Vec<u8> {
    let mut key = ROUTE_MANIFEST_PREFIX.to_vec();
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn persistent_route_generation_prefix(generation: u64) -> Vec<u8> {
    let mut key = vec![b'g'];
    key.extend_from_slice(&generation.to_be_bytes());
    key.push(b'p');
    key
}

fn persistent_route_partition_prefix(generation: u64, partition: [u8; 32]) -> Vec<u8> {
    let mut key = persistent_route_generation_prefix(generation);
    key.extend_from_slice(&partition);
    key
}

fn persistent_route_key(generation: u64, partition: [u8; 32], id: RepresentationId) -> Vec<u8> {
    let mut key = persistent_route_partition_prefix(generation, partition);
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn persistent_route_id_prefix(generation: u64) -> Vec<u8> {
    let mut key = vec![b'g'];
    key.extend_from_slice(&generation.to_be_bytes());
    key.push(b'i');
    key
}

fn persistent_route_id_key(generation: u64, id: RepresentationId) -> Vec<u8> {
    let mut key = persistent_route_id_prefix(generation);
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn parse_persistent_route_key(key: &[u8]) -> AnnRuntimeResultV2<(u64, [u8; 32], RepresentationId)> {
    if key.len() != 78 || key.first() != Some(&b'g') || key.get(9) != Some(&b'p') {
        return Err(AnnRuntimeErrorV2::Invariant(
            "persistent route key is invalid",
        ));
    }
    let generation = u64::from_be_bytes(
        key[1..9]
            .try_into()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("route generation is truncated"))?,
    );
    let partition = key[10..42]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("route partition is truncated"))?;
    let id = std::str::from_utf8(&key[42..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("route ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("route ID is invalid"))?;
    Ok((generation, partition, id))
}

fn parse_persistent_route_id_key(key: &[u8]) -> AnnRuntimeResultV2<(u64, RepresentationId)> {
    if key.len() != 46 || key.first() != Some(&b'g') || key.get(9) != Some(&b'i') {
        return Err(AnnRuntimeErrorV2::Invariant(
            "persistent route ID key is invalid",
        ));
    }
    let generation = u64::from_be_bytes(
        key[1..9]
            .try_into()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("route ID generation is truncated"))?,
    );
    let id = std::str::from_utf8(&key[10..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("route ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("route ID is invalid"))?;
    Ok((generation, id))
}

fn universe_header_key(universe: [u8; 32]) -> Vec<u8> {
    let mut key = vec![b'h'];
    key.extend_from_slice(&universe);
    key
}

fn universe_partition_prefix(universe: [u8; 32]) -> Vec<u8> {
    let mut key = vec![b'p'];
    key.extend_from_slice(&universe);
    key
}

fn universe_partition_key(universe: [u8; 32], partition: [u8; 32]) -> Vec<u8> {
    let mut key = universe_partition_prefix(universe);
    key.extend_from_slice(&partition);
    key
}

fn parse_universe_partition_key(key: &[u8]) -> AnnRuntimeResultV2<([u8; 32], [u8; 32])> {
    if key.len() != 65 || key.first() != Some(&b'p') {
        return Err(AnnRuntimeErrorV2::Invariant(
            "authorized partition key is invalid",
        ));
    }
    let universe = key[1..33]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized universe ID is truncated"))?;
    let partition = key[33..65]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized partition is truncated"))?;
    Ok((universe, partition))
}

fn universe_route_partition_prefix(universe: [u8; 32], partition: [u8; 32]) -> Vec<u8> {
    let mut key = vec![b'r'];
    key.extend_from_slice(&universe);
    key.extend_from_slice(&partition);
    key
}

fn universe_route_partition_key(
    universe: [u8; 32],
    partition: [u8; 32],
    id: RepresentationId,
) -> Vec<u8> {
    let mut key = universe_route_partition_prefix(universe, partition);
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn universe_route_id_prefix(universe: [u8; 32]) -> Vec<u8> {
    let mut key = vec![b'i'];
    key.extend_from_slice(&universe);
    key
}

fn universe_route_id_key(universe: [u8; 32], id: RepresentationId) -> Vec<u8> {
    let mut key = universe_route_id_prefix(universe);
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn parse_universe_route_id_key(key: &[u8]) -> AnnRuntimeResultV2<([u8; 32], RepresentationId)> {
    if key.len() != 69 || key.first() != Some(&b'i') {
        return Err(AnnRuntimeErrorV2::Invariant(
            "authorized route ID key is invalid",
        ));
    }
    let universe = key[1..33]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized universe ID is truncated"))?;
    let id = std::str::from_utf8(&key[33..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized route ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized route ID is invalid"))?;
    Ok((universe, id))
}

fn parse_universe_route_partition_key(
    key: &[u8],
) -> AnnRuntimeResultV2<([u8; 32], [u8; 32], RepresentationId)> {
    if key.len() != 101 || key.first() != Some(&b'r') {
        return Err(AnnRuntimeErrorV2::Invariant(
            "authorized partition route key is invalid",
        ));
    }
    let universe = key[1..33]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized universe ID is truncated"))?;
    let partition = key[33..65]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized route partition is truncated"))?;
    let id = std::str::from_utf8(&key[65..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized route ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("authorized route ID is invalid"))?;
    Ok((universe, partition, id))
}

fn overlay_delta_id_key(id: RepresentationId) -> Vec<u8> {
    let mut key = vec![b'd'];
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn overlay_delta_partition_prefix(partition: Option<[u8; 32]>) -> Vec<u8> {
    let mut key = vec![b'p'];
    if let Some(partition) = partition {
        key.extend_from_slice(&partition);
    }
    key
}

fn overlay_delta_partition_key(partition: [u8; 32], id: RepresentationId) -> Vec<u8> {
    let mut key = overlay_delta_partition_prefix(Some(partition));
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn overlay_tombstone_key(id: RepresentationId) -> Vec<u8> {
    let mut key = vec![b't'];
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn lease_generation_prefix(generation: u64) -> Vec<u8> {
    let mut key = vec![b'g'];
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn lease_key(generation: u64, lease: [u8; 32]) -> Vec<u8> {
    let mut key = lease_generation_prefix(generation);
    key.extend_from_slice(&lease);
    key
}

fn runtime_id(
    domain: &[u8],
    storage_sequence: u64,
    generation: u64,
    snapshot: CommitSeq,
    local: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&storage_sequence.to_be_bytes());
    hasher.update(&generation.to_be_bytes());
    hasher.update(&snapshot.get().to_be_bytes());
    hasher.update(&local.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn parse_overlay_partition_key(key: &[u8]) -> AnnRuntimeResultV2<([u8; 32], RepresentationId)> {
    if key.len() != 69 || key.first() != Some(&b'p') {
        return Err(AnnRuntimeErrorV2::Invariant(
            "overlay partition key is invalid",
        ));
    }
    let partition = key[1..33]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay partition is truncated"))?;
    let id = std::str::from_utf8(&key[33..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay ID is invalid"))?;
    Ok((partition, id))
}

fn parse_overlay_id_key(key: &[u8], tag: u8) -> AnnRuntimeResultV2<RepresentationId> {
    if key.len() != 37 || key.first() != Some(&tag) {
        return Err(AnnRuntimeErrorV2::Invariant("overlay point key is invalid"));
    }
    std::str::from_utf8(&key[1..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay point ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("overlay point ID is invalid"))
}

fn put_universe_route<W: WriteTransaction>(
    write: &mut W,
    universes: &Keyspace,
    universe: [u8; 32],
    row: UniverseRouteRowV2,
) -> AnnRuntimeResultV2<()> {
    validate_universe_route_row(&row, row.route.representation_id)?;
    let bytes = serde_json::to_vec(&row)
        .map_err(|_| AnnRuntimeErrorV2::Invariant("universe route encode failed"))?;
    if bytes.len() > ANN_V2_MAX_OBJECT_BYTES {
        return Err(AnnV2Error::ResourceExhausted {
            resource: "universe_route_bytes",
            limit: ANN_V2_MAX_OBJECT_BYTES as u64,
            required: bytes.len() as u64,
        }
        .into());
    }
    write.put(
        universes,
        universe_route_partition_key(universe, row.partition, row.route.representation_id),
        bytes.clone(),
    )?;
    write.put(
        universes,
        universe_route_id_key(universe, row.route.representation_id),
        bytes,
    )?;
    Ok(())
}

fn validate_universe_route_row(
    row: &UniverseRouteRowV2,
    id: RepresentationId,
) -> AnnRuntimeResultV2<()> {
    validate_route(&row.route)?;
    if row.route.representation_id != id
        || ann_v2_partition_key(
            row.route.vector_space_id,
            canonical_policy_digest(&row.route.policy)?,
        )? != row.partition
    {
        return Err(AnnRuntimeErrorV2::Invariant(
            "authorized route row fields diverge",
        ));
    }
    Ok(())
}

fn put_universe_partition<W: WriteTransaction>(
    write: &mut W,
    universes: &Keyspace,
    universe: [u8; 32],
    partition: [u8; 32],
    base_total: u64,
    authorized_base: u64,
) -> AnnRuntimeResultV2<()> {
    if authorized_base > base_total {
        return Err(AnnRuntimeErrorV2::Invariant(
            "authorized partition count exceeds base count",
        ));
    }
    write.put(
        universes,
        universe_partition_key(universe, partition),
        serde_json::to_vec(&UniversePartitionV2 {
            partition,
            base_total,
            authorized_base,
        })
        .map_err(|_| AnnRuntimeErrorV2::Invariant("universe partition encode failed"))?,
    )?;
    Ok(())
}

fn build_generation_prefix(generation: u64) -> Vec<u8> {
    let mut key = vec![b'r'];
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn build_partition_prefix(generation: u64, partition: [u8; 32]) -> Vec<u8> {
    let mut key = build_generation_prefix(generation);
    key.extend_from_slice(&partition);
    key
}

fn build_route_key(generation: u64, partition: [u8; 32], id: RepresentationId) -> Vec<u8> {
    let mut key = build_partition_prefix(generation, partition);
    key.extend_from_slice(id.to_string().as_bytes());
    key
}

fn parse_build_route_key(key: &[u8]) -> AnnRuntimeResultV2<(u64, [u8; 32], RepresentationId)> {
    if key.len() != 77 || key.first() != Some(&b'r') {
        return Err(AnnRuntimeErrorV2::Invariant("staged route key is invalid"));
    }
    let generation = u64::from_be_bytes(
        key[1..9]
            .try_into()
            .map_err(|_| AnnRuntimeErrorV2::Invariant("staged generation is truncated"))?,
    );
    let partition = key[9..41]
        .try_into()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("staged partition is truncated"))?;
    let id = std::str::from_utf8(&key[41..])
        .map_err(|_| AnnRuntimeErrorV2::Invariant("staged ID is not UTF-8"))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Invariant("staged ID is invalid"))?;
    Ok((generation, partition, id))
}

fn node_prefix(generation: u64, partition: [u8; 32]) -> AnnRuntimeResultV2<Vec<u8>> {
    let mut prefix = ann_v2_generation_prefix(generation)?;
    prefix.push(b'n');
    prefix.extend_from_slice(&partition);
    Ok(prefix)
}

fn partition_manifest_prefix(generation: u64) -> AnnRuntimeResultV2<Vec<u8>> {
    let mut prefix = ann_v2_generation_prefix(generation)?;
    prefix.push(b'p');
    Ok(prefix)
}

fn tree_key(
    scope: AnnMerkleScopeV2,
    leaf_count: u64,
    level: u16,
    index: u64,
) -> Result<AnnObjectKeyV2, AnnV2Error> {
    match scope {
        AnnMerkleScopeV2::PartitionNodes {
            generation,
            partition_key,
        } => AnnObjectKeyV2::partition_tree(generation, partition_key, leaf_count, level, index),
        AnnMerkleScopeV2::GenerationPartitions { generation } => {
            AnnObjectKeyV2::global_tree(generation, leaf_count, level, index)
        }
    }
}

fn checked_add(resource: &'static str, left: u64, right: u64) -> AnnRuntimeResultV2<u64> {
    left.checked_add(right)
        .ok_or(AnnRuntimeErrorV2::Invariant(resource))
}

fn intersect_until(
    left: Option<TimestampMicros>,
    right: Option<TimestampMicros>,
) -> Option<TimestampMicros> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn deterministic_level_v2(id: RepresentationId) -> u8 {
    let digest = blake3::hash(id.as_uuid().as_bytes());
    (digest.as_bytes()[0].leading_zeros() / 2).min(4) as u8
}

fn bounded_dimensions(space: &VectorSpace) -> AnnRuntimeResultV2<usize> {
    let dimensions = usize::try_from(space.dimensions)
        .map_err(|_| AnnRuntimeErrorV2::Source("vector dimensions overflow"))?;
    if dimensions == 0 || dimensions > ANN_V2_MAX_VECTOR_DIMENSIONS {
        return Err(AnnRuntimeErrorV2::Source(
            "vector dimensions exceed the runtime point-read limit",
        ));
    }
    Ok(dimensions)
}

fn canonical_policy_digest(policy: &IndexPolicy) -> AnnRuntimeResultV2<[u8; 32]> {
    policy
        .validate()
        .map_err(|_| AnnRuntimeErrorV2::Source("index policy is invalid"))?;
    let bytes = serde_json::to_vec(policy)
        .map_err(|_| AnnRuntimeErrorV2::Source("index policy encode failed"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_DIGEST_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn validate_route(route: &AnnVectorRouteV2) -> AnnRuntimeResultV2<()> {
    if route.representation_id.as_uuid().is_nil()
        || route.vector_space_id.as_uuid().is_nil()
        || route.membership_epoch == 0
    {
        return Err(AnnRuntimeErrorV2::Source("route identity is invalid"));
    }
    route
        .policy
        .validate()
        .map_err(|_| AnnRuntimeErrorV2::Source("route policy is invalid"))?;
    if route
        .valid_until
        .is_some_and(|until| until <= route.valid_from)
        || route
            .tombstone_at
            .is_some_and(|deleted| deleted < route.projected_at)
    {
        return Err(AnnRuntimeErrorV2::Source(
            "route validity or tombstone ordering is invalid",
        ));
    }
    Ok(())
}

fn validate_route_page(
    start_after: Option<RepresentationId>,
    max_entries: usize,
    max_bytes: usize,
    page: &AnnVectorRoutePageV2,
) -> AnnRuntimeResultV2<()> {
    if max_entries == 0
        || max_entries > ANN_V2_MAX_PAGE_ENTRIES
        || max_bytes == 0
        || max_bytes > ANN_V2_MAX_PAGE_BYTES
        || page.routes.len() > max_entries
    {
        return Err(AnnRuntimeErrorV2::Source("route page is oversized"));
    }
    let mut previous = start_after;
    let mut used_bytes = 0_usize;
    for route in &page.routes {
        validate_route(route)?;
        let route_bytes = serde_json::to_vec(route)
            .map_err(|_| AnnRuntimeErrorV2::Source("route encode failed"))?
            .len();
        used_bytes = used_bytes
            .checked_add(route_bytes)
            .ok_or(AnnRuntimeErrorV2::Source(
                "route page byte count overflowed",
            ))?;
        if used_bytes > max_bytes {
            return Err(AnnRuntimeErrorV2::Source(
                "route page exceeds its byte limit",
            ));
        }
        if previous.is_some_and(|prior| route.representation_id <= prior) {
            return Err(AnnRuntimeErrorV2::Source(
                "route page is not in strict exclusive order",
            ));
        }
        previous = Some(route.representation_id);
    }
    match (page.continuation, page.routes.last()) {
        (Some(_), None) => Err(AnnRuntimeErrorV2::Source(
            "empty route page has continuation",
        )),
        (Some(continuation), Some(last)) if continuation != last.representation_id => Err(
            AnnRuntimeErrorV2::Source("route continuation is not the final ID"),
        ),
        _ => Ok(()),
    }
}

fn verify_runtime_generation<R: AnnObjectReaderV2>(
    reader: &R,
    manifest: &AnnGenerationManifestV2,
) -> AnnRuntimeResultV2<AnnGenerationVerificationV2> {
    let verification = verify_ann_generation_v2(reader, manifest)?;
    let prefix = partition_manifest_prefix(manifest.generation)?;
    let mut cursor = None;
    let mut verified_partitions = 0_u64;
    loop {
        let request = AnnObjectPageRequestV2 {
            prefix: &prefix,
            start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
            max_entries: ANN_V2_MAX_PAGE_ENTRIES,
            max_bytes: ANN_V2_MAX_PAGE_BYTES,
        };
        let page = reader.scan_page(request)?;
        for object in page.objects() {
            let partition = AnnPartitionManifestV2::decode_json(object.value())?;
            verify_partition_connectivity(reader, &partition)?;
            verified_partitions =
                checked_add("verified connected partitions", verified_partitions, 1)?;
        }
        let Some(next) = page.continuation().cloned() else {
            break;
        };
        cursor = Some(next);
    }
    if verified_partitions != manifest.partition_count {
        return Err(AnnRuntimeErrorV2::Invariant(
            "connected partition count is incomplete",
        ));
    }
    Ok(verification)
}

fn verify_partition_connectivity<R: AnnObjectReaderV2>(
    reader: &R,
    partition: &AnnPartitionManifestV2,
) -> AnnRuntimeResultV2<()> {
    let mut queue = VecDeque::from([partition.entry]);
    let mut visited = BTreeSet::from([partition.entry]);
    while let Some(id) = queue.pop_front() {
        let node = read_node_object(reader, partition, id)?;
        for neighbour in &node.levels[0].neighbours {
            if visited.insert(*neighbour) {
                if visited.len() as u64 > partition.node_count {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "base-layer traversal exceeds the partition node count",
                    ));
                }
                queue.push_back(*neighbour);
            }
        }
    }
    if visited.len() as u64 != partition.node_count {
        return Err(AnnRuntimeErrorV2::Invariant(
            "ANN base layer is disconnected",
        ));
    }
    Ok(())
}

struct PersistentUniverseReaderV2<'a, S: ReadSnapshot> {
    snapshot: &'a S,
    universes: &'a Keyspace,
    overlay: &'a Keyspace,
    universe_id: [u8; 32],
}

impl<S: ReadSnapshot> PersistentUniverseReaderV2<'_, S> {
    fn is_tombstoned(&self, id: RepresentationId) -> AnnRuntimeResultV2<bool> {
        Ok(self
            .snapshot
            .get(self.overlay, &overlay_tombstone_key(id))?
            .is_some())
    }

    fn route(&self, id: RepresentationId) -> AnnRuntimeResultV2<Option<UniverseRouteRowV2>> {
        if self.is_tombstoned(id)? {
            return Ok(None);
        }
        let row: Option<UniverseRouteRowV2> = read_canonical_json(
            self.snapshot,
            self.universes,
            &universe_route_id_key(self.universe_id, id),
            "authorized route row is invalid",
        )?;
        if let Some(row) = &row {
            validate_universe_route_row(row, id)?;
            let partition_copy: Option<UniverseRouteRowV2> = read_canonical_json(
                self.snapshot,
                self.universes,
                &universe_route_partition_key(self.universe_id, row.partition, id),
                "authorized partition route row is invalid",
            )?;
            if partition_copy.as_ref() != Some(row) {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized route point indexes diverge",
                ));
            }
        }
        Ok(row)
    }

    fn count_visible_base_routes(
        &self,
        partition: [u8; 32],
        snapshot: CommitSeq,
        valid_at: Option<TimestampMicros>,
    ) -> AnnRuntimeResultV2<u64> {
        let prefix = universe_route_partition_prefix(self.universe_id, partition);
        let mut cursor = None;
        let mut count = 0_u64;
        loop {
            let page = self.snapshot.scan_prefix_page(
                self.universes,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: cursor.as_deref(),
                    max_entries: ANN_V2_MAX_PAGE_ENTRIES,
                    max_bytes: ANN_V2_MAX_PAGE_BYTES,
                },
            )?;
            if page.continuation.is_some() && page.entries.is_empty() {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized partition route page made no progress",
                ));
            }
            for entry in &page.entries {
                let (row_universe, row_partition, row_id) =
                    parse_universe_route_partition_key(&entry.key)?;
                let row: UniverseRouteRowV2 =
                    decode_canonical_json(&entry.value, "authorized partition route is invalid")?;
                validate_universe_route_row(&row, row_id)?;
                let id_copy: Option<UniverseRouteRowV2> = read_canonical_json(
                    self.snapshot,
                    self.universes,
                    &universe_route_id_key(self.universe_id, row_id),
                    "authorized route ID row is invalid",
                )?;
                if row_universe != self.universe_id
                    || row_partition != partition
                    || row.partition != partition
                    || id_copy.as_ref() != Some(&row)
                {
                    return Err(AnnRuntimeErrorV2::Invariant(
                        "authorized partition route indexes diverge",
                    ));
                }
                if row.origin == UniverseRouteOriginV2::Base
                    && !self.is_tombstoned(row.route.representation_id)?
                    && row.route.visible_at(snapshot, valid_at)
                {
                    count = checked_add("visible authorized routes", count, 1)?;
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(AnnRuntimeErrorV2::Invariant(
                    "authorized partition route cursor did not advance",
                ));
            }
            cursor = Some(next);
        }
        Ok(count)
    }
}

#[derive(Clone, Copy, Debug)]
struct QueryCandidateV2 {
    id: RepresentationId,
    score: f32,
}

#[allow(
    clippy::too_many_arguments,
    reason = "persistent partition identity and policy-safe query controls stay explicit"
)]
fn traverse_persistent_partition<R: AnnObjectReaderV2, S: AnnVectorSourceV2>(
    reader: &R,
    source: &S,
    partition: &AnnPartitionManifestV2,
    space: &VectorSpace,
    query: &[f32],
    universe: &PersistentUniverseReaderV2<'_, impl ReadSnapshot>,
    max_visits: usize,
    ef_search: usize,
) -> AnnRuntimeResultV2<(BTreeSet<RepresentationId>, usize, u64)> {
    let dimensions = bounded_dimensions(space)?;
    let mut current = partition.entry;
    let mut node_reads = 0_usize;
    let mut vector_reads = 0_u64;
    let mut score_cache = BTreeMap::new();

    for level in (1..=partition.max_level).rev() {
        loop {
            let current_score = score_query_candidate(
                source,
                universe,
                space,
                query,
                current,
                dimensions,
                &mut score_cache,
                &mut vector_reads,
            )?;
            let node = read_node_object(reader, partition, current)?;
            node_reads = node_reads.saturating_add(1);
            if node_reads > max_visits {
                return Ok((BTreeSet::from([current]), max_visits, vector_reads));
            }
            let mut best = QueryCandidateV2 {
                id: current,
                score: current_score,
            };
            for neighbour in &node.levels[usize::from(level)].neighbours {
                let candidate_score = score_query_candidate(
                    source,
                    universe,
                    space,
                    query,
                    *neighbour,
                    dimensions,
                    &mut score_cache,
                    &mut vector_reads,
                )?;
                if candidate_score > best.score
                    || (candidate_score == best.score && *neighbour < best.id)
                {
                    best = QueryCandidateV2 {
                        id: *neighbour,
                        score: candidate_score,
                    };
                }
            }
            if best.id == current {
                break;
            }
            current = best.id;
        }
    }

    let mut queue = VecDeque::from([current]);
    let mut discovered = BTreeSet::from([current]);
    let mut ranked = Vec::new();
    while let Some(id) = queue.pop_front() {
        if node_reads >= max_visits {
            break;
        }
        let candidate_score = score_query_candidate(
            source,
            universe,
            space,
            query,
            id,
            dimensions,
            &mut score_cache,
            &mut vector_reads,
        )?;
        ranked.push(QueryCandidateV2 {
            id,
            score: candidate_score,
        });
        let node = read_node_object(reader, partition, id)?;
        node_reads = node_reads.saturating_add(1);
        for neighbour in &node.levels[0].neighbours {
            if discovered.len() < max_visits && discovered.insert(*neighbour) {
                queue.push_back(*neighbour);
            }
        }
    }
    ranked.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok((
        ranked
            .into_iter()
            .take(ef_search)
            .map(|candidate| candidate.id)
            .collect(),
        node_reads,
        vector_reads,
    ))
}

fn read_node_object<R: AnnObjectReaderV2>(
    reader: &R,
    partition: &AnnPartitionManifestV2,
    id: RepresentationId,
) -> AnnRuntimeResultV2<AnnNodeV2> {
    let key = AnnObjectKeyV2::node(partition.generation, partition.partition_key, id)?;
    let request = AnnObjectReadRequestV2 {
        key: &key,
        max_bytes: crate::ANN_V2_MAX_NODE_BYTES,
    };
    let response = reader.get_bounded(request)?;
    let object = response
        .into_object()
        .ok_or(AnnRuntimeErrorV2::Invariant("query node is absent"))?;
    Ok(AnnNodeV2::decode_canonical(object.value())?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "authorization membership, dimension bound, and read counters are independent gates"
)]
fn score_query_candidate<S: AnnVectorSourceV2>(
    source: &S,
    universe: &PersistentUniverseReaderV2<'_, impl ReadSnapshot>,
    space: &VectorSpace,
    query: &[f32],
    id: RepresentationId,
    dimensions: usize,
    cache: &mut BTreeMap<RepresentationId, f32>,
    vector_reads: &mut u64,
) -> AnnRuntimeResultV2<f32> {
    if let Some(existing) = cache.get(&id) {
        return Ok(*existing);
    }
    let Some(row) = universe.route(id)? else {
        return Err(AnnRuntimeErrorV2::Invariant(
            "ANN attempted to materialize an unauthorized vector",
        ));
    };
    if row.origin != UniverseRouteOriginV2::Base {
        return Err(AnnRuntimeErrorV2::Invariant(
            "ANN base traversal reached a delta-only representation",
        ));
    }
    let values = source.read_vector(id, dimensions)?;
    validate_values(space, &values)
        .map_err(|_| AnnRuntimeErrorV2::Source("stored vector is invalid"))?;
    let value = score(space.metric, query, &values)
        .map_err(|_| AnnRuntimeErrorV2::Source("vector score is invalid"))?;
    cache.insert(id, value);
    *vector_reads = vector_reads.saturating_add(1);
    Ok(value)
}

#[cfg(test)]
#[path = "ann_v2_runtime_tests.rs"]
mod tests;
