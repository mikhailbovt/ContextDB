//! Durable, paged full-precision vector and policy-routing source for ANN-v2.
//!
//! Import is append-only and restartable. Every page is written atomically,
//! duplicate bytes are idempotent, and an existing identifier can never be
//! rebound. Publication recomputes the vector, route, and vector-space roots
//! from bounded scans before replacing the import fence with an immutable seal.

use std::collections::BTreeSet;
use std::str::FromStr;

use contextdb_core::{LineageNode, RepresentationId, Validate, VectorSpaceId};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
    WriteTransaction,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::ann_v2_runtime::{
    MAX_TARGET_BYTES, REGISTRY_DIGEST_DOMAIN, ROUTE_ROOT_DOMAIN, VECTOR_ROOT_DOMAIN,
    route_from_record,
};
use crate::{
    ANN_V2_MAX_NODES, ANN_V2_MAX_PAGE_BYTES, ANN_V2_MAX_PAGE_ENTRIES, ANN_V2_MAX_VECTOR_DIMENSIONS,
    AnnRuntimeErrorV2, AnnRuntimeResultV2, AnnSourceSealV2, AnnVectorRoutePageV2, AnnVectorRouteV2,
    AnnVectorSourceV2, VectorRecord, VectorSpace, validate_values,
};

const CONTROL_KEYSPACE: &str = "ann_source_control";
const SPACE_KEYSPACE: &str = "ann_source_spaces";
const ROUTE_KEYSPACE: &str = "ann_source_routes";
const VECTOR_KEYSPACE: &str = "ann_source_vectors";
const TARGET_KEYSPACE: &str = "ann_source_targets";
const ACTIVE_KEY: &[u8] = b"active_source";
const IMPORT_FENCE_KEY: &[u8] = b"import_fence";
const SOURCE_FORMAT_VERSION: u16 = 1;
const SOURCE_PAGE_ENTRIES: usize = 1_024;
const SOURCE_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_VECTOR_SPACES: u64 = 65_536;
const MAX_SPACE_BYTES: usize = 64 * 1024;

/// Immutable identity and expected cardinality of one source import.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnSourceImportPlanV2 {
    pub vector_store_generation: u64,
    pub route_generation: u64,
    pub expected_vector_spaces: u64,
    pub expected_records: u64,
}

impl AnnSourceImportPlanV2 {
    fn validate(self) -> AnnRuntimeResultV2<()> {
        if self.vector_store_generation == 0 || self.route_generation == 0 {
            return Err(AnnRuntimeErrorV2::Source("source generation is zero"));
        }
        if self.expected_vector_spaces == 0 || self.expected_vector_spaces > MAX_VECTOR_SPACES {
            return Err(AnnRuntimeErrorV2::Source(
                "vector-space count exceeds the durable source limit",
            ));
        }
        if self.expected_records == 0 || self.expected_records > ANN_V2_MAX_NODES {
            return Err(AnnRuntimeErrorV2::Source(
                "record count exceeds the durable source limit",
            ));
        }
        Ok(())
    }
}

/// Bounded verification evidence produced from physical source rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnSourceVerificationV2 {
    pub seal: AnnSourceSealV2,
    pub vector_space_count: u64,
    pub record_count: u64,
    pub storage_sequence: u64,
    pub vector_space_pages: u64,
    pub route_pages: u64,
    pub vector_key_pages: u64,
    pub target_key_pages: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportFenceV2 {
    format_version: u16,
    plan: AnnSourceImportPlanV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifestV2 {
    format_version: u16,
    plan: AnnSourceImportPlanV2,
    vector_store_root: [u8; 32],
    route_root: [u8; 32],
    vector_space_registry_digest: [u8; 32],
    vector_space_count: u64,
    record_count: u64,
}

impl SourceManifestV2 {
    fn seal(&self) -> AnnSourceSealV2 {
        AnnSourceSealV2 {
            vector_store_generation: self.plan.vector_store_generation,
            vector_store_root: self.vector_store_root,
            route_generation: self.plan.route_generation,
            route_root: self.route_root,
            vector_space_registry_digest: self.vector_space_registry_digest,
        }
    }

    fn validate(&self) -> AnnRuntimeResultV2<()> {
        if self.format_version != SOURCE_FORMAT_VERSION {
            return Err(AnnRuntimeErrorV2::Source(
                "durable source manifest version is unsupported",
            ));
        }
        self.plan.validate()?;
        if self.vector_space_count != self.plan.expected_vector_spaces
            || self.record_count != self.plan.expected_records
        {
            return Err(AnnRuntimeErrorV2::Source(
                "durable source manifest cardinality diverges from its import plan",
            ));
        }
        self.seal().validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredVectorV2 {
    format_version: u16,
    vector_space_id: VectorSpaceId,
    values: Vec<f32>,
}

#[derive(Debug)]
struct SourceKeyspaces {
    control: Keyspace,
    spaces: Keyspace,
    routes: Keyspace,
    vectors: Keyspace,
    targets: Keyspace,
}

impl SourceKeyspaces {
    fn new() -> AnnRuntimeResultV2<Self> {
        Ok(Self {
            control: Keyspace::new(CONTROL_KEYSPACE)?,
            spaces: Keyspace::new(SPACE_KEYSPACE)?,
            routes: Keyspace::new(ROUTE_KEYSPACE)?,
            vectors: Keyspace::new(VECTOR_KEYSPACE)?,
            targets: Keyspace::new(TARGET_KEYSPACE)?,
        })
    }
}

/// Restartable writer for one immutable durable ANN source.
pub struct AnnSourceImportV2<E: StorageEngine> {
    engine: E,
    keys: SourceKeyspaces,
    plan: AnnSourceImportPlanV2,
    durability: Durability,
    sealed: bool,
}

impl<E: StorageEngine> std::fmt::Debug for AnnSourceImportV2<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnnSourceImportV2")
            .field("plan", &self.plan)
            .field("sealed", &self.sealed)
            .finish_non_exhaustive()
    }
}

impl<E: StorageEngine> AnnSourceImportV2<E> {
    /// Writes or verifies one immutable vector-space definition.
    pub fn put_vector_space(&self, space: &VectorSpace) -> AnnRuntimeResultV2<()> {
        space
            .validate()
            .map_err(|_| AnnRuntimeErrorV2::Source("vector-space definition is invalid"))?;
        let key = id_key(space.id);
        let value = canonical_encode_bounded(
            space,
            MAX_SPACE_BYTES,
            "vector-space definition exceeds the durable source byte limit",
        )?;
        let mut write = self.engine.begin_write()?;
        verify_control_state(&write, &self.keys, self.plan, self.sealed)?;
        let changed = stage_exact(
            &mut write,
            &self.keys.spaces,
            key,
            value,
            self.sealed,
            "vector-space identifier diverged during resumed import",
        )?;
        finish_optional_write(write, changed, self.durability)
    }

    /// Writes one bounded, atomic page of immutable vector/route/target rows.
    /// Existing byte-identical rows make retry after interruption idempotent.
    pub fn put_records_page(&self, records: &[VectorRecord]) -> AnnRuntimeResultV2<()> {
        if records.is_empty() {
            return Ok(());
        }
        if records.len() > SOURCE_PAGE_ENTRIES {
            return Err(AnnRuntimeErrorV2::Source(
                "source import page exceeds the entry limit",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut encoded = Vec::with_capacity(records.len());
        let mut page_bytes = 0_usize;
        for record in records {
            if !ids.insert(record.id) {
                return Err(AnnRuntimeErrorV2::Source(
                    "source import page repeats a representation identifier",
                ));
            }
            record
                .policy
                .validate()
                .map_err(|_| AnnRuntimeErrorV2::Source("vector route policy is invalid"))?;
            if record
                .tombstone_at
                .is_some_and(|deleted| deleted < record.projected_at)
            {
                return Err(AnnRuntimeErrorV2::Source(
                    "vector tombstone precedes projection",
                ));
            }
            record
                .target
                .validate()
                .map_err(|_| AnnRuntimeErrorV2::Source("vector target is invalid"))?;
            if record.values.is_empty() || record.values.len() > ANN_V2_MAX_VECTOR_DIMENSIONS {
                return Err(AnnRuntimeErrorV2::Source(
                    "vector dimensions exceed the durable source limit",
                ));
            }
            let key = id_key(record.id);
            let route = canonical_encode_bounded(
                &route_from_record(record),
                SOURCE_PAGE_BYTES,
                "route exceeds the durable source byte limit",
            )?;
            let vector = canonical_encode_bounded(
                &StoredVectorV2 {
                    format_version: SOURCE_FORMAT_VERSION,
                    vector_space_id: record.vector_space_id,
                    values: record.values.clone(),
                },
                SOURCE_PAGE_BYTES,
                "vector exceeds the durable source byte limit",
            )?;
            let target = canonical_encode_bounded(
                &record.target,
                MAX_TARGET_BYTES,
                "target exceeds the durable source byte limit",
            )?;
            let row_bytes = key
                .len()
                .checked_mul(3)
                .and_then(|keys| keys.checked_add(route.len()))
                .and_then(|bytes| bytes.checked_add(vector.len()))
                .and_then(|bytes| bytes.checked_add(target.len()))
                .ok_or(AnnRuntimeErrorV2::Source(
                    "source import page byte count overflowed",
                ))?;
            page_bytes = page_bytes
                .checked_add(row_bytes)
                .ok_or(AnnRuntimeErrorV2::Source(
                    "source import page byte count overflowed",
                ))?;
            if page_bytes > SOURCE_PAGE_BYTES {
                return Err(AnnRuntimeErrorV2::Source(
                    "source import page exceeds the byte limit",
                ));
            }
            encoded.push((record, key, route, vector, target));
        }

        let mut write = self.engine.begin_write()?;
        verify_control_state(&write, &self.keys, self.plan, self.sealed)?;
        let mut changed = false;
        for (record, key, route, vector, target) in encoded {
            let space_bytes = write
                .get(&self.keys.spaces, &id_key(record.vector_space_id))?
                .ok_or(AnnRuntimeErrorV2::Source(
                    "vector record references an unregistered vector space",
                ))?;
            if space_bytes.len() > MAX_SPACE_BYTES {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector-space exceeds the byte limit",
                ));
            }
            let space: VectorSpace =
                canonical_decode(&space_bytes, "stored vector-space definition is invalid")?;
            if space.id != record.vector_space_id {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector-space key and value diverge",
                ));
            }
            validate_values(&space, &record.values)
                .map_err(|_| AnnRuntimeErrorV2::Source("vector values are invalid"))?;

            let existing_route = write.get(&self.keys.routes, &key)?;
            let existing_vector = write.get(&self.keys.vectors, &key)?;
            let existing_target = write.get(&self.keys.targets, &key)?;
            let present = [
                existing_route.is_some(),
                existing_vector.is_some(),
                existing_target.is_some(),
            ];
            if present.iter().any(|value| *value) && !present.iter().all(|value| *value) {
                return Err(AnnRuntimeErrorV2::Source(
                    "vector source row is partially materialized",
                ));
            }
            if let (Some(old_route), Some(old_vector), Some(old_target)) =
                (existing_route, existing_vector, existing_target)
            {
                if old_route != route || old_vector != vector || old_target != target {
                    return Err(AnnRuntimeErrorV2::Source(
                        "representation identifier diverged during resumed import",
                    ));
                }
                continue;
            }
            if self.sealed {
                return Err(AnnRuntimeErrorV2::Source(
                    "sealed source is missing an imported representation",
                ));
            }
            write.put(&self.keys.routes, key.clone(), route)?;
            write.put(&self.keys.vectors, key.clone(), vector)?;
            write.put(&self.keys.targets, key, target)?;
            changed = true;
        }
        finish_optional_write(write, changed, self.durability)
    }

    /// Recomputes every root through bounded pages and atomically publishes the
    /// source. No row is made mutable by publication.
    pub fn finish(self) -> AnnRuntimeResultV2<PersistentAnnVectorSourceV2<E>> {
        if self.sealed {
            return PersistentAnnVectorSourceV2::open(self.engine);
        }
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        verify_control_state(&read, &self.keys, self.plan, false)?;
        let computed = verify_rows(&read, &self.keys, self.plan)?;
        let manifest = SourceManifestV2 {
            format_version: SOURCE_FORMAT_VERSION,
            plan: self.plan,
            vector_store_root: computed.seal.vector_store_root,
            route_root: computed.seal.route_root,
            vector_space_registry_digest: computed.seal.vector_space_registry_digest,
            vector_space_count: computed.vector_space_count,
            record_count: computed.record_count,
        };
        manifest.validate()?;
        let verified_sequence = read.sequence();
        drop(read);

        let mut write = self.engine.begin_write()?;
        if write.sequence() != verified_sequence {
            return Err(AnnRuntimeErrorV2::Source(
                "durable source changed while its roots were being published",
            ));
        }
        verify_control_state(&write, &self.keys, self.plan, false)?;
        write.put(
            &self.keys.control,
            ACTIVE_KEY.to_vec(),
            canonical_encode(&manifest, "source manifest encode failed")?,
        )?;
        write.delete(&self.keys.control, IMPORT_FENCE_KEY.to_vec())?;
        let receipt = write.commit(self.durability)?;
        Ok(PersistentAnnVectorSourceV2 {
            engine: self.engine,
            keys: self.keys,
            manifest,
            verification: AnnSourceVerificationV2 {
                storage_sequence: receipt.sequence,
                ..computed
            },
        })
    }
}

/// Immutable, storage-neutral, paged implementation of [`AnnVectorSourceV2`].
pub struct PersistentAnnVectorSourceV2<E: StorageEngine> {
    engine: E,
    keys: SourceKeyspaces,
    manifest: SourceManifestV2,
    verification: AnnSourceVerificationV2,
}

impl<E: StorageEngine> std::fmt::Debug for PersistentAnnVectorSourceV2<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistentAnnVectorSourceV2")
            .field("verification", &self.verification)
            .finish_non_exhaustive()
    }
}

impl<E: StorageEngine> PersistentAnnVectorSourceV2<E> {
    /// Creates or resumes a source import. A completed source accepts only
    /// byte-identical retries of the same plan and rows.
    pub fn begin_import(
        engine: E,
        plan: AnnSourceImportPlanV2,
        durability: Durability,
    ) -> AnnRuntimeResultV2<AnnSourceImportV2<E>> {
        plan.validate()?;
        let keys = SourceKeyspaces::new()?;
        let mut write = engine.begin_write()?;
        let active = read_optional_canonical::<SourceManifestV2>(
            &write,
            &keys.control,
            ACTIVE_KEY,
            "durable source manifest is invalid",
        )?;
        let fence = read_optional_canonical::<ImportFenceV2>(
            &write,
            &keys.control,
            IMPORT_FENCE_KEY,
            "durable source import fence is invalid",
        )?;
        if active.is_some() && fence.is_some() {
            return Err(AnnRuntimeErrorV2::Source(
                "durable source has both an active manifest and import fence",
            ));
        }
        let sealed = if let Some(active) = active {
            active.validate()?;
            if active.plan != plan {
                return Err(AnnRuntimeErrorV2::Source(
                    "sealed source diverges from the requested import plan",
                ));
            }
            write.rollback()?;
            true
        } else if let Some(fence) = fence {
            validate_fence(&fence, plan)?;
            write.rollback()?;
            false
        } else {
            ensure_source_rows_empty(&write, &keys)?;
            let fence = ImportFenceV2 {
                format_version: SOURCE_FORMAT_VERSION,
                plan,
            };
            write.put(
                &keys.control,
                IMPORT_FENCE_KEY.to_vec(),
                canonical_encode(&fence, "source import fence encode failed")?,
            )?;
            write.commit(durability)?;
            false
        };
        Ok(AnnSourceImportV2 {
            engine,
            keys,
            plan,
            durability,
            sealed,
        })
    }

    /// Opens and exhaustively verifies a published source using bounded pages.
    pub fn open(engine: E) -> AnnRuntimeResultV2<Self> {
        let keys = SourceKeyspaces::new()?;
        let read = engine.begin_read(SnapshotSelector::Latest)?;
        let manifest = read_optional_canonical::<SourceManifestV2>(
            &read,
            &keys.control,
            ACTIVE_KEY,
            "durable source manifest is invalid",
        )?
        .ok_or(AnnRuntimeErrorV2::Source(
            "durable source has no active manifest",
        ))?;
        manifest.validate()?;
        if read.get(&keys.control, IMPORT_FENCE_KEY)?.is_some() {
            return Err(AnnRuntimeErrorV2::Source(
                "published durable source retains an import fence",
            ));
        }
        let verification = verify_rows(&read, &keys, manifest.plan)?;
        if verification.seal != manifest.seal()
            || verification.vector_space_count != manifest.vector_space_count
            || verification.record_count != manifest.record_count
        {
            return Err(AnnRuntimeErrorV2::Source(
                "durable source roots diverge from the published manifest",
            ));
        }
        drop(read);
        Ok(Self {
            engine,
            keys,
            manifest,
            verification,
        })
    }

    #[must_use]
    pub const fn verification(&self) -> AnnSourceVerificationV2 {
        self.verification
    }

    fn validate_control<R: ReadSnapshot>(&self, read: &R) -> AnnRuntimeResultV2<()> {
        let active = read_optional_canonical::<SourceManifestV2>(
            read,
            &self.keys.control,
            ACTIVE_KEY,
            "durable source manifest is invalid",
        )?
        .ok_or(AnnRuntimeErrorV2::Source(
            "durable source active manifest disappeared",
        ))?;
        if active != self.manifest || read.get(&self.keys.control, IMPORT_FENCE_KEY)?.is_some() {
            return Err(AnnRuntimeErrorV2::Source(
                "durable source control state diverged after open",
            ));
        }
        Ok(())
    }
}

impl<E: StorageEngine> AnnVectorSourceV2 for PersistentAnnVectorSourceV2<E> {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2> {
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        self.validate_control(&read)?;
        Ok(self.manifest.seal())
    }

    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace> {
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        self.validate_control(&read)?;
        let bytes = read
            .get(&self.keys.spaces, &id_key(id))?
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector space"))?;
        if bytes.len() > MAX_SPACE_BYTES {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector-space exceeds the byte limit",
            ));
        }
        let space: VectorSpace =
            canonical_decode(&bytes, "stored vector-space definition is invalid")?;
        if space.id != id {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector-space key and value diverge",
            ));
        }
        space
            .validate()
            .map_err(|_| AnnRuntimeErrorV2::Source("stored vector-space is invalid"))?;
        Ok(space)
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
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        self.validate_control(&read)?;
        let start_key = start_after.map(id_key);
        let page = read.scan_prefix_page(
            &self.keys.routes,
            ScanPageRequest {
                prefix: b"",
                start_after: start_key.as_deref(),
                max_entries,
                max_bytes,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Source(
                "route page continuation made no progress",
            ));
        }
        let mut routes = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let id = parse_representation_key(&entry.key)?;
            let route: AnnVectorRouteV2 =
                canonical_decode(&entry.value, "stored vector route is invalid")?;
            validate_route(id, &route)?;
            routes.push(route);
        }
        let continuation = page
            .continuation
            .as_deref()
            .map(parse_representation_key)
            .transpose()?;
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
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        self.validate_control(&read)?;
        let key = id_key(id);
        let route_bytes = read
            .get(&self.keys.routes, &key)?
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector representation"))?;
        if route_bytes.len() > SOURCE_PAGE_BYTES {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector route exceeds the byte limit",
            ));
        }
        let route: AnnVectorRouteV2 =
            canonical_decode(&route_bytes, "stored vector route is invalid")?;
        validate_route(id, &route)?;
        let vector_bytes = read
            .get(&self.keys.vectors, &key)?
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector representation"))?;
        if vector_bytes.len() > SOURCE_PAGE_BYTES {
            return Err(AnnRuntimeErrorV2::Source(
                "stored full-precision vector exceeds the byte limit",
            ));
        }
        let vector: StoredVectorV2 =
            canonical_decode(&vector_bytes, "stored full-precision vector is invalid")?;
        if vector.format_version != SOURCE_FORMAT_VERSION
            || vector.vector_space_id != route.vector_space_id
            || vector.values.len() != dimensions
        {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector and route dimensions or space diverge",
            ));
        }
        let space_bytes = read
            .get(&self.keys.spaces, &id_key(vector.vector_space_id))?
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector space"))?;
        if space_bytes.len() > MAX_SPACE_BYTES {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector-space exceeds the byte limit",
            ));
        }
        let space: VectorSpace =
            canonical_decode(&space_bytes, "stored vector-space definition is invalid")?;
        if space.id != vector.vector_space_id {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector-space key and value diverge",
            ));
        }
        validate_values(&space, &vector.values)
            .map_err(|_| AnnRuntimeErrorV2::Source("stored vector values are invalid"))?;
        Ok(vector.values)
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        if max_bytes == 0 || max_bytes > MAX_TARGET_BYTES {
            return Err(AnnRuntimeErrorV2::Source("target byte limit is invalid"));
        }
        let read = self.engine.begin_read(SnapshotSelector::Latest)?;
        self.validate_control(&read)?;
        let key = id_key(id);
        let route_bytes = read
            .get(&self.keys.routes, &key)?
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector representation"))?;
        if route_bytes.len() > SOURCE_PAGE_BYTES {
            return Err(AnnRuntimeErrorV2::Source(
                "stored vector route exceeds the byte limit",
            ));
        }
        let route: AnnVectorRouteV2 =
            canonical_decode(&route_bytes, "stored vector route is invalid")?;
        validate_route(id, &route)?;
        let target_bytes = read
            .get(&self.keys.targets, &key)?
            .ok_or(AnnRuntimeErrorV2::Source("unknown vector representation"))?;
        if target_bytes.len() > max_bytes {
            return Err(AnnRuntimeErrorV2::Source(
                "target exceeds the point-read byte limit",
            ));
        }
        let target: LineageNode =
            canonical_decode(&target_bytes, "stored vector target is invalid")?;
        target
            .validate()
            .map_err(|_| AnnRuntimeErrorV2::Source("stored vector target is invalid"))?;
        Ok(target)
    }
}

fn verify_rows<R: ReadSnapshot>(
    read: &R,
    keys: &SourceKeyspaces,
    plan: AnnSourceImportPlanV2,
) -> AnnRuntimeResultV2<AnnSourceVerificationV2> {
    plan.validate()?;
    let mut registry = blake3::Hasher::new();
    registry.update(REGISTRY_DIGEST_DOMAIN);
    let mut vector_space_count = 0_u64;
    let mut vector_space_pages = 0_u64;
    scan_pages(
        read,
        &keys.spaces,
        |entry| {
            let id = parse_vector_space_key(&entry.key)?;
            if entry.value.len() > MAX_SPACE_BYTES {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector-space exceeds the byte limit",
                ));
            }
            let space: VectorSpace =
                canonical_decode(&entry.value, "stored vector-space definition is invalid")?;
            if space.id != id {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector-space key, value, or size is invalid",
                ));
            }
            space
                .validate()
                .map_err(|_| AnnRuntimeErrorV2::Source("stored vector-space is invalid"))?;
            registry.update(id.as_uuid().as_bytes());
            registry.update(&usize_to_u64(entry.value.len())?.to_be_bytes());
            registry.update(&entry.value);
            vector_space_count =
                checked_increment(vector_space_count, "vector-space count overflowed")?;
            Ok(())
        },
        &mut vector_space_pages,
    )?;
    if vector_space_count != plan.expected_vector_spaces {
        return Err(AnnRuntimeErrorV2::Source(
            "durable source vector-space count diverges from its import plan",
        ));
    }

    let mut vectors = blake3::Hasher::new();
    vectors.update(VECTOR_ROOT_DOMAIN);
    vectors.update(&plan.vector_store_generation.to_be_bytes());
    let mut routes = blake3::Hasher::new();
    routes.update(ROUTE_ROOT_DOMAIN);
    routes.update(&plan.route_generation.to_be_bytes());
    let mut record_count = 0_u64;
    let mut route_pages = 0_u64;
    scan_pages(
        read,
        &keys.routes,
        |entry| {
            let id = parse_representation_key(&entry.key)?;
            let route: AnnVectorRouteV2 =
                canonical_decode(&entry.value, "stored vector route is invalid")?;
            validate_route(id, &route)?;
            let vector_bytes =
                read.get(&keys.vectors, &entry.key)?
                    .ok_or(AnnRuntimeErrorV2::Source(
                        "route is missing its full-precision vector",
                    ))?;
            if vector_bytes.len() > SOURCE_PAGE_BYTES {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored full-precision vector exceeds the byte limit",
                ));
            }
            let vector: StoredVectorV2 =
                canonical_decode(&vector_bytes, "stored full-precision vector is invalid")?;
            if vector.format_version != SOURCE_FORMAT_VERSION
                || vector.vector_space_id != route.vector_space_id
            {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector and route vector spaces diverge",
                ));
            }
            let space_bytes = read
                .get(&keys.spaces, &id_key(vector.vector_space_id))?
                .ok_or(AnnRuntimeErrorV2::Source(
                    "vector references an unregistered vector space",
                ))?;
            if space_bytes.len() > MAX_SPACE_BYTES {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector-space exceeds the byte limit",
                ));
            }
            let space: VectorSpace =
                canonical_decode(&space_bytes, "stored vector-space definition is invalid")?;
            if space.id != vector.vector_space_id {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector-space key and value diverge",
                ));
            }
            validate_values(&space, &vector.values)
                .map_err(|_| AnnRuntimeErrorV2::Source("stored vector values are invalid"))?;
            let target_bytes =
                read.get(&keys.targets, &entry.key)?
                    .ok_or(AnnRuntimeErrorV2::Source(
                        "route is missing its vector target",
                    ))?;
            if target_bytes.len() > MAX_TARGET_BYTES {
                return Err(AnnRuntimeErrorV2::Source(
                    "stored vector target exceeds the byte limit",
                ));
            }
            let target: LineageNode =
                canonical_decode(&target_bytes, "stored vector target is invalid")?;
            target
                .validate()
                .map_err(|_| AnnRuntimeErrorV2::Source("stored vector target is invalid"))?;

            vectors.update(id.as_uuid().as_bytes());
            vectors.update(vector.vector_space_id.as_uuid().as_bytes());
            vectors.update(&usize_to_u64(vector.values.len())?.to_be_bytes());
            for value in vector.values {
                vectors.update(&value.to_bits().to_be_bytes());
            }
            vectors.update(&usize_to_u64(target_bytes.len())?.to_be_bytes());
            vectors.update(&target_bytes);
            routes.update(&usize_to_u64(entry.value.len())?.to_be_bytes());
            routes.update(&entry.value);
            record_count = checked_increment(record_count, "source record count overflowed")?;
            Ok(())
        },
        &mut route_pages,
    )?;
    if record_count != plan.expected_records {
        return Err(AnnRuntimeErrorV2::Source(
            "durable source record count diverges from its import plan",
        ));
    }

    let mut vector_count = 0_u64;
    let mut vector_key_pages = 0_u64;
    scan_pages(
        read,
        &keys.vectors,
        |entry| {
            parse_representation_key(&entry.key)?;
            if read.get(&keys.routes, &entry.key)?.is_none() {
                return Err(AnnRuntimeErrorV2::Source(
                    "full-precision vector has no routing row",
                ));
            }
            vector_count = checked_increment(vector_count, "vector count overflowed")?;
            Ok(())
        },
        &mut vector_key_pages,
    )?;
    let mut target_count = 0_u64;
    let mut target_key_pages = 0_u64;
    scan_pages(
        read,
        &keys.targets,
        |entry| {
            parse_representation_key(&entry.key)?;
            if read.get(&keys.routes, &entry.key)?.is_none() {
                return Err(AnnRuntimeErrorV2::Source(
                    "vector target has no routing row",
                ));
            }
            target_count = checked_increment(target_count, "target count overflowed")?;
            Ok(())
        },
        &mut target_key_pages,
    )?;
    if vector_count != record_count || target_count != record_count {
        return Err(AnnRuntimeErrorV2::Source(
            "durable source route, vector, and target keysets diverge",
        ));
    }

    let seal = AnnSourceSealV2 {
        vector_store_generation: plan.vector_store_generation,
        vector_store_root: *vectors.finalize().as_bytes(),
        route_generation: plan.route_generation,
        route_root: *routes.finalize().as_bytes(),
        vector_space_registry_digest: *registry.finalize().as_bytes(),
    };
    seal.validate()?;
    Ok(AnnSourceVerificationV2 {
        seal,
        vector_space_count,
        record_count,
        storage_sequence: read.sequence(),
        vector_space_pages,
        route_pages,
        vector_key_pages,
        target_key_pages,
    })
}

fn scan_pages<R: ReadSnapshot>(
    read: &R,
    keyspace: &Keyspace,
    mut visit: impl FnMut(&contextdb_storage::Entry) -> AnnRuntimeResultV2<()>,
    page_count: &mut u64,
) -> AnnRuntimeResultV2<()> {
    let mut continuation: Option<Vec<u8>> = None;
    loop {
        let page = read.scan_prefix_page(
            keyspace,
            ScanPageRequest {
                prefix: b"",
                start_after: continuation.as_deref(),
                max_entries: SOURCE_PAGE_ENTRIES,
                max_bytes: SOURCE_PAGE_BYTES,
            },
        )?;
        *page_count = checked_increment(*page_count, "source page count overflowed")?;
        if page.entries.len() > SOURCE_PAGE_ENTRIES {
            return Err(AnnRuntimeErrorV2::Source(
                "storage returned an oversized source page",
            ));
        }
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(AnnRuntimeErrorV2::Source(
                "source page continuation made no progress",
            ));
        }
        for entry in &page.entries {
            visit(entry)?;
        }
        let Some(next) = page.continuation else {
            return Ok(());
        };
        if continuation
            .as_ref()
            .is_some_and(|previous| next <= *previous)
        {
            return Err(AnnRuntimeErrorV2::Source(
                "source page continuation did not advance",
            ));
        }
        continuation = Some(next);
    }
}

fn validate_route(id: RepresentationId, route: &AnnVectorRouteV2) -> AnnRuntimeResultV2<()> {
    if route.representation_id != id || route.membership_epoch == 0 {
        return Err(AnnRuntimeErrorV2::Source(
            "stored vector route identity or epoch is invalid",
        ));
    }
    route
        .policy
        .validate()
        .map_err(|_| AnnRuntimeErrorV2::Source("stored vector route policy is invalid"))?;
    if route
        .valid_until
        .is_some_and(|until| until <= route.valid_from)
        || route
            .tombstone_at
            .is_some_and(|deleted| deleted < route.projected_at)
    {
        return Err(AnnRuntimeErrorV2::Source(
            "stored vector route time bounds are invalid",
        ));
    }
    Ok(())
}

fn verify_control_state<R: ReadSnapshot>(
    read: &R,
    keys: &SourceKeyspaces,
    plan: AnnSourceImportPlanV2,
    sealed: bool,
) -> AnnRuntimeResultV2<()> {
    let active = read_optional_canonical::<SourceManifestV2>(
        read,
        &keys.control,
        ACTIVE_KEY,
        "durable source manifest is invalid",
    )?;
    let fence = read_optional_canonical::<ImportFenceV2>(
        read,
        &keys.control,
        IMPORT_FENCE_KEY,
        "durable source import fence is invalid",
    )?;
    if sealed {
        let active = active.ok_or(AnnRuntimeErrorV2::Source(
            "sealed durable source manifest disappeared",
        ))?;
        active.validate()?;
        if active.plan != plan || fence.is_some() {
            return Err(AnnRuntimeErrorV2::Source(
                "sealed durable source control state diverged",
            ));
        }
    } else {
        if active.is_some() {
            return Err(AnnRuntimeErrorV2::Source(
                "unfinished import unexpectedly has an active manifest",
            ));
        }
        validate_fence(
            &fence.ok_or(AnnRuntimeErrorV2::Source(
                "durable source import fence disappeared",
            ))?,
            plan,
        )?;
    }
    Ok(())
}

fn validate_fence(fence: &ImportFenceV2, plan: AnnSourceImportPlanV2) -> AnnRuntimeResultV2<()> {
    if fence.format_version != SOURCE_FORMAT_VERSION || fence.plan != plan {
        return Err(AnnRuntimeErrorV2::Source(
            "durable source import fence diverges from the requested plan",
        ));
    }
    fence.plan.validate()
}

fn ensure_source_rows_empty<R: ReadSnapshot>(
    read: &R,
    keys: &SourceKeyspaces,
) -> AnnRuntimeResultV2<()> {
    for keyspace in [&keys.spaces, &keys.routes, &keys.vectors, &keys.targets] {
        let page = read.scan_prefix_page(
            keyspace,
            ScanPageRequest {
                prefix: b"",
                start_after: None,
                max_entries: 1,
                max_bytes: SOURCE_PAGE_BYTES,
            },
        )?;
        if !page.entries.is_empty() || page.continuation.is_some() {
            return Err(AnnRuntimeErrorV2::Source(
                "unfenced durable source contains orphaned rows",
            ));
        }
    }
    Ok(())
}

fn stage_exact<W: WriteTransaction>(
    write: &mut W,
    keyspace: &Keyspace,
    key: Vec<u8>,
    value: Vec<u8>,
    sealed: bool,
    divergence: &'static str,
) -> AnnRuntimeResultV2<bool> {
    match write.get(keyspace, &key)? {
        Some(existing) if existing == value => Ok(false),
        Some(_) => Err(AnnRuntimeErrorV2::Source(divergence)),
        None if sealed => Err(AnnRuntimeErrorV2::Source(
            "sealed durable source is missing an immutable row",
        )),
        None => {
            write.put(keyspace, key, value)?;
            Ok(true)
        }
    }
}

fn finish_optional_write<W: WriteTransaction>(
    write: W,
    changed: bool,
    durability: Durability,
) -> AnnRuntimeResultV2<()> {
    if changed {
        write.commit(durability)?;
    } else {
        write.rollback()?;
    }
    Ok(())
}

fn read_optional_canonical<T: DeserializeOwned + Serialize>(
    read: &impl ReadSnapshot,
    keyspace: &Keyspace,
    key: &[u8],
    error: &'static str,
) -> AnnRuntimeResultV2<Option<T>> {
    read.get(keyspace, key)?
        .map(|bytes| canonical_decode(&bytes, error))
        .transpose()
}

fn canonical_encode<T: Serialize>(value: &T, error: &'static str) -> AnnRuntimeResultV2<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| AnnRuntimeErrorV2::Source(error))
}

pub(crate) fn canonical_encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    error: &'static str,
) -> AnnRuntimeResultV2<Vec<u8>> {
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(maximum.min(4 * 1024)),
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| AnnRuntimeErrorV2::Source(error))?;
    Ok(writer.bytes)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("bounded source encoding overflowed"))?;
        if required > self.maximum {
            return Err(std::io::Error::other(
                "bounded source encoding limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn canonical_decode<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    error: &'static str,
) -> AnnRuntimeResultV2<T> {
    let value: T = serde_json::from_slice(bytes).map_err(|_| AnnRuntimeErrorV2::Source(error))?;
    let canonical = serde_json::to_vec(&value).map_err(|_| AnnRuntimeErrorV2::Source(error))?;
    if canonical != bytes {
        return Err(AnnRuntimeErrorV2::Source(error));
    }
    Ok(value)
}

fn id_key(id: impl ToString) -> Vec<u8> {
    id.to_string().into_bytes()
}

fn parse_representation_key(bytes: &[u8]) -> AnnRuntimeResultV2<RepresentationId> {
    parse_id(bytes, "stored representation key is invalid")
}

fn parse_vector_space_key(bytes: &[u8]) -> AnnRuntimeResultV2<VectorSpaceId> {
    parse_id(bytes, "stored vector-space key is invalid")
}

fn parse_id<T: FromStr>(bytes: &[u8], error: &'static str) -> AnnRuntimeResultV2<T> {
    std::str::from_utf8(bytes)
        .map_err(|_| AnnRuntimeErrorV2::Source(error))?
        .parse()
        .map_err(|_| AnnRuntimeErrorV2::Source(error))
}

fn usize_to_u64(value: usize) -> AnnRuntimeResultV2<u64> {
    u64::try_from(value).map_err(|_| AnnRuntimeErrorV2::Source("source size exceeds u64"))
}

fn checked_increment(value: u64, error: &'static str) -> AnnRuntimeResultV2<u64> {
    value.checked_add(1).ok_or(AnnRuntimeErrorV2::Source(error))
}
