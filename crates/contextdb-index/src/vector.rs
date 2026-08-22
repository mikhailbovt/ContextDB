#[cfg(feature = "ann-hnsw")]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    CommitSeq, LineageNode, Modality, RepresentationId, TimeRange, TimestampMicros, VectorSpaceId,
};
use serde::{Deserialize, Serialize};

use crate::{IndexError, IndexPolicy, IndexPrincipal, Result};

#[cfg(feature = "ann-hnsw")]
const MAX_HNSW_NEIGHBOURS: usize = 64;
#[cfg(feature = "ann-hnsw")]
const MIN_HNSW_CONSTRUCTION_VISITS: usize = 64;
#[cfg(feature = "ann-hnsw")]
const MAX_HNSW_CONSTRUCTION_VISITS: usize = 2_048;
#[cfg(feature = "ann-hnsw")]
const MAX_ANN_GENERATION_NODES: usize = 1_000_000;
#[cfg(feature = "ann-hnsw")]
const MAX_ANN_GENERATION_BYTES: usize = 512 * 1024 * 1024;
/// Hard upper bound for one ANN traversal, including upper-layer routing.
#[cfg(feature = "ann-hnsw")]
pub const MAX_ANN_SEARCH_VISITS: usize = 65_536;

/// Similarity function fixed for the lifetime of a vector space.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorMetric {
    Cosine,
    DotProduct,
    Euclidean,
}

/// Immutable compatibility contract for supplied or generated embeddings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorSpace {
    pub id: VectorSpaceId,
    pub dimensions: u32,
    pub metric: VectorMetric,
    pub model_family: String,
    pub model_revision: String,
    pub preprocessing_revision: String,
    pub modality: Modality,
}

impl VectorSpace {
    pub fn validate(&self) -> Result<()> {
        if self.dimensions == 0 {
            return Err(IndexError::Invalid("vector dimensions must be positive"));
        }
        if self.model_family.trim().is_empty()
            || self.model_revision.trim().is_empty()
            || self.preprocessing_revision.trim().is_empty()
        {
            return Err(IndexError::Invalid(
                "vector compatibility identifiers must not be blank",
            ));
        }
        Ok(())
    }
}

/// Add-only vector-space registry. An ID can never be rebound to new semantics.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VectorSpaceRegistry(BTreeMap<VectorSpaceId, VectorSpace>);

impl VectorSpaceRegistry {
    pub fn register(&mut self, space: VectorSpace) -> Result<()> {
        space.validate()?;
        if let Some(existing) = self.0.get(&space.id) {
            if existing != &space {
                return Err(IndexError::IncompatibleVectorSpace);
            }
            return Ok(());
        }
        self.0.insert(space.id, space);
        Ok(())
    }

    pub fn get(&self, id: VectorSpaceId) -> Result<&VectorSpace> {
        self.0.get(&id).ok_or(IndexError::UnknownVectorSpace(id))
    }

    #[cfg(feature = "ann-hnsw")]
    pub(crate) fn ann_v2_iter(&self) -> impl Iterator<Item = (&VectorSpaceId, &VectorSpace)> {
        self.0.iter()
    }
}

/// Full-precision immutable representation. Updates use a new representation ID.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorRecord {
    pub id: RepresentationId,
    pub target: LineageNode,
    pub vector_space_id: VectorSpaceId,
    pub values: Vec<f32>,
    pub policy: IndexPolicy,
    pub valid_time: TimeRange,
    pub projected_at: CommitSeq,
    pub lineage: Vec<LineageNode>,
    pub tombstone_at: Option<CommitSeq>,
}

/// Opaque policy-filtered universe. It contains IDs, never vector bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedVectorUniverse {
    snapshot: CommitSeq,
    generation: u64,
    record_ids: BTreeSet<RepresentationId>,
    #[cfg(feature = "ann-hnsw")]
    partition_keys: BTreeSet<String>,
}

/// One exact-reranked vector result.
#[derive(Clone, Debug, PartialEq)]
pub struct VectorHit {
    pub representation_id: RepresentationId,
    pub target: LineageNode,
    pub score: f32,
}

/// Privacy-safe vector query diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VectorTrace {
    pub snapshot: CommitSeq,
    pub generation: u64,
    pub watermark: CommitSeq,
    pub authorized_scored: u64,
    pub ann_visits: u64,
    pub exact_fallback_scored: u64,
    pub returned: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VectorSearchResult {
    pub hits: Vec<VectorHit>,
    pub trace: VectorTrace,
}

/// Snapshot-independent query values and temporal/result constraints.
#[derive(Clone, Copy, Debug)]
pub struct VectorQuery<'a> {
    pub vector_space_id: VectorSpaceId,
    pub values: &'a [f32],
    pub valid_at: Option<TimestampMicros>,
    pub limit: usize,
}

/// Hard limits for approximate traversal and candidate retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnBudget {
    pub max_visits: usize,
    pub ef_search: usize,
}

/// Result of one explicit ANN-generation retention pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnnGenerationPruneReport {
    /// Retention floor before this call.
    pub previous_oldest_retained_snapshot: CommitSeq,
    /// Caller-selected oldest snapshot which remains queryable through ANN.
    pub oldest_retained_snapshot: CommitSeq,
    /// Generation selected exactly at the retention floor, or zero for exact mode.
    pub baseline_generation: u64,
    /// Active generation protected from deletion.
    pub active_generation: u64,
    /// Published generations reclaimed by this call.
    pub generations_deleted: u64,
    /// Raw portable-generation bytes reclaimed by this call.
    pub payload_bytes_deleted: u64,
    /// Whether an unpublished generation older than the new floor was discarded.
    pub staged_generation_discarded: bool,
}

/// Self-verifying portable HNSW generation bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentAnnGeneration {
    pub schema_version: u16,
    pub generation: u64,
    pub watermark: CommitSeq,
    pub payload_digest: [u8; 32],
    pub payload: Vec<u8>,
}

/// Self-verifying full-precision vector store. ANN remains a separate,
/// disposable generation and never becomes the canonical representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentVectorStore {
    pub schema_version: u16,
    pub watermark: CommitSeq,
    pub payload_digest: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorStorePayload {
    schema_version: u16,
    watermark: CommitSeq,
    spaces: VectorSpaceRegistry,
    records: BTreeMap<RepresentationId, VectorRecord>,
}

#[cfg(feature = "ann-hnsw")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnPayload {
    schema_version: u16,
    generation: u64,
    watermark: CommitSeq,
    spaces: VectorSpaceRegistry,
    partitions: BTreeMap<String, HnswPartition>,
}

#[cfg(feature = "ann-hnsw")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HnswPartition {
    vector_space_id: VectorSpaceId,
    policy: IndexPolicy,
    entry: RepresentationId,
    max_level: u8,
    nodes: BTreeMap<RepresentationId, HnswNode>,
}

#[cfg(feature = "ann-hnsw")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HnswNode {
    levels: Vec<Vec<RepresentationId>>,
}

#[cfg(feature = "ann-hnsw")]
#[derive(Clone, Copy, Debug)]
struct RankedAnnCandidate {
    score: f32,
    id: RepresentationId,
}

#[cfg(feature = "ann-hnsw")]
impl PartialEq for RankedAnnCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.score.total_cmp(&other.score).is_eq() && self.id == other.id
    }
}

#[cfg(feature = "ann-hnsw")]
impl Eq for RankedAnnCandidate {}

#[cfg(feature = "ann-hnsw")]
impl PartialOrd for RankedAnnCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "ann-hnsw")]
impl Ord for RankedAnnCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .total_cmp(&other.score)
            // For equal scores, the smaller stable ID is the better candidate.
            .then_with(|| other.id.cmp(&self.id))
    }
}

/// Full-precision oracle, immutable generations, and mutable delta.
#[derive(Clone, Debug, Default)]
pub struct VectorIndex {
    registry: VectorSpaceRegistry,
    records: BTreeMap<RepresentationId, VectorRecord>,
    #[cfg(feature = "ann-hnsw")]
    generations: BTreeMap<u64, PersistentAnnGeneration>,
    #[cfg(feature = "ann-hnsw")]
    generation_payloads: BTreeMap<u64, AnnPayload>,
    #[cfg(feature = "ann-hnsw")]
    staged: Option<PersistentAnnGeneration>,
    #[cfg(feature = "ann-hnsw")]
    staged_payload: Option<AnnPayload>,
    #[cfg(feature = "ann-hnsw")]
    active_generation: u64,
    #[cfg(feature = "ann-hnsw")]
    oldest_retained_snapshot: CommitSeq,
}

impl VectorIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn registry(&self) -> &VectorSpaceRegistry {
        &self.registry
    }

    #[cfg(feature = "ann-hnsw")]
    pub(crate) fn ann_v2_records(&self) -> &BTreeMap<RepresentationId, VectorRecord> {
        &self.records
    }

    #[cfg(feature = "ann-hnsw")]
    pub(crate) fn ann_v2_spaces(&self) -> &VectorSpaceRegistry {
        &self.registry
    }

    pub fn register_space(&mut self, space: VectorSpace) -> Result<()> {
        self.registry.register(space)
    }

    /// Inserts one immutable full-precision vector after compatibility checks.
    pub fn insert(&mut self, record: VectorRecord) -> Result<()> {
        if self.records.contains_key(&record.id) {
            return Err(IndexError::Invalid(
                "vector representation IDs are immutable",
            ));
        }
        let space = self.registry.get(record.vector_space_id)?;
        record.policy.validate()?;
        validate_values(space, &record.values)?;
        if record
            .tombstone_at
            .is_some_and(|deleted| deleted < record.projected_at)
        {
            return Err(IndexError::Invalid("vector tombstone precedes projection"));
        }
        self.records.insert(record.id, record);
        Ok(())
    }

    /// Applies a logical tombstone without removing lineage or old generations.
    pub fn tombstone(&mut self, id: RepresentationId, at: CommitSeq) -> Result<()> {
        let record = self
            .records
            .get_mut(&id)
            .ok_or(IndexError::UnknownRepresentation(id))?;
        if at < record.projected_at {
            return Err(IndexError::Invalid("vector tombstone precedes projection"));
        }
        record.tombstone_at = Some(at);
        Ok(())
    }

    /// Builds but does not publish one deterministic multi-level HNSW generation.
    ///
    /// Construction uses at most 64 neighbours and a fixed per-level visit cap;
    /// it never performs an all-pairs scan. Full-precision exact reranking stays
    /// authoritative, so this bounded builder is an accelerator rather than a
    /// semantic source of truth.
    #[cfg(feature = "ann-hnsw")]
    pub fn stage_rebuild(
        &mut self,
        generation: u64,
        watermark: CommitSeq,
        neighbours_per_level: usize,
    ) -> Result<[u8; 32]> {
        if generation <= self.active_generation || watermark < self.oldest_retained_snapshot {
            return Err(IndexError::StaleGeneration);
        }
        if self
            .generations
            .get(&self.active_generation)
            .is_some_and(|active| watermark < active.watermark)
        {
            return Err(IndexError::StaleGeneration);
        }
        if neighbours_per_level == 0 {
            return Err(IndexError::InvalidBudget);
        }
        if neighbours_per_level > MAX_HNSW_NEIGHBOURS {
            return Err(IndexError::Invalid(
                "HNSW neighbours exceed bounded construction limit",
            ));
        }
        let mut grouped: BTreeMap<String, Vec<&VectorRecord>> = BTreeMap::new();
        let mut visible_records = 0_usize;
        for record in self.records.values() {
            if record.projected_at <= watermark
                && record
                    .tombstone_at
                    .is_none_or(|deleted| deleted > watermark)
            {
                visible_records = visible_records.saturating_add(1);
                if visible_records > MAX_ANN_GENERATION_NODES {
                    return Err(IndexError::Invalid(
                        "ANN generation exceeds bounded node limit",
                    ));
                }
                let key = partition_key(record.vector_space_id, &record.policy)?;
                grouped.entry(key).or_default().push(record);
            }
        }
        let mut partitions = BTreeMap::new();
        for (key, mut records) in grouped {
            records.sort_by_key(|record| record.id);
            let first = records
                .first()
                .ok_or(IndexError::Invalid("empty HNSW partition"))?;
            let partition = build_partition(
                first.vector_space_id,
                first.policy.clone(),
                &records,
                self.registry.get(first.vector_space_id)?,
                neighbours_per_level,
            )?;
            partitions.insert(key, partition);
        }
        let payload = AnnPayload {
            schema_version: 1,
            generation,
            watermark,
            spaces: self.registry.clone(),
            partitions,
        };
        let bytes = serde_json::to_vec(&payload)?;
        if bytes.len() > MAX_ANN_GENERATION_BYTES {
            return Err(IndexError::Invalid(
                "ANN generation exceeds bounded byte limit",
            ));
        }
        let digest = *blake3::hash(&bytes).as_bytes();
        self.staged = Some(PersistentAnnGeneration {
            schema_version: 1,
            generation,
            watermark,
            payload_digest: digest,
            payload: bytes,
        });
        self.staged_payload = Some(payload);
        Ok(digest)
    }

    /// Reports that HNSW generation building is not compiled in.
    #[cfg(not(feature = "ann-hnsw"))]
    pub fn stage_rebuild(
        &mut self,
        _generation: u64,
        _watermark: CommitSeq,
        _neighbours_per_level: usize,
    ) -> Result<[u8; 32]> {
        Err(IndexError::CapabilityUnavailable {
            capability: "ann-hnsw",
        })
    }

    /// Atomically switches the active generation after full bundle verification.
    #[cfg(feature = "ann-hnsw")]
    pub fn publish_staged(&mut self, generation: u64) -> Result<()> {
        let bundle = self
            .staged
            .as_ref()
            .ok_or(IndexError::GenerationNotReady(generation))?;
        let payload = self
            .staged_payload
            .as_ref()
            .ok_or(IndexError::GenerationNotReady(generation))?;
        if bundle.generation != generation
            || payload.generation != generation
            || generation <= self.active_generation
            || bundle.watermark < self.oldest_retained_snapshot
            || self
                .generations
                .get(&self.active_generation)
                .is_some_and(|active| bundle.watermark < active.watermark)
        {
            return Err(IndexError::StaleGeneration);
        }
        let validated = validated_bundle_payload(bundle)?;
        if &validated != payload {
            return Err(IndexError::Invalid("ANN staged payload changed"));
        }
        validate_ann_payload_against_records(payload, &self.records)?;
        let bundle = self
            .staged
            .take()
            .ok_or(IndexError::GenerationNotReady(generation))?;
        let payload = self
            .staged_payload
            .take()
            .ok_or(IndexError::GenerationNotReady(generation))?;
        self.generations.insert(generation, bundle);
        self.generation_payloads.insert(generation, payload);
        self.active_generation = generation;
        Ok(())
    }

    /// Reports that HNSW generation publication is not compiled in.
    #[cfg(not(feature = "ann-hnsw"))]
    pub fn publish_staged(&mut self, _generation: u64) -> Result<()> {
        Err(IndexError::CapabilityUnavailable {
            capability: "ann-hnsw",
        })
    }

    /// Imports a crash-safe generation without publishing it.
    #[cfg(feature = "ann-hnsw")]
    pub fn import_staged(&mut self, bundle: PersistentAnnGeneration) -> Result<()> {
        if bundle.generation <= self.active_generation
            || bundle.watermark < self.oldest_retained_snapshot
            || self
                .generations
                .get(&self.active_generation)
                .is_some_and(|active| bundle.watermark < active.watermark)
        {
            return Err(IndexError::StaleGeneration);
        }
        let payload = validated_bundle_payload(&bundle)?;
        let mut registry = self.registry.clone();
        for space in payload.spaces.0.values() {
            registry.register(space.clone())?;
        }
        validate_ann_payload_against_records(&payload, &self.records)?;
        self.registry = registry;
        self.staged = Some(bundle);
        self.staged_payload = Some(payload);
        Ok(())
    }

    /// Advances the explicit ANN retention floor and reclaims generations which
    /// cannot be selected by any retained snapshot.
    ///
    /// The generation selected exactly at `oldest_retained_snapshot`, the active
    /// generation, and the newest generation at every later watermark are kept.
    /// Requests older than the published floor fail instead of silently falling
    /// back to a different generation. Repeating the same request is idempotent.
    #[cfg(feature = "ann-hnsw")]
    pub fn prune_ann_generations(
        &mut self,
        oldest_retained_snapshot: CommitSeq,
    ) -> Result<AnnGenerationPruneReport> {
        if oldest_retained_snapshot < self.oldest_retained_snapshot {
            return Err(IndexError::StaleGeneration);
        }
        if !self.generations.keys().eq(self.generation_payloads.keys())
            || self.staged.is_some() != self.staged_payload.is_some()
        {
            return Err(IndexError::Invalid("ANN generation cache is inconsistent"));
        }

        let previous_oldest_retained_snapshot = self.oldest_retained_snapshot;
        let baseline_generation = self.generation_for(oldest_retained_snapshot);
        let mut retained = BTreeSet::new();
        if baseline_generation != 0 {
            retained.insert(baseline_generation);
        }
        if self.active_generation != 0 {
            retained.insert(self.active_generation);
        }
        let mut latest_by_watermark = BTreeMap::new();
        for (generation, bundle) in &self.generations {
            if bundle.watermark > oldest_retained_snapshot {
                latest_by_watermark.insert(bundle.watermark, *generation);
            }
        }
        retained.extend(latest_by_watermark.into_values());

        let obsolete = self
            .generations
            .keys()
            .filter(|generation| !retained.contains(generation))
            .copied()
            .collect::<Vec<_>>();
        let mut payload_bytes_deleted = 0_u64;
        for generation in &obsolete {
            if let Some(bundle) = self.generations.remove(generation) {
                payload_bytes_deleted = payload_bytes_deleted
                    .saturating_add(u64::try_from(bundle.payload.len()).unwrap_or(u64::MAX));
            }
            self.generation_payloads.remove(generation);
        }

        let staged_generation_discarded = self
            .staged
            .as_ref()
            .is_some_and(|bundle| bundle.watermark < oldest_retained_snapshot);
        if staged_generation_discarded {
            if let Some(bundle) = self.staged.take() {
                payload_bytes_deleted = payload_bytes_deleted
                    .saturating_add(u64::try_from(bundle.payload.len()).unwrap_or(u64::MAX));
            }
            self.staged_payload = None;
        }
        self.oldest_retained_snapshot = oldest_retained_snapshot;

        Ok(AnnGenerationPruneReport {
            previous_oldest_retained_snapshot,
            oldest_retained_snapshot,
            baseline_generation,
            active_generation: self.active_generation,
            generations_deleted: u64::try_from(obsolete.len()).unwrap_or(u64::MAX),
            payload_bytes_deleted,
            staged_generation_discarded,
        })
    }

    /// Reports that ANN retention is unavailable without HNSW support.
    #[cfg(not(feature = "ann-hnsw"))]
    pub fn prune_ann_generations(
        &mut self,
        _oldest_retained_snapshot: CommitSeq,
    ) -> Result<AnnGenerationPruneReport> {
        Err(IndexError::CapabilityUnavailable {
            capability: "ann-hnsw",
        })
    }

    /// Reports that HNSW generation import is not compiled in.
    #[cfg(not(feature = "ann-hnsw"))]
    pub fn import_staged(&mut self, _bundle: PersistentAnnGeneration) -> Result<()> {
        Err(IndexError::CapabilityUnavailable {
            capability: "ann-hnsw",
        })
    }

    #[cfg(feature = "ann-hnsw")]
    pub fn export_generation(&self, generation: u64) -> Result<PersistentAnnGeneration> {
        self.generations
            .get(&generation)
            .cloned()
            .ok_or(IndexError::GenerationNotReady(generation))
    }

    /// Reports that HNSW generation export is not compiled in.
    #[cfg(not(feature = "ann-hnsw"))]
    pub fn export_generation(&self, _generation: u64) -> Result<PersistentAnnGeneration> {
        Err(IndexError::CapabilityUnavailable {
            capability: "ann-hnsw",
        })
    }

    /// Exports full-precision records visible at a projection watermark.
    pub fn export_store(&self, watermark: CommitSeq) -> Result<PersistentVectorStore> {
        let records = self
            .records
            .iter()
            .filter(|(_, record)| record.projected_at <= watermark)
            .map(|(id, record)| (*id, record.clone()))
            .collect();
        let payload = VectorStorePayload {
            schema_version: 1,
            watermark,
            spaces: self.registry.clone(),
            records,
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(PersistentVectorStore {
            schema_version: 1,
            watermark,
            payload_digest: *blake3::hash(&bytes).as_bytes(),
            payload: bytes,
        })
    }

    /// Restores a verified full-precision store into an empty vector index.
    pub fn import_store(&mut self, bundle: PersistentVectorStore) -> Result<()> {
        if !self.records.is_empty() || !self.registry.0.is_empty() {
            return Err(IndexError::Invalid(
                "vector store restore target must be empty",
            ));
        }
        if bundle.schema_version != 1
            || *blake3::hash(&bundle.payload).as_bytes() != bundle.payload_digest
        {
            return Err(IndexError::Invalid(
                "vector store schema or digest mismatch",
            ));
        }
        let payload: VectorStorePayload = serde_json::from_slice(&bundle.payload)?;
        if payload.schema_version != bundle.schema_version || payload.watermark != bundle.watermark
        {
            return Err(IndexError::Invalid("vector store manifest mismatch"));
        }
        let mut registry = VectorSpaceRegistry::default();
        for space in payload.spaces.0.values() {
            registry.register(space.clone())?;
        }
        for record in payload.records.values() {
            record.policy.validate()?;
            validate_values(registry.get(record.vector_space_id)?, &record.values)?;
            if record.projected_at > payload.watermark
                || record
                    .tombstone_at
                    .is_some_and(|deleted| deleted < record.projected_at)
            {
                return Err(IndexError::Invalid(
                    "vector store record violates watermark or tombstone ordering",
                ));
            }
        }
        self.registry = registry;
        self.records = payload.records;
        Ok(())
    }

    /// Creates the authorization universe before touching any vector values.
    pub fn authorize(
        &self,
        principal: &IndexPrincipal,
        snapshot: CommitSeq,
    ) -> Result<AuthorizedVectorUniverse> {
        #[cfg(feature = "ann-hnsw")]
        let generation = self.generation_for(snapshot);
        #[cfg(not(feature = "ann-hnsw"))]
        let generation = 0;
        let mut ids = BTreeSet::new();
        #[cfg(feature = "ann-hnsw")]
        let mut partition_keys = BTreeSet::new();
        for (id, record) in &self.records {
            if record.projected_at <= snapshot
                && record.tombstone_at.is_none_or(|deleted| deleted > snapshot)
                && record.policy.authorizes(principal, snapshot)
            {
                ids.insert(*id);
                #[cfg(feature = "ann-hnsw")]
                partition_keys.insert(partition_key(record.vector_space_id, &record.policy)?);
            }
        }
        Ok(AuthorizedVectorUniverse {
            snapshot,
            generation,
            record_ids: ids,
            #[cfg(feature = "ann-hnsw")]
            partition_keys,
        })
    }

    /// Full-precision filtered oracle with a hard score budget.
    pub fn search_exact(
        &self,
        universe: &AuthorizedVectorUniverse,
        query: VectorQuery<'_>,
        max_scored: usize,
    ) -> Result<VectorSearchResult> {
        if query.limit == 0 || max_scored == 0 {
            return Err(IndexError::InvalidBudget);
        }
        let space = self.registry.get(query.vector_space_id)?;
        validate_values(space, query.values)?;
        let eligible = self.eligible_ids(universe, query.vector_space_id, query.valid_at)?;
        let mut hits = Vec::new();
        for id in eligible.iter().take(max_scored) {
            let record = self
                .records
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            hits.push(hit(
                record,
                score(space.metric, query.values, &record.values)?,
            ));
        }
        sort_hits(&mut hits, query.limit);
        Ok(VectorSearchResult {
            trace: VectorTrace {
                snapshot: universe.snapshot,
                // Exact mode has no ANN-generation dependency even when the
                // authorization universe was issued while ANN was available.
                generation: 0,
                // Exact scoring evaluates the already-authorized snapshot and
                // is independent of disposable ANN-generation retention.
                watermark: universe.snapshot,
                authorized_scored: u64::try_from(eligible.len().min(max_scored))
                    .unwrap_or(u64::MAX),
                ann_visits: 0,
                exact_fallback_scored: u64::try_from(eligible.len().min(max_scored))
                    .unwrap_or(u64::MAX),
                returned: u64::try_from(hits.len()).unwrap_or(u64::MAX),
            },
            hits,
        })
    }

    /// Searches intact authorized policy partitions through persistent HNSW,
    /// then exact-reranks. Partial partitions and post-generation deltas fall
    /// back to exact scoring so forbidden/tombstoned nodes cannot bridge paths.
    #[cfg(feature = "ann-hnsw")]
    pub fn search_ann(
        &self,
        universe: &AuthorizedVectorUniverse,
        query: VectorQuery<'_>,
        budget: AnnBudget,
    ) -> Result<VectorSearchResult> {
        if universe.snapshot < self.oldest_retained_snapshot {
            return Err(IndexError::Invalid(
                "ANN snapshot precedes the explicit retention floor",
            ));
        }
        if query.limit == 0
            || budget.max_visits == 0
            || budget.max_visits > MAX_ANN_SEARCH_VISITS
            || budget.ef_search == 0
            || budget.ef_search > budget.max_visits
        {
            return Err(IndexError::InvalidBudget);
        }
        let space = self.registry.get(query.vector_space_id)?;
        validate_values(space, query.values)?;
        let eligible = self.eligible_ids(universe, query.vector_space_id, query.valid_at)?;
        if universe.generation == 0 {
            return self.search_exact(universe, query, budget.ef_search);
        }
        let bundle = self
            .generations
            .get(&universe.generation)
            .ok_or(IndexError::GenerationNotReady(universe.generation))?;
        let payload = self
            .generation_payloads
            .get(&universe.generation)
            .ok_or(IndexError::GenerationNotReady(universe.generation))?;
        let mut retained_candidates = BTreeSet::new();
        let mut reranked = 0_usize;
        let mut ann_visits = 0_usize;
        let mut fallback = 0_usize;
        for partition_key in &universe.partition_keys {
            let Some(partition) = payload.partitions.get(partition_key) else {
                continue;
            };
            if partition.vector_space_id != query.vector_space_id {
                continue;
            }
            if partition.nodes.keys().all(|id| eligible.contains(id)) {
                let remaining = budget.max_visits.saturating_sub(ann_visits);
                if remaining == 0 {
                    break;
                }
                let (ids, visits) = traverse_partition(
                    partition,
                    &self.records,
                    space.metric,
                    query.values,
                    remaining,
                    budget.ef_search,
                )?;
                ann_visits = ann_visits.saturating_add(visits);
                for id in ids {
                    let record = self
                        .records
                        .get(&id)
                        .ok_or(IndexError::UnknownRepresentation(id))?;
                    retain_ann_candidate(
                        &mut retained_candidates,
                        RankedAnnCandidate {
                            score: score(space.metric, query.values, &record.values)?,
                            id,
                        },
                        budget.ef_search,
                    );
                    reranked = reranked.saturating_add(1);
                }
            } else {
                for id in partition.nodes.keys().filter(|id| eligible.contains(id)) {
                    if fallback >= budget.max_visits {
                        break;
                    }
                    let record = self
                        .records
                        .get(id)
                        .ok_or(IndexError::UnknownRepresentation(*id))?;
                    retain_ann_candidate(
                        &mut retained_candidates,
                        RankedAnnCandidate {
                            score: score(space.metric, query.values, &record.values)?,
                            id: *id,
                        },
                        budget.ef_search,
                    );
                    reranked = reranked.saturating_add(1);
                    fallback = fallback.saturating_add(1);
                }
            }
        }
        for id in &eligible {
            if fallback >= budget.max_visits {
                break;
            }
            let record = self
                .records
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            let key = partition_key(record.vector_space_id, &record.policy)?;
            let indexed = payload
                .partitions
                .get(&key)
                .is_some_and(|partition| partition.nodes.contains_key(id));
            if !indexed {
                retain_ann_candidate(
                    &mut retained_candidates,
                    RankedAnnCandidate {
                        score: score(space.metric, query.values, &record.values)?,
                        id: *id,
                    },
                    budget.ef_search,
                );
                reranked = reranked.saturating_add(1);
                fallback = fallback.saturating_add(1);
            }
        }
        let mut hits = Vec::with_capacity(retained_candidates.len().min(query.limit));
        for candidate in retained_candidates.iter().rev().take(query.limit) {
            let record = self
                .records
                .get(&candidate.id)
                .ok_or(IndexError::UnknownRepresentation(candidate.id))?;
            hits.push(hit(record, candidate.score));
        }
        Ok(VectorSearchResult {
            trace: VectorTrace {
                snapshot: universe.snapshot,
                generation: universe.generation,
                watermark: bundle.watermark,
                authorized_scored: u64::try_from(reranked).unwrap_or(u64::MAX),
                ann_visits: u64::try_from(ann_visits).unwrap_or(u64::MAX),
                exact_fallback_scored: u64::try_from(fallback).unwrap_or(u64::MAX),
                returned: u64::try_from(hits.len()).unwrap_or(u64::MAX),
            },
            hits,
        })
    }

    /// Reports that HNSW search is absent without inspecting query vectors,
    /// authorization membership, or indexed content.
    #[cfg(not(feature = "ann-hnsw"))]
    pub fn search_ann(
        &self,
        _universe: &AuthorizedVectorUniverse,
        _query: VectorQuery<'_>,
        _budget: AnnBudget,
    ) -> Result<VectorSearchResult> {
        Err(IndexError::CapabilityUnavailable {
            capability: "ann-hnsw",
        })
    }

    fn eligible_ids(
        &self,
        universe: &AuthorizedVectorUniverse,
        space: VectorSpaceId,
        valid_at: Option<TimestampMicros>,
    ) -> Result<BTreeSet<RepresentationId>> {
        let mut eligible = BTreeSet::new();
        for id in &universe.record_ids {
            let record = self
                .records
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            if record.vector_space_id == space
                && valid_at.is_none_or(|instant| record.valid_time.contains(instant))
            {
                eligible.insert(*id);
            }
        }
        Ok(eligible)
    }

    #[cfg(feature = "ann-hnsw")]
    fn generation_for(&self, snapshot: CommitSeq) -> u64 {
        self.generations
            .iter()
            .rev()
            .find_map(|(generation, bundle)| (bundle.watermark <= snapshot).then_some(*generation))
            .unwrap_or(0)
    }
}

#[cfg(feature = "ann-hnsw")]
fn build_partition(
    vector_space_id: VectorSpaceId,
    policy: IndexPolicy,
    records: &[&VectorRecord],
    space: &VectorSpace,
    neighbours: usize,
) -> Result<HnswPartition> {
    if neighbours == 0 {
        return Err(IndexError::InvalidBudget);
    }
    if neighbours > MAX_HNSW_NEIGHBOURS {
        return Err(IndexError::Invalid(
            "HNSW neighbours exceed bounded construction limit",
        ));
    }

    let mut levels = BTreeMap::new();
    for record in records {
        levels.insert(record.id, deterministic_level(record.id));
    }

    let records_by_id = records
        .iter()
        .map(|record| (record.id, *record))
        .collect::<BTreeMap<_, _>>();
    let first = records
        .first()
        .ok_or(IndexError::Invalid("empty HNSW partition"))?;
    let mut entry = first.id;
    let mut max_level = levels[&entry];
    let mut nodes = BTreeMap::from([(
        entry,
        HnswNode {
            levels: vec![Vec::new(); usize::from(max_level) + 1],
        },
    )]);
    let construction_visits = neighbours
        .saturating_mul(16)
        .clamp(MIN_HNSW_CONSTRUCTION_VISITS, MAX_HNSW_CONSTRUCTION_VISITS);

    // Insert records deterministically. Each level search is explicitly capped,
    // so construction is O(records * levels * construction_visits) rather than
    // the former all-pairs O(records^2) rebuild. Full-precision records remain
    // authoritative and every ANN result is still exact-reranked.
    for record in records.iter().skip(1) {
        let node_level = levels[&record.id];
        let mut route = entry;

        for level in ((node_level.saturating_add(1))..=max_level).rev() {
            let ranked = bounded_construction_candidates(
                route,
                record,
                level,
                &nodes,
                &records_by_id,
                space.metric,
                construction_visits,
            )?;
            if let Some(best) = ranked.first() {
                route = best.1;
            }
        }

        let mut node_levels = vec![Vec::new(); usize::from(node_level) + 1];
        for level in (0..=node_level.min(max_level)).rev() {
            let ranked = bounded_construction_candidates(
                route,
                record,
                level,
                &nodes,
                &records_by_id,
                space.metric,
                construction_visits,
            )?;
            if let Some(best) = ranked.first() {
                route = best.1;
            }
            node_levels[usize::from(level)] = ranked
                .into_iter()
                .take(neighbours)
                .map(|(_, id)| id)
                .collect();
        }

        let selected = node_levels.clone();
        nodes.insert(
            record.id,
            HnswNode {
                levels: node_levels,
            },
        );
        for (level, linked) in selected.into_iter().enumerate() {
            for neighbour in linked {
                let neighbour_node = nodes
                    .get_mut(&neighbour)
                    .ok_or(IndexError::UnknownRepresentation(neighbour))?;
                let neighbours_at_level = neighbour_node
                    .levels
                    .get_mut(level)
                    .ok_or(IndexError::Invalid("ANN neighbour level is absent"))?;
                neighbours_at_level.push(record.id);
                prune_construction_neighbours(
                    neighbour,
                    level,
                    &mut nodes,
                    &records_by_id,
                    space.metric,
                    neighbours,
                    record.id,
                )?;
            }
        }

        if node_level > max_level {
            entry = record.id;
            max_level = node_level;
        }
    }

    // Preserve a deterministic directed base-layer backbone from the entry.
    // Reciprocal HNSW pruning can otherwise leave a valid-looking component
    // unreachable under a small neighbour cap.
    let traversal_order = std::iter::once(entry)
        .chain(nodes.keys().copied().filter(|id| *id != entry))
        .collect::<Vec<_>>();
    for pair in traversal_order.windows(2) {
        let owner = pair[0];
        let required = pair[1];
        let owner_base = nodes
            .get_mut(&owner)
            .and_then(|node| node.levels.first_mut())
            .ok_or(IndexError::Invalid("ANN base layer is absent"))?;
        if !owner_base.contains(&required) {
            owner_base.push(required);
        }
        prune_construction_neighbours(
            owner,
            0,
            &mut nodes,
            &records_by_id,
            space.metric,
            neighbours,
            required,
        )?;
    }

    Ok(HnswPartition {
        vector_space_id,
        policy,
        entry,
        max_level,
        nodes,
    })
}

#[cfg(feature = "ann-hnsw")]
fn bounded_construction_candidates(
    start: RepresentationId,
    query: &VectorRecord,
    level: u8,
    nodes: &BTreeMap<RepresentationId, HnswNode>,
    records: &BTreeMap<RepresentationId, &VectorRecord>,
    metric: VectorMetric,
    max_visits: usize,
) -> Result<Vec<(f32, RepresentationId)>> {
    let mut queue = VecDeque::from([start]);
    let mut queued = BTreeSet::from([start]);
    let mut ranked = Vec::new();
    while let Some(id) = queue.pop_front() {
        if ranked.len() >= max_visits {
            break;
        }
        let candidate = records
            .get(&id)
            .ok_or(IndexError::UnknownRepresentation(id))?;
        ranked.push((score(metric, &query.values, &candidate.values)?, id));
        if let Some(neighbours) = nodes
            .get(&id)
            .and_then(|node| node.levels.get(usize::from(level)))
        {
            for neighbour in neighbours {
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

#[cfg(feature = "ann-hnsw")]
fn prune_construction_neighbours(
    owner: RepresentationId,
    level: usize,
    nodes: &mut BTreeMap<RepresentationId, HnswNode>,
    records: &BTreeMap<RepresentationId, &VectorRecord>,
    metric: VectorMetric,
    max_neighbours: usize,
    required: RepresentationId,
) -> Result<()> {
    let owner_record = records
        .get(&owner)
        .ok_or(IndexError::UnknownRepresentation(owner))?;
    let mut candidates = nodes
        .get(&owner)
        .and_then(|node| node.levels.get(level))
        .ok_or(IndexError::Invalid("ANN owner level is absent"))?
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|candidate| {
            let record = records
                .get(&candidate)
                .ok_or(IndexError::UnknownRepresentation(candidate))?;
            Ok((
                score(metric, &owner_record.values, &record.values)?,
                candidate,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
    });
    let mut retained = candidates
        .into_iter()
        .take(max_neighbours)
        .map(|(_, id)| id)
        .collect::<Vec<_>>();
    if !retained.contains(&required) {
        let last = retained
            .last_mut()
            .ok_or(IndexError::Invalid("ANN reciprocal neighbour is absent"))?;
        *last = required;
    }
    nodes
        .get_mut(&owner)
        .and_then(|node| node.levels.get_mut(level))
        .ok_or(IndexError::Invalid("ANN owner level is absent"))?
        .clone_from(&retained);
    Ok(())
}

#[cfg(feature = "ann-hnsw")]
fn retain_ann_candidate(
    retained: &mut BTreeSet<RankedAnnCandidate>,
    candidate: RankedAnnCandidate,
    limit: usize,
) {
    retained.insert(candidate);
    if retained.len() > limit {
        retained.pop_first();
    }
}

#[cfg(feature = "ann-hnsw")]
fn traverse_partition(
    partition: &HnswPartition,
    records: &BTreeMap<RepresentationId, VectorRecord>,
    metric: VectorMetric,
    query: &[f32],
    max_visits: usize,
    ef_search: usize,
) -> Result<(BTreeSet<RepresentationId>, usize)> {
    let mut current = partition.entry;
    let mut visits = 0_usize;
    let mut scores = BTreeMap::new();
    for level in (1..=partition.max_level).rev() {
        while let Some(current_score) = score_ann_candidate(
            current,
            records,
            metric,
            query,
            &mut scores,
            &mut visits,
            max_visits,
        )? {
            let mut improved = None;
            for neighbour in partition
                .nodes
                .get(&current)
                .and_then(|node| node.levels.get(usize::from(level)))
                .into_iter()
                .flatten()
            {
                let Some(candidate_score) = score_ann_candidate(
                    *neighbour,
                    records,
                    metric,
                    query,
                    &mut scores,
                    &mut visits,
                    max_visits,
                )?
                else {
                    break;
                };
                if candidate_score > current_score
                    && improved.is_none_or(|(best_score, best_id)| {
                        candidate_score > best_score
                            || (candidate_score == best_score && *neighbour < best_id)
                    })
                {
                    improved = Some((candidate_score, *neighbour));
                }
            }
            let Some((_, next)) = improved else {
                break;
            };
            current = next;
        }
    }

    let current_score = score_ann_candidate(
        current,
        records,
        metric,
        query,
        &mut scores,
        &mut visits,
        max_visits,
    )?
    .ok_or(IndexError::InvalidBudget)?;
    let current_candidate = RankedAnnCandidate {
        score: current_score,
        id: current,
    };
    let mut frontier = BTreeSet::from([current_candidate]);
    let mut best = BTreeSet::from([current_candidate]);
    let mut discovered = BTreeSet::from([current]);
    while visits < max_visits {
        let Some(candidate) = frontier.pop_last() else {
            break;
        };
        if best.len() >= ef_search
            && best
                .first()
                .is_some_and(|worst_retained| candidate < *worst_retained)
        {
            break;
        }
        if let Some(neighbours) = partition
            .nodes
            .get(&candidate.id)
            .and_then(|node| node.levels.first())
        {
            for neighbour in neighbours {
                if discovered.contains(neighbour) || visits >= max_visits {
                    continue;
                }
                let Some(candidate_score) = score_ann_candidate(
                    *neighbour,
                    records,
                    metric,
                    query,
                    &mut scores,
                    &mut visits,
                    max_visits,
                )?
                else {
                    break;
                };
                discovered.insert(*neighbour);
                let next = RankedAnnCandidate {
                    score: candidate_score,
                    id: *neighbour,
                };
                if best.len() < ef_search
                    || best
                        .first()
                        .is_some_and(|worst_retained| next > *worst_retained)
                {
                    best.insert(next);
                    if best.len() > ef_search {
                        best.pop_first();
                    }
                    frontier.insert(next);
                    if frontier.len() > ef_search {
                        frontier.pop_first();
                    }
                }
            }
        }
    }
    Ok((
        best.into_iter().map(|candidate| candidate.id).collect(),
        visits,
    ))
}

#[cfg(feature = "ann-hnsw")]
fn score_ann_candidate(
    id: RepresentationId,
    records: &BTreeMap<RepresentationId, VectorRecord>,
    metric: VectorMetric,
    query: &[f32],
    scores: &mut BTreeMap<RepresentationId, f32>,
    visits: &mut usize,
    max_visits: usize,
) -> Result<Option<f32>> {
    if let Some(existing) = scores.get(&id) {
        return Ok(Some(*existing));
    }
    if *visits >= max_visits {
        return Ok(None);
    }
    let value = score(
        metric,
        query,
        &records
            .get(&id)
            .ok_or(IndexError::UnknownRepresentation(id))?
            .values,
    )?;
    scores.insert(id, value);
    *visits = visits.saturating_add(1);
    Ok(Some(value))
}

#[cfg(feature = "ann-hnsw")]
fn validated_bundle_payload(bundle: &PersistentAnnGeneration) -> Result<AnnPayload> {
    if bundle.payload.len() > MAX_ANN_GENERATION_BYTES {
        return Err(IndexError::Invalid(
            "ANN generation exceeds bounded byte limit",
        ));
    }
    if bundle.schema_version != 1
        || *blake3::hash(&bundle.payload).as_bytes() != bundle.payload_digest
    {
        return Err(IndexError::Invalid("ANN bundle schema or digest mismatch"));
    }
    let payload: AnnPayload = serde_json::from_slice(&bundle.payload)?;
    if payload.schema_version != bundle.schema_version
        || payload.generation != bundle.generation
        || payload.watermark != bundle.watermark
    {
        return Err(IndexError::Invalid("ANN bundle manifest mismatch"));
    }
    let mut total_nodes = 0_usize;
    for (key, partition) in &payload.partitions {
        partition.policy.validate()?;
        payload.spaces.get(partition.vector_space_id)?;
        if *key != partition_key(partition.vector_space_id, &partition.policy)? {
            return Err(IndexError::Invalid("ANN partition key is invalid"));
        }
        if !partition.nodes.contains_key(&partition.entry) {
            return Err(IndexError::Invalid("ANN entry is absent"));
        }
        total_nodes = total_nodes.saturating_add(partition.nodes.len());
        if total_nodes > MAX_ANN_GENERATION_NODES {
            return Err(IndexError::Invalid(
                "ANN generation exceeds bounded node limit",
            ));
        }
        let expected_max_level = partition
            .nodes
            .keys()
            .map(|id| deterministic_level(*id))
            .max()
            .ok_or(IndexError::Invalid("empty HNSW partition"))?;
        let expected_entry = partition
            .nodes
            .keys()
            .filter(|id| deterministic_level(**id) == expected_max_level)
            .min()
            .copied()
            .ok_or(IndexError::Invalid("ANN entry is absent"))?;
        if partition.max_level != expected_max_level || partition.entry != expected_entry {
            return Err(IndexError::Invalid("ANN entry level is invalid"));
        }
        for (id, node) in &partition.nodes {
            if node.levels.len() != usize::from(deterministic_level(*id)) + 1 {
                return Err(IndexError::Invalid("ANN node level count is invalid"));
            }
            for (level, neighbours) in node.levels.iter().enumerate() {
                if neighbours.len() > MAX_HNSW_NEIGHBOURS {
                    return Err(IndexError::Invalid("ANN neighbour limit is exceeded"));
                }
                let unique = neighbours.iter().copied().collect::<BTreeSet<_>>();
                if unique.len() != neighbours.len()
                    || unique.contains(id)
                    || unique.iter().any(|neighbour| {
                        partition
                            .nodes
                            .get(neighbour)
                            .is_none_or(|candidate| candidate.levels.len() <= level)
                    })
                {
                    return Err(IndexError::Invalid("ANN neighbour linkage is invalid"));
                }
            }
        }
        validate_ann_partition_connectivity(partition)?;
    }
    Ok(payload)
}

#[cfg(feature = "ann-hnsw")]
fn validate_ann_partition_connectivity(partition: &HnswPartition) -> Result<()> {
    let mut pending = VecDeque::from([partition.entry]);
    let mut reachable = BTreeSet::new();
    while let Some(id) = pending.pop_front() {
        if !reachable.insert(id) {
            continue;
        }
        let neighbours = partition
            .nodes
            .get(&id)
            .and_then(|node| node.levels.first())
            .ok_or(IndexError::Invalid("ANN base layer is absent"))?;
        for neighbour in neighbours {
            if !reachable.contains(neighbour) {
                pending.push_back(*neighbour);
            }
        }
    }
    if reachable.len() != partition.nodes.len() {
        return Err(IndexError::Invalid("ANN base layer is disconnected"));
    }
    Ok(())
}

#[cfg(feature = "ann-hnsw")]
fn validate_ann_payload_against_records(
    payload: &AnnPayload,
    records: &BTreeMap<RepresentationId, VectorRecord>,
) -> Result<()> {
    let mut actual = BTreeMap::<String, BTreeSet<RepresentationId>>::new();
    for partition in payload.partitions.values() {
        let key = partition_key(partition.vector_space_id, &partition.policy)?;
        for id in partition.nodes.keys() {
            let record = records
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            if record.vector_space_id != partition.vector_space_id
                || record.policy != partition.policy
                || record.projected_at > payload.watermark
                || record
                    .tombstone_at
                    .is_some_and(|deleted| deleted <= payload.watermark)
            {
                return Err(IndexError::Invalid(
                    "ANN generation disagrees with full-precision records",
                ));
            }
            actual.entry(key.clone()).or_default().insert(*id);
        }
    }
    let mut expected = BTreeMap::<String, BTreeSet<RepresentationId>>::new();
    for record in records.values() {
        if record.projected_at <= payload.watermark
            && record
                .tombstone_at
                .is_none_or(|deleted| deleted > payload.watermark)
        {
            expected
                .entry(partition_key(record.vector_space_id, &record.policy)?)
                .or_default()
                .insert(record.id);
        }
    }
    if actual != expected {
        return Err(IndexError::Invalid(
            "ANN generation membership is incomplete or extraneous",
        ));
    }
    for partition in payload.partitions.values() {
        let metric = payload.spaces.get(partition.vector_space_id)?.metric;
        for (owner, node) in &partition.nodes {
            let owner_record = records
                .get(owner)
                .ok_or(IndexError::UnknownRepresentation(*owner))?;
            for neighbours in &node.levels {
                let mut previous = None;
                for neighbour in neighbours {
                    let neighbour_record = records
                        .get(neighbour)
                        .ok_or(IndexError::UnknownRepresentation(*neighbour))?;
                    let ranked = RankedAnnCandidate {
                        score: score(metric, &owner_record.values, &neighbour_record.values)?,
                        id: *neighbour,
                    };
                    if previous.is_some_and(|prior| ranked > prior) {
                        return Err(IndexError::Invalid("ANN neighbour order is non-canonical"));
                    }
                    previous = Some(ranked);
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "ann-hnsw")]
fn partition_key(space: VectorSpaceId, policy: &IndexPolicy) -> Result<String> {
    let bytes = serde_json::to_vec(&(space, policy))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[cfg(feature = "ann-hnsw")]
fn deterministic_level(id: RepresentationId) -> u8 {
    let digest = blake3::hash(id.as_uuid().as_bytes());
    (digest.as_bytes()[0].leading_zeros() / 2).min(4) as u8
}

pub(crate) fn validate_values(space: &VectorSpace, values: &[f32]) -> Result<()> {
    let expected = usize::try_from(space.dimensions)
        .map_err(|_| IndexError::Invalid("vector dimensions exceed platform size"))?;
    if values.len() != expected {
        return Err(IndexError::DimensionMismatch {
            expected,
            actual: values.len(),
        });
    }
    if values.iter().any(|value| !value.is_finite()) {
        return Err(IndexError::Invalid("vector values must be finite"));
    }
    if space.metric == VectorMetric::Cosine && norm(values) == 0.0 {
        return Err(IndexError::Invalid("cosine vector must be non-zero"));
    }
    Ok(())
}

pub(crate) fn score(metric: VectorMetric, left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(IndexError::DimensionMismatch {
            expected: left.len(),
            actual: right.len(),
        });
    }
    let dot = left.iter().zip(right).map(|(a, b)| a * b).sum::<f32>();
    let value = match metric {
        VectorMetric::DotProduct => dot,
        VectorMetric::Cosine => dot / (norm(left) * norm(right)),
        VectorMetric::Euclidean => -left
            .iter()
            .zip(right)
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt(),
    };
    if value.is_finite() {
        Ok(value)
    } else {
        Err(IndexError::Invalid("vector score is not finite"))
    }
}

fn norm(values: &[f32]) -> f32 {
    values.iter().map(|value| value * value).sum::<f32>().sqrt()
}

fn hit(record: &VectorRecord, score: f32) -> VectorHit {
    VectorHit {
        representation_id: record.id,
        target: record.target.clone(),
        score,
    }
}

fn sort_hits(hits: &mut Vec<VectorHit>, limit: usize) {
    hits.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.representation_id.cmp(&right.representation_id))
    });
    hits.truncate(limit);
}
