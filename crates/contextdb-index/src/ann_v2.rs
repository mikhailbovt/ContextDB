//! Bounded, storage-neutral physical contracts for paged ANN generation v2.
//!
//! This module defines formats and validation only. It intentionally does not
//! build, publish, authorize, or query a generation. In particular, exposing
//! these types does not advertise a persistent-ANN runtime capability.

use std::str::FromStr;

use contextdb_core::{CommitSeq, RepresentationId, TimestampMicros, VectorSpaceId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Physical format number for paged ANN generations.
pub const ANN_V2_FORMAT_VERSION: u16 = 2;
/// Maximum HNSW level admitted by the initial v2 format.
pub const ANN_V2_MAX_LEVEL: u8 = 4;
/// Maximum neighbours stored in one node level.
pub const ANN_V2_MAX_NEIGHBOURS_PER_LEVEL: usize = 64;
/// Minimum deterministic construction-search budget.
pub const ANN_V2_MIN_CONSTRUCTION_VISITS: u32 = 64;
/// Maximum deterministic construction-search budget.
pub const ANN_V2_MAX_CONSTRUCTION_VISITS: u32 = 2_048;
/// Maximum partitions represented by one generation.
pub const ANN_V2_MAX_PARTITIONS: u64 = 1_048_576;
/// Maximum nodes represented by one generation.
pub const ANN_V2_MAX_NODES: u64 = 20_000_000;
/// Maximum level rows represented by one generation.
pub const ANN_V2_MAX_LEVEL_ROWS: u64 = ANN_V2_MAX_NODES * (ANN_V2_MAX_LEVEL as u64 + 1);
/// Maximum neighbour references represented by one generation.
pub const ANN_V2_MAX_NEIGHBOUR_REFS: u64 =
    ANN_V2_MAX_LEVEL_ROWS * ANN_V2_MAX_NEIGHBOURS_PER_LEVEL as u64;
/// Maximum encoded bytes in one generation.
pub const ANN_V2_MAX_GENERATION_BYTES: u64 = 256 * 1024 * 1024 * 1024;
/// Maximum encoded bytes in one node value.
pub const ANN_V2_MAX_NODE_BYTES: usize = 16 * 1024;
/// Maximum encoded bytes in a partition manifest.
pub const ANN_V2_MAX_PARTITION_MANIFEST_BYTES: usize = 64 * 1024;
/// Maximum encoded bytes in a generation manifest.
pub const ANN_V2_MAX_GENERATION_MANIFEST_BYTES: usize = 64 * 1024;
/// Maximum encoded bytes in any single portable ANN object.
pub const ANN_V2_MAX_OBJECT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum entries in one portable ANN object page.
pub const ANN_V2_MAX_PAGE_ENTRIES: usize = 1_024;
/// Maximum key/value/digest bytes in one portable ANN object page.
pub const ANN_V2_MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum bytes in one canonical ANN object key.
pub const ANN_V2_MAX_KEY_BYTES: usize = 64;
/// Maximum authenticated Merkle-tree depth.
pub const ANN_V2_MAX_MERKLE_LEVEL: u16 = 64;

const NODE_MAGIC: [u8; 4] = *b"CANN";
const NODE_KIND: u8 = 1;
const UUID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const GENERATION_PREFIX_BYTES: usize = 9;
const PARTITION_KEY_BYTES: usize = 42;
const NODE_KEY_BYTES: usize = 58;
const PARTITION_TREE_KEY_BYTES: usize = 52;
const GLOBAL_TREE_KEY_BYTES: usize = 20;
const NODE_FIXED_BODY_BYTES: usize = 73;
const NODE_MIN_WIRE_BYTES: usize = NODE_FIXED_BODY_BYTES + DIGEST_BYTES;

const NODE_DIGEST_DOMAIN: &[u8] = b"contextdb.ann-v2.node/v1\0";
const OBJECT_DIGEST_DOMAIN: &[u8] = b"contextdb.ann-v2.object/v1\0";
const GENERATION_DIGEST_DOMAIN: &[u8] = b"contextdb.ann-v2.generation/v1\0";
const PARTITION_DIGEST_DOMAIN: &[u8] = b"contextdb.ann-v2.partition/v1\0";
const PARTITION_KEY_DOMAIN: &[u8] = b"contextdb.ann-v2.partition-key/v1\0";
const MERKLE_LEAF_DOMAIN: &[u8] = b"contextdb.ann-v2.merkle-leaf/v1\0";
const MERKLE_INTERNAL_DOMAIN: &[u8] = b"contextdb.ann-v2.merkle-internal/v1\0";
const MERKLE_ROOT_DOMAIN: &[u8] = b"contextdb.ann-v2.merkle-root/v1\0";

/// Validation or canonical-codec failure for ANN generation v2 contracts.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AnnV2Error {
    /// A reader encountered a format it does not implement.
    #[error("unsupported ANN format {actual}; expected {expected}")]
    UnsupportedFormat {
        /// Format found in the input.
        actual: u16,
        /// Format required by this reader.
        expected: u16,
    },
    /// A structural invariant failed without exposing stored content.
    #[error("invalid ANN v2 structure: {0}")]
    Invalid(&'static str),
    /// A finite resource limit was exceeded.
    #[error("ANN v2 resource exhausted for {resource}: limit {limit}, required {required}")]
    ResourceExhausted {
        /// Stable resource identifier.
        resource: &'static str,
        /// Configured hard maximum.
        limit: u64,
        /// Smallest known required amount.
        required: u64,
    },
    /// An authenticated value disagreed with its declared digest.
    #[error("ANN v2 digest mismatch for {0}")]
    DigestMismatch(&'static str),
    /// Input decoded semantically but did not use the one canonical encoding.
    #[error("ANN v2 value is not canonically encoded")]
    NonCanonical,
}

/// ANN v2 format result.
pub type AnnV2Result<T> = Result<T, AnnV2Error>;

/// Deterministic ANN construction algorithm selected by a v2 generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnAlgorithmV2 {
    /// Deterministic bounded HNSW with exact full-precision scoring.
    DeterministicHnswV1,
}

impl AnnAlgorithmV2 {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::DeterministicHnswV1 => 1,
        }
    }
}

/// Privacy partitioning scheme selected by a v2 generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnPartitionSchemeV2 {
    /// Vector space plus exact canonical `IndexPolicy` digest.
    ExactPolicyV1,
}

impl AnnPartitionSchemeV2 {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::ExactPolicyV1 => 1,
        }
    }
}

/// Frozen construction parameters authenticated by a generation manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnBuildParametersV2 {
    /// Deterministic graph construction algorithm.
    pub algorithm: AnnAlgorithmV2,
    /// Policy-safe partitioning algorithm.
    pub partition_scheme: AnnPartitionSchemeV2,
    /// Highest node level admitted by this generation.
    pub max_level: u8,
    /// Maximum neighbours retained in each level row.
    pub neighbours_per_level: u16,
    /// Maximum candidate visits during one construction-level search.
    pub construction_max_visits: u32,
}

impl AnnBuildParametersV2 {
    /// Validates all algorithmic hard bounds before construction or allocation.
    pub fn validate(self) -> AnnV2Result<()> {
        if self.max_level > ANN_V2_MAX_LEVEL {
            return exhausted(
                "max_level",
                u64::from(ANN_V2_MAX_LEVEL),
                u64::from(self.max_level),
            );
        }
        if self.neighbours_per_level == 0
            || usize::from(self.neighbours_per_level) > ANN_V2_MAX_NEIGHBOURS_PER_LEVEL
        {
            return exhausted(
                "neighbours_per_level",
                ANN_V2_MAX_NEIGHBOURS_PER_LEVEL as u64,
                u64::from(self.neighbours_per_level),
            );
        }
        if !(ANN_V2_MIN_CONSTRUCTION_VISITS..=ANN_V2_MAX_CONSTRUCTION_VISITS)
            .contains(&self.construction_max_visits)
        {
            return Err(AnnV2Error::Invalid(
                "construction visit budget is outside the supported range",
            ));
        }
        Ok(())
    }
}

/// Immutable binding from an ANN generation to its exact vector and route sources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnSourceSealV2 {
    /// Full-precision vector-store generation used by the builder.
    pub vector_store_generation: u64,
    /// Authenticated full-precision vector-store root.
    pub vector_store_root: [u8; 32],
    /// Routing-only generation used to form exact policy partitions.
    pub route_generation: u64,
    /// Authenticated routing-only generation root.
    pub route_root: [u8; 32],
    /// Digest of immutable vector-space compatibility definitions.
    pub vector_space_registry_digest: [u8; 32],
}

impl AnnSourceSealV2 {
    /// Rejects placeholder generations and unsealed zero digests.
    pub fn validate(self) -> AnnV2Result<()> {
        if self.vector_store_generation == 0 || self.route_generation == 0 {
            return Err(AnnV2Error::Invalid("source generation is zero"));
        }
        if is_zero_digest(&self.vector_store_root)
            || is_zero_digest(&self.route_root)
            || is_zero_digest(&self.vector_space_registry_digest)
        {
            return Err(AnnV2Error::Invalid("source seal contains a zero digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AnnAlgorithmWireV2 {
    DeterministicHnswV1,
}

impl From<AnnAlgorithmV2> for AnnAlgorithmWireV2 {
    fn from(value: AnnAlgorithmV2) -> Self {
        match value {
            AnnAlgorithmV2::DeterministicHnswV1 => Self::DeterministicHnswV1,
        }
    }
}

impl From<AnnAlgorithmWireV2> for AnnAlgorithmV2 {
    fn from(value: AnnAlgorithmWireV2) -> Self {
        match value {
            AnnAlgorithmWireV2::DeterministicHnswV1 => Self::DeterministicHnswV1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AnnPartitionSchemeWireV2 {
    ExactPolicyV1,
}

impl From<AnnPartitionSchemeV2> for AnnPartitionSchemeWireV2 {
    fn from(value: AnnPartitionSchemeV2) -> Self {
        match value {
            AnnPartitionSchemeV2::ExactPolicyV1 => Self::ExactPolicyV1,
        }
    }
}

impl From<AnnPartitionSchemeWireV2> for AnnPartitionSchemeV2 {
    fn from(value: AnnPartitionSchemeWireV2) -> Self {
        match value {
            AnnPartitionSchemeWireV2::ExactPolicyV1 => Self::ExactPolicyV1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnBuildParametersWireV2 {
    algorithm: AnnAlgorithmWireV2,
    partition_scheme: AnnPartitionSchemeWireV2,
    max_level: u8,
    neighbours_per_level: u16,
    construction_max_visits: u32,
}

impl From<AnnBuildParametersV2> for AnnBuildParametersWireV2 {
    fn from(value: AnnBuildParametersV2) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            partition_scheme: value.partition_scheme.into(),
            max_level: value.max_level,
            neighbours_per_level: value.neighbours_per_level,
            construction_max_visits: value.construction_max_visits,
        }
    }
}

impl From<AnnBuildParametersWireV2> for AnnBuildParametersV2 {
    fn from(value: AnnBuildParametersWireV2) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            partition_scheme: value.partition_scheme.into(),
            max_level: value.max_level,
            neighbours_per_level: value.neighbours_per_level,
            construction_max_visits: value.construction_max_visits,
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnGenerationManifestWireV2 {
    format_version: u16,
    generation: u64,
    watermark: CommitSeq,
    source: AnnSourceSealWireV2,
    build: AnnBuildParametersWireV2,
    partition_count: u64,
    node_count: u64,
    level_row_count: u64,
    neighbour_count: u64,
    object_bytes: u64,
    partition_tree_root: [u8; 32],
    manifest_digest: [u8; 32],
}

impl From<&AnnGenerationManifestV2> for AnnGenerationManifestWireV2 {
    fn from(value: &AnnGenerationManifestV2) -> Self {
        Self {
            format_version: value.format_version,
            generation: value.generation,
            watermark: value.watermark,
            source: value.source.into(),
            build: value.build.into(),
            partition_count: value.partition_count,
            node_count: value.node_count,
            level_row_count: value.level_row_count,
            neighbour_count: value.neighbour_count,
            object_bytes: value.object_bytes,
            partition_tree_root: value.partition_tree_root,
            manifest_digest: value.manifest_digest,
        }
    }
}

impl TryFrom<AnnGenerationManifestWireV2> for AnnGenerationManifestV2 {
    type Error = AnnV2Error;

    fn try_from(value: AnnGenerationManifestWireV2) -> AnnV2Result<Self> {
        let manifest = Self {
            format_version: value.format_version,
            generation: value.generation,
            watermark: value.watermark,
            source: value.source.into(),
            build: value.build.into(),
            partition_count: value.partition_count,
            node_count: value.node_count,
            level_row_count: value.level_row_count,
            neighbour_count: value.neighbour_count,
            object_bytes: value.object_bytes,
            partition_tree_root: value.partition_tree_root,
            manifest_digest: value.manifest_digest,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Small authenticated root for one paged ANN generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnGenerationManifestV2 {
    /// Physical generation format. Must be [`ANN_V2_FORMAT_VERSION`].
    pub format_version: u16,
    /// Monotonically increasing generation number.
    pub generation: u64,
    /// Highest semantic projection commit incorporated into the base graph.
    pub watermark: CommitSeq,
    /// Exact vector/routing source binding.
    pub source: AnnSourceSealV2,
    /// Frozen deterministic construction parameters.
    pub build: AnnBuildParametersV2,
    /// Number of partition manifests authenticated by `partition_tree_root`.
    pub partition_count: u64,
    /// Total HNSW nodes across every partition.
    pub node_count: u64,
    /// Total node-level adjacency rows.
    pub level_row_count: u64,
    /// Total neighbour references across every node-level row.
    pub neighbour_count: u64,
    /// Aggregate encoded generation object bytes.
    pub object_bytes: u64,
    /// Merkle root over ordered partition manifests.
    pub partition_tree_root: [u8; 32],
    /// Domain-separated digest of every preceding logical field.
    pub manifest_digest: [u8; 32],
}

impl AnnGenerationManifestV2 {
    /// Computes the canonical digest without serializing or allocating a payload.
    #[must_use]
    pub fn computed_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GENERATION_DIGEST_DOMAIN);
        hash_u16(&mut hasher, self.format_version);
        hash_u64(&mut hasher, self.generation);
        hash_u64(&mut hasher, self.watermark.get());
        hash_source_seal(&mut hasher, self.source);
        hash_build_parameters(&mut hasher, self.build);
        hash_u64(&mut hasher, self.partition_count);
        hash_u64(&mut hasher, self.node_count);
        hash_u64(&mut hasher, self.level_row_count);
        hash_u64(&mut hasher, self.neighbour_count);
        hash_u64(&mut hasher, self.object_bytes);
        hasher.update(&self.partition_tree_root);
        *hasher.finalize().as_bytes()
    }

    /// Validates the shape and returns a copy sealed with its canonical digest.
    pub fn seal(mut self) -> AnnV2Result<Self> {
        self.validate_shape()?;
        self.manifest_digest = self.computed_digest();
        self.validate()?;
        Ok(self)
    }

    /// Validates format, caps, count relationships, empty-root encoding, and digest.
    pub fn validate(&self) -> AnnV2Result<()> {
        self.validate_shape()?;
        if self.manifest_digest != self.computed_digest() {
            return Err(AnnV2Error::DigestMismatch("generation manifest"));
        }
        Ok(())
    }

    /// Encodes a validated control manifest in the one canonical JSON representation.
    pub fn encode_json(&self) -> AnnV2Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(&AnnGenerationManifestWireV2::from(self))
            .map_err(|_| AnnV2Error::Invalid("generation manifest JSON encode failed"))?;
        ensure_usize_bound(
            "generation_manifest_bytes",
            bytes.len(),
            ANN_V2_MAX_GENERATION_MANIFEST_BYTES,
        )?;
        Ok(bytes)
    }

    /// Decodes one bounded control manifest and validates its canonical digest.
    pub fn decode_json(bytes: &[u8]) -> AnnV2Result<Self> {
        ensure_usize_bound(
            "generation_manifest_bytes",
            bytes.len(),
            ANN_V2_MAX_GENERATION_MANIFEST_BYTES,
        )?;
        let wire: AnnGenerationManifestWireV2 = serde_json::from_slice(bytes)
            .map_err(|_| AnnV2Error::Invalid("generation manifest JSON is invalid"))?;
        let manifest = Self::try_from(wire)?;
        manifest.validate()?;
        if manifest.encode_json()?.as_slice() != bytes {
            return Err(AnnV2Error::NonCanonical);
        }
        Ok(manifest)
    }

    fn validate_shape(&self) -> AnnV2Result<()> {
        ensure_format(self.format_version)?;
        if self.generation == 0 {
            return Err(AnnV2Error::Invalid("generation is zero"));
        }
        self.source.validate()?;
        self.build.validate()?;
        ensure_u64_bound(
            "generation_partitions",
            self.partition_count,
            ANN_V2_MAX_PARTITIONS,
        )?;
        ensure_u64_bound("generation_nodes", self.node_count, ANN_V2_MAX_NODES)?;
        ensure_u64_bound(
            "generation_level_rows",
            self.level_row_count,
            ANN_V2_MAX_LEVEL_ROWS,
        )?;
        ensure_u64_bound(
            "generation_neighbours",
            self.neighbour_count,
            ANN_V2_MAX_NEIGHBOUR_REFS,
        )?;
        ensure_u64_bound(
            "generation_object_bytes",
            self.object_bytes,
            ANN_V2_MAX_GENERATION_BYTES,
        )?;

        if self.partition_count == 0 {
            if self.node_count != 0
                || self.level_row_count != 0
                || self.neighbour_count != 0
                || self.object_bytes != 0
                || self.partition_tree_root != ann_v2_empty_partition_root(self.generation)?
            {
                return Err(AnnV2Error::Invalid(
                    "empty generation counters or root are not canonical",
                ));
            }
            return Ok(());
        }
        if self.node_count == 0
            || self.partition_count > self.node_count
            || self.object_bytes == 0
            || is_zero_digest(&self.partition_tree_root)
        {
            return Err(AnnV2Error::Invalid(
                "non-empty generation has inconsistent primary counters",
            ));
        }
        let maximum_rows = checked_count_product(
            "generation_level_rows",
            self.node_count,
            u64::from(self.build.max_level) + 1,
        )?;
        if self.level_row_count < self.node_count || self.level_row_count > maximum_rows {
            return Err(AnnV2Error::Invalid(
                "generation level-row count is inconsistent",
            ));
        }
        let maximum_neighbours = checked_count_product(
            "generation_neighbours",
            self.level_row_count,
            u64::from(self.build.neighbours_per_level),
        )?;
        if self.neighbour_count > maximum_neighbours {
            return Err(AnnV2Error::Invalid(
                "generation neighbour count is inconsistent",
            ));
        }
        Ok(())
    }
}

/// Authenticated summary for one exact-policy ANN partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnPartitionManifestV2 {
    /// Physical partition format. Must be [`ANN_V2_FORMAT_VERSION`].
    pub format_version: u16,
    /// Generation that owns this partition.
    pub generation: u64,
    /// Stable digest of vector space plus exact policy.
    pub partition_key: [u8; 32],
    /// Stable digest of the routing-only canonical policy.
    pub policy_digest: [u8; 32],
    /// Immutable vector-space compatibility identity.
    pub vector_space_id: VectorSpaceId,
    /// Deterministic HNSW entry node.
    pub entry: RepresentationId,
    /// Highest level present in this partition.
    pub max_level: u8,
    /// Leaf position in the generation-wide partition tree.
    pub global_leaf_index: u64,
    /// Nodes in this partition.
    pub node_count: u64,
    /// Node-level rows in this partition.
    pub level_row_count: u64,
    /// Neighbour references in this partition.
    pub neighbour_count: u64,
    /// Aggregate encoded node-object bytes in this partition.
    pub node_bytes: u64,
    /// Merkle root over ordered node objects.
    pub node_tree_root: [u8; 32],
    /// Latest validity start shared by every base node.
    pub valid_for_all_from: TimestampMicros,
    /// Earliest validity end shared by every base node, if finite.
    pub valid_for_all_until: Option<TimestampMicros>,
    /// Routing membership epoch captured by the builder.
    pub membership_epoch: u64,
    /// Domain-separated digest of every preceding logical field.
    pub manifest_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnPartitionManifestWireV2 {
    format_version: u16,
    generation: u64,
    partition_key: [u8; 32],
    policy_digest: [u8; 32],
    vector_space_id: VectorSpaceId,
    entry: RepresentationId,
    max_level: u8,
    global_leaf_index: u64,
    node_count: u64,
    level_row_count: u64,
    neighbour_count: u64,
    node_bytes: u64,
    node_tree_root: [u8; 32],
    valid_for_all_from: TimestampMicros,
    valid_for_all_until: Option<TimestampMicros>,
    membership_epoch: u64,
    manifest_digest: [u8; 32],
}

impl From<&AnnPartitionManifestV2> for AnnPartitionManifestWireV2 {
    fn from(value: &AnnPartitionManifestV2) -> Self {
        Self {
            format_version: value.format_version,
            generation: value.generation,
            partition_key: value.partition_key,
            policy_digest: value.policy_digest,
            vector_space_id: value.vector_space_id,
            entry: value.entry,
            max_level: value.max_level,
            global_leaf_index: value.global_leaf_index,
            node_count: value.node_count,
            level_row_count: value.level_row_count,
            neighbour_count: value.neighbour_count,
            node_bytes: value.node_bytes,
            node_tree_root: value.node_tree_root,
            valid_for_all_from: value.valid_for_all_from,
            valid_for_all_until: value.valid_for_all_until,
            membership_epoch: value.membership_epoch,
            manifest_digest: value.manifest_digest,
        }
    }
}

impl TryFrom<AnnPartitionManifestWireV2> for AnnPartitionManifestV2 {
    type Error = AnnV2Error;

    fn try_from(value: AnnPartitionManifestWireV2) -> AnnV2Result<Self> {
        let manifest = Self {
            format_version: value.format_version,
            generation: value.generation,
            partition_key: value.partition_key,
            policy_digest: value.policy_digest,
            vector_space_id: value.vector_space_id,
            entry: value.entry,
            max_level: value.max_level,
            global_leaf_index: value.global_leaf_index,
            node_count: value.node_count,
            level_row_count: value.level_row_count,
            neighbour_count: value.neighbour_count,
            node_bytes: value.node_bytes,
            node_tree_root: value.node_tree_root,
            valid_for_all_from: value.valid_for_all_from,
            valid_for_all_until: value.valid_for_all_until,
            membership_epoch: value.membership_epoch,
            manifest_digest: value.manifest_digest,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

impl AnnPartitionManifestV2 {
    /// Computes the canonical digest without serializing or allocating a payload.
    #[must_use]
    pub fn computed_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PARTITION_DIGEST_DOMAIN);
        hash_u16(&mut hasher, self.format_version);
        hash_u64(&mut hasher, self.generation);
        hasher.update(&self.partition_key);
        hasher.update(&self.policy_digest);
        hasher.update(self.vector_space_id.as_uuid().as_bytes());
        hasher.update(self.entry.as_uuid().as_bytes());
        hash_u8(&mut hasher, self.max_level);
        hash_u64(&mut hasher, self.global_leaf_index);
        hash_u64(&mut hasher, self.node_count);
        hash_u64(&mut hasher, self.level_row_count);
        hash_u64(&mut hasher, self.neighbour_count);
        hash_u64(&mut hasher, self.node_bytes);
        hasher.update(&self.node_tree_root);
        hash_i64(&mut hasher, self.valid_for_all_from.0);
        match self.valid_for_all_until {
            Some(until) => {
                hash_u8(&mut hasher, 1);
                hash_i64(&mut hasher, until.0);
            }
            None => hash_u8(&mut hasher, 0),
        }
        hash_u64(&mut hasher, self.membership_epoch);
        *hasher.finalize().as_bytes()
    }

    /// Validates the shape and returns a copy sealed with its canonical digest.
    pub fn seal(mut self) -> AnnV2Result<Self> {
        self.validate_shape()?;
        self.manifest_digest = self.computed_digest();
        self.validate()?;
        Ok(self)
    }

    /// Validates format, caps, count relationships, time interval, and digest.
    pub fn validate(&self) -> AnnV2Result<()> {
        self.validate_shape()?;
        if self.manifest_digest != self.computed_digest() {
            return Err(AnnV2Error::DigestMismatch("partition manifest"));
        }
        Ok(())
    }

    /// Encodes a validated control manifest in the one canonical JSON representation.
    pub fn encode_json(&self) -> AnnV2Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(&AnnPartitionManifestWireV2::from(self))
            .map_err(|_| AnnV2Error::Invalid("partition manifest JSON encode failed"))?;
        ensure_usize_bound(
            "partition_manifest_bytes",
            bytes.len(),
            ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
        )?;
        Ok(bytes)
    }

    /// Decodes one bounded control manifest and validates its canonical digest.
    pub fn decode_json(bytes: &[u8]) -> AnnV2Result<Self> {
        ensure_usize_bound(
            "partition_manifest_bytes",
            bytes.len(),
            ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
        )?;
        let wire: AnnPartitionManifestWireV2 = serde_json::from_slice(bytes)
            .map_err(|_| AnnV2Error::Invalid("partition manifest JSON is invalid"))?;
        let manifest = Self::try_from(wire)?;
        manifest.validate()?;
        if manifest.encode_json()?.as_slice() != bytes {
            return Err(AnnV2Error::NonCanonical);
        }
        Ok(manifest)
    }

    fn validate_shape(&self) -> AnnV2Result<()> {
        ensure_format(self.format_version)?;
        if self.generation == 0
            || self.membership_epoch == 0
            || is_zero_digest(&self.partition_key)
            || is_zero_digest(&self.policy_digest)
            || is_zero_digest(&self.node_tree_root)
            || is_nil_representation(self.entry)
        {
            return Err(AnnV2Error::Invalid(
                "partition identity contains a zero placeholder",
            ));
        }
        if self.partition_key != ann_v2_partition_key(self.vector_space_id, self.policy_digest)? {
            return Err(AnnV2Error::Invalid(
                "partition key disagrees with vector space and policy digest",
            ));
        }
        if self.max_level > ANN_V2_MAX_LEVEL {
            return exhausted(
                "partition_max_level",
                u64::from(ANN_V2_MAX_LEVEL),
                u64::from(self.max_level),
            );
        }
        ensure_u64_bound(
            "partition_leaf_index",
            self.global_leaf_index,
            ANN_V2_MAX_PARTITIONS.saturating_sub(1),
        )?;
        if self.node_count == 0 {
            return Err(AnnV2Error::Invalid("empty ANN partition is forbidden"));
        }
        ensure_u64_bound("partition_nodes", self.node_count, ANN_V2_MAX_NODES)?;
        ensure_u64_bound(
            "partition_level_rows",
            self.level_row_count,
            ANN_V2_MAX_LEVEL_ROWS,
        )?;
        ensure_u64_bound(
            "partition_neighbours",
            self.neighbour_count,
            ANN_V2_MAX_NEIGHBOUR_REFS,
        )?;
        ensure_u64_bound(
            "partition_node_bytes",
            self.node_bytes,
            ANN_V2_MAX_GENERATION_BYTES,
        )?;
        if self.node_bytes == 0 {
            return Err(AnnV2Error::Invalid("partition node bytes are zero"));
        }
        let maximum_rows = checked_count_product(
            "partition_level_rows",
            self.node_count,
            u64::from(self.max_level) + 1,
        )?;
        if self.level_row_count < self.node_count || self.level_row_count > maximum_rows {
            return Err(AnnV2Error::Invalid(
                "partition level-row count is inconsistent",
            ));
        }
        let maximum_neighbours = checked_count_product(
            "partition_neighbours",
            self.level_row_count,
            ANN_V2_MAX_NEIGHBOURS_PER_LEVEL as u64,
        )?;
        if self.neighbour_count > maximum_neighbours {
            return Err(AnnV2Error::Invalid(
                "partition neighbour count is inconsistent",
            ));
        }
        if self
            .valid_for_all_until
            .is_some_and(|until| until <= self.valid_for_all_from)
        {
            return Err(AnnV2Error::Invalid(
                "partition shared validity interval is empty",
            ));
        }
        Ok(())
    }
}

/// One canonical HNSW adjacency level in a bounded node object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnLevelV2 {
    /// Zero-based HNSW level.
    pub level: u8,
    /// Strictly ID-ordered unique neighbours.
    pub neighbours: Vec<RepresentationId>,
}

/// One bounded node object containing every level for one representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnNodeV2 {
    /// Generation that owns this node.
    pub generation: u64,
    /// Exact-policy partition digest.
    pub partition_key: [u8; 32],
    /// Immutable vector representation identity.
    pub representation_id: RepresentationId,
    /// Leaf position in this partition's node tree.
    pub leaf_index: u64,
    /// Contiguous levels starting at zero.
    pub levels: Vec<AnnLevelV2>,
}

impl AnnNodeV2 {
    /// Validates identity, row order, neighbour bounds, and canonical wire length.
    pub fn validate(&self) -> AnnV2Result<()> {
        if self.generation == 0
            || is_zero_digest(&self.partition_key)
            || is_nil_representation(self.representation_id)
        {
            return Err(AnnV2Error::Invalid(
                "node identity contains a zero placeholder",
            ));
        }
        ensure_u64_bound(
            "node_leaf_index",
            self.leaf_index,
            ANN_V2_MAX_NODES.saturating_sub(1),
        )?;
        if self.levels.is_empty() || self.levels.len() > usize::from(ANN_V2_MAX_LEVEL) + 1 {
            return Err(AnnV2Error::Invalid("node level count is invalid"));
        }
        for (expected, row) in self.levels.iter().enumerate() {
            if usize::from(row.level) != expected {
                return Err(AnnV2Error::Invalid("node levels are not contiguous"));
            }
            if row.neighbours.len() > ANN_V2_MAX_NEIGHBOURS_PER_LEVEL {
                return exhausted(
                    "node_level_neighbours",
                    ANN_V2_MAX_NEIGHBOURS_PER_LEVEL as u64,
                    usize_to_u64(row.neighbours.len()),
                );
            }
            if row.neighbours.iter().any(|id| is_nil_representation(*id))
                || row.neighbours.contains(&self.representation_id)
                || row.neighbours.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(AnnV2Error::Invalid(
                    "node neighbours are not unique canonical IDs",
                ));
            }
        }
        let _ = self.canonical_wire_len()?;
        Ok(())
    }

    /// Returns the exact canonical wire length using checked arithmetic.
    pub fn canonical_wire_len(&self) -> AnnV2Result<usize> {
        let mut length = NODE_FIXED_BODY_BYTES;
        for row in &self.levels {
            length = checked_usize_add("node_bytes", length, 3)?;
            let neighbour_bytes =
                checked_usize_product("node_neighbour_bytes", row.neighbours.len(), UUID_BYTES)?;
            length = checked_usize_add("node_bytes", length, neighbour_bytes)?;
        }
        length = checked_usize_add("node_bytes", length, DIGEST_BYTES)?;
        ensure_usize_bound("node_bytes", length, ANN_V2_MAX_NODE_BYTES)?;
        Ok(length)
    }

    /// Encodes one deterministic binary node with a trailing BLAKE3 digest.
    pub fn encode_canonical(&self) -> AnnV2Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(self.canonical_wire_len()?);
        bytes.extend_from_slice(&NODE_MAGIC);
        bytes.extend_from_slice(&ANN_V2_FORMAT_VERSION.to_be_bytes());
        bytes.push(NODE_KIND);
        bytes.push(0);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.partition_key);
        push_uuid_bytes(&mut bytes, self.representation_id);
        bytes.extend_from_slice(&self.leaf_index.to_be_bytes());
        bytes.push(u8::try_from(self.levels.len()).map_err(|_| {
            AnnV2Error::Invalid("node level count exceeds the wire representation")
        })?);
        for row in &self.levels {
            bytes.push(row.level);
            let count = u16::try_from(row.neighbours.len()).map_err(|_| {
                AnnV2Error::Invalid("node neighbour count exceeds the wire representation")
            })?;
            bytes.extend_from_slice(&count.to_be_bytes());
            for neighbour in &row.neighbours {
                push_uuid_bytes(&mut bytes, *neighbour);
            }
        }
        let digest = digest_with_domain(NODE_DIGEST_DOMAIN, &bytes);
        bytes.extend_from_slice(&digest);
        debug_assert_eq!(bytes.len(), self.canonical_wire_len().unwrap_or_default());
        Ok(bytes)
    }

    /// Decodes, authenticates, validates, and canonicalizes one bounded node value.
    pub fn decode_canonical(bytes: &[u8]) -> AnnV2Result<Self> {
        ensure_usize_bound("node_bytes", bytes.len(), ANN_V2_MAX_NODE_BYTES)?;
        if bytes.len() < NODE_MIN_WIRE_BYTES {
            return Err(AnnV2Error::Invalid("node value is truncated"));
        }
        let body_len = bytes
            .len()
            .checked_sub(DIGEST_BYTES)
            .ok_or(AnnV2Error::Invalid("node digest is truncated"))?;
        let (body, declared_digest) = bytes.split_at(body_len);
        if declared_digest != digest_with_domain(NODE_DIGEST_DOMAIN, body) {
            return Err(AnnV2Error::DigestMismatch("node object"));
        }

        let mut cursor = 0_usize;
        if take(body, &mut cursor, NODE_MAGIC.len())? != NODE_MAGIC {
            return Err(AnnV2Error::Invalid("node magic is invalid"));
        }
        let format_version = read_u16(body, &mut cursor)?;
        ensure_format(format_version)?;
        if read_u8(body, &mut cursor)? != NODE_KIND || read_u8(body, &mut cursor)? != 0 {
            return Err(AnnV2Error::Invalid("node kind or reserved byte is invalid"));
        }
        let generation = read_u64(body, &mut cursor)?;
        let partition_key: [u8; 32] = take(body, &mut cursor, 32)?
            .try_into()
            .map_err(|_| AnnV2Error::Invalid("node partition digest is truncated"))?;
        let representation_id = read_uuid_bytes(body, &mut cursor)?;
        let leaf_index = read_u64(body, &mut cursor)?;
        let level_count = usize::from(read_u8(body, &mut cursor)?);
        if level_count == 0 || level_count > usize::from(ANN_V2_MAX_LEVEL) + 1 {
            return Err(AnnV2Error::Invalid("node level count is invalid"));
        }
        let mut levels = Vec::with_capacity(level_count);
        for _ in 0..level_count {
            let level = read_u8(body, &mut cursor)?;
            let neighbour_count = usize::from(read_u16(body, &mut cursor)?);
            if neighbour_count > ANN_V2_MAX_NEIGHBOURS_PER_LEVEL {
                return exhausted(
                    "node_level_neighbours",
                    ANN_V2_MAX_NEIGHBOURS_PER_LEVEL as u64,
                    usize_to_u64(neighbour_count),
                );
            }
            let required =
                checked_usize_product("node_neighbour_bytes", neighbour_count, UUID_BYTES)?;
            if body.len().saturating_sub(cursor) < required {
                return Err(AnnV2Error::Invalid("node neighbour list is truncated"));
            }
            let mut neighbours = Vec::with_capacity(neighbour_count);
            for _ in 0..neighbour_count {
                neighbours.push(read_uuid_bytes(body, &mut cursor)?);
            }
            levels.push(AnnLevelV2 { level, neighbours });
        }
        if cursor != body.len() {
            return Err(AnnV2Error::NonCanonical);
        }
        let node = Self {
            generation,
            partition_key,
            representation_id,
            leaf_index,
            levels,
        };
        node.validate()?;
        if node.encode_canonical()?.as_slice() != bytes {
            return Err(AnnV2Error::NonCanonical);
        }
        Ok(node)
    }
}

/// Role of one key in the paged ANN object keyspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnObjectKindV2 {
    /// One partition manifest.
    PartitionManifest,
    /// One bounded HNSW node.
    Node,
    /// One node-tree hash inside a partition.
    PartitionTree,
    /// One generation-wide partition-tree hash.
    GlobalTree,
}

/// Domain and identity of one ANN v2 Merkle tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnMerkleScopeV2 {
    /// Ordered node objects belonging to one exact-policy partition.
    PartitionNodes {
        /// Generation containing the partition.
        generation: u64,
        /// Canonical vector-space/policy partition digest.
        partition_key: [u8; 32],
    },
    /// Ordered partition-manifest objects belonging to one generation.
    GenerationPartitions {
        /// Generation containing the manifests.
        generation: u64,
    },
}

impl AnnMerkleScopeV2 {
    fn validate(self) -> AnnV2Result<()> {
        if self.generation() == 0 {
            return Err(AnnV2Error::Invalid("Merkle scope generation is zero"));
        }
        if let Self::PartitionNodes { partition_key, .. } = self
            && is_zero_digest(&partition_key)
        {
            return Err(AnnV2Error::Invalid(
                "Merkle partition scope contains a zero digest",
            ));
        }
        Ok(())
    }

    const fn generation(self) -> u64 {
        match self {
            Self::PartitionNodes { generation, .. } | Self::GenerationPartitions { generation } => {
                generation
            }
        }
    }

    const fn object_kind(self) -> AnnObjectKindV2 {
        match self {
            Self::PartitionNodes { .. } => AnnObjectKindV2::PartitionTree,
            Self::GenerationPartitions { .. } => AnnObjectKindV2::GlobalTree,
        }
    }

    const fn maximum_leaves(self) -> u64 {
        match self {
            Self::PartitionNodes { .. } => ANN_V2_MAX_NODES,
            Self::GenerationPartitions { .. } => ANN_V2_MAX_PARTITIONS,
        }
    }

    const fn domain_tag(self) -> u8 {
        match self {
            Self::PartitionNodes { .. } => 1,
            Self::GenerationPartitions { .. } => 2,
        }
    }
}

/// Exact level widths for a duplicate-last Merkle tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnMerkleGeometryV2 {
    leaf_count: u64,
    root_level: u16,
    object_count: u64,
}

impl AnnMerkleGeometryV2 {
    /// Computes bounded geometry for the exact tree scope and leaf count.
    pub fn new(scope: AnnMerkleScopeV2, leaf_count: u64) -> AnnV2Result<Self> {
        scope.validate()?;
        ensure_u64_bound("Merkle leaves", leaf_count, scope.maximum_leaves())?;
        if leaf_count == 0 && matches!(scope, AnnMerkleScopeV2::PartitionNodes { .. }) {
            return Err(AnnV2Error::Invalid(
                "partition node Merkle tree cannot be empty",
            ));
        }

        let mut width = leaf_count;
        let mut root_level = 0_u16;
        let mut object_count = 0_u64;
        while width != 0 {
            object_count = checked_count_add("Merkle objects", object_count, width)?;
            if width == 1 {
                break;
            }
            width = half_rounded_up(width);
            root_level = root_level
                .checked_add(1)
                .ok_or(AnnV2Error::Invalid("Merkle level overflowed"))?;
            if root_level > ANN_V2_MAX_MERKLE_LEVEL {
                return exhausted(
                    "Merkle level",
                    u64::from(ANN_V2_MAX_MERKLE_LEVEL),
                    u64::from(root_level),
                );
            }
        }
        Ok(Self {
            leaf_count,
            root_level,
            object_count,
        })
    }

    /// Number of leaf objects at level zero.
    #[must_use]
    pub const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    /// Exact level containing the single unbound top hash.
    #[must_use]
    pub const fn root_level(self) -> u16 {
        self.root_level
    }

    /// Total physical hash objects over every level.
    #[must_use]
    pub const fn object_count(self) -> u64 {
        self.object_count
    }

    /// Exact number of physical objects at `level`.
    pub fn width_at(self, level: u16) -> AnnV2Result<u64> {
        if self.leaf_count == 0 || level > self.root_level {
            return Err(AnnV2Error::Invalid(
                "Merkle level is outside the exact tree geometry",
            ));
        }
        let mut width = self.leaf_count;
        for _ in 0..level {
            width = half_rounded_up(width);
        }
        Ok(width)
    }
}

/// Bounded inclusion proof using one sibling per level above the leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnMerkleProofV2 {
    leaf_index: u64,
    leaf_count: u64,
    siblings: Vec<[u8; 32]>,
}

impl AnnMerkleProofV2 {
    /// Creates a proof only when its index and sibling count match exact geometry.
    pub fn new(
        scope: AnnMerkleScopeV2,
        leaf_index: u64,
        leaf_count: u64,
        siblings: Vec<[u8; 32]>,
    ) -> AnnV2Result<Self> {
        let proof = Self {
            leaf_index,
            leaf_count,
            siblings,
        };
        proof.validate(scope)?;
        Ok(proof)
    }

    /// Validates proof bounds without hashing or allocating.
    pub fn validate(&self, scope: AnnMerkleScopeV2) -> AnnV2Result<()> {
        let geometry = AnnMerkleGeometryV2::new(scope, self.leaf_count)?;
        if self.leaf_count == 0 || self.leaf_index >= self.leaf_count {
            return Err(AnnV2Error::Invalid("Merkle proof leaf index is invalid"));
        }
        if self.siblings.len() != usize::from(geometry.root_level()) {
            return Err(AnnV2Error::Invalid(
                "Merkle proof sibling count disagrees with tree geometry",
            ));
        }
        if self.siblings.iter().any(is_zero_digest) {
            return Err(AnnV2Error::Invalid(
                "Merkle proof contains a zero sibling digest",
            ));
        }
        Ok(())
    }

    /// Returns the proven zero-based leaf position.
    #[must_use]
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Returns the exact tree leaf count authenticated by this proof.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Returns the bounded bottom-up sibling hashes.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }
}

/// Computes the canonical privacy partition key from vector space and policy only.
pub fn ann_v2_partition_key(
    vector_space_id: VectorSpaceId,
    policy_digest: [u8; 32],
) -> AnnV2Result<[u8; 32]> {
    if vector_space_id
        .as_uuid()
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || is_zero_digest(&policy_digest)
    {
        return Err(AnnV2Error::Invalid(
            "partition key input contains a zero identity",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(PARTITION_KEY_DOMAIN);
    hasher.update(vector_space_id.as_uuid().as_bytes());
    hasher.update(&policy_digest);
    Ok(*hasher.finalize().as_bytes())
}

/// Computes one leaf from an exact validated portable object encoding.
///
/// The leaf preimage is the leaf domain, key length/key, value length/value,
/// and the object's deterministic portable digest, all in that order.
pub fn ann_v2_merkle_leaf(object: &AnnObjectV2) -> AnnV2Result<[u8; 32]> {
    object.validate()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_LEAF_DOMAIN);
    hash_u16(
        &mut hasher,
        u16::try_from(object.key().as_bytes().len())
            .map_err(|_| AnnV2Error::Invalid("Merkle leaf key length overflowed"))?,
    );
    hasher.update(object.key().as_bytes());
    hash_u64(&mut hasher, usize_to_u64(object.value().len()));
    hasher.update(object.value());
    hasher.update(&object.digest());
    Ok(*hasher.finalize().as_bytes())
}

/// Combines two children into one level-bound internal hash.
///
/// At an odd-width level the final child is duplicated, so callers pass the
/// same digest as both `left` and `right`. `level` is the resulting parent level.
pub fn ann_v2_merkle_internal(
    level: u16,
    left: [u8; 32],
    right: [u8; 32],
) -> AnnV2Result<[u8; 32]> {
    if level == 0 || level > ANN_V2_MAX_MERKLE_LEVEL {
        return Err(AnnV2Error::Invalid("Merkle internal level is invalid"));
    }
    if is_zero_digest(&left) || is_zero_digest(&right) {
        return Err(AnnV2Error::Invalid(
            "Merkle internal child contains a zero digest",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_INTERNAL_DOMAIN);
    hash_u16(&mut hasher, level);
    hasher.update(&left);
    hasher.update(&right);
    Ok(*hasher.finalize().as_bytes())
}

/// Binds a tree top (or an empty tree) to its role, identity, leaf count, and depth.
pub fn ann_v2_merkle_root(
    scope: AnnMerkleScopeV2,
    leaf_count: u64,
    top: Option<[u8; 32]>,
) -> AnnV2Result<[u8; 32]> {
    let geometry = AnnMerkleGeometryV2::new(scope, leaf_count)?;
    match (leaf_count, top) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err(AnnV2Error::Invalid(
                "empty Merkle root unexpectedly has a top hash",
            ));
        }
        (_, None) => return Err(AnnV2Error::Invalid("non-empty Merkle root has no top hash")),
        (_, Some(value)) if is_zero_digest(&value) => {
            return Err(AnnV2Error::Invalid("Merkle root top hash is zero"));
        }
        (_, Some(_)) => {}
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_ROOT_DOMAIN);
    hash_u8(&mut hasher, scope.domain_tag());
    hash_u64(&mut hasher, scope.generation());
    if let AnnMerkleScopeV2::PartitionNodes { partition_key, .. } = scope {
        hasher.update(&partition_key);
    }
    hash_u64(&mut hasher, leaf_count);
    hash_u16(&mut hasher, geometry.root_level());
    match top {
        Some(value) => {
            hash_u8(&mut hasher, 1);
            hasher.update(&value);
        }
        None => hash_u8(&mut hasher, 0),
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Verifies one bounded proof, including duplicate-last odd-node semantics.
pub fn ann_v2_verify_merkle_proof(
    scope: AnnMerkleScopeV2,
    leaf_hash: [u8; 32],
    proof: &AnnMerkleProofV2,
    expected_root: [u8; 32],
) -> AnnV2Result<()> {
    proof.validate(scope)?;
    if is_zero_digest(&leaf_hash) || is_zero_digest(&expected_root) {
        return Err(AnnV2Error::Invalid(
            "Merkle proof input contains a zero digest",
        ));
    }
    let mut current = leaf_hash;
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    for (offset, sibling) in proof.siblings.iter().enumerate() {
        let level = u16::try_from(offset + 1)
            .map_err(|_| AnnV2Error::Invalid("Merkle proof level overflowed"))?;
        if index.is_multiple_of(2) {
            if index + 1 >= width && *sibling != current {
                return Err(AnnV2Error::Invalid(
                    "Merkle odd-node proof does not duplicate its final child",
                ));
            }
            current = ann_v2_merkle_internal(level, current, *sibling)?;
        } else {
            current = ann_v2_merkle_internal(level, *sibling, current)?;
        }
        index /= 2;
        width = half_rounded_up(width);
    }
    let actual = ann_v2_merkle_root(scope, proof.leaf_count, Some(current))?;
    if actual != expected_root {
        return Err(AnnV2Error::DigestMismatch("Merkle proof root"));
    }
    Ok(())
}

/// Validated canonical key for one generation object.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AnnObjectKeyV2(Vec<u8>);

impl AnnObjectKeyV2 {
    /// Validates and owns raw canonical key bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> AnnV2Result<Self> {
        validate_object_key(&bytes)?;
        Ok(Self(bytes))
    }

    /// Creates the partition-manifest key for a generation.
    pub fn partition_manifest(generation: u64, partition: [u8; 32]) -> AnnV2Result<Self> {
        let mut bytes = generation_prefix(generation)?;
        bytes.push(b'p');
        bytes.extend_from_slice(&partition);
        Self::from_bytes(bytes)
    }

    /// Creates one node-object key.
    pub fn node(
        generation: u64,
        partition: [u8; 32],
        representation: RepresentationId,
    ) -> AnnV2Result<Self> {
        let mut bytes = generation_prefix(generation)?;
        bytes.push(b'n');
        bytes.extend_from_slice(&partition);
        bytes.extend_from_slice(representation.as_uuid().as_bytes());
        Self::from_bytes(bytes)
    }

    /// Creates one per-partition node-tree key.
    pub fn partition_tree(
        generation: u64,
        partition: [u8; 32],
        leaf_count: u64,
        level: u16,
        index: u64,
    ) -> AnnV2Result<Self> {
        let mut bytes = generation_prefix(generation)?;
        bytes.push(b't');
        bytes.extend_from_slice(&partition);
        bytes.extend_from_slice(&level.to_be_bytes());
        bytes.extend_from_slice(&index.to_be_bytes());
        let key = Self::from_bytes(bytes)?;
        key.validate_merkle_geometry(
            AnnMerkleScopeV2::PartitionNodes {
                generation,
                partition_key: partition,
            },
            leaf_count,
        )?;
        Ok(key)
    }

    /// Creates one generation-wide partition-tree key.
    pub fn global_tree(
        generation: u64,
        leaf_count: u64,
        level: u16,
        index: u64,
    ) -> AnnV2Result<Self> {
        let mut bytes = generation_prefix(generation)?;
        bytes.push(b'q');
        bytes.extend_from_slice(&level.to_be_bytes());
        bytes.extend_from_slice(&index.to_be_bytes());
        let key = Self::from_bytes(bytes)?;
        key.validate_merkle_geometry(
            AnnMerkleScopeV2::GenerationPartitions { generation },
            leaf_count,
        )?;
        Ok(key)
    }

    /// Returns the encoded key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the generation encoded in this key.
    #[must_use]
    pub fn generation(&self) -> u64 {
        let bytes: [u8; 8] = self.0[1..9].try_into().unwrap_or([0; 8]);
        u64::from_be_bytes(bytes)
    }

    /// Returns the role encoded in this key.
    #[must_use]
    pub fn kind(&self) -> AnnObjectKindV2 {
        match self.0[9] {
            b'p' => AnnObjectKindV2::PartitionManifest,
            b'n' => AnnObjectKindV2::Node,
            b't' => AnnObjectKindV2::PartitionTree,
            b'q' => AnnObjectKindV2::GlobalTree,
            _ => unreachable!("validated ANN key has a known kind"),
        }
    }

    /// Validates a tree key against the exact leaf-count geometry and tree scope.
    ///
    /// [`Self::from_bytes`] intentionally performs only structural validation because
    /// leaf count is not encoded in a portable key. Publication validation must call
    /// this contextual check (directly or through [`verify_ann_generation_v2`]).
    pub fn validate_merkle_geometry(
        &self,
        scope: AnnMerkleScopeV2,
        leaf_count: u64,
    ) -> AnnV2Result<()> {
        scope.validate()?;
        let geometry = AnnMerkleGeometryV2::new(scope, leaf_count)?;
        if self.generation() != scope.generation() || self.kind() != scope.object_kind() {
            return Err(AnnV2Error::Invalid(
                "Merkle key disagrees with its tree scope",
            ));
        }
        if let AnnMerkleScopeV2::PartitionNodes { partition_key, .. } = scope
            && self.as_bytes()[10..42] != partition_key
        {
            return Err(AnnV2Error::Invalid(
                "Merkle key disagrees with its partition scope",
            ));
        }
        let (level, index) = tree_coordinates(self)?;
        if level > geometry.root_level() || index >= geometry.width_at(level)? {
            return Err(AnnV2Error::Invalid(
                "Merkle key is outside the exact tree geometry",
            ));
        }
        Ok(())
    }
}

/// Returns the fixed generation prefix used for bounded cleanup and export scans.
pub fn ann_v2_generation_prefix(generation: u64) -> AnnV2Result<Vec<u8>> {
    generation_prefix(generation)
}

/// One bounded, self-digesting key/value object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnObjectV2 {
    key: AnnObjectKeyV2,
    value: Vec<u8>,
    digest: [u8; 32],
}

impl AnnObjectV2 {
    /// Creates and validates an object, computing its canonical digest.
    pub fn new(key: AnnObjectKeyV2, value: Vec<u8>) -> AnnV2Result<Self> {
        ensure_usize_bound("object_bytes", value.len(), ANN_V2_MAX_OBJECT_BYTES)?;
        if value.is_empty() {
            return Err(AnnV2Error::Invalid("ANN object value is empty"));
        }
        let digest = object_digest(&key, &value);
        let object = Self { key, value, digest };
        object.validate()?;
        Ok(object)
    }

    /// Restores and validates an object supplied by a portable source.
    pub fn from_parts(key: AnnObjectKeyV2, value: Vec<u8>, digest: [u8; 32]) -> AnnV2Result<Self> {
        let object = Self { key, value, digest };
        object.validate()?;
        Ok(object)
    }

    /// Validates role-specific size, identity, codec, and digest invariants.
    pub fn validate(&self) -> AnnV2Result<()> {
        ensure_usize_bound("object_bytes", self.value.len(), ANN_V2_MAX_OBJECT_BYTES)?;
        if self.value.is_empty() {
            return Err(AnnV2Error::Invalid("ANN object value is empty"));
        }
        match self.key.kind() {
            AnnObjectKindV2::PartitionManifest => {
                ensure_usize_bound(
                    "partition_manifest_bytes",
                    self.value.len(),
                    ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
                )?;
                let manifest = AnnPartitionManifestV2::decode_json(&self.value)?;
                if manifest.generation != self.key.generation()
                    || self.key.as_bytes()[10..42] != manifest.partition_key
                {
                    return Err(AnnV2Error::Invalid(
                        "partition manifest disagrees with its object key",
                    ));
                }
            }
            AnnObjectKindV2::Node => {
                ensure_usize_bound("node_bytes", self.value.len(), ANN_V2_MAX_NODE_BYTES)?;
                let node = AnnNodeV2::decode_canonical(&self.value)?;
                if node.generation != self.key.generation()
                    || self.key.as_bytes()[10..42] != node.partition_key
                    || self.key.as_bytes()[42..58] != *node.representation_id.as_uuid().as_bytes()
                {
                    return Err(AnnV2Error::Invalid("node disagrees with its object key"));
                }
            }
            AnnObjectKindV2::PartitionTree | AnnObjectKindV2::GlobalTree => {
                if self.value.len() != DIGEST_BYTES || is_zero_digest_slice(&self.value) {
                    return Err(AnnV2Error::Invalid(
                        "Merkle object is not one sealed digest",
                    ));
                }
            }
        }
        if self.digest != object_digest(&self.key, &self.value) {
            return Err(AnnV2Error::DigestMismatch("portable object"));
        }
        let _ = self.encoded_len()?;
        Ok(())
    }

    /// Returns key plus value plus explicit portable digest bytes.
    pub fn encoded_len(&self) -> AnnV2Result<usize> {
        let key_and_value = checked_usize_add(
            "portable_object_bytes",
            self.key.as_bytes().len(),
            self.value.len(),
        )?;
        checked_usize_add("portable_object_bytes", key_and_value, DIGEST_BYTES)
    }

    /// Returns the validated canonical key.
    #[must_use]
    pub const fn key(&self) -> &AnnObjectKeyV2 {
        &self.key
    }

    /// Returns the bounded encoded value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns the canonical key/value digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Bounded point-read request whose maximum is constrained by the object's role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnObjectReadRequestV2<'a> {
    /// Canonical object key to read.
    pub key: &'a AnnObjectKeyV2,
    /// Maximum value bytes the adapter may materialize.
    pub max_bytes: usize,
}

impl AnnObjectReadRequestV2<'_> {
    /// Rejects zero and role-inappropriate read limits before backend access.
    pub fn validate(self) -> AnnV2Result<()> {
        let maximum = match self.key.kind() {
            AnnObjectKindV2::PartitionManifest => ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
            AnnObjectKindV2::Node => ANN_V2_MAX_NODE_BYTES,
            AnnObjectKindV2::PartitionTree | AnnObjectKindV2::GlobalTree => DIGEST_BYTES,
        };
        if self.max_bytes == 0 {
            return Err(AnnV2Error::Invalid("object read byte limit is zero"));
        }
        ensure_usize_bound("object_read_bytes", self.max_bytes, maximum)
    }
}

/// Point-read result bound to the exact key and byte limit that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnObjectReadResponseV2 {
    requested_key: AnnObjectKeyV2,
    max_bytes: usize,
    object: Option<AnnObjectV2>,
}

impl AnnObjectReadResponseV2 {
    /// Creates a response only after validating the request and returned object.
    pub fn new(
        request: AnnObjectReadRequestV2<'_>,
        object: Option<AnnObjectV2>,
    ) -> AnnV2Result<Self> {
        let response = Self {
            requested_key: request.key.clone(),
            max_bytes: request.max_bytes,
            object,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    /// Revalidates this response against the exact caller request.
    pub fn validate_for(&self, request: AnnObjectReadRequestV2<'_>) -> AnnV2Result<()> {
        request.validate()?;
        if self.requested_key != *request.key || self.max_bytes != request.max_bytes {
            return Err(AnnV2Error::Invalid(
                "object read response disagrees with its exact request",
            ));
        }
        if let Some(object) = &self.object {
            object.validate()?;
            if object.key() != request.key {
                return Err(AnnV2Error::Invalid(
                    "point-read object disagrees with the requested key",
                ));
            }
            ensure_usize_bound("object_read_bytes", object.value().len(), request.max_bytes)?;
        }
        Ok(())
    }

    /// Returns the validated object, or `None` when the exact key was absent.
    #[must_use]
    pub const fn object(&self) -> Option<&AnnObjectV2> {
        self.object.as_ref()
    }

    /// Consumes the response and returns the validated object.
    #[must_use]
    pub fn into_object(self) -> Option<AnnObjectV2> {
        self.object
    }
}

/// Exclusive bounded request for one portable ANN object page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnObjectPageRequestV2<'a> {
    /// Prefix every returned object key must match.
    pub prefix: &'a [u8],
    /// Last key returned by the preceding page, excluded from this page.
    pub start_after: Option<&'a [u8]>,
    /// Maximum objects returned in one page.
    pub max_entries: usize,
    /// Maximum aggregate encoded object bytes returned in one page.
    pub max_bytes: usize,
}

impl AnnObjectPageRequestV2<'_> {
    /// Validates finite portable bounds and the exclusive cursor.
    pub fn validate(self) -> AnnV2Result<()> {
        if self.prefix.is_empty() || self.prefix.len() > ANN_V2_MAX_KEY_BYTES {
            return Err(AnnV2Error::Invalid("object page prefix length is invalid"));
        }
        if self.max_entries == 0 || self.max_entries > ANN_V2_MAX_PAGE_ENTRIES {
            return exhausted(
                "object_page_entries",
                ANN_V2_MAX_PAGE_ENTRIES as u64,
                usize_to_u64(self.max_entries),
            );
        }
        if self.max_bytes == 0 || self.max_bytes > ANN_V2_MAX_PAGE_BYTES {
            return exhausted(
                "object_page_bytes",
                ANN_V2_MAX_PAGE_BYTES as u64,
                usize_to_u64(self.max_bytes),
            );
        }
        if let Some(cursor) = self.start_after {
            validate_object_key(cursor)?;
            if !cursor.starts_with(self.prefix) {
                return Err(AnnV2Error::Invalid(
                    "object page cursor is outside the requested prefix",
                ));
            }
        }
        Ok(())
    }
}

/// One validated, strictly key-ordered portable ANN object page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnObjectPageV2 {
    objects: Vec<AnnObjectV2>,
    continuation: Option<AnnObjectKeyV2>,
}

impl AnnObjectPageV2 {
    /// Creates and validates a page against the exact request that produced it.
    pub fn new(
        request: AnnObjectPageRequestV2<'_>,
        objects: Vec<AnnObjectV2>,
        continuation: Option<AnnObjectKeyV2>,
    ) -> AnnV2Result<Self> {
        let page = Self {
            objects,
            continuation,
        };
        page.validate_for(request)?;
        Ok(page)
    }

    /// Validates order, prefix, cursor, byte budget, and continuation progress.
    pub fn validate_for(&self, request: AnnObjectPageRequestV2<'_>) -> AnnV2Result<()> {
        request.validate()?;
        if self.objects.len() > request.max_entries {
            return exhausted(
                "object_page_entries",
                usize_to_u64(request.max_entries),
                usize_to_u64(self.objects.len()),
            );
        }
        let mut used = 0_usize;
        let mut previous = request.start_after;
        for object in &self.objects {
            object.validate()?;
            let key = object.key().as_bytes();
            if !key.starts_with(request.prefix) {
                return Err(AnnV2Error::Invalid(
                    "object page key is outside the requested prefix",
                ));
            }
            if previous.is_some_and(|prior| key <= prior) {
                return Err(AnnV2Error::Invalid(
                    "object page keys are not in strict exclusive order",
                ));
            }
            used = checked_usize_add("object_page_bytes", used, object.encoded_len()?)?;
            if used > request.max_bytes {
                return exhausted(
                    "object_page_bytes",
                    usize_to_u64(request.max_bytes),
                    usize_to_u64(used),
                );
            }
            previous = Some(key);
        }
        match (&self.continuation, self.objects.last()) {
            (Some(_), None) => {
                return Err(AnnV2Error::Invalid("empty object page has a continuation"));
            }
            (Some(continuation), Some(last)) if continuation != last.key() => {
                return Err(AnnV2Error::Invalid(
                    "object page continuation is not the final returned key",
                ));
            }
            (Some(continuation), Some(_))
                if !continuation.as_bytes().starts_with(request.prefix) =>
            {
                return Err(AnnV2Error::Invalid(
                    "object page continuation is outside the requested prefix",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns ordered objects without transferring ownership.
    #[must_use]
    pub fn objects(&self) -> &[AnnObjectV2] {
        &self.objects
    }

    /// Returns the exclusive cursor for the next page when more data is known.
    #[must_use]
    pub const fn continuation(&self) -> Option<&AnnObjectKeyV2> {
        self.continuation.as_ref()
    }

    /// Consumes the page into its ordered objects and continuation.
    #[must_use]
    pub fn into_parts(self) -> (Vec<AnnObjectV2>, Option<AnnObjectKeyV2>) {
        (self.objects, self.continuation)
    }
}

/// Storage-neutral bounded object reader used by future live and portable adapters.
pub trait AnnObjectReaderV2 {
    /// Reads one request-bound object without admitting a value larger than `max_bytes`.
    fn get_bounded(
        &self,
        request: AnnObjectReadRequestV2<'_>,
    ) -> AnnV2Result<AnnObjectReadResponseV2>;

    /// Reads one strictly ordered exclusive-cursor page.
    ///
    /// A `None` continuation asserts that the requested prefix is exhausted;
    /// otherwise the continuation is the final returned key and the next call
    /// must use it as the exclusive cursor.
    fn scan_page(&self, request: AnnObjectPageRequestV2<'_>) -> AnnV2Result<AnnObjectPageV2>;
}

/// Canonical scope-bound root used by a generation containing no partitions.
pub fn ann_v2_empty_partition_root(generation: u64) -> AnnV2Result<[u8; 32]> {
    ann_v2_merkle_root(
        AnnMerkleScopeV2::GenerationPartitions { generation },
        0,
        None,
    )
}

/// Evidence returned only after a complete bounded generation verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnGenerationVerificationV2 {
    generation: u64,
    manifest_digest: [u8; 32],
    partition_count: u64,
    node_count: u64,
    level_row_count: u64,
    neighbour_count: u64,
    object_count: u64,
    object_bytes: u64,
}

impl AnnGenerationVerificationV2 {
    /// Verified generation number.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Digest of the exact generation manifest that was verified.
    #[must_use]
    pub const fn manifest_digest(self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Exact verified partition count.
    #[must_use]
    pub const fn partition_count(self) -> u64 {
        self.partition_count
    }

    /// Exact verified node count.
    #[must_use]
    pub const fn node_count(self) -> u64 {
        self.node_count
    }

    /// Exact verified node-level row count.
    #[must_use]
    pub const fn level_row_count(self) -> u64 {
        self.level_row_count
    }

    /// Exact verified neighbour-reference count.
    #[must_use]
    pub const fn neighbour_count(self) -> u64 {
        self.neighbour_count
    }

    /// Exact verified portable object count, including physical tree hashes.
    #[must_use]
    pub const fn object_count(self) -> u64 {
        self.object_count
    }

    /// Exact verified key/value/digest bytes for every generation object.
    #[must_use]
    pub const fn object_bytes(self) -> u64 {
        self.object_bytes
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AnnAggregateCountsV2 {
    partitions: u64,
    nodes: u64,
    level_rows: u64,
    neighbours: u64,
    partition_tree_objects: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AnnObjectSpaceCountsV2 {
    partitions: u64,
    nodes: u64,
    partition_tree: u64,
    global_tree: u64,
    total: u64,
    bytes: u64,
}

/// Performs the complete storage-neutral gate required before publication or recovery adoption.
///
/// The reader is consumed through validated 1,024-entry/8-MiB pages and exact
/// role-bounded point reads. The gate authenticates every manifest/node leaf,
/// both physical Merkle trees, exact counters and bytes, entry membership,
/// neighbour locality/level membership, and the complete generation keyspace.
/// It does not publish, mutate storage, authorize queries, or advertise a live
/// ANN implementation.
pub fn verify_ann_generation_v2<R: AnnObjectReaderV2>(
    reader: &R,
    manifest: &AnnGenerationManifestV2,
) -> AnnV2Result<AnnGenerationVerificationV2> {
    manifest.validate()?;
    let global_scope = AnnMerkleScopeV2::GenerationPartitions {
        generation: manifest.generation,
    };
    let global_geometry = AnnMerkleGeometryV2::new(global_scope, manifest.partition_count)?;
    let partition_prefix = kind_prefix(manifest.generation, b'p')?;
    let mut totals = AnnAggregateCountsV2::default();

    scan_objects(reader, &partition_prefix, |partition_object| {
        totals.partitions = checked_count_add("verified partitions", totals.partitions, 1)?;
        ensure_u64_bound(
            "verified partitions",
            totals.partitions,
            manifest.partition_count,
        )?;
        let partition = AnnPartitionManifestV2::decode_json(partition_object.value())?;
        if partition.generation != manifest.generation {
            return Err(AnnV2Error::Invalid(
                "partition manifest belongs to another generation",
            ));
        }
        if partition.global_leaf_index != totals.partitions - 1 {
            return Err(AnnV2Error::Invalid(
                "partition leaf indices are not unique and contiguous",
            ));
        }
        if partition.max_level > manifest.build.max_level {
            return Err(AnnV2Error::Invalid(
                "partition maximum level exceeds generation build parameters",
            ));
        }

        let partition_tree_objects =
            verify_ann_partition_v2(reader, manifest, &partition, partition_object)?;
        totals.partition_tree_objects = checked_count_add(
            "partition Merkle objects",
            totals.partition_tree_objects,
            partition_tree_objects,
        )?;
        totals.nodes = checked_count_add("verified nodes", totals.nodes, partition.node_count)?;
        totals.level_rows = checked_count_add(
            "verified level rows",
            totals.level_rows,
            partition.level_row_count,
        )?;
        totals.neighbours = checked_count_add(
            "verified neighbours",
            totals.neighbours,
            partition.neighbour_count,
        )?;
        ensure_u64_bound("verified nodes", totals.nodes, manifest.node_count)?;
        ensure_u64_bound(
            "verified level rows",
            totals.level_rows,
            manifest.level_row_count,
        )?;
        ensure_u64_bound(
            "verified neighbours",
            totals.neighbours,
            manifest.neighbour_count,
        )?;

        let global_leaf_key = AnnObjectKeyV2::global_tree(
            manifest.generation,
            manifest.partition_count,
            0,
            partition.global_leaf_index,
        )?;
        let global_leaf = read_required_object(reader, &global_leaf_key)?;
        if tree_object_digest(&global_leaf)? != ann_v2_merkle_leaf(partition_object)? {
            return Err(AnnV2Error::DigestMismatch("global partition-tree leaf"));
        }
        Ok(())
    })?;

    if totals.partitions != manifest.partition_count
        || totals.nodes != manifest.node_count
        || totals.level_rows != manifest.level_row_count
        || totals.neighbours != manifest.neighbour_count
    {
        return Err(AnnV2Error::Invalid(
            "generation aggregate counters disagree with partition manifests",
        ));
    }

    verify_physical_merkle_tree(
        reader,
        global_scope,
        manifest.partition_count,
        manifest.partition_tree_root,
    )?;

    let expected_object_count = checked_count_add(
        "generation objects",
        checked_count_add(
            "generation objects",
            checked_count_add(
                "generation objects",
                manifest.partition_count,
                manifest.node_count,
            )?,
            totals.partition_tree_objects,
        )?,
        global_geometry.object_count(),
    )?;
    let actual_objects = verify_complete_object_space(
        reader,
        manifest.generation,
        expected_object_count,
        manifest.object_bytes,
    )?;
    if actual_objects.partitions != manifest.partition_count
        || actual_objects.nodes != manifest.node_count
        || actual_objects.partition_tree != totals.partition_tree_objects
        || actual_objects.global_tree != global_geometry.object_count()
    {
        return Err(AnnV2Error::Invalid(
            "generation keyspace kind counts are incomplete",
        ));
    }

    Ok(AnnGenerationVerificationV2 {
        generation: manifest.generation,
        manifest_digest: manifest.manifest_digest,
        partition_count: totals.partitions,
        node_count: totals.nodes,
        level_row_count: totals.level_rows,
        neighbour_count: totals.neighbours,
        object_count: actual_objects.total,
        object_bytes: actual_objects.bytes,
    })
}

fn verify_ann_partition_v2<R: AnnObjectReaderV2>(
    reader: &R,
    generation: &AnnGenerationManifestV2,
    partition: &AnnPartitionManifestV2,
    partition_object: &AnnObjectV2,
) -> AnnV2Result<u64> {
    let expected_partition_key =
        AnnObjectKeyV2::partition_manifest(generation.generation, partition.partition_key)?;
    if partition_object.key() != &expected_partition_key {
        return Err(AnnV2Error::Invalid(
            "partition object key disagrees with its canonical identity",
        ));
    }

    let node_prefix = partition_kind_prefix(generation.generation, b'n', partition.partition_key)?;
    let mut node_count = 0_u64;
    let mut level_rows = 0_u64;
    let mut neighbours = 0_u64;
    let mut node_bytes = 0_u64;
    let mut observed_max_level = 0_u8;
    let mut entry_present = false;

    scan_objects(reader, &node_prefix, |node_object| {
        node_count = checked_count_add("verified partition nodes", node_count, 1)?;
        ensure_u64_bound("verified partition nodes", node_count, partition.node_count)?;
        let node = AnnNodeV2::decode_canonical(node_object.value())?;
        if node.leaf_index != node_count - 1 {
            return Err(AnnV2Error::Invalid(
                "node leaf indices are not unique and contiguous",
            ));
        }
        let node_max_level = u8::try_from(node.levels.len() - 1)
            .map_err(|_| AnnV2Error::Invalid("node maximum level overflowed"))?;
        if node_max_level > partition.max_level || node_max_level > generation.build.max_level {
            return Err(AnnV2Error::Invalid(
                "node maximum level exceeds its partition or build parameters",
            ));
        }
        observed_max_level = observed_max_level.max(node_max_level);
        entry_present |= node.representation_id == partition.entry;

        level_rows = checked_count_add(
            "verified partition level rows",
            level_rows,
            usize_to_u64(node.levels.len()),
        )?;
        ensure_u64_bound(
            "verified partition level rows",
            level_rows,
            partition.level_row_count,
        )?;
        for row in &node.levels {
            if row.neighbours.len() > usize::from(generation.build.neighbours_per_level) {
                return Err(AnnV2Error::Invalid(
                    "node degree exceeds generation build parameters",
                ));
            }
            neighbours = checked_count_add(
                "verified partition neighbours",
                neighbours,
                usize_to_u64(row.neighbours.len()),
            )?;
            ensure_u64_bound(
                "verified partition neighbours",
                neighbours,
                partition.neighbour_count,
            )?;
            for neighbour in &row.neighbours {
                let neighbour_key = AnnObjectKeyV2::node(
                    generation.generation,
                    partition.partition_key,
                    *neighbour,
                )?;
                let neighbour_object = read_required_object(reader, &neighbour_key)?;
                let neighbour_node = AnnNodeV2::decode_canonical(neighbour_object.value())?;
                if usize::from(row.level) >= neighbour_node.levels.len() {
                    return Err(AnnV2Error::Invalid(
                        "neighbour is not present in the referenced local level",
                    ));
                }
            }
        }
        node_bytes = checked_count_add(
            "verified partition node bytes",
            node_bytes,
            usize_to_u64(node_object.encoded_len()?),
        )?;
        ensure_u64_bound(
            "verified partition node bytes",
            node_bytes,
            partition.node_bytes,
        )?;

        let leaf_key = AnnObjectKeyV2::partition_tree(
            generation.generation,
            partition.partition_key,
            partition.node_count,
            0,
            node.leaf_index,
        )?;
        let leaf_object = read_required_object(reader, &leaf_key)?;
        if tree_object_digest(&leaf_object)? != ann_v2_merkle_leaf(node_object)? {
            return Err(AnnV2Error::DigestMismatch("partition node-tree leaf"));
        }
        Ok(())
    })?;

    if node_count != partition.node_count
        || level_rows != partition.level_row_count
        || neighbours != partition.neighbour_count
        || node_bytes != partition.node_bytes
    {
        return Err(AnnV2Error::Invalid(
            "partition counters disagree with its node objects",
        ));
    }
    if !entry_present {
        return Err(AnnV2Error::Invalid(
            "partition entry node is absent from the partition",
        ));
    }
    if observed_max_level != partition.max_level {
        return Err(AnnV2Error::Invalid(
            "partition maximum level is not present in its nodes",
        ));
    }

    let scope = AnnMerkleScopeV2::PartitionNodes {
        generation: generation.generation,
        partition_key: partition.partition_key,
    };
    verify_physical_merkle_tree(
        reader,
        scope,
        partition.node_count,
        partition.node_tree_root,
    )
}

fn verify_physical_merkle_tree<R: AnnObjectReaderV2>(
    reader: &R,
    scope: AnnMerkleScopeV2,
    leaf_count: u64,
    expected_root: [u8; 32],
) -> AnnV2Result<u64> {
    let geometry = AnnMerkleGeometryV2::new(scope, leaf_count)?;
    let prefix = tree_prefix(scope)?;
    let mut seen = 0_u64;
    let mut expected_level = 0_u16;
    let mut expected_index = 0_u64;
    let mut top = None;

    scan_objects(reader, &prefix, |object| {
        seen = checked_count_add("verified Merkle objects", seen, 1)?;
        ensure_u64_bound("verified Merkle objects", seen, geometry.object_count())?;
        let expected_key = merkle_object_key(scope, leaf_count, expected_level, expected_index)?;
        if object.key() != &expected_key {
            return Err(AnnV2Error::Invalid(
                "Merkle objects do not fill exact level/index geometry",
            ));
        }
        object.key().validate_merkle_geometry(scope, leaf_count)?;
        let actual = tree_object_digest(object)?;
        if expected_level > 0 {
            let child_width = geometry.width_at(expected_level - 1)?;
            let left_index = expected_index
                .checked_mul(2)
                .ok_or(AnnV2Error::Invalid("Merkle child index overflowed"))?;
            let left_key = merkle_object_key(scope, leaf_count, expected_level - 1, left_index)?;
            let left = tree_object_digest(&read_required_object(reader, &left_key)?)?;
            let right = if left_index + 1 < child_width {
                let right_key =
                    merkle_object_key(scope, leaf_count, expected_level - 1, left_index + 1)?;
                tree_object_digest(&read_required_object(reader, &right_key)?)?
            } else {
                left
            };
            if actual != ann_v2_merkle_internal(expected_level, left, right)? {
                return Err(AnnV2Error::DigestMismatch(
                    "physical Merkle internal object",
                ));
            }
        }
        if expected_level == geometry.root_level() && expected_index == 0 {
            top = Some(actual);
        }

        expected_index += 1;
        if expected_index == geometry.width_at(expected_level)? {
            expected_index = 0;
            expected_level += 1;
        }
        Ok(())
    })?;

    if seen != geometry.object_count() {
        return Err(AnnV2Error::Invalid(
            "Merkle object count disagrees with exact tree geometry",
        ));
    }
    let actual_root = ann_v2_merkle_root(scope, leaf_count, top)?;
    if actual_root != expected_root {
        return Err(AnnV2Error::DigestMismatch("scope-bound Merkle root"));
    }
    Ok(seen)
}

fn verify_complete_object_space<R: AnnObjectReaderV2>(
    reader: &R,
    generation: u64,
    expected_count: u64,
    expected_bytes: u64,
) -> AnnV2Result<AnnObjectSpaceCountsV2> {
    let prefix = generation_prefix(generation)?;
    let mut counts = AnnObjectSpaceCountsV2::default();
    scan_objects(reader, &prefix, |object| {
        counts.total = checked_count_add("generation object count", counts.total, 1)?;
        ensure_u64_bound("generation object count", counts.total, expected_count)?;
        counts.bytes = checked_count_add(
            "generation object bytes",
            counts.bytes,
            usize_to_u64(object.encoded_len()?),
        )?;
        ensure_u64_bound("generation object bytes", counts.bytes, expected_bytes)?;
        match object.key().kind() {
            AnnObjectKindV2::PartitionManifest => {
                counts.partitions =
                    checked_count_add("generation partition objects", counts.partitions, 1)?;
            }
            AnnObjectKindV2::Node => {
                counts.nodes = checked_count_add("generation node objects", counts.nodes, 1)?;
            }
            AnnObjectKindV2::PartitionTree => {
                counts.partition_tree = checked_count_add(
                    "generation partition-tree objects",
                    counts.partition_tree,
                    1,
                )?;
            }
            AnnObjectKindV2::GlobalTree => {
                counts.global_tree =
                    checked_count_add("generation global-tree objects", counts.global_tree, 1)?;
            }
        }
        Ok(())
    })?;
    if counts.total != expected_count || counts.bytes != expected_bytes {
        return Err(AnnV2Error::Invalid(
            "generation object count or bytes are incomplete",
        ));
    }
    Ok(counts)
}

fn scan_objects<R, F>(reader: &R, prefix: &[u8], mut visit: F) -> AnnV2Result<()>
where
    R: AnnObjectReaderV2,
    F: FnMut(&AnnObjectV2) -> AnnV2Result<()>,
{
    let mut cursor: Option<AnnObjectKeyV2> = None;
    loop {
        let request = AnnObjectPageRequestV2 {
            prefix,
            start_after: cursor.as_ref().map(AnnObjectKeyV2::as_bytes),
            max_entries: ANN_V2_MAX_PAGE_ENTRIES,
            max_bytes: ANN_V2_MAX_PAGE_BYTES,
        };
        request.validate()?;
        let page = reader.scan_page(request)?;
        page.validate_for(request)?;
        for object in page.objects() {
            visit(object)?;
        }
        let Some(next) = page.continuation().cloned() else {
            break;
        };
        if cursor.as_ref().is_some_and(|previous| next <= *previous) {
            return Err(AnnV2Error::Invalid(
                "object page cursor did not make strict progress",
            ));
        }
        cursor = Some(next);
    }
    Ok(())
}

fn read_required_object<R: AnnObjectReaderV2>(
    reader: &R,
    key: &AnnObjectKeyV2,
) -> AnnV2Result<AnnObjectV2> {
    let request = AnnObjectReadRequestV2 {
        key,
        max_bytes: object_role_max_bytes(key.kind()),
    };
    let response = reader.get_bounded(request)?;
    response.validate_for(request)?;
    response
        .into_object()
        .ok_or(AnnV2Error::Invalid("required ANN object is absent"))
}

const fn object_role_max_bytes(kind: AnnObjectKindV2) -> usize {
    match kind {
        AnnObjectKindV2::PartitionManifest => ANN_V2_MAX_PARTITION_MANIFEST_BYTES,
        AnnObjectKindV2::Node => ANN_V2_MAX_NODE_BYTES,
        AnnObjectKindV2::PartitionTree | AnnObjectKindV2::GlobalTree => DIGEST_BYTES,
    }
}

fn tree_object_digest(object: &AnnObjectV2) -> AnnV2Result<[u8; 32]> {
    object.validate()?;
    if !matches!(
        object.key().kind(),
        AnnObjectKindV2::PartitionTree | AnnObjectKindV2::GlobalTree
    ) {
        return Err(AnnV2Error::Invalid("ANN object is not a Merkle object"));
    }
    object
        .value()
        .try_into()
        .map_err(|_| AnnV2Error::Invalid("Merkle object digest length is invalid"))
}

fn kind_prefix(generation: u64, kind: u8) -> AnnV2Result<Vec<u8>> {
    let mut prefix = generation_prefix(generation)?;
    prefix.push(kind);
    Ok(prefix)
}

fn partition_kind_prefix(
    generation: u64,
    kind: u8,
    partition_key: [u8; 32],
) -> AnnV2Result<Vec<u8>> {
    if is_zero_digest(&partition_key) {
        return Err(AnnV2Error::Invalid(
            "partition prefix contains a zero digest",
        ));
    }
    let mut prefix = kind_prefix(generation, kind)?;
    prefix.extend_from_slice(&partition_key);
    Ok(prefix)
}

fn tree_prefix(scope: AnnMerkleScopeV2) -> AnnV2Result<Vec<u8>> {
    match scope {
        AnnMerkleScopeV2::PartitionNodes {
            generation,
            partition_key,
        } => partition_kind_prefix(generation, b't', partition_key),
        AnnMerkleScopeV2::GenerationPartitions { generation } => kind_prefix(generation, b'q'),
    }
}

fn merkle_object_key(
    scope: AnnMerkleScopeV2,
    leaf_count: u64,
    level: u16,
    index: u64,
) -> AnnV2Result<AnnObjectKeyV2> {
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

fn ensure_format(actual: u16) -> AnnV2Result<()> {
    if actual == ANN_V2_FORMAT_VERSION {
        Ok(())
    } else {
        Err(AnnV2Error::UnsupportedFormat {
            actual,
            expected: ANN_V2_FORMAT_VERSION,
        })
    }
}

fn ensure_u64_bound(resource: &'static str, value: u64, maximum: u64) -> AnnV2Result<()> {
    if value <= maximum {
        Ok(())
    } else {
        exhausted(resource, maximum, value)
    }
}

fn ensure_usize_bound(resource: &'static str, value: usize, maximum: usize) -> AnnV2Result<()> {
    ensure_u64_bound(resource, usize_to_u64(value), usize_to_u64(maximum))
}

fn exhausted<T>(resource: &'static str, limit: u64, required: u64) -> AnnV2Result<T> {
    Err(AnnV2Error::ResourceExhausted {
        resource,
        limit,
        required,
    })
}

fn checked_count_product(resource: &'static str, left: u64, right: u64) -> AnnV2Result<u64> {
    left.checked_mul(right)
        .ok_or(AnnV2Error::ResourceExhausted {
            resource,
            limit: u64::MAX,
            required: u64::MAX,
        })
}

fn checked_count_add(resource: &'static str, left: u64, right: u64) -> AnnV2Result<u64> {
    left.checked_add(right)
        .ok_or(AnnV2Error::ResourceExhausted {
            resource,
            limit: u64::MAX,
            required: u64::MAX,
        })
}

const fn half_rounded_up(value: u64) -> u64 {
    value / 2 + value % 2
}

fn checked_usize_product(resource: &'static str, left: usize, right: usize) -> AnnV2Result<usize> {
    left.checked_mul(right)
        .ok_or(AnnV2Error::ResourceExhausted {
            resource,
            limit: u64::MAX,
            required: u64::MAX,
        })
}

fn checked_usize_add(resource: &'static str, left: usize, right: usize) -> AnnV2Result<usize> {
    left.checked_add(right)
        .ok_or(AnnV2Error::ResourceExhausted {
            resource,
            limit: u64::MAX,
            required: u64::MAX,
        })
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn is_zero_digest(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn is_zero_digest_slice(digest: &[u8]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn is_nil_representation(id: RepresentationId) -> bool {
    id.as_uuid().as_bytes().iter().all(|byte| *byte == 0)
}

fn hash_u8(hasher: &mut blake3::Hasher, value: u8) {
    hasher.update(&[value]);
}

fn hash_u16(hasher: &mut blake3::Hasher, value: u16) {
    hasher.update(&value.to_be_bytes());
}

fn hash_u32(hasher: &mut blake3::Hasher, value: u32) {
    hasher.update(&value.to_be_bytes());
}

fn hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_be_bytes());
}

fn hash_i64(hasher: &mut blake3::Hasher, value: i64) {
    hasher.update(&value.to_be_bytes());
}

fn hash_source_seal(hasher: &mut blake3::Hasher, source: AnnSourceSealV2) {
    hash_u64(hasher, source.vector_store_generation);
    hasher.update(&source.vector_store_root);
    hash_u64(hasher, source.route_generation);
    hasher.update(&source.route_root);
    hasher.update(&source.vector_space_registry_digest);
}

fn hash_build_parameters(hasher: &mut blake3::Hasher, build: AnnBuildParametersV2) {
    hash_u8(hasher, build.algorithm.canonical_tag());
    hash_u8(hasher, build.partition_scheme.canonical_tag());
    hash_u8(hasher, build.max_level);
    hash_u16(hasher, build.neighbours_per_level);
    hash_u32(hasher, build.construction_max_visits);
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_u64(&mut hasher, usize_to_u64(bytes.len()));
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn object_digest(key: &AnnObjectKeyV2, value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OBJECT_DIGEST_DOMAIN);
    hash_u16(
        &mut hasher,
        u16::try_from(key.as_bytes().len()).unwrap_or(u16::MAX),
    );
    hasher.update(key.as_bytes());
    hash_u64(&mut hasher, usize_to_u64(value.len()));
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

fn push_uuid_bytes(output: &mut Vec<u8>, id: RepresentationId) {
    output.extend_from_slice(id.as_uuid().as_bytes());
}

fn read_uuid_bytes(bytes: &[u8], cursor: &mut usize) -> AnnV2Result<RepresentationId> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let raw = take(bytes, cursor, UUID_BYTES)?;
    if raw.iter().all(|byte| *byte == 0) {
        return Err(AnnV2Error::Invalid("node UUID is nil"));
    }
    let mut text = [0_u8; 36];
    for index in [8, 13, 18, 23] {
        text[index] = b'-';
    }
    let mut destination = 0_usize;
    for byte in raw {
        while text[destination] == b'-' {
            destination += 1;
        }
        text[destination] = HEX[usize::from(byte >> 4)];
        text[destination + 1] = HEX[usize::from(byte & 0x0f)];
        destination += 2;
    }
    let value = std::str::from_utf8(&text)
        .map_err(|_| AnnV2Error::Invalid("node UUID encoding is invalid"))?;
    RepresentationId::from_str(value).map_err(|_| AnnV2Error::Invalid("node UUID is invalid"))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> AnnV2Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or(AnnV2Error::Invalid("ANN value cursor overflowed"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(AnnV2Error::Invalid("ANN value is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> AnnV2Result<u8> {
    Ok(take(bytes, cursor, 1)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> AnnV2Result<u16> {
    let value: [u8; 2] = take(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| AnnV2Error::Invalid("u16 is truncated"))?;
    Ok(u16::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> AnnV2Result<u64> {
    let value: [u8; 8] = take(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| AnnV2Error::Invalid("u64 is truncated"))?;
    Ok(u64::from_be_bytes(value))
}

fn generation_prefix(generation: u64) -> AnnV2Result<Vec<u8>> {
    if generation == 0 {
        return Err(AnnV2Error::Invalid("generation is zero"));
    }
    let mut bytes = Vec::with_capacity(GENERATION_PREFIX_BYTES);
    bytes.push(b'g');
    bytes.extend_from_slice(&generation.to_be_bytes());
    Ok(bytes)
}

fn validate_object_key(bytes: &[u8]) -> AnnV2Result<()> {
    ensure_usize_bound("object_key_bytes", bytes.len(), ANN_V2_MAX_KEY_BYTES)?;
    if bytes.first() != Some(&b'g') || bytes.len() < 10 {
        return Err(AnnV2Error::Invalid("ANN object key prefix is invalid"));
    }
    let generation = u64::from_be_bytes(
        bytes[1..9]
            .try_into()
            .map_err(|_| AnnV2Error::Invalid("ANN object generation is truncated"))?,
    );
    if generation == 0 {
        return Err(AnnV2Error::Invalid("ANN object generation is zero"));
    }
    match bytes[9] {
        b'p' if bytes.len() == PARTITION_KEY_BYTES => {
            validate_partition_key_digest(bytes)?;
        }
        b'n' if bytes.len() == NODE_KEY_BYTES => {
            validate_partition_key_digest(bytes)?;
            if bytes[42..58].iter().all(|byte| *byte == 0) {
                return Err(AnnV2Error::Invalid("ANN node key contains a nil UUID"));
            }
        }
        b't' if bytes.len() == PARTITION_TREE_KEY_BYTES => {
            validate_partition_key_digest(bytes)?;
            validate_tree_suffix(bytes, 42, ANN_V2_MAX_NODES)?;
        }
        b'q' if bytes.len() == GLOBAL_TREE_KEY_BYTES => {
            validate_tree_suffix(bytes, 10, ANN_V2_MAX_PARTITIONS)?;
        }
        _ => {
            return Err(AnnV2Error::Invalid(
                "ANN object key kind or length is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_partition_key_digest(bytes: &[u8]) -> AnnV2Result<()> {
    if bytes[10..42].iter().all(|byte| *byte == 0) {
        Err(AnnV2Error::Invalid(
            "ANN object key contains a zero partition digest",
        ))
    } else {
        Ok(())
    }
}

fn validate_tree_suffix(bytes: &[u8], offset: usize, maximum_leaves: u64) -> AnnV2Result<()> {
    let level = u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .map_err(|_| AnnV2Error::Invalid("Merkle level is truncated"))?,
    );
    let index = u64::from_be_bytes(
        bytes[offset + 2..offset + 10]
            .try_into()
            .map_err(|_| AnnV2Error::Invalid("Merkle index is truncated"))?,
    );
    if level > ANN_V2_MAX_MERKLE_LEVEL || index >= maximum_leaves {
        return Err(AnnV2Error::Invalid("Merkle key exceeds format bounds"));
    }
    Ok(())
}

fn tree_coordinates(key: &AnnObjectKeyV2) -> AnnV2Result<(u16, u64)> {
    let offset = match key.kind() {
        AnnObjectKindV2::PartitionTree => 42,
        AnnObjectKindV2::GlobalTree => 10,
        AnnObjectKindV2::PartitionManifest | AnnObjectKindV2::Node => {
            return Err(AnnV2Error::Invalid("ANN object key is not a Merkle key"));
        }
    };
    let bytes = key.as_bytes();
    let level = u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .map_err(|_| AnnV2Error::Invalid("Merkle level is truncated"))?,
    );
    let index = u64::from_be_bytes(
        bytes[offset + 2..offset + 10]
            .try_into()
            .map_err(|_| AnnV2Error::Invalid("Merkle index is truncated"))?,
    );
    Ok((level, index))
}
