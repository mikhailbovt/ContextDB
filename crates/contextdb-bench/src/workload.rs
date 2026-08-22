//! Deterministic, streaming BENCH-H workload generation.

use serde::{Deserialize, Serialize};

use crate::digest::{hex, sha256_hex};
use crate::{BENCH_H_WORKLOAD_VERSION, BenchError, Result};

/// BENCH-H scale tier attached to a run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScaleTier {
    /// Fast package-level correctness coverage.
    Smoke,
    /// Bounded local native measurement below RFC published tiers.
    Development,
    /// Ten-million-record storage stress run without semantic graph/vector coverage.
    #[serde(rename = "development-10m-storage-records")]
    Development10mStorageRecords,
    /// RFC small tier: 100k nodes and one million edges in a full-stack adapter.
    Small,
    /// RFC medium tier: five million nodes and 50 million edges.
    Medium,
    /// ERRATA E-009 v1 certification floor: at least ten million nodes.
    CertificationV1,
    /// Larger non-release research workload.
    Research,
}

impl ScaleTier {
    /// Stable machine-readable tier label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Development => "bounded-development",
            Self::Development10mStorageRecords => "development-10m-storage-records",
            Self::Small => "small-100k-nodes",
            Self::Medium => "medium-5m-nodes",
            Self::CertificationV1 => "certification-v1-10m-nodes",
            Self::Research => "research",
        }
    }
}

/// Complete deterministic workload and operations budget.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchConfig {
    /// Stable workload generator version.
    pub workload_version: String,
    /// Dataset/operation seed.
    pub seed: u64,
    /// Number of primary logical records.
    pub records: u64,
    /// Records committed per synchronized transaction.
    pub batch_records: u64,
    /// Recall operations in cold and warm scenarios.
    pub recall_queries: u64,
    /// Operations in the seeded mixed workload.
    pub mixed_operations: u64,
    /// Journal observations used by portable backup/restore.
    pub journal_observations: u64,
    /// Synthetic value bytes per primary record.
    pub value_bytes: usize,
    /// Subject-local prefix partitions.
    pub subjects: u32,
    /// Incremental record counts measured on the scaling curve.
    pub scale_points: Vec<u64>,
    /// Maximum estimated streaming buffer size.
    pub working_buffer_budget_bytes: u64,
    /// Maximum phase-boundary process RSS.
    pub process_rss_budget_bytes: u64,
    /// Explicit tier label.
    pub tier: ScaleTier,
}

impl BenchConfig {
    /// Small exhaustive package-test configuration.
    #[must_use]
    pub fn smoke() -> Self {
        Self {
            workload_version: BENCH_H_WORKLOAD_VERSION.to_owned(),
            seed: 0xc07e_57db_0017_0001,
            records: 256,
            batch_records: 32,
            recall_queries: 128,
            mixed_operations: 128,
            journal_observations: 12,
            value_bytes: 128,
            subjects: 16,
            scale_points: vec![64, 128, 256],
            working_buffer_budget_bytes: 16 * 1024 * 1024,
            process_rss_budget_bytes: 1024 * 1024 * 1024,
            tier: ScaleTier::Smoke,
        }
    }

    /// Bounded native development configuration suitable for a local run.
    #[must_use]
    pub fn development() -> Self {
        Self {
            workload_version: BENCH_H_WORKLOAD_VERSION.to_owned(),
            seed: 0xc07e_57db_0017_0002,
            records: 20_000,
            batch_records: 250,
            recall_queries: 2_000,
            mixed_operations: 2_000,
            journal_observations: 100,
            value_bytes: 256,
            subjects: 64,
            scale_points: vec![1_000, 5_000, 10_000, 20_000],
            working_buffer_budget_bytes: 64 * 1024 * 1024,
            process_rss_budget_bytes: 2 * 1024 * 1024 * 1024,
            tier: ScaleTier::Development,
        }
    }

    /// Validates every bounded allocation and workload invariant.
    pub fn validate(&self) -> Result<()> {
        if self.workload_version != BENCH_H_WORKLOAD_VERSION {
            return invalid("workload_version", "unsupported generator version");
        }
        for (field, value) in [
            ("records", self.records),
            ("batch_records", self.batch_records),
            ("recall_queries", self.recall_queries),
            ("mixed_operations", self.mixed_operations),
            ("journal_observations", self.journal_observations),
            (
                "working_buffer_budget_bytes",
                self.working_buffer_budget_bytes,
            ),
            ("process_rss_budget_bytes", self.process_rss_budget_bytes),
        ] {
            if value == 0 {
                return invalid(field, "value must be positive");
            }
        }
        if self.batch_records > self.records {
            return invalid("batch_records", "batch cannot exceed record count");
        }
        if !(32..=65_536).contains(&self.value_bytes) {
            return invalid("value_bytes", "value size must be between 32 and 65536");
        }
        if self.subjects == 0 || u64::from(self.subjects) > self.records {
            return invalid("subjects", "subjects must be in 1..=records");
        }
        if self.scale_points.is_empty()
            || self
                .scale_points
                .iter()
                .any(|point| *point == 0 || *point > self.records)
            || !self.scale_points.windows(2).all(|pair| pair[0] < pair[1])
            || self.scale_points.last().copied() != Some(self.records)
        {
            return invalid(
                "scale_points",
                "points must be unique, ascending, nonzero, and end at records",
            );
        }
        let batch_bytes = self
            .batch_records
            .checked_mul(
                u64::try_from(self.value_bytes)
                    .map_err(|_| BenchError::ArithmeticOverflow("value byte count conversion"))?,
            )
            .and_then(|bytes| bytes.checked_add(self.batch_records.saturating_mul(96)))
            .ok_or(BenchError::ArithmeticOverflow("working batch estimate"))?;
        if batch_bytes > self.working_buffer_budget_bytes {
            return invalid(
                "working_buffer_budget_bytes",
                "estimated batch allocation exceeds declared budget",
            );
        }
        if matches!(
            self.tier,
            ScaleTier::Small | ScaleTier::Medium | ScaleTier::CertificationV1
        ) {
            return invalid(
                "tier",
                "semantic scale tiers require an explicit full-stack coverage manifest and are not valid for the storage-record workload",
            );
        }
        if matches!(self.tier, ScaleTier::Development10mStorageRecords) && self.records < 10_000_000
        {
            return invalid(
                "records",
                "the 10M storage-record development tier requires at least 10M records",
            );
        }
        Ok(())
    }

    /// Returns a copy with bounded storage-record-dependent fields adjusted.
    ///
    /// A generic record count is not evidence of semantic nodes, graph edges, or vectors, so
    /// this method never promotes a storage workload to an RFC semantic scale tier.
    pub fn with_records(mut self, records: u64) -> Result<Self> {
        self.records = records;
        self.batch_records = self.batch_records.min(records).max(1);
        self.scale_points = default_scale_points(records);
        self.tier = if records >= 10_000_000 {
            ScaleTier::Development10mStorageRecords
        } else {
            ScaleTier::Development
        };
        self.validate()?;
        Ok(self)
    }
}

fn default_scale_points(records: u64) -> Vec<u64> {
    let mut points = vec![records / 4, records / 2, records];
    for normative in [100_000, 5_000_000, 10_000_000] {
        if normative <= records {
            points.push(normative);
        }
    }
    points.retain(|point| *point > 0);
    points.sort_unstable();
    points.dedup();
    points
}

/// One synthetic primary record generated without retaining the whole dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchRecord {
    /// Stable ordinal.
    pub ordinal: u64,
    /// Subject-local partition.
    pub subject: u32,
    /// Portable primary key.
    pub key: Vec<u8>,
    /// Deterministic synthetic value.
    pub value: Vec<u8>,
}

/// Streaming deterministic dataset used by storage adapters.
#[derive(Clone, Debug)]
pub struct DeterministicDataset {
    config: BenchConfig,
    manifest_sha256: String,
}

impl DeterministicDataset {
    /// Validates the configuration and binds a canonical workload-manifest digest.
    pub fn new(config: BenchConfig) -> Result<Self> {
        config.validate()?;
        let manifest = serde_json::to_vec(&config)?;
        Ok(Self {
            config,
            manifest_sha256: sha256_hex(&manifest),
        })
    }

    /// Workload configuration.
    #[must_use]
    pub const fn config(&self) -> &BenchConfig {
        &self.config
    }

    /// SHA-256 of the canonical generator configuration.
    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Generates one record by stable ordinal.
    pub fn record(&self, ordinal: u64) -> Result<BenchRecord> {
        if ordinal >= self.config.records {
            return invalid("ordinal", "record ordinal is outside the dataset");
        }
        let subject_modulus = u64::from(self.config.subjects);
        let subject = u32::try_from(ordinal % subject_modulus)
            .map_err(|_| BenchError::ArithmeticOverflow("subject conversion"))?;
        let key = format!("subject/{subject:08}/record/{ordinal:016x}").into_bytes();
        let mut value = vec![0_u8; self.config.value_bytes];
        value[..8].copy_from_slice(&ordinal.to_be_bytes());
        value[8..12].copy_from_slice(&subject.to_be_bytes());
        let mut state = self.config.seed ^ ordinal.rotate_left(17);
        for chunk in value[12..].chunks_mut(8) {
            state = splitmix64(state);
            let bytes = state.to_le_bytes();
            let length = chunk.len();
            chunk.copy_from_slice(&bytes[..length]);
        }
        Ok(BenchRecord {
            ordinal,
            subject,
            key,
            value,
        })
    }

    /// Deterministically selects a record ordinal for a query number.
    #[must_use]
    pub fn query_ordinal(&self, query: u64) -> u64 {
        splitmix64(self.config.seed ^ query.wrapping_mul(0x9e37_79b9_7f4a_7c15))
            % self.config.records
    }

    /// Subject prefix used by exact filtered recall.
    #[must_use]
    pub fn subject_prefix(&self, subject: u32) -> Vec<u8> {
        format!("subject/{:08}/", subject % self.config.subjects).into_bytes()
    }

    /// BLAKE3 digest of the complete generated logical stream.
    pub fn expected_logical_digest(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb-bench-h-logical-v1\0");
        for ordinal in 0..self.config.records {
            let record = self.record(ordinal)?;
            hash_framed(&mut hasher, &record.key)?;
            hash_framed(&mut hasher, &record.value)?;
        }
        Ok(hex(hasher.finalize().as_bytes()))
    }
}

/// Hashes lexicographically scanned key/value records without concatenation ambiguity.
pub(crate) fn hash_framed(hasher: &mut blake3::Hasher, bytes: &[u8]) -> Result<()> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| BenchError::ArithmeticOverflow("digest frame length"))?;
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T> {
    Err(BenchError::InvalidConfiguration {
        field,
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "deterministic workload tests use immediate failure semantics"
    )]

    use super::{BenchConfig, DeterministicDataset, ScaleTier};

    #[test]
    fn stream_and_queries_are_reproducible() {
        let first = DeterministicDataset::new(BenchConfig::smoke()).expect("dataset");
        let second = DeterministicDataset::new(BenchConfig::smoke()).expect("dataset");
        assert_eq!(
            first.record(42).expect("record"),
            second.record(42).expect("record")
        );
        assert_eq!(first.query_ordinal(99), second.query_ordinal(99));
        assert_eq!(
            first.expected_logical_digest().expect("digest"),
            second.expected_logical_digest().expect("digest")
        );
        assert_eq!(first.manifest_sha256(), second.manifest_sha256());
    }

    #[test]
    fn storage_config_cannot_claim_semantic_certification_by_mutating_metadata() {
        let mut config = BenchConfig::development()
            .with_records(10_000_000)
            .expect("10M storage config");
        config.tier = ScaleTier::CertificationV1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ten_million_custom_run_remains_a_storage_development_tier() {
        let config = BenchConfig::development()
            .with_records(10_000_000)
            .expect("10M configuration");
        assert_eq!(config.tier, ScaleTier::Development10mStorageRecords);
        assert!(config.scale_points.contains(&100_000));
        assert!(config.scale_points.contains(&5_000_000));
        assert!(config.scale_points.contains(&10_000_000));
    }
}
