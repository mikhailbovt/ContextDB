//! Reusable ownership boundary for the durable ContextDB runtime foundation.
//!
//! This crate deliberately stops before claiming a complete application
//! service. It owns one Fjall storage authority and opens the native ordered
//! journal and typed graph over clones of that same transactional engine. The
//! versioned manifest distinguishes capabilities which are usable through this
//! composition from dependencies which merely compile in the provisional
//! `server-v1` aggregate profile.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub use contextdb_core::{
    CAPABILITY_MANIFEST_SCHEMA_VERSION, CapabilityManifestV1, CapabilityState,
};
use contextdb_format::{
    FORMAT_MANIFEST_SCHEMA_V1, FormatRegistry, ReaderCapability, StoredFormatManifest,
};
use contextdb_graph::GraphStore;
use contextdb_journal::JournalCoordinator;
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, VerifyMode,
    WriteTransaction,
};
use contextdb_storage_fjall::FjallStorage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema emitted for the durable format declaration owned by this crate.
pub const FORMAT_MANIFEST_SCHEMA_VERSION: u16 = 1;
/// Schema emitted for the combined public runtime manifest.
pub const RUNTIME_MANIFEST_SCHEMA_VERSION: u16 = 1;
/// Portable format version selected by the runtime foundation.
pub const RUNTIME_FORMAT_VERSION: u32 = 1;
/// Provisional aggregate profile name. The suffix prevents a release-ready claim.
pub const SERVER_V1_FOUNDATION_PROFILE: &str = "server-v1-foundation";
/// Minimal embedded profile name used without the aggregate server feature.
pub const EMBEDDED_FOUNDATION_PROFILE: &str = "embedded-foundation";

const MANIFEST_KEYSPACE: &str = "contextdb_runtime_manifest";
const FORMAT_MANIFEST_KEY: &[u8] = b"format/v1";

/// Durable, backend-readable format declaration.
///
/// This value is intentionally independent from optional build features. A
/// database opened by the embedded foundation and by the aggregate server
/// build therefore has the same primary format contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FormatManifestV1 {
    /// Schema of this manifest object.
    pub schema_version: u16,
    /// Shared physical-format manifest schema identifier.
    pub schema_identifier: String,
    /// Exact writable backend identity.
    pub storage_backend: String,
    /// Primary writer identity validated through `contextdb-format`.
    pub primary: StoredFormatManifest,
    /// Optional projections which may be rebuilt or ignored.
    pub optional_rebuildable_features: BTreeSet<String>,
}

impl FormatManifestV1 {
    fn foundation() -> Self {
        Self {
            schema_version: FORMAT_MANIFEST_SCHEMA_VERSION,
            schema_identifier: FORMAT_MANIFEST_SCHEMA_V1.to_owned(),
            storage_backend: "fjall".to_owned(),
            primary: StoredFormatManifest {
                family: "runtime-primary".to_owned(),
                writer: RUNTIME_FORMAT_VERSION,
                required_features: BTreeSet::from([
                    "native-ordered-journal-v1".to_owned(),
                    "runtime-owner-manifest-v1".to_owned(),
                    "typed-temporal-graph-store-v1".to_owned(),
                ]),
            },
            optional_rebuildable_features: BTreeSet::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != FORMAT_MANIFEST_SCHEMA_VERSION
            || self.schema_identifier != FORMAT_MANIFEST_SCHEMA_V1
            || self.storage_backend != "fjall"
            || self.primary.required_features.is_empty()
            || self
                .optional_rebuildable_features
                .iter()
                .any(|feature| !valid_identifier(feature))
        {
            return Err(RuntimeError::InvalidFormatManifest);
        }
        self.primary.validate()?;
        let mut registry = FormatRegistry::new();
        registry.register_reader(self.primary.family.clone(), foundation_reader_capability()?)?;
        registry.ensure_readable(&self.primary)?;
        Ok(())
    }
}

fn compiled_capability_manifest() -> CapabilityManifestV1 {
    let mut capabilities = BTreeMap::from([
        (
            "durable_fjall_storage".to_owned(),
            CapabilityState::Available,
        ),
        ("embedded_builder".to_owned(), CapabilityState::Available),
        ("native_graph_store".to_owned(), CapabilityState::Available),
        (
            "ordered_journal_recovery".to_owned(),
            CapabilityState::Available,
        ),
        (
            "restart_verification".to_owned(),
            CapabilityState::Available,
        ),
        (
            "ann_hnsw_runtime".to_owned(),
            compiled_or_unsupported(cfg!(feature = "ann-hnsw")),
        ),
        (
            "compression_zstd".to_owned(),
            compiled_or_unsupported(cfg!(feature = "compression-zstd")),
        ),
        (
            "grpc_transport".to_owned(),
            compiled_or_unsupported(cfg!(feature = "transport-grpc")),
        ),
        (
            "http_transport".to_owned(),
            compiled_or_unsupported(cfg!(feature = "transport-http")),
        ),
        (
            "lexical_tantivy".to_owned(),
            compiled_or_unsupported(cfg!(feature = "lexical-tantivy")),
        ),
    ]);
    for unsupported in [
        "async_maintenance",
        "background_semantic_adjudication",
        "bootstrap",
        "candidate_hierarchy_dag",
        "checkpoint",
        "compact",
        "consolidate",
        "context_pack_recall",
        "handoff",
        "hard_delete",
        "journal_graph_projection",
        "live_restore",
        "native_service_executor",
        "observation_semantic_extraction",
        "policy_first_candidate_recall",
        "policy_first_candidate_traversal",
        "quarantined_memory_proposals",
        "reflect",
        "resume",
        "runtime_state",
        "storage_migration",
    ] {
        capabilities.insert(unsupported.to_owned(), CapabilityState::Unsupported);
    }
    CapabilityManifestV1::new(
        if cfg!(feature = "server-v1") {
            SERVER_V1_FOUNDATION_PROFILE
        } else {
            EMBEDDED_FOUNDATION_PROFILE
        },
        false,
        capabilities,
    )
}

/// Public manifest combining durable compatibility and process capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifestV1 {
    /// Schema of the combined runtime declaration.
    pub schema_version: u16,
    /// Durable format contract read from the database.
    pub format: FormatManifestV1,
    /// Reader range and required-feature support compiled into this binary.
    pub reader: ReaderCapability,
    /// Capabilities compiled into this process.
    pub runtime: CapabilityManifestV1,
}

impl RuntimeManifestV1 {
    fn compiled(format: FormatManifestV1) -> Result<Self> {
        let reader = foundation_reader_capability()?;
        Ok(Self {
            schema_version: RUNTIME_MANIFEST_SCHEMA_VERSION,
            format,
            reader,
            runtime: compiled_capability_manifest(),
        })
    }

    /// Returns the state of a stable capability identifier.
    #[must_use]
    pub fn capability(&self, capability: &str) -> Option<CapabilityState> {
        self.runtime.capability(capability)
    }
}

/// Content-free verification status for one opened runtime owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatus {
    /// Honest profile name from the capability manifest.
    pub profile: String,
    /// Current physical storage sequence.
    pub storage_sequence: u64,
    /// Current ordered journal sequence.
    pub journal_commit_seq: u64,
    /// BLAKE3 digest of the exact canonical durable format manifest.
    pub format_manifest_digest: String,
    /// Always false for this bounded foundation.
    pub server_v1_release_ready: bool,
}

/// Builder for an embedded persistent ContextDB runtime owner.
#[derive(Clone, Debug, Default)]
pub struct ContextDbBuilder {
    path: Option<PathBuf>,
}

impl ContextDbBuilder {
    /// Selects the Fjall database directory.
    #[must_use]
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Opens the durable runtime and verifies its manifest and journal prefix.
    pub fn open(self) -> Result<ContextDb> {
        let path = self.path.ok_or(RuntimeError::MissingPath)?;
        if path.as_os_str().is_empty() {
            return Err(RuntimeError::MissingPath);
        }
        ContextDb::open(path)
    }
}

/// Reusable owner for one durable ContextDB foundation.
///
/// Journal and graph access remains deliberately low-level until the native
/// service executor can coordinate publication across both components.
pub struct ContextDb {
    path: PathBuf,
    storage: FjallStorage,
    journal: JournalCoordinator<FjallStorage>,
    graph: GraphStore<FjallStorage>,
    manifest: RuntimeManifestV1,
}

impl std::fmt::Debug for ContextDb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContextDb")
            .field("path", &self.path)
            .field("profile", &self.manifest.runtime.profile)
            .field("storage", &self.storage)
            .field("journal", &self.journal)
            .field("graph", &self.graph)
            .finish_non_exhaustive()
    }
}

impl ContextDb {
    /// Starts an embedded builder. A path is mandatory before [`ContextDbBuilder::open`].
    #[must_use]
    pub fn builder() -> ContextDbBuilder {
        ContextDbBuilder::default()
    }

    fn open(path: PathBuf) -> Result<Self> {
        let storage = FjallStorage::open(&path)?;
        let format = install_or_verify_format_manifest(&storage)?;
        let journal = JournalCoordinator::new(storage.clone())?;
        let graph = GraphStore::new(storage.clone())?;
        let database = Self {
            path,
            storage,
            journal,
            graph,
            manifest: RuntimeManifestV1::compiled(format)?,
        };
        database.verify()?;
        Ok(database)
    }

    /// Returns the selected database directory exactly as supplied to the builder.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the combined durable-format and runtime-capability manifest.
    #[must_use]
    pub const fn manifest(&self) -> &RuntimeManifestV1 {
        &self.manifest
    }

    /// Returns the native ordered journal.
    ///
    /// This is a foundation API, not an atomic journal+graph application
    /// service. Callers must not describe it as full `server-v1` behavior.
    #[must_use]
    pub const fn journal(&self) -> &JournalCoordinator<FjallStorage> {
        &self.journal
    }

    /// Returns the typed temporal graph store sharing the same Fjall engine.
    #[must_use]
    pub const fn graph(&self) -> &GraphStore<FjallStorage> {
        &self.graph
    }

    /// Revalidates the durable manifest and complete ordered journal prefix.
    pub fn verify(&self) -> Result<RuntimeStatus> {
        let stored = load_format_manifest(&self.storage)?
            .ok_or(RuntimeError::MissingDurableFormatManifest)?;
        ensure_expected_format(&stored)?;
        let journal = self.journal.verify(VerifyMode::Deep)?;
        let canonical = serde_json::to_vec(&stored)?;
        Ok(RuntimeStatus {
            profile: self.manifest.runtime.profile.clone(),
            storage_sequence: self.storage.head_sequence()?,
            journal_commit_seq: journal.commit_seq.get(),
            format_manifest_digest: blake3::hash(&canonical).to_hex().to_string(),
            server_v1_release_ready: self.manifest.runtime.server_v1_release_ready,
        })
    }
}

fn compiled_or_unsupported(enabled: bool) -> CapabilityState {
    if enabled {
        CapabilityState::CompiledOnly
    } else {
        CapabilityState::Unsupported
    }
}

fn foundation_reader_capability() -> Result<ReaderCapability> {
    Ok(ReaderCapability::new(
        RUNTIME_FORMAT_VERSION,
        RUNTIME_FORMAT_VERSION,
        FormatManifestV1::foundation().primary.required_features,
    )?)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn manifest_keyspace() -> Result<Keyspace> {
    Keyspace::new(MANIFEST_KEYSPACE).map_err(RuntimeError::Storage)
}

fn install_or_verify_format_manifest(storage: &FjallStorage) -> Result<FormatManifestV1> {
    if let Some(manifest) = load_format_manifest(storage)? {
        ensure_expected_format(&manifest)?;
        return Ok(manifest);
    }

    let expected = FormatManifestV1::foundation();
    expected.validate()?;
    let keyspace = manifest_keyspace()?;
    let mut transaction = storage.begin_write()?;
    if let Some(bytes) = transaction.get(&keyspace, FORMAT_MANIFEST_KEY)? {
        transaction.rollback()?;
        let manifest = decode_format_manifest(&bytes)?;
        ensure_expected_format(&manifest)?;
        return Ok(manifest);
    }
    transaction.put(
        &keyspace,
        FORMAT_MANIFEST_KEY.to_vec(),
        serde_json::to_vec(&expected)?,
    )?;
    let receipt = transaction.commit(Durability::Sync)?;
    if receipt.durability != Durability::Sync {
        return Err(RuntimeError::DurabilityNotAchieved);
    }
    Ok(expected)
}

fn load_format_manifest(storage: &FjallStorage) -> Result<Option<FormatManifestV1>> {
    let keyspace = manifest_keyspace()?;
    let snapshot = storage.begin_read(SnapshotSelector::Latest)?;
    snapshot
        .get(&keyspace, FORMAT_MANIFEST_KEY)?
        .map(|bytes| decode_format_manifest(&bytes))
        .transpose()
}

fn decode_format_manifest(bytes: &[u8]) -> Result<FormatManifestV1> {
    let manifest: FormatManifestV1 =
        serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidFormatManifest)?;
    manifest.validate()?;
    let canonical = serde_json::to_vec(&manifest)?;
    if canonical != bytes {
        return Err(RuntimeError::NonCanonicalFormatManifest);
    }
    Ok(manifest)
}

fn ensure_expected_format(actual: &FormatManifestV1) -> Result<()> {
    actual.validate()?;
    let expected = FormatManifestV1::foundation();
    if actual != &expected {
        return Err(RuntimeError::IncompatibleFormatManifest {
            expected_digest: manifest_digest(&expected)?,
            actual_digest: manifest_digest(actual)?,
        });
    }
    Ok(())
}

fn manifest_digest(manifest: &FormatManifestV1) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(manifest)?)
        .to_hex()
        .to_string())
}

/// Runtime composition failures. Errors never include stored content bytes.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The embedded builder was opened without a database path.
    #[error("a non-empty ContextDB path is required")]
    MissingPath,
    /// Physical storage rejected an operation.
    #[error(transparent)]
    Storage(#[from] contextdb_storage::StorageError),
    /// Ordered journal recovery or verification failed.
    #[error(transparent)]
    Journal(#[from] contextdb_journal::JournalError),
    /// Typed graph construction failed.
    #[error(transparent)]
    Graph(#[from] contextdb_graph::GraphError),
    /// Durable format compatibility validation failed.
    #[error(transparent)]
    Format(#[from] contextdb_format::FormatError),
    /// Canonical manifest serialization failed.
    #[error("runtime manifest serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The durable format manifest is malformed or outside supported bounds.
    #[error("durable runtime format manifest is invalid")]
    InvalidFormatManifest,
    /// The durable manifest bytes were valid JSON but not canonical JSON.
    #[error("durable runtime format manifest is not canonical")]
    NonCanonicalFormatManifest,
    /// An existing database does not match the exact supported primary format.
    #[error(
        "durable runtime format is incompatible: expected {expected_digest}, found {actual_digest}"
    )]
    IncompatibleFormatManifest {
        /// Digest of the format supported by this runtime.
        expected_digest: String,
        /// Digest of the on-disk format declaration.
        actual_digest: String,
    },
    /// A previously initialized runtime no longer contains its format declaration.
    #[error("durable runtime format manifest is missing")]
    MissingDurableFormatManifest,
    /// The backend acknowledged a weaker durability class than requested.
    #[error("runtime format manifest did not achieve synchronized durability")]
    DurabilityNotAchieved,
}

/// Runtime result type.
pub type Result<T> = std::result::Result<T, RuntimeError>;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "runtime foundation tests use immediate failure semantics"
    )]

    use contextdb_storage::{Durability, ReadSnapshot, StorageEngine, WriteTransaction};

    use super::{CapabilityState, ContextDb, FormatManifestV1, RuntimeError};

    #[test]
    fn builder_requires_a_path() {
        assert!(ContextDb::builder().open().is_err());
    }

    #[test]
    fn restart_preserves_one_format_manifest_and_verified_heads() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime.ctxb");
        let first = ContextDb::builder()
            .path(&path)
            .open()
            .expect("open runtime foundation");
        let first_status = first.verify().expect("verify first open");
        assert_eq!(first_status.journal_commit_seq, 0);
        assert!(first_status.storage_sequence > 0);
        assert!(!first_status.server_v1_release_ready);
        assert_eq!(
            first.manifest().capability("native_service_executor"),
            Some(CapabilityState::Unsupported)
        );
        for capability in [
            "background_semantic_adjudication",
            "candidate_hierarchy_dag",
            "consolidate",
            "observation_semantic_extraction",
            "policy_first_candidate_recall",
            "policy_first_candidate_traversal",
            "quarantined_memory_proposals",
            "reflect",
        ] {
            assert_eq!(
                first.manifest().capability(capability),
                Some(CapabilityState::Unsupported),
                "foundation runtime does not execute {capability}"
            );
        }
        drop(first);

        let reopened = ContextDb::builder()
            .path(&path)
            .open()
            .expect("reopen runtime foundation");
        let reopened_status = reopened.verify().expect("verify reopened runtime");
        assert_eq!(reopened_status, first_status);
        assert_eq!(reopened.path(), path);
        assert_eq!(
            reopened.manifest().capability("ordered_journal_recovery"),
            Some(CapabilityState::Available)
        );
    }

    #[test]
    fn unknown_required_format_feature_fails_closed_on_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("unknown-feature.ctxb");
        let database = ContextDb::builder()
            .path(&path)
            .open()
            .expect("open runtime foundation");
        let keyspace = super::manifest_keyspace().expect("manifest keyspace");
        let mut transaction = database.storage.begin_write().expect("write transaction");
        let bytes = transaction
            .get(&keyspace, super::FORMAT_MANIFEST_KEY)
            .expect("read manifest")
            .expect("manifest exists");
        let mut manifest: FormatManifestV1 =
            serde_json::from_slice(&bytes).expect("decode manifest");
        manifest
            .primary
            .required_features
            .insert("future-required-feature-v9".to_owned());
        transaction
            .put(
                &keyspace,
                super::FORMAT_MANIFEST_KEY.to_vec(),
                serde_json::to_vec(&manifest).expect("encode manifest"),
            )
            .expect("replace manifest");
        transaction
            .commit(Durability::Sync)
            .expect("commit manifest fixture");
        drop(database);

        let error = ContextDb::builder()
            .path(path)
            .open()
            .expect_err("unknown required feature must fail closed");
        assert!(matches!(
            error,
            RuntimeError::Format(contextdb_format::FormatError::UnknownRequiredFeature { .. })
        ));
    }

    #[cfg(feature = "server-v1")]
    #[test]
    fn server_v1_aggregate_is_compiled_but_not_misreported_as_wired() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = ContextDb::builder()
            .path(directory.path().join("server-v1.ctxb"))
            .open()
            .expect("open aggregate foundation");
        assert_eq!(
            database.manifest().runtime.profile,
            super::SERVER_V1_FOUNDATION_PROFILE
        );
        assert!(!database.manifest().runtime.server_v1_release_ready);
        for compiled_only in [
            "ann_hnsw_runtime",
            "compression_zstd",
            "grpc_transport",
            "http_transport",
            "lexical_tantivy",
        ] {
            assert_eq!(
                database.manifest().capability(compiled_only),
                Some(CapabilityState::CompiledOnly),
                "{compiled_only} must not be reported as wired"
            );
        }
    }
}
