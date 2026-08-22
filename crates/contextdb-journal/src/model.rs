use contextdb_core::{
    CommitSeq, DerivedWorkItem, MaintenanceMutationSet, MutationId, ObservationId, ObservationUnit,
    PublicationId, SemanticMutationSet, Validate,
};
use contextdb_storage::{Durability, StorageSequence, VerifyMode};
use serde::{Deserialize, Serialize};

use crate::{JournalError, Result};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Opaque caller-provided key used to make a logical operation replay-safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validates a non-blank bounded key. Only its BLAKE3 digest is persisted.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(JournalError::InvalidIdempotencyKey);
        }
        Ok(Self(value))
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        *blake3::hash(self.0.as_bytes()).as_bytes()
    }
}

/// Commit boundary at which deterministic fault injection can interrupt work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitStage {
    /// Typed bytes and references were validated, before opening a writer.
    AfterValidation,
    /// Every frame was staged, before the atomic physical commit.
    AfterStaging,
    /// Atomic commit completed, but the caller has not received its receipt.
    AfterCommitBeforeAck,
}

/// Durability and optional deterministic failpoint for one logical commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitOptions {
    /// Durability which the physical backend must achieve before acknowledgement.
    pub durability: Durability,
    /// One-shot failpoint used by crash-consistency tests.
    pub fail_at: Option<CommitStage>,
}

impl Default for CommitOptions {
    fn default() -> Self {
        Self {
            durability: Durability::Sync,
            fail_at: None,
        }
    }
}

/// Exact JSON bytes whose decoded observation passed core validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedObservationBytes {
    bytes: Vec<u8>,
    observation: ObservationUnit,
    digest: [u8; 32],
}

impl ValidatedObservationBytes {
    /// Decodes and validates an observation while retaining the original bytes.
    pub fn from_json(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        let observation: ObservationUnit = serde_json::from_slice(&bytes)?;
        observation.validate()?;
        let digest = operation_digest(b"observation-accepted-v1", &bytes);
        Ok(Self {
            bytes,
            observation,
            digest,
        })
    }

    /// Serializes a typed observation once, then validates the retained bytes.
    pub fn from_observation(observation: &ObservationUnit) -> Result<Self> {
        Self::from_json(serde_json::to_vec(observation)?)
    }

    /// Returns the accepted observation identity.
    #[must_use]
    pub const fn observation_id(&self) -> ObservationId {
        self.observation.id
    }

    /// Returns the exact validated bytes stored for replay.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the operation-separated exact-request digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Exact JSON bytes whose decoded semantic mutation passed core validation.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMutationBytes {
    bytes: Vec<u8>,
    mutation: SemanticMutationSet,
    digest: [u8; 32],
}

impl ValidatedMutationBytes {
    /// Decodes and validates a mutation while retaining the exact input bytes.
    pub fn from_json(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        let mutation: SemanticMutationSet = serde_json::from_slice(&bytes)?;
        mutation.validate()?;
        if !mutation.observation_appends.is_empty() {
            return Err(JournalError::EmbeddedObservationAppend);
        }
        let digest = operation_digest(b"semantic-publication-v1", &bytes);
        Ok(Self {
            bytes,
            mutation,
            digest,
        })
    }

    /// Serializes a typed mutation once, then validates the retained bytes.
    pub fn from_mutation(mutation: &SemanticMutationSet) -> Result<Self> {
        Self::from_json(serde_json::to_vec(mutation)?)
    }

    /// Returns the mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> MutationId {
        self.mutation.id
    }

    /// Returns the exact validated bytes persisted for deterministic replay.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the operation-separated exact-request digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the validated typed mutation.
    #[must_use]
    pub const fn mutation(&self) -> &SemanticMutationSet {
        &self.mutation
    }
}

/// Exact JSON bytes whose decoded maintenance mutation passed core validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMaintenanceBytes {
    bytes: Vec<u8>,
    mutation: MaintenanceMutationSet,
    digest: [u8; 32],
}

impl ValidatedMaintenanceBytes {
    /// Decodes and validates a maintenance operation while retaining exact bytes.
    pub fn from_json(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        let mutation: MaintenanceMutationSet = serde_json::from_slice(&bytes)?;
        mutation.validate()?;
        let digest = operation_digest(b"maintenance-publication-v1", &bytes);
        Ok(Self {
            bytes,
            mutation,
            digest,
        })
    }

    /// Serializes a typed operation once, then validates retained bytes.
    pub fn from_mutation(mutation: &MaintenanceMutationSet) -> Result<Self> {
        Self::from_json(serde_json::to_vec(mutation)?)
    }

    /// Returns the mutation identity.
    #[must_use]
    pub const fn mutation_id(&self) -> MutationId {
        self.mutation.id
    }

    /// Returns the exact validated bytes persisted for replay.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the operation-separated exact-request digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the validated typed mutation.
    #[must_use]
    pub const fn mutation(&self) -> &MaintenanceMutationSet {
        &self.mutation
    }
}

/// Receipt for a separately accepted immutable observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationReceipt {
    /// Observation identity.
    pub observation_id: ObservationId,
    /// Monotonic logical acceptance sequence.
    pub commit_seq: CommitSeq,
    /// Requested and achieved durability for the acknowledged commit.
    pub durability: Durability,
    /// Whether this receipt was reconstructed by an idempotent retry.
    pub replayed: bool,
    /// Exact accepted request digest.
    pub request_digest: [u8; 32],
}

/// Receipt for one atomic semantic publication and its outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicationReceipt {
    /// Mutation identity.
    pub mutation_id: MutationId,
    /// Immutable publication-record identity.
    pub publication_id: PublicationId,
    /// Monotonic logical publication sequence.
    pub commit_seq: CommitSeq,
    /// Requested and achieved durability for the acknowledged commit.
    pub durability: Durability,
    /// Number of derived work descriptors atomically published.
    pub outbox_count: u32,
    /// Whether this receipt was reconstructed by an idempotent retry.
    pub replayed: bool,
    /// Digest of exact validated mutation bytes.
    pub mutation_digest: [u8; 32],
}

/// Receipt for one atomic policy/maintenance publication and its outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceReceipt {
    /// Maintenance mutation identity.
    pub mutation_id: MutationId,
    /// Immutable maintenance publication identity.
    pub publication_id: PublicationId,
    /// Monotonic logical publication sequence.
    pub commit_seq: CommitSeq,
    /// Requested and achieved durability for the acknowledged commit.
    pub durability: Durability,
    /// Number of rebuildable work descriptors atomically published.
    pub outbox_count: u32,
    /// Whether this receipt was reconstructed by an idempotent retry.
    pub replayed: bool,
    /// Digest of exact validated maintenance bytes.
    pub mutation_digest: [u8; 32],
}

/// One checksummed logical event in a consistent journal snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEvent {
    /// Separately accepted immutable observation.
    ObservationAccepted {
        /// Logical commit sequence.
        commit_seq: CommitSeq,
        /// Observation identity.
        observation_id: ObservationId,
        /// Exact validated observation bytes.
        exact_bytes: Vec<u8>,
        /// Request digest.
        request_digest: [u8; 32],
    },
    /// Atomic semantic publication with exact mutation and rebuildable work.
    SemanticPublished {
        /// Logical commit sequence.
        commit_seq: CommitSeq,
        /// Mutation identity.
        mutation_id: MutationId,
        /// Publication identity.
        publication_id: PublicationId,
        /// Exact validated mutation bytes.
        exact_mutation_bytes: Vec<u8>,
        /// Mutation digest.
        mutation_digest: [u8; 32],
        /// Atomically published derived work descriptors.
        outbox: Vec<DerivedWorkItem>,
    },
    /// Atomic policy or projection-maintenance publication.
    MaintenancePublished {
        /// Logical commit sequence.
        commit_seq: CommitSeq,
        /// Maintenance mutation identity.
        mutation_id: MutationId,
        /// Immutable publication identity.
        publication_id: PublicationId,
        /// Exact validated maintenance bytes.
        exact_mutation_bytes: Vec<u8>,
        /// Mutation digest.
        mutation_digest: [u8; 32],
        /// Atomically published rebuildable work descriptors.
        outbox: Vec<DerivedWorkItem>,
    },
}

/// Self-verifying portable copy of the backend-independent logical journal.
///
/// `payload` contains only versioned ContextDB frames and ordered keys; it does
/// not contain substrate pages or backend-specific metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableJournalBackup {
    /// Portable backup container schema.
    pub schema_version: u16,
    /// Last completely published logical commit represented by the payload.
    pub commit_seq: CommitSeq,
    /// Number of logical journal records across all journal keyspaces.
    pub records: u64,
    /// BLAKE3 digest of the exact payload bytes.
    pub payload_digest: [u8; 32],
    /// Canonical JSON bytes of the private portable payload schema.
    pub payload: Vec<u8>,
}

/// Result of atomically restoring a portable logical backup into an empty DB.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReport {
    /// Restored logical head.
    pub commit_seq: CommitSeq,
    /// Count of restored journal records.
    pub records: u64,
    /// Verified payload identity.
    pub payload_digest: [u8; 32],
    /// Physical synchronized commit which installed the backup.
    pub storage_sequence: StorageSequence,
}

impl JournalEvent {
    /// Returns the event's logical commit sequence.
    #[must_use]
    pub const fn commit_seq(&self) -> CommitSeq {
        match self {
            Self::ObservationAccepted { commit_seq, .. }
            | Self::SemanticPublished { commit_seq, .. }
            | Self::MaintenancePublished { commit_seq, .. } => *commit_seq,
        }
    }
}

/// Selects a logical journal snapshot independent of physical storage sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalSnapshotSelector {
    /// Latest completely published logical snapshot.
    Latest,
    /// Exact logical prefix.
    At(CommitSeq),
}

/// Materialized, checksum-validated logical journal prefix.
#[derive(Clone, Debug, PartialEq)]
pub struct JournalSnapshot {
    /// Logical sequence represented by this prefix.
    pub commit_seq: CommitSeq,
    /// Physical stable snapshot used to materialize it.
    pub storage_sequence: StorageSequence,
    /// Ordered logical events through `commit_seq`.
    pub events: Vec<JournalEvent>,
}

/// Exact semantic mutation recovered for deterministic replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayMutation {
    /// Publication sequence.
    pub commit_seq: CommitSeq,
    /// Mutation identity.
    pub mutation_id: MutationId,
    /// Digest of exact bytes.
    pub mutation_digest: [u8; 32],
    /// Exact bytes originally validated and published.
    pub exact_bytes: Vec<u8>,
}

/// Exact policy/maintenance mutation recovered for deterministic replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayMaintenance {
    /// Publication sequence.
    pub commit_seq: CommitSeq,
    /// Mutation identity.
    pub mutation_id: MutationId,
    /// Digest of exact bytes.
    pub mutation_digest: [u8; 32],
    /// Exact bytes originally validated and published.
    pub exact_bytes: Vec<u8>,
}

/// Result of startup tail cleanup and prefix validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Last complete logical commit.
    pub commit_seq: CommitSeq,
    /// Physical sequence after optional cleanup.
    pub storage_sequence: StorageSequence,
    /// Unpublished journal/outbox records removed from beyond logical head.
    pub removed_tail_records: u64,
    /// Sanitized recovery warnings.
    pub warnings: Vec<String>,
}

/// Combined physical and semantic verification report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalVerifyReport {
    /// Verification depth.
    pub mode: VerifyMode,
    /// Last complete logical commit.
    pub commit_seq: CommitSeq,
    /// Physical snapshot verified.
    pub storage_sequence: StorageSequence,
    /// Logical event count.
    pub events: u64,
    /// Outbox frame count.
    pub outbox_records: u64,
    /// Idempotency receipt count.
    pub idempotency_records: u64,
    /// Physical and semantic non-fatal warnings.
    pub warnings: Vec<String>,
}

pub(crate) fn operation_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
