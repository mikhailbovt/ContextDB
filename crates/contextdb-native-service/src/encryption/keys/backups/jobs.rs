//! Independently retained worker bindings and terminal logical-cleanup results.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

use super::*;
use crate::{
    NativeBackupCleanupProgress, NativeBackupCleanupStage, NativeRemovalRequestReceipt, integrity,
    raw_index::budget_error, storage_error,
};

mod publication;
#[cfg(test)]
mod tests;
mod verification;

// Leave room for sealing/key overhead inside the catalog's 1 MiB scan pages.
const MAX_EVENT_BYTES: usize = 256 * 1024;

/// Exact acceptance in the custody job journal, outside native backup/restore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupCleanupJobReceipt {
    /// Authority retaining the input, worker binding and cleanup result.
    pub authority_id: Uuid,
    /// Global job-event position for start, verified import or finish.
    pub sequence: u64,
    /// Commitment to the immutable job binding, result and predecessor receipts.
    pub digest: String,
}

impl NativeBackupCleanupJobReceipt {
    pub(super) fn validate(&self, keys: &NativeCustodyKeys) -> contextdb_storage::Result<()> {
        if keys.identity.version < 4
            || self.authority_id != keys.authority_id()
            || self.sequence == 0
        {
            return Err(failure("archive job authority or sequence differs"));
        }
        valid_digest(&self.digest)
    }
}

/// Fixed input and native owner. Retries never select a different readable branch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupCleanupJobBinding {
    /// Workspace granting this request, hashed without its cleartext identifier.
    pub workspace_digest: String,
    /// Exact independently retained removal request.
    pub request: NativeRemovalRequestReceipt,
    /// Original issuance this worker follows across successive requests.
    pub original: NativeBackupRegistration,
    /// Complete membership of the fixed input, possibly a prior replacement.
    pub source: NativeBackupContentsInventory,
    /// Ordered accepted path from the original to that input; empty for the original.
    pub source_path: Vec<NativeBackupReplacementReceipt>,
    /// Complete, independently retained input bytes.
    pub source_artifact: NativeBackupArtifactReceipt,
    /// Registered native instance that owns this work, preserved across reopen.
    pub worker_instance: Uuid,
    /// Exact fence of the preceding worker, present only in a replacement's first
    /// job. Old jobs and native-copy obligations remain independently retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_seal: Option<NativeBackupWorkerSeal>,
    /// Pristine physical sequence at initial or replacement admission. Import
    /// occurs only at this sequence; continuing the same worker needs no import.
    pub restore_at: Option<u64>,
}

/// Durable cleanup job. A terminal result covers this fixed archive only, not
/// physical erasure, key disposal, current availability or global removal admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupCleanupJob {
    /// Latest accepted job event, recoverable using either its start or finish receipt.
    pub receipt: NativeBackupCleanupJobReceipt,
    /// Immutable identity and input; never replaced by a caller's checkpoint.
    pub binding: NativeBackupCleanupJobBinding,
    /// Exact input import was verified on this worker. Later requests inherit
    /// the initialized worker; interrupted first imports must verify its bytes.
    pub initialized: bool,
    /// Actual coordinator result, present only for Available or Unchanged.
    /// Intermediate progress is recovered from the worker's existing native journals.
    pub terminal: Option<NativeBackupCleanupProgress>,
    /// Exact native archive digest observed at terminal verification, including
    /// maintenance-only changes when no pruning or replacement was required.
    pub terminal_archive_digest: Option<String>,
}

impl NativeBackupCleanupJob {
    pub(crate) fn next_source(
        &self,
    ) -> ServiceResult<(
        NativeBackupContentsInventory,
        Vec<NativeBackupReplacementReceipt>,
        NativeBackupArtifactReceipt,
    )> {
        let result = self.terminal.as_ref().ok_or_else(|| {
            ServiceError::new(
                ErrorCode::EvidenceRequired,
                "archive worker has an unfinished cleanup request",
                false,
            )
        })?;
        let mut path = self.binding.source_path.clone();
        if let (Some(proof), Some(artifact)) = (&result.replacement, &result.artifact) {
            path.push(proof.receipt.clone());
            return Ok((proof.target.clone(), path, artifact.receipt.clone()));
        }
        Ok((
            self.binding.source.clone(),
            path,
            self.binding.source_artifact.clone(),
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobEvent {
    previous: Option<String>,
    prior: Option<NativeBackupCleanupJobReceipt>,
    value: NativeBackupCleanupJob,
}

impl JobEvent {
    fn commitment(&self) -> ServiceResult<String> {
        crate::canonical_digest(&(
            "contextdb/native-backup-cleanup-job/v1",
            self.value.receipt.authority_id,
            self.value.receipt.sequence,
            &self.previous,
            &self.prior,
            &self.value.binding,
            self.value.initialized,
            &self.value.terminal,
            &self.value.terminal_archive_digest,
        ))
    }
}

fn event_key(sequence: u64) -> Vec<u8> {
    format!("backup/job/event/{sequence:020}").into_bytes()
}

fn job_key(binding: &NativeBackupCleanupJobBinding) -> Vec<u8> {
    format!(
        "backup/job/request/{}/{}/{}",
        binding.workspace_digest, binding.request.digest, binding.original.archive_digest
    )
    .into_bytes()
}

fn original_key(digest: &str) -> Vec<u8> {
    format!("backup/job/original/{digest}").into_bytes()
}

fn worker_key(instance: Uuid) -> Vec<u8> {
    format!("backup/job/worker/{instance}").into_bytes()
}
