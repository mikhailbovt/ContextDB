//! Durable operational checkpoints owned by the native publication authority.

use contextdb_continuity::OwnedRunCheckpoint;
use contextdb_core::{AgentRunId, ObservationId};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::{AuthenticatedRequestContext, CaptureReceipt, CapturedOriginal, ServiceResult};

/// Save one bounded source-addressed checkpoint and its run head atomically.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveRunCheckpointRequest {
    /// Fresh host authentication and runtime capability.
    pub context: AuthenticatedRequestContext,
    /// Same key and event identity on an uncertain acknowledgement.
    pub idempotency_key: String,
    /// Immutable checkpoint observation.
    pub event_id: ObservationId,
    /// Expected prior revision, or zero for a new run.
    pub expected_revision: u64,
    /// Explicit bounded operating state, containing original references.
    pub checkpoint: OwnedRunCheckpoint,
}

/// A checkpoint is eligible for use only after its native synchronized receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRunCheckpoint {
    /// Validated state; its references still need current authorization at use.
    pub checkpoint: OwnedRunCheckpoint,
    /// Same capture domain as conversation originals.
    pub receipt: CaptureReceipt,
}

/// Accepted events after a checkpoint, recovered from the same native producer.
/// This closes the crash interval between message capture and checkpoint save.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCaptureTail {
    /// At most 64 events in exact producer order; missing positions are errors.
    pub events: Vec<CapturedOriginal>,
    /// A larger tail requires explicit recovery, never silent truncation.
    pub more: bool,
}

/// Embedded operational-state port; transport adapters cannot mint its authority.
pub trait OwnedRunPort: Send + Sync {
    /// Recover already accepted record handoffs before starting/resuming a run
    /// or preparing another interaction. This must not republish memory or relax
    /// source policy. Backends require their administrative host grants; partial
    /// work remains resumable when the shared budget or cancellation stops it.
    fn recover_record_writes(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;

    /// Publish the captured checkpoint and compare-and-swap run head together.
    fn save_run_checkpoint(
        &self,
        request: SaveRunCheckpointRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SavedRunCheckpoint>;

    /// Load the current operational head under current run policy.
    /// Original contents are rehydrated separately under their own source policy.
    fn load_run_checkpoint(
        &self,
        context: &AuthenticatedRequestContext,
        run: AgentRunId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<SavedRunCheckpoint>>;

    /// Read a bounded uncheckpointed tail against an unchanged current head.
    /// Fresh source permissions apply to every returned original.
    fn read_run_tail(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RunCaptureTail>;
}
