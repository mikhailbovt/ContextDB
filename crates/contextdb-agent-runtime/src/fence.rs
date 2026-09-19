//! The embedded native admission adapter. The final remote handoff is outside the
//! database lock; external atomicity requires the registered target's CAS contract.

use contextdb_capture::ToolAction;
use contextdb_continuity::PendingToolInvocation;
use contextdb_core::{ContentDigest, ModelCallId};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, CaptureReceipt, ContextLeasePort, PreparedContext, ServiceResult,
    ToolAdmissionClass,
};
use std::sync::Arc;

use crate::{ModelDispatchFence, ToolDispatchFence, invalid};

/// Required checks executed by the same owner that publishes original and state revisions.
pub struct OwnerDispatchFence<S: ?Sized> {
    owner: Arc<S>,
}
impl<S: ?Sized> std::fmt::Debug for OwnerDispatchFence<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerDispatchFence").finish_non_exhaustive()
    }
}
impl<S: ContextLeasePort + ?Sized> OwnerDispatchFence<S> {
    /// Use the owned runtime's publication authority, never a separate watcher.
    pub fn new(owner: Arc<S>) -> Self {
        Self { owner }
    }
}
impl<S: ContextLeasePort + ?Sized> ModelDispatchFence for OwnerDispatchFence<S> {
    fn before_model(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        prepared: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let lease = self
            .owner
            .register_context_lease(context, prepared, budget)?;
        if let Err(error) = self
            .owner
            .admit_model(context, &lease, checkpoint, call, request, budget)
        {
            let _ = self.owner.release_context_lease(context, &lease, budget);
            return Err(error);
        }
        Ok(())
    }
}
impl<S: ContextLeasePort + ?Sized> ToolDispatchFence for OwnerDispatchFence<S> {
    fn before_tool(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        planned: &PendingToolInvocation,
        action: &ToolAction,
        class: ToolAdmissionClass,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let bytes =
            serde_json::to_vec(action).map_err(|_| invalid("tool admission encoding failed"))?;
        crate::charge(budget, 1, bytes.len() as u64)?;
        let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
        self.owner
            .admit_tool(context, checkpoint, planned, digest, class, budget)
    }
}
