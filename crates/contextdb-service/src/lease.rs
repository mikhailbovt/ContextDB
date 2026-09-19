//! Owner-registered context subscriptions and immediate dispatch checks.

use contextdb_continuity::PendingToolInvocation;
use contextdb_core::{ContentDigest, ModelCallId, TimestampMicros};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::{AuthenticatedRequestContext, CaptureReceipt, PreparedContext, ServiceResult};

/// Opaque short-lived owner registration. It retains dependencies, not a physical snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLease {
    /// Unpredictable process-bound registration identity.
    pub token: String,
    /// Earliest known wall-clock applicability or consent boundary.
    pub valid_until: TimestampMicros,
}

/// Coalesced subscription status; it never substitutes for dispatch validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextLeaseStatus {
    /// Registered epochs, current policy and both clocks still match.
    Current,
    /// Some subscribed scope or source permission changed, including negative state.
    Invalidated,
    /// Deadline, explicit release or owner restart ended the registration.
    Expired,
}

/// Trusted host effect classification, independent of a model's proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolAdmissionClass {
    /// The built-in bounded original-context expansion, with no external effect.
    MemoryExpansion,
    /// A registered external target; unresolved interpretation blocks admission.
    ExternalEffect,
}

/// Native publication authority owns comparison and subscription registration.
/// A successful check is local admission, not an atomic remote transaction.
pub trait ContextLeasePort: Send + Sync {
    /// Atomically compare the owner-sealed preparation and register dependencies.
    fn register_context_lease(
        &self,
        context: &AuthenticatedRequestContext,
        prepared: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ContextLease>;
    /// Poll a bounded coalesced epoch subscription under current authorization.
    fn context_lease_status(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ContextLeaseStatus>;
    /// Release resident dependency state; no captured original is erased.
    fn release_context_lease(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;
    /// Validate the registered full wire and current run head immediately before handoff.
    fn admit_model(
        &self,
        context: &AuthenticatedRequestContext,
        lease: &ContextLease,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;
    /// Recheck the proposal's admitted decision context and exact action at dispatch.
    fn admit_tool(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        planned: &PendingToolInvocation,
        action_digest: ContentDigest,
        class: ToolAdmissionClass,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()>;
}
