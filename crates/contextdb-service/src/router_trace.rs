//! Embedded reads of accepted protected routing material under current rights.

use std::collections::BTreeSet;
use std::fmt;

use contextdb_context::OutgoingBase;
use contextdb_context::router::{
    AuthorizedRouterRequest, RouterManifest, RouterMaterialVerification, RouterPreparedMaterial,
    RouterSelectionPlan,
};
use contextdb_core::{ContentDigest, ObservationId, RouterTraceHeader};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::{AuthenticatedRequestContext, CaptureReceipt, ServiceResult};

/// Current authenticated read of one exact owner-issued capture receipt.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAcceptedRouterTraceRequest {
    /// Actual caller and purpose; ordinary reading does not grant training use.
    pub context: AuthenticatedRequestContext,
    /// Exact synchronized acceptance, including its owner token and domain.
    pub receipt: CaptureReceipt,
}

impl fmt::Debug for ReadAcceptedRouterTraceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadAcceptedRouterTraceRequest")
            .field("event_id", &self.receipt.event_id)
            .field("workspace_commit", &self.receipt.workspace_commit)
            .finish_non_exhaustive()
    }
}

/// Opaque protected origin references, never serialized authorization grants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRouterTraceLineage {
    /// Every captured original in the native origin closure, including discards.
    pub originals: BTreeSet<ObservationId>,
    /// Native commitments to exact registered generic record controls.
    pub record_versions: BTreeSet<ContentDigest>,
    /// Native commitments to exact historical state controls.
    pub state_versions: BTreeSet<ContentDigest>,
    /// Commitment to the whole retained transitive custody closure.
    /// The direct accepted envelope commitment remains in the trace header.
    pub custody_closure_digest: ContentDigest,
}

/// Complete accepted material read; selection replay remains separately reported.
///
/// The native owner authorized all dependencies at this call's latest snapshot.
/// This result is not a lease, cached grant, export admission or training approval.
/// Its accepted wire commitment does not establish a new source-wire materialization
/// or tokenizer/renderer replay; those are separate consumers of the original read port.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRouterTraceRead {
    /// Exact owner-issued acceptance of the enclosing model request occurrence.
    pub receipt: CaptureReceipt,
    /// Accepted page and compiler commitments, without duplicating page text.
    pub header: RouterTraceHeader,
    /// Frozen compiler request and complete admitted unit/support inventory.
    pub request: AuthorizedRouterRequest,
    /// Actual retained score evaluations and selected proposal.
    pub plan: RouterSelectionPlan,
    /// Compiler manifest for the accepted complete reader wire.
    pub manifest: RouterManifest,
    /// Ordered query-time control, working, hot and current material.
    pub base: OutgoingBase,
    /// Retained prepared candidates and every support alternative's evidence.
    pub material: RouterPreparedMaterial,
    /// Independent compiler material and historical replay availability columns.
    pub verification: RouterMaterialVerification,
    /// Protected all-candidate lineage references; no authority labels are exposed.
    pub lineage: AcceptedRouterTraceLineage,
    /// V2's accepted behavior observations. Reading these does not execute R0,
    /// verify historical selection or admit export/training use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_observation: Option<contextdb_context::router::RouterReplayObservation>,
}

impl fmt::Debug for AcceptedRouterTraceRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptedRouterTraceRead")
            .field("event_id", &self.receipt.event_id)
            .field("workspace_commit", &self.receipt.workspace_commit)
            .field("trace_digest", &self.header.trace_digest)
            .field("byte_length", &self.header.byte_length)
            .field("candidate_count", &self.request.units.len())
            .field("original_count", &self.lineage.originals.len())
            .finish_non_exhaustive()
    }
}

/// Authorized absence of usable protected material, distinct from denial/error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedRouterTraceUnavailable {
    /// The accepted occurrence predates tracing or explicitly used the Off profile.
    LegacyOff,
    /// Authorized retained history proves legitimate removal of the original body.
    Pruned,
    /// An accepted material profile has no supported compiler projection.
    UnsupportedMaterialProfile,
}

/// Current owner-authorized accepted material, or explicit authorized absence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AcceptedRouterTraceReadResult {
    /// Complete accepted bytes were read; inspect the separate replay columns.
    Complete(Box<AcceptedRouterTraceRead>),
    /// No current material was fabricated or rediscovered to fill this absence.
    Unavailable(AcceptedRouterTraceUnavailable),
}

/// Read-only embedded host port; transports do not acquire it implicitly.
pub trait AcceptedRouterTracePort: Send + Sync {
    /// Resolve one exact receipt and materialize its complete protected trace.
    ///
    /// Authentication, current whole-custody rights, receipt and native history
    /// precede protected body materialization in one latest snapshot. The caller
    /// supplies the enclosing cancellation/work/byte/deadline allowance.
    fn read_accepted_router_trace(
        &self,
        request: ReadAcceptedRouterTraceRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AcceptedRouterTraceReadResult>;
}
