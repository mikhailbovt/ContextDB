//! Embedded reads of accepted protected routing material under current rights.

use std::collections::BTreeSet;
use std::fmt;

use contextdb_context::router::{
    AuthorizedRouterRequest, RouterManifest, RouterMaterialVerification, RouterPreparedMaterial,
    RouterReplayUnavailableReason, RouterSelectionPlan,
};
use contextdb_context::{OutgoingBase, OutgoingEncoder, TokenCounter};
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
/// or tokenizer/renderer replay; use the separate source-wire verification port.
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

/// Trusted host runtime for an optional detached historical replay.
/// This borrowed integration is never supplied by serialized model input.
#[derive(Clone, Copy, Debug)]
pub struct RouterSourceWireRuntime<'a> {
    /// Exact tokenizer revision expected by the retained compiler profile.
    pub tokenizer: &'a dyn TokenCounter,
    /// Complete outgoing protocol encoder, including non-text charges.
    pub encoder: &'a dyn OutgoingEncoder,
}

/// Independent outcomes for current source bytes and historical computation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum CurrentSourceWireStatus {
    /// This call performed and passed the corresponding check.
    Verified,
    /// The operation lacks supported inputs for this independent check.
    Unavailable(CurrentSourceWireUnavailableReason),
}

/// Missing or unsupported historical computation; current denial is an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum CurrentSourceWireUnavailableReason {
    /// No trusted tokenizer/encoder was supplied.
    MissingRuntime,
    /// The accepted trace does not retain full prepared selector state.
    MissingReplayPreparation,
    /// The detached compiler reports an unsupported replay profile.
    Replay(RouterReplayUnavailableReason),
    /// The reproduced protocol count is a conservative bound.
    NonExactRequestCount,
}

/// Read-only proof for one accepted request in one current native snapshot.
///
/// Every retained trace origin is currently authorized. Only the accepted wire's
/// source spans and stored novel parts are materialized and checked against the
/// actual capture manifest. This does not establish all discarded candidate
/// bytes, a dispatch lease, export rights or permission to train a model.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSourceWireVerification {
    /// Exact native acceptance checked by this call.
    pub receipt: CaptureReceipt,
    /// Accepted compiler/page/wire commitments.
    pub header: RouterTraceHeader,
    /// Digest of the newly reconstructed complete request.
    pub wire_digest: ContentDigest,
    /// Actual reconstructed byte length.
    pub wire_byte_length: u64,
    /// Opaque commitment to this call's current authority, snapshot and custody.
    pub current_authority_binding: ContentDigest,
    /// Current authorization of every retained origin, including discards.
    pub current_custody: CurrentSourceWireStatus,
    /// Exact reconstruction of accepted source spans and stored parts.
    pub source_wire: CurrentSourceWireStatus,
    /// Actual detached replay of retained selection behavior.
    pub historical_selection: CurrentSourceWireStatus,
    /// Exact complete-protocol count, distinct from a conservative bound.
    pub trusted_token_count: CurrentSourceWireStatus,
    /// Present only after an exact complete-protocol count was reproduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_input_tokens: Option<u32>,
}

impl fmt::Debug for CurrentSourceWireVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentSourceWireVerification")
            .field("event_id", &self.receipt.event_id)
            .field("wire_digest", &self.wire_digest)
            .field("wire_byte_length", &self.wire_byte_length)
            .field("source_wire", &self.source_wire)
            .field("historical_selection", &self.historical_selection)
            .field("trusted_token_count", &self.trusted_token_count)
            .finish_non_exhaustive()
    }
}

/// Complete current proof or authorized absence of accepted trace material.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CurrentSourceWireVerificationResult {
    /// Inspect the independent verification columns.
    Complete(Box<CurrentSourceWireVerification>),
    /// The exact accepted occurrence has no usable protected trace.
    Unavailable(AcceptedRouterTraceUnavailable),
}

/// Embedded verification port; it returns commitments, never request plaintext.
pub trait AcceptedRouterSourceWirePort: Send + Sync {
    /// Authorize the exact receipt and whole custody before protected reads,
    /// then reconstruct its actual capture wire under the same shared budget.
    /// An optional trusted runtime additionally requires ModelProcessing and
    /// may replay v2's historical R0 selection and complete protocol count.
    fn verify_accepted_router_source_wire(
        &self,
        request: ReadAcceptedRouterTraceRequest,
        runtime: Option<RouterSourceWireRuntime<'_>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<CurrentSourceWireVerificationResult>;
}
