//! Authenticated host capture port, separate from model-proposed semantic memory.

use serde::{Deserialize, Serialize};

use crate::{AuthenticatedRequestContext, ServiceResult};
use contextdb_core::{ContentDigest, EventEnvelope, ObservationId, StreamId, WorkspaceId};

/// Receipt domain of the native continuous capture owner.
pub const NATIVE_CAPTURE_DOMAIN: &str = "contextdb.native-capture/v1";

/// Synchronized durability promised by this capture port.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDurability {
    /// A synchronized native transaction contains all acknowledged data.
    Sync,
}

/// Domain-bound receipt. The token is verified by the owner, not trusted as input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceipt {
    /// Exact publication domain, distinct from legacy chat and physical storage.
    pub domain: String,
    /// Native database identity.
    pub database_id: String,
    /// Workspace whose logical sequence is represented.
    pub workspace_id: WorkspaceId,
    /// Immutable accepted event identity.
    pub event_id: ObservationId,
    /// Workspace-local logical position, never a physical snapshot handle.
    pub workspace_commit: u64,
    /// BLAKE3 of the complete accepted event envelope.
    pub event_digest: ContentDigest,
    /// Verified original bytes, or absent for explicitly omitted payloads.
    pub payload_digest: Option<ContentDigest>,
    /// Acknowledged durability.
    pub durability: CaptureDurability,
    /// Owner-authenticated binding of all receipt fields.
    pub token: String,
}

/// Per-call publication result; this flag is not part of the durable receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureAcceptance {
    /// Durable publication identity, identical for exact retries.
    pub receipt: CaptureReceipt,
    /// True only for the invocation that first committed this event.
    pub newly_accepted: bool,
}

/// Host append request. Authentication precedes event inspection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    /// Authority established by the host adapter, never by the event body.
    pub context: AuthenticatedRequestContext,
    /// Retry identity scoped to the authenticated producer.
    pub idempotency_key: String,
    /// Exact observed event.
    pub event: EventEnvelope,
}

/// Read an accepted event under current authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOriginalRequest {
    /// Current authenticated reader.
    pub context: AuthenticatedRequestContext,
    /// Exact source identity.
    pub event_id: ObservationId,
    /// Optional read-your-writes fence.
    pub after_receipt: Option<CaptureReceipt>,
}

/// Original event and its verified receipt; omission/partial status remains explicit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedOriginal {
    /// Exact stored envelope, including original payload bytes.
    pub event: EventEnvelope,
    /// Durable publication receipt.
    pub receipt: CaptureReceipt,
}

/// Missing inclusive producer sequence range.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureGapRange {
    /// First missing sequence.
    pub from: u64,
    /// Last missing sequence.
    pub through: u64,
}

/// Producer capture coverage. A head alone does not prove completeness.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerCoverage {
    /// Highest observed sequence.
    pub head: u64,
    /// Accepted contiguous prefix.
    pub contiguous_through: u64,
    /// Bounded, ordered missing ranges.
    pub gaps: Vec<CaptureGapRange>,
}

/// Sole capture/publication owner used by host adapters.
///
/// This is an embedded authenticated-host interface. Exposing it to an
/// untrusted transport requires that transport's verified adapter authority;
/// model-facing memory proposal tools do not acquire this port implicitly.
pub trait CapturePort: Send + Sync {
    /// Atomically accept the original, receipt, producer coverage and projection work.
    fn append_event(&self, request: CaptureRequest) -> ServiceResult<CaptureReceipt> {
        self.append_event_with_status(request)
            .map(|accepted| accepted.receipt)
    }

    /// Distinguish first publication from retry atomically at the owner.
    fn append_event_with_status(&self, request: CaptureRequest)
    -> ServiceResult<CaptureAcceptance>;

    /// Fetch exact accepted bytes without extraction, embeddings or promotion.
    fn read_original(&self, request: ReadOriginalRequest) -> ServiceResult<CapturedOriginal>;

    /// Verify a native receipt and its durable read fence under current permissions.
    fn resolve_capture_receipt(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &CaptureReceipt,
    ) -> ServiceResult<()>;

    /// Read the current capture coverage of one authenticated producer stream.
    fn producer_coverage(
        &self,
        context: &AuthenticatedRequestContext,
        producer: StreamId,
    ) -> ServiceResult<ProducerCoverage>;
}

/// Host staging request for a large immutable original.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagePayloadRequest {
    /// Authenticated custody authority.
    pub context: AuthenticatedRequestContext,
    /// Stable retry identity, reused through recovery.
    pub idempotency_key: String,
    /// Immutable content block identity selected by the host.
    pub block_id: contextdb_core::ContentBlockId,
    /// Full observed source bytes, subject to the advertised capture bound.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for StagePayloadRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagePayloadRequest")
            .field("block_id", &self.block_id)
            .field("byte_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Durable staging receipt, explicitly separate from event publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadReceipt {
    /// Native database identity.
    pub database_id: String,
    /// Policy-bound immutable reference.
    pub reference: contextdb_core::OriginalPayloadRef,
    /// Synchronized staging durability; an event still needs its capture receipt.
    pub durability: CaptureDurability,
}

/// Bounded original staging and source-span materialization for host adapters.
pub trait PayloadPort: CapturePort {
    /// Synchronize a complete large original before any event can reference it.
    fn stage_payload(&self, request: StagePayloadRequest) -> ServiceResult<PayloadReceipt>;

    /// Read an exact immutable source span under its current source permissions.
    fn read_original_span(
        &self,
        context: &AuthenticatedRequestContext,
        span: &contextdb_core::OriginalSourceSpan,
    ) -> ServiceResult<Vec<u8>>;
}
