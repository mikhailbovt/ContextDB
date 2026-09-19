//! Raw history recall remains distinct from semantic publication and resolution.

use contextdb_core::{
    ContentDigest, ObservationId, OriginalSourceSpan, RawFilter, RawSource, RawTextQuery,
};
use serde::{Deserialize, Serialize};

use crate::{AuthenticatedRequestContext, CaptureReceipt, PayloadPort, ServiceResult};

/// Explicit finite work allowance. A bounded page is not an exhaustive top-k.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecallBudget {
    /// Maximum source routing rows inspected on one page.
    pub max_records: u32,
    /// Maximum original bytes inspected for lexical matching on one page.
    pub max_payload_bytes: u64,
}

impl Default for RawRecallBudget {
    fn default() -> Self {
        Self {
            max_records: 1024,
            max_payload_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Exhaustive raw-source selection, resumed using a bound cursor.
/// Timeline traversal follows capture order; explicit ID sets follow ID order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecallRequest {
    /// Current host-established authority.
    pub context: AuthenticatedRequestContext,
    /// Source metadata predicates.
    pub filter: RawFilter,
    /// Optional exact/lexical predicate. No embeddings are required.
    pub text: Option<RawTextQuery>,
    /// Optional workspace logical knowledge position, never a physical snapshot.
    pub known_at: Option<u64>,
    /// Optional native read-your-writes fence.
    pub after_receipt: Option<CaptureReceipt>,
    /// At most 256 sources per page.
    pub page_size: u32,
    /// Per-page work and materialization allowance.
    pub budget: RawRecallBudget,
    /// Opaque authenticated continuation; omission starts a fresh selection.
    pub continuation: Option<String>,
}

/// Attributed source and verified lexical occurrence spans, without inferred truth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecallHit {
    /// Immutable source metadata and explicit completeness/omission status.
    pub source: RawSource,
    /// One original-byte match per term, or one exact phrase; empty for range recall.
    pub matches: Vec<OriginalSourceSpan>,
}

/// Why a page stopped. Only `Complete` establishes exhaustive selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPageStatus {
    /// All matching sources at the fixed knowledge position were visited.
    Complete,
    /// More sources may match after this page.
    PageLimit,
    /// Work allowance exhausted; resume instead of interpreting absence as no match.
    WorkLimit,
    /// Original-byte allowance exhausted; resume or enlarge the explicit allowance.
    ByteLimit,
}

/// Raw sources in stable traversal order. No global archive counts are disclosed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecallPage {
    /// Authorized source hits.
    pub hits: Vec<RawRecallHit>,
    /// Completion or explicit partial-work status.
    pub status: RawPageStatus,
    /// Logical selection identity, opaque to consumers.
    pub snapshot: String,
    /// Present unless selection completed.
    pub continuation: Option<String>,
}

/// Mint an exact source-span reference while reading its bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializeOriginalRequest {
    /// Current authenticated authority, checked again at materialization.
    pub context: AuthenticatedRequestContext,
    /// Immutable source event.
    pub event_id: ObservationId,
    /// Expected payload version from discovery or the native capture receipt.
    pub payload_digest: ContentDigest,
    /// Inclusive original byte offset.
    pub start: u64,
    /// Exclusive original byte offset; at most 1 MiB per response.
    pub end: u64,
}

/// Exact returned bytes plus source attribution and a verifiable span.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedOriginal {
    /// Completeness and attribution of the whole original observation.
    pub source: RawSource,
    /// Exact returned range and its digest.
    pub span: OriginalSourceSpan,
    /// Original bytes; never reconstructed from an assertion or summary.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for MaterializedOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaterializedOriginal")
            .field("source", &self.source)
            .field("span", &self.span)
            .field("byte_length", &self.bytes.len())
            .finish()
    }
}

/// Authenticated host interface for original history, independent of promotion.
pub trait RawRecallPort: PayloadPort {
    /// Exhaustive paged raw retrieval with explicit incomplete-work status.
    fn recall_originals(&self, request: RawRecallRequest) -> ServiceResult<RawRecallPage>;
    /// Rechecks current source permissions before materializing immutable bytes.
    fn materialize_original(
        &self,
        request: MaterializeOriginalRequest,
    ) -> ServiceResult<MaterializedOriginal>;
}
