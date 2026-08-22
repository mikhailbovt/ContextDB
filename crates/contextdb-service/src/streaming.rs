use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{AccessPolicy, AuthenticatedRequestContext, ErrorCode, ServiceError, ServiceResult};

/// Source compression declared by a revision manifest.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// Uncompressed canonical payloads.
    #[default]
    Identity,
    /// Gzip-compressed source transport. The structured reference profile
    /// negotiates this fail-closed until a bounded byte decoder is configured.
    Gzip,
    /// Zstandard-compressed source transport. The structured reference profile
    /// negotiates this fail-closed until a bounded byte decoder is configured.
    Zstd,
}

/// Manifest that opens one immutable source revision snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisionManifest {
    /// Stable logical source identifier.
    pub source_id: String,
    /// Stable source revision identifier.
    pub revision_id: String,
    /// Stable snapshot identifier declared by the source.
    pub snapshot_id: String,
    /// Exact number of following observation frames.
    pub expected_items: u64,
    /// BLAKE3 digest over the ordered canonical observation frames.
    pub ordered_items_digest: String,
    /// Requested source compression. `Identity` executes on the structured v1
    /// surface; non-identity values must be executed by a future bounded byte
    /// transport and otherwise return typed `Unsupported`.
    pub compression: Compression,
    /// Content-free revision attributes.
    pub attributes: BTreeMap<String, String>,
}

/// Observation payload carried inside a resumable snapshot stream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamObservation {
    /// Caller-controlled idempotency key, scoped by actor and operation.
    pub idempotency_key: String,
    /// Stable immutable observation identity.
    pub observation_id: String,
    /// Content-free source metadata.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Exact observation content after declared transport decompression.
    pub content: serde_json::Value,
    /// Policy envelope stored separately from erasable content.
    pub access: AccessPolicy,
}

/// Explicit end marker required before a source revision becomes current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotComplete {
    /// Must equal the opening manifest snapshot identifier.
    pub snapshot_id: String,
    /// Must equal the manifest count and accepted frame count.
    pub item_count: u64,
    /// Must equal the manifest and computed ordered digest.
    pub ordered_items_digest: String,
}

/// One ordered frame in a resumable source-revision ingestion stream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum IngestFrameValue {
    /// Opens the stream and declares its complete immutable source revision.
    Manifest(SourceRevisionManifest),
    /// One ordered observation.
    Observation(StreamObservation),
    /// Explicitly closes and atomically publishes the source revision marker.
    SnapshotComplete(SnapshotComplete),
}

/// Authenticated, cursor-bound streaming ingestion frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestFrame {
    /// Fully attributed caller and authentication evidence.
    pub context: AuthenticatedRequestContext,
    /// Stable client-selected stream identity.
    pub stream_id: String,
    /// Zero-based stream position. Manifest is zero.
    pub position: u64,
    /// Cursor returned by the preceding partial acknowledgement.
    pub resume_cursor: Option<String>,
    /// Typed frame payload.
    pub value: IngestFrameValue,
}

/// Durable disposition of one accepted stream frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestDisposition {
    /// Frame is durably buffered but the source revision is not current.
    Accepted,
    /// Exact earlier frame was replayed without duplicate effects.
    Replayed,
    /// Explicit completion marker committed the whole source revision.
    SnapshotCommitted,
}

/// Per-frame partial acknowledgement with a resumable authenticated cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestAck {
    /// Stable stream identity.
    pub stream_id: String,
    /// Acknowledged input position.
    pub position: u64,
    /// Durable frame outcome.
    pub disposition: IngestDisposition,
    /// Digest of the exact canonical frame.
    pub frame_digest: String,
    /// Cursor required for the next position or retry.
    pub resume_cursor: String,
    /// Final database commit sequence after completion.
    pub commit_seq: Option<u64>,
    /// Stable observation references already committed by completion.
    pub partial_result_refs: Vec<String>,
    /// Host-controlled absolute Unix-epoch lease deadline in milliseconds.
    ///
    /// `Some` means the buffered, incomplete stream is resumable only before
    /// this instant. An exact retry after the deadline returns
    /// [`ErrorCode::SnapshotExpired`]. `None` means that this service profile
    /// does not advertise a finite staging lease, and is always used for a
    /// completed snapshot acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_ms: Option<u64>,
}

/// Returns the stable, payload-free outcome for a stream whose advertised
/// staging lease has expired.
///
/// Durable implementations use this only after authenticating the caller and
/// matching a retained stream tombstone. The tombstone, rather than this
/// helper, is responsible for permanently preventing stale stream-ID reuse.
#[must_use]
pub fn stream_lease_expired_error() -> ServiceError {
    ServiceError::new(
        ErrorCode::SnapshotExpired,
        "source snapshot staging lease expired",
        false,
    )
    .with_context(
        Vec::new(),
        Some("stream_lease_expired".to_owned()),
        Some("open a new source stream with a new stream ID".to_owned()),
        None,
    )
}

/// Computes the manifest digest over ordered canonical observation frames.
pub fn ordered_items_digest(items: &[StreamObservation]) -> ServiceResult<String> {
    let bytes = serde_json::to_vec(items).map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "stream observation serialization failed",
            false,
        )
    })?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
