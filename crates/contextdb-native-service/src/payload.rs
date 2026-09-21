//! Bounded durable originals and exact request replay on the native owner.

use std::collections::BTreeSet;

use contextdb_core::{
    ContentBlockId, ContentDigest, EventEnvelope, EventKind, EventPayload, OriginalPayloadRef,
    OriginalSourceSpan, RequestPart,
};
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, Capability, CaptureDurability, ErrorCode,
    PayloadPort, PayloadReceipt, ServiceError, ServiceResult, StagePayloadRequest,
};
use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use serde::{Deserialize, Serialize};

use super::{
    META_MANIFEST_KEY, Manifest, NativeService, canonical_digest, decode, encode, exhausted,
    integrity, invalid, manifest_checksum, not_found, permission_denied, policy_allows,
    request_context_binding, require_capability, require_sync, storage_error,
    trusted_structured_policy, validate_access, validate_identifier,
};

pub(super) const SOURCE_FEATURE: &str = "continuous-sources-v1";
pub(super) const REQUEST_TRANSFORM_FEATURE: &str = "continuous-request-transforms-v1";
pub(super) const MODEL_PROTOCOL_FEATURE: &str = "continuous-model-protocol-v1";
/// Maximum complete staged original or reconstructed request.
pub const CAPTURE_MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
/// Maximum ordered segments in one request occurrence.
pub const CAPTURE_MAX_REQUEST_PARTS: usize = 512;
const CHUNK_BYTES: usize = 256 * 1024;

pub(crate) mod keys;
mod pruning;
pub use keys::NativePayloadKeyInventory;
pub use pruning::NativePayloadPruningProgress;
pub(super) use pruning::{PAYLOAD_PRUNING_FEATURE, PayloadPruningPublication};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadHeader {
    version: u16,
    reference: OriginalPayloadRef,
    access: AccessPolicy,
    chunks: u32,
    chunk_digests: Vec<ContentDigest>,
    accepted_global_commit: u64,
    idempotency_digest: String,
}

impl PayloadPort for NativeService {
    fn stage_payload(&self, request: StagePayloadRequest) -> ServiceResult<PayloadReceipt> {
        require_capability(&request.context, Capability::Observe)?;
        validate_identifier(&request.idempotency_key, "payload idempotency key")?;
        if request.bytes.len() > CAPTURE_MAX_PAYLOAD_BYTES {
            return Err(exhausted(
                "original exceeds the 64 MiB staged payload limit",
            ));
        }
        let chunk_digests = request
            .bytes
            .chunks(CHUNK_BYTES)
            .map(raw_digest)
            .collect::<Vec<_>>();
        let byte_length =
            u64::try_from(request.bytes.len()).map_err(|_| exhausted("payload length overflow"))?;
        let reference = OriginalPayloadRef {
            block_id: request.block_id,
            digest: raw_digest(&request.bytes),
            byte_length,
            manifest_digest: chunk_manifest_digest(byte_length, &chunk_digests)?,
        };
        let binding = request_context_binding(&request.context.request)?;
        let identity = canonical_digest(&(
            SOURCE_FEATURE,
            &binding,
            &request.context.actor_id,
            &request.context.agent_id,
            &request.idempotency_key,
        ))?;
        let digest = canonical_digest(&(
            &reference,
            &binding,
            &request.context.actor_id,
            &request.context.agent_id,
        ))?;
        let _guard = self.lock_writes()?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if let Some(receipt) =
            self.replay::<PayloadReceipt, _>(&tx, identity.as_bytes(), "stage_payload", &digest)?
        {
            self.authorized_payload_header(&tx, &request.context, &reference)?;
            return Ok(receipt);
        }
        if tx
            .get(&self.keyspaces.continuous, &header_key(reference.block_id))
            .map_err(storage_error)?
            .is_some()
        {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "payload identity was already staged; reuse its original retry key",
                false,
            ));
        }
        self.enable_source_format(&mut tx)?;
        let frame = self.begin_frame(&tx, &request.context.request.workspace_id, false)?;
        let access = trusted_structured_policy(&request.context.request);
        validate_access(&access)?;
        let chunks = u32::try_from(request.bytes.len().div_ceil(CHUNK_BYTES))
            .map_err(|_| exhausted("payload chunk count overflow"))?;
        let header = PayloadHeader {
            version: 1,
            reference: reference.clone(),
            access,
            chunks,
            chunk_digests,
            accepted_global_commit: frame.global_commit,
            idempotency_digest: identity.clone(),
        };
        for (index, bytes) in request.bytes.chunks(CHUNK_BYTES).enumerate() {
            tx.put(
                &self.keyspaces.continuous,
                chunk_key(
                    reference.block_id,
                    u32::try_from(index)
                        .map_err(|_| exhausted("payload chunk ordinal overflow"))?,
                ),
                bytes.to_vec(),
            )
            .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            header_key(reference.block_id),
            encode(&header)?,
        )
        .map_err(storage_error)?;
        let receipt = PayloadReceipt {
            database_id: self.database_id.clone(),
            reference,
            durability: CaptureDurability::Sync,
        };
        self.finish_frame(
            &mut tx,
            &frame,
            "stage_payload",
            identity.as_bytes(),
            &digest,
            &receipt,
        )?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }

    fn read_original_span(
        &self,
        context: &AuthenticatedRequestContext,
        span: &OriginalSourceSpan,
    ) -> ServiceResult<Vec<u8>> {
        require_capability(context, Capability::ReadEvidence)?;
        require_capability(context, Capability::RawEvidence)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.source_span(&snapshot, Some(context), span, false)
    }
}

impl NativeService {
    /// The caller authorizes the event and its complete dependency closure first.
    pub(super) fn original_range<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        event: &EventEnvelope,
        start: u64,
        end: u64,
    ) -> ServiceResult<Vec<u8>> {
        self.original_range_with_policy(snapshot, Some(context), event, start, end)
    }

    /// Internal custody maintenance only; never an untrusted materialization port.
    pub(super) fn original_range_for_custody<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        start: u64,
        end: u64,
    ) -> ServiceResult<Vec<u8>> {
        self.original_range_with_policy(snapshot, None, event, start, end)
    }

    fn original_range_with_policy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        event: &EventEnvelope,
        start: u64,
        end: u64,
    ) -> ServiceResult<Vec<u8>> {
        match &event.payload {
            EventPayload::InlineUtf8 { text, .. } => {
                Ok(text.as_bytes()[source_range(start, end, text.len())?].to_vec())
            }
            EventPayload::InlineBytes { bytes, .. } => {
                Ok(bytes[source_range(start, end, bytes.len())?].to_vec())
            }
            EventPayload::Staged { reference, .. } => {
                let header = self.checked_payload_header(snapshot, context, reference)?;
                self.payload_range(snapshot, &header, start, end)
            }
            EventPayload::Assembly { manifest } => {
                let bytes = self.assemble_request(snapshot, context, manifest)?;
                Ok(bytes[source_range(start, end, bytes.len())?].to_vec())
            }
            EventPayload::Omitted { .. } => Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "original bytes are explicitly unavailable",
                false,
            )),
        }
    }

    pub(super) fn payload_index_policy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        reference: &OriginalPayloadRef,
    ) -> ServiceResult<AccessPolicy> {
        Ok(self
            .checked_payload_header(snapshot, None, reference)?
            .access)
    }

    pub(super) fn enable_source_format<T: WriteTransaction>(
        &self,
        tx: &mut T,
    ) -> ServiceResult<()> {
        self.enable_capture_format(tx)?;
        let mut manifest: Manifest = decode(
            &tx.get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if manifest.features.insert(SOURCE_FEATURE.into()) {
            manifest.checksum = manifest_checksum(&manifest)?;
            tx.put(
                &self.keyspaces.meta,
                META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(super) fn enable_request_transform_format<T: WriteTransaction>(
        &self,
        tx: &mut T,
    ) -> ServiceResult<()> {
        let mut manifest: Manifest = decode(
            &tx.get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if manifest.features.insert(REQUEST_TRANSFORM_FEATURE.into()) {
            manifest.checksum = manifest_checksum(&manifest)?;
            tx.put(
                &self.keyspaces.meta,
                META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(super) fn validate_capture_sources<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        event: &EventEnvelope,
    ) -> ServiceResult<()> {
        match &event.provenance {
            Some(contextdb_core::EventProvenance::ModelOutput {
                request_event_id, ..
            }) => {
                self.authorized_capture_policy(snapshot, context, *request_event_id)?;
                self.authorize_capture_dependencies(snapshot, context, *request_event_id)?;
                self.validate_model_output_origin(snapshot, event)?;
            }
            Some(contextdb_core::EventProvenance::Tool {
                call_id,
                request_event_id,
                action_digest,
            }) if event.kind != EventKind::ToolRequested => {
                self.authorized_capture_policy(snapshot, context, *request_event_id)?;
                self.authorize_capture_dependencies(snapshot, context, *request_event_id)?;
                let intent = self.load_captured_original(snapshot, *request_event_id)?;
                if intent.event.kind != EventKind::ToolRequested
                    || intent.event.provenance.as_ref()
                        != Some(&contextdb_core::EventProvenance::Tool {
                            call_id: *call_id,
                            request_event_id: *request_event_id,
                            action_digest: *action_digest,
                        })
                    || intent.event.run_id != event.run_id
                    || intent.event.task_id != event.task_id
                {
                    return Err(invalid("tool outcome belongs to another action or task"));
                }
            }
            Some(contextdb_core::EventProvenance::Artifact {
                artifact_id,
                base_digest,
                ..
            }) if event.supersedes_event_id.is_some() => {
                let previous = event
                    .supersedes_event_id
                    .ok_or_else(|| invalid("artifact predecessor absent"))?;
                self.authorized_capture_policy(snapshot, context, previous)?;
                let previous = self.load_captured_original(snapshot, previous)?;
                if previous.event.payload.digest() != *base_digest
                    || !matches!(previous.event.provenance, Some(contextdb_core::EventProvenance::Artifact { artifact_id: old_id, .. }) if old_id == *artifact_id)
                {
                    return Err(invalid(
                        "artifact base differs from the observed predecessor",
                    ));
                }
            }
            _ => {}
        }
        match &event.payload {
            EventPayload::Staged { reference, .. } => {
                let header = self.authorized_payload_header(snapshot, context, reference)?;
                self.payload_bytes(snapshot, &header)?;
            }
            EventPayload::Assembly { manifest } => {
                if event.kind != EventKind::ModelRequested || event.upstream_truncated {
                    return Err(invalid(
                        "request manifest requires a complete observed model request",
                    ));
                }
                let bytes = self.assemble_request(snapshot, Some(context), manifest)?;
                if raw_digest(&bytes) != manifest.wire_digest {
                    return Err(invalid(
                        "request manifest wire digest differs from its ordered bytes",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn authorized_payload_header<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        reference: &OriginalPayloadRef,
    ) -> ServiceResult<PayloadHeader> {
        self.require_suppression_current(
            snapshot,
            &super::digest_bytes(context.request.workspace_id.as_bytes()),
        )?;
        let header = self.payload_header(snapshot, reference.block_id)?;
        self.require_payload_unpruned(snapshot, reference.block_id)?;
        if !policy_allows(&context.request, &header.access) {
            return Err(permission_denied());
        }
        if &header.reference != reference {
            return Err(invalid(
                "payload reference differs from the durable original",
            ));
        }
        Ok(header)
    }

    fn payload_header<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ContentBlockId,
    ) -> ServiceResult<PayloadHeader> {
        let header: PayloadHeader = decode(
            &snapshot
                .get(&self.keyspaces.continuous, &header_key(id))
                .map_err(storage_error)?
                .ok_or_else(not_found)?,
            "payload header",
        )?;
        validate_access(&header.access)?;
        let length = usize::try_from(header.reference.byte_length)
            .map_err(|_| integrity("payload length overflow"))?;
        if header.version != 1
            || header.reference.block_id != id
            || length > CAPTURE_MAX_PAYLOAD_BYTES
            || usize::try_from(header.chunks).map_err(|_| integrity("payload chunks overflow"))?
                != length.div_ceil(CHUNK_BYTES)
            || header.accepted_global_commit == 0
            || header.chunk_digests.len() != length.div_ceil(CHUNK_BYTES)
            || header.reference.manifest_digest
                != chunk_manifest_digest(header.reference.byte_length, &header.chunk_digests)?
        {
            return Err(integrity("payload header is invalid"));
        }
        Ok(header)
    }

    fn payload_bytes<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        header: &PayloadHeader,
    ) -> ServiceResult<Vec<u8>> {
        self.require_payload_unpruned(snapshot, header.reference.block_id)?;
        let length = usize::try_from(header.reference.byte_length)
            .map_err(|_| integrity("payload length overflow"))?;
        let mut bytes = Vec::with_capacity(length);
        for index in 0..header.chunks {
            let chunk = snapshot
                .get(
                    &self.keyspaces.continuous,
                    &chunk_key(header.reference.block_id, index),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("durable payload chunk is absent"))?;
            if chunk.len() != CHUNK_BYTES.min(length - bytes.len())
                || raw_digest(&chunk)
                    != header.chunk_digests
                        [usize::try_from(index).map_err(|_| integrity("chunk ordinal overflow"))?]
            {
                return Err(integrity("payload chunk length is invalid"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if raw_digest(&bytes) != header.reference.digest {
            return Err(integrity("staged original digest is invalid"));
        }
        Ok(bytes)
    }

    fn payload_range<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        header: &PayloadHeader,
        start: u64,
        end: u64,
    ) -> ServiceResult<Vec<u8>> {
        self.require_payload_unpruned(snapshot, header.reference.block_id)?;
        let length = usize::try_from(header.reference.byte_length)
            .map_err(|_| integrity("payload length overflow"))?;
        let range = source_range(start, end, length)?;
        let mut bytes = Vec::with_capacity(range.len());
        if range.is_empty() {
            return Ok(bytes);
        }
        for index in (range.start / CHUNK_BYTES)..range.end.div_ceil(CHUNK_BYTES) {
            let chunk = snapshot
                .get(
                    &self.keyspaces.continuous,
                    &chunk_key(
                        header.reference.block_id,
                        u32::try_from(index).map_err(|_| integrity("chunk ordinal overflow"))?,
                    ),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("source chunk is absent"))?;
            let offset = index * CHUNK_BYTES;
            if chunk.len() != CHUNK_BYTES.min(length - offset)
                || raw_digest(&chunk) != header.chunk_digests[index]
            {
                return Err(integrity("source chunk binding is invalid"));
            }
            bytes.extend_from_slice(
                &chunk[range.start.saturating_sub(offset)..(range.end - offset).min(chunk.len())],
            );
        }
        Ok(bytes)
    }

    pub(super) fn source_span<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        span: &OriginalSourceSpan,
        independent_root: bool,
    ) -> ServiceResult<Vec<u8>> {
        if let Some(context) = context {
            self.authorized_capture_policy(snapshot, context, span.event_id)?;
            self.authorize_capture_dependencies(snapshot, context, span.event_id)?;
        }
        let original = self.load_captured_original(snapshot, span.event_id)?;
        if independent_root
            && (original.event.kind == EventKind::ModelRequested
                || matches!(original.event.payload, EventPayload::Assembly { .. }))
        {
            return Err(invalid(
                "model request echo cannot become an independent source root",
            ));
        }
        if matches!(original.event.payload, EventPayload::Omitted { .. }) {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "original source bytes are explicitly unavailable",
                false,
            ));
        }
        if original.event.payload.digest() != Some(span.payload_digest) {
            return Err(invalid("source payload digest mismatch"));
        }
        let selected = match &original.event.payload {
            EventPayload::InlineUtf8 { text, .. } => {
                text.as_bytes()[source_range(span.start, span.end, text.len())?].to_vec()
            }
            EventPayload::InlineBytes { bytes, .. } => {
                bytes[source_range(span.start, span.end, bytes.len())?].to_vec()
            }
            EventPayload::Staged { reference, .. } => {
                let header = self.checked_payload_header(snapshot, context, reference)?;
                self.payload_range(snapshot, &header, span.start, span.end)?
            }
            EventPayload::Assembly { manifest } => {
                let bytes = self.assemble_request(snapshot, context, manifest)?;
                bytes[source_range(span.start, span.end, bytes.len())?].to_vec()
            }
            EventPayload::Omitted { .. } => {
                return Err(ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "original source bytes are explicitly unavailable",
                    false,
                ));
            }
        };
        if raw_digest(&selected) != span.span_digest {
            return Err(invalid("source span digest mismatch"));
        }
        Ok(selected)
    }

    fn assemble_request<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        manifest: &contextdb_core::ModelRequestManifest,
    ) -> ServiceResult<Vec<u8>> {
        validate_identifier(&manifest.renderer, "request renderer")?;
        let length = usize::try_from(manifest.byte_length)
            .map_err(|_| exhausted("request length overflow"))?;
        if length > CAPTURE_MAX_PAYLOAD_BYTES || manifest.parts.len() > CAPTURE_MAX_REQUEST_PARTS {
            return Err(exhausted("request replay budget exceeded"));
        }
        let mut bytes = Vec::with_capacity(length);
        let mut inline_bytes = 0_usize;
        for part in &manifest.parts {
            let part_length = match part {
                RequestPart::Source { span } => span
                    .end
                    .checked_sub(span.start)
                    .ok_or_else(|| invalid("source range is reversed"))?,
                RequestPart::JsonStringSource {
                    span, byte_length, ..
                } => {
                    if span
                        .end
                        .checked_sub(span.start)
                        .is_none_or(|size| size > 1024 * 1024)
                        || *byte_length > 6 * 1024 * 1024
                    {
                        return Err(exhausted(
                            "JSON source transform exceeds its bounded profile",
                        ));
                    }
                    *byte_length
                }
                RequestPart::Novel { bytes } => u64::try_from(bytes.len())
                    .map_err(|_| exhausted("novel byte length overflow"))?,
                RequestPart::StoredNovel { payload } => payload.byte_length,
            };
            if part_length
                > u64::try_from(length.saturating_sub(bytes.len()))
                    .map_err(|_| exhausted("wire byte length overflow"))?
            {
                return Err(invalid("request parts exceed the declared wire length"));
            }
            let part_bytes = match part {
                RequestPart::Source { span } => self.source_span(snapshot, context, span, true)?,
                RequestPart::JsonStringSource {
                    span,
                    byte_length,
                    digest,
                } => {
                    let original = self.source_span(snapshot, context, span, true)?;
                    let text = std::str::from_utf8(&original)
                        .map_err(|_| invalid("JSON source transform requires exact UTF-8"))?;
                    let encoded = serde_json::to_vec(text)
                        .map_err(|_| invalid("JSON source transform failed"))?;
                    let contents = &encoded[1..encoded.len() - 1];
                    if contents.len() as u64 != *byte_length || raw_digest(contents) != *digest {
                        return Err(invalid(
                            "JSON source transform differs from its wire binding",
                        ));
                    }
                    contents.to_vec()
                }
                RequestPart::Novel { bytes } => {
                    inline_bytes = inline_bytes
                        .checked_add(bytes.len())
                        .ok_or_else(|| exhausted("novel byte budget overflow"))?;
                    if inline_bytes > super::CAPTURE_MAX_INLINE_BYTES {
                        return Err(exhausted("large novel wire bytes require durable staging"));
                    }
                    bytes.clone()
                }
                RequestPart::StoredNovel { payload } => {
                    let header = self.checked_payload_header(snapshot, context, payload)?;
                    self.payload_bytes(snapshot, &header)?
                }
            };
            if part_bytes.len() > length.saturating_sub(bytes.len()) {
                return Err(invalid("request parts exceed the declared wire length"));
            }
            bytes.extend_from_slice(&part_bytes);
        }
        if bytes.len() != length || raw_digest(&bytes) != manifest.wire_digest {
            return Err(invalid("request replay does not match its wire binding"));
        }
        Ok(bytes)
    }

    // The absent principal is reserved to host-admin deep integrity verification.
    fn checked_payload_header<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        reference: &OriginalPayloadRef,
    ) -> ServiceResult<PayloadHeader> {
        let header = match context {
            Some(context) => self.authorized_payload_header(snapshot, context, reference)?,
            None => self.payload_header(snapshot, reference.block_id)?,
        };
        if &header.reference != reference {
            return Err(integrity("stored payload reference binding differs"));
        }
        Ok(header)
    }

    pub(super) fn verify_capture_source_integrity<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
    ) -> ServiceResult<()> {
        self.validate_model_output_origin(snapshot, event)
            .map_err(|_| integrity("model output differs from its captured request"))?;
        match &event.payload {
            EventPayload::Staged { reference, .. } => {
                let header = self.checked_payload_header(snapshot, None, reference)?;
                self.payload_bytes(snapshot, &header)?;
            }
            EventPayload::Assembly { manifest } => {
                if manifest
                    .parts
                    .iter()
                    .any(|part| matches!(part, RequestPart::JsonStringSource { .. }))
                {
                    let format: Manifest = decode(
                        &snapshot
                            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                            .map_err(storage_error)?
                            .ok_or_else(|| integrity("manifest absent"))?,
                        "manifest",
                    )?;
                    if !format.features.contains(REQUEST_TRANSFORM_FEATURE) {
                        return Err(integrity("request transform format feature is absent"));
                    }
                }
                self.assemble_request(snapshot, None, manifest)
                    .map_err(|_| integrity("request source/wire closure is invalid"))?;
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_model_output_origin<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
    ) -> ServiceResult<()> {
        let Some(contextdb_core::EventProvenance::ModelOutput {
            model_call_id,
            request_event_id,
            ..
        }) = &event.provenance
        else {
            return Ok(());
        };
        let request = self.load_captured_original(snapshot, *request_event_id)?;
        if request.event.kind != EventKind::ModelRequested
            || request.event.run_id != event.run_id
            || request.event.session_id != event.session_id
            || !matches!(request.event.payload, EventPayload::Assembly { ref manifest } if manifest.model_call_id == *model_call_id)
        {
            return Err(invalid(
                "model output origin belongs to another request or run",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_payload_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let pruned = self.verify_payload_pruning_records(snapshot)?;
        let rows = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"payload/")
            .map_err(storage_error)?;
        if rows.is_empty() {
            return Ok(());
        }
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("manifest absent"))?,
            "manifest",
        )?;
        if !manifest.features.contains(SOURCE_FEATURE) {
            return Err(integrity("staged payload format feature is absent"));
        }
        let mut expected: BTreeSet<_> = pruned.keys().map(|id| pruning::pruning_key(*id)).collect();
        let mut budget = super::retention::audit_budget();
        for row in &rows {
            if !row.key.starts_with(b"payload/header/") {
                continue;
            }
            let declared: PayloadHeader = decode(&row.value, "payload header")?;
            let header = self.payload_header(snapshot, declared.reference.block_id)?;
            if !pruned.contains_key(&header.reference.block_id) {
                self.payload_bytes(snapshot, &header)?;
            }
            expected.insert(header_key(header.reference.block_id));
            let from = pruned.get(&header.reference.block_id).copied().unwrap_or(0);
            for index in from..header.chunks {
                if pruned.contains_key(&header.reference.block_id) {
                    self.verified_pruning_chunk(snapshot, &header, index, &mut budget)?;
                }
                expected.insert(chunk_key(header.reference.block_id, index));
            }
            self.verify_payload_header_control(snapshot, &header)?;
        }
        if expected.len() != rows.len() || rows.iter().any(|row| !expected.contains(&row.key)) {
            return Err(integrity("payload chunk/header closure is invalid"));
        }
        Ok(())
    }

    pub(super) fn verify_payload_journal_reference<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &super::StoredEvent,
    ) -> ServiceResult<()> {
        match (&event.accepted_payload, event.operation.as_str()) {
            (Some(reference), "stage_payload") => {
                let header = self
                    .payload_header(snapshot, reference.block_id)
                    .map_err(|_| integrity("journal payload reference is absent"))?;
                if &header.reference != reference
                    || header.accepted_global_commit != event.global_commit
                {
                    return Err(integrity("journal payload reference differs"));
                }
            }
            (None, operation) if operation != "stage_payload" => {}
            _ => return Err(integrity("journal payload reference kind is invalid")),
        }
        Ok(())
    }
}

fn source_range(start: u64, end: u64, length: usize) -> ServiceResult<std::ops::Range<usize>> {
    let start =
        usize::try_from(start).map_err(|_| invalid("source range start exceeds platform"))?;
    let end = usize::try_from(end).map_err(|_| invalid("source range end exceeds platform"))?;
    if start > end || end > length {
        return Err(invalid("source span is outside its immutable original"));
    }
    Ok(start..end)
}

fn header_key(id: ContentBlockId) -> Vec<u8> {
    format!("payload/header/{id}").into_bytes()
}
fn chunk_key(id: ContentBlockId, index: u32) -> Vec<u8> {
    let mut key = format!("payload/chunk/{id}/").into_bytes();
    key.extend_from_slice(&index.to_be_bytes());
    key
}
fn raw_digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn chunk_manifest_digest(
    byte_length: u64,
    digests: &[ContentDigest],
) -> ServiceResult<ContentDigest> {
    Ok(raw_digest(&encode(&(
        "payload-chunks/v1",
        CHUNK_BYTES,
        byte_length,
        digests,
    ))?))
}
