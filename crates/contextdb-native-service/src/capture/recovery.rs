//! Journal-bound control metadata for eventual explicit payload removal.
//! This witness does not itself authorize deletion or substitute for an original.

use std::collections::BTreeSet;

use contextdb_core::{
    AgentRunId, EventCoverage, EventKind, EventRole, PayloadOmission, ScopeId, SessionId, SourceId,
    TaskId, TimestampMicros,
};

use super::*;

pub(in super::super) const RECOVERY_FEATURE: &str = "continuous-capture-recovery-v1";
const ACTIVATED: &[u8] = b"recovery/activated";
const MAX_RECOVERY_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_CONTROL_BYTES: usize = 2 * MAX_RECOVERY_BYTES;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
enum PayloadShape {
    Utf8,
    Bytes,
    Staged,
    Assembly,
    Omitted { reason: PayloadOmission },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadMetadata {
    shape: PayloadShape,
    bytes: Option<u64>,
    digest: Option<ContentDigest>,
    media_type_digest: Option<ContentDigest>,
    renderer_digest: Option<ContentDigest>,
    model_call: Option<contextdb_core::ModelCallId>,
}

/// Only IDs, times, typed states, commitments and dependency handles. Arbitrary
/// adapter/source/gap strings and checkpoint content are deliberately not copied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct CaptureRecovery {
    version: u16,
    pub(in super::super) scope_ids: BTreeSet<ScopeId>,
    producer_id: StreamId,
    kind: EventKind,
    role: EventRole,
    recorded_at: TimestampMicros,
    observed_at: Option<TimestampMicros>,
    source_id: SourceId,
    source_version_digest: Option<ContentDigest>,
    adapter_digest: ContentDigest,
    session_id: Option<SessionId>,
    run_id: Option<AgentRunId>,
    task_id: Option<TaskId>,
    parent_event_ids: BTreeSet<ObservationId>,
    supersedes_event_id: Option<ObservationId>,
    pub(in super::super) coverage: EventCoverage,
    pub(in super::super) upstream_truncated: bool,
    gap_reason_digest: Option<ContentDigest>,
    pub(super) response_stream: Option<ResponseStream>,
    provenance: Option<EventProvenance>,
    payload: PayloadMetadata,
    pub(in super::super) inputs: crate::custody::Inputs,
    pub(super) checkpoint: Option<crate::owned::CheckpointControl>,
    /// Preserves trace presence and immutable commitments after body pruning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) router_trace: Option<contextdb_core::RouterTraceHeader>,
}

impl CaptureRecovery {
    pub(super) fn verify_features(&self, manifest: &Manifest) -> ServiceResult<()> {
        if self.version != if self.router_trace.is_some() { 2 } else { 1 }
            || self.router_trace.is_some() != self.inputs.trace_controls.is_some()
            || (self.router_trace.is_some()
                && !manifest
                    .features
                    .contains(crate::router_trace::TRACE_FEATURE))
        {
            return Err(integrity(
                "capture recovery router trace format is incomplete",
            ));
        }
        if let Some(header) = &self.router_trace {
            Validate::validate(header)
                .map_err(|_| integrity("capture recovery router trace header is invalid"))?;
            if header.version == contextdb_core::ROUTER_REPLAY_TRACE_VERSION
                && !manifest
                    .features
                    .contains(crate::router_trace::TRACE_REPLAY_FEATURE)
            {
                return Err(integrity(
                    "capture recovery router replay feature is absent",
                ));
            }
            if self.payload.model_call != Some(header.model_call_id)
                || self.payload.digest != Some(header.wire_digest)
                || self.payload.bytes != Some(header.wire_byte_length)
            {
                return Err(integrity(
                    "capture recovery router trace wire binding differs",
                ));
            }
            let controls = self
                .inputs
                .trace_controls
                .as_ref()
                .ok_or_else(|| integrity("capture recovery router trace inputs are absent"))?;
            controls.validate()?;
            if digest(&encode(controls)?) != header.origin_closure_digest {
                return Err(integrity("capture recovery router trace origins changed"));
            }
        }
        if (matches!(self.provenance, Some(EventProvenance::ModelOutput { .. }))
            && !manifest
                .features
                .contains(crate::payload::MODEL_PROTOCOL_FEATURE))
            || (self.checkpoint.is_some()
                && !manifest.features.contains(crate::owned::OWNED_FEATURE))
            || ((self.provenance.is_some()
                || matches!(
                    self.payload.shape,
                    PayloadShape::Staged | PayloadShape::Assembly
                ))
                && !manifest.features.contains(crate::payload::SOURCE_FEATURE))
        {
            return Err(integrity(
                "capture recovery requires missing source format features",
            ));
        }
        Ok(())
    }

    pub(in super::super) fn owned_payload(&self) -> Option<contextdb_core::ContentBlockId> {
        if self.payload.shape == PayloadShape::Staged {
            self.inputs.payloads.first().map(|value| value.block_id)
        } else {
            None
        }
    }

    pub(super) fn from_event(event: &EventEnvelope) -> ServiceResult<Self> {
        Self::from_event_with_inputs(event, crate::custody::inputs(event)?)
    }

    pub(super) fn from_event_with_inputs(
        event: &EventEnvelope,
        inputs: crate::custody::Inputs,
    ) -> ServiceResult<Self> {
        let (shape, bytes, media_type, renderer, model_call) = match &event.payload {
            EventPayload::InlineUtf8 { text, .. } => (
                PayloadShape::Utf8,
                Some(text.len() as u64),
                None,
                None,
                None,
            ),
            EventPayload::InlineBytes {
                bytes, media_type, ..
            } => (
                PayloadShape::Bytes,
                Some(bytes.len() as u64),
                Some(media_type.as_str()),
                None,
                None,
            ),
            EventPayload::Staged {
                reference,
                media_type,
            } => (
                PayloadShape::Staged,
                Some(reference.byte_length),
                Some(media_type.as_str()),
                None,
                None,
            ),
            EventPayload::Assembly { manifest } => (
                PayloadShape::Assembly,
                Some(manifest.byte_length),
                None,
                Some(manifest.renderer.as_str()),
                Some(manifest.model_call_id),
            ),
            EventPayload::Omitted { reason } => (
                PayloadShape::Omitted { reason: *reason },
                None,
                None,
                None,
                None,
            ),
        };
        let checkpoint = crate::owned::CheckpointControl::from_event(event)?;
        let router_trace = match &event.payload {
            EventPayload::Assembly { manifest } => manifest
                .router_trace
                .as_ref()
                .map(|trace| trace.header.clone()),
            _ => None,
        };
        let metadata = Self {
            version: if router_trace.is_some() { 2 } else { 1 },
            scope_ids: event.scope_ids.clone(),
            producer_id: event.producer_id,
            kind: event.kind,
            role: event.role,
            recorded_at: event.recorded_at,
            observed_at: event.observed_at,
            source_id: event.source_id,
            source_version_digest: event.source_version.as_deref().map(text_digest),
            adapter_digest: text_digest(&event.adapter_id),
            session_id: event.session_id,
            run_id: event.run_id,
            task_id: event.task_id,
            parent_event_ids: event.parent_event_ids.clone(),
            supersedes_event_id: event.supersedes_event_id,
            coverage: event.coverage,
            upstream_truncated: event.upstream_truncated,
            gap_reason_digest: event.gap_reason.as_deref().map(text_digest),
            response_stream: event.response_stream.clone(),
            provenance: event.provenance.clone(),
            payload: PayloadMetadata {
                shape,
                bytes,
                digest: event.payload.digest(),
                media_type_digest: media_type.map(text_digest),
                renderer_digest: renderer.map(text_digest),
                model_call,
            },
            inputs,
            checkpoint,
            router_trace,
        };
        if encode(&metadata)?.len() > MAX_RECOVERY_BYTES {
            return Err(exhausted("capture recovery metadata exceeds 1 MiB"));
        }
        Ok(metadata)
    }

    pub(super) fn digest(&self) -> ServiceResult<ContentDigest> {
        Ok(digest(&encode(&(RECOVERY_FEATURE, self))?))
    }
}

impl NativeService {
    pub(super) fn capture_record_with_budget<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<CaptureRecord> {
        budget.check().map_err(crate::raw_index::budget_error)?;
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &record_key(id))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("capture control metadata is absent"))?;
        if bytes.len() > MAX_CAPTURE_CONTROL_BYTES {
            return Err(integrity(
                "capture control metadata exceeds its stored bound",
            ));
        }
        budget
            .charge(1, bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        decode(&bytes, "bounded capture control metadata")
    }

    pub(crate) fn capture_recovery_metadata<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<(CaptureReceipt, Option<CaptureRecovery>)> {
        let record = self.capture_record_with_budget(snapshot, id, budget)?;
        if let Some(recovery) = &record.recovery {
            self.verify_recovery_features(snapshot, recovery)?;
        }
        Ok((record.receipt, record.recovery))
    }
    /// Administrative metadata for either a complete original or an explicitly
    /// pruned original with independently retained control authority. Never used
    /// to manufacture an EventEnvelope or a successful original read.
    pub(in super::super) fn verified_capture_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<VerifiedCaptureControl> {
        let record = self.capture_record_with_budget(snapshot, id, budget)?;
        if let Some(recovery) = &record.recovery {
            self.verify_recovery_features(snapshot, recovery)?;
        }
        if let Some(control_digest) = self.verify_pruned_source(snapshot, id, budget)? {
            return Ok(VerifiedCaptureControl {
                receipt: record.receipt,
                recovery: record
                    .recovery
                    .ok_or_else(|| integrity("pruned recovery is absent"))?,
                control_digest,
                original: None,
            });
        }
        let original = self.load_captured_original_with_budget(snapshot, id, budget)?;
        budget
            .charge(1, encode(&original.event)?.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        let recovery = if let Some(recovery) = record.recovery {
            recovery
        } else {
            let controls = crate::router_trace::decode_envelope(&original.event, budget)?
                .map(|envelope| envelope.origins);
            let inputs = crate::custody::inputs_with_trace_controls(&original.event, controls)?;
            CaptureRecovery::from_event_with_inputs(&original.event, inputs)?
        };
        Ok(VerifiedCaptureControl {
            control_digest: self.capture_control_digest(snapshot, &original)?,
            recovery,
            receipt: original.receipt,
            original: Some(original.event),
        })
    }

    // The retained authority has already proved membership of this exact source.
    // Only immutable control bytes are read here; this is not disclosure authority.
    pub(in super::super) fn verify_retained_capture_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        source: &crate::NativeDeletionSource,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<()> {
        let bytes = snapshot
            .get(
                &self.keyspaces.continuous,
                &record_key(source.receipt.event_id),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained capture control is missing"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        let record: CaptureRecord = decode(&bytes, "retained capture control")?;
        if let Some(recovery) = &record.recovery {
            self.verify_recovery_features(snapshot, recovery)?;
        }
        if record.receipt != source.receipt
            || control_digest(&bytes) != source.control_digest
            || record.work()?.recovery_digest != Some(source.recovery_digest)
        {
            return Err(integrity(
                "capture control differs from the retained removal source",
            ));
        }
        let (global, _) = self.select_snapshot(
            snapshot,
            &source.receipt.workspace_id.to_string(),
            Some(source.receipt.workspace_commit),
        )?;
        let bytes = snapshot
            .get(&self.keyspaces.events, &global.to_be_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained capture journal is missing"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(crate::raw_index::budget_error)?;
        let journal: crate::StoredEvent = decode(&bytes, "retained capture journal")?;
        if journal.operation != "capture"
            || journal.accepted_original.as_ref() != Some(&record.work()?)
            || journal.workspace_digest
                != digest_bytes(source.receipt.workspace_id.to_string().as_bytes())
            || journal.workspace_commit != source.receipt.workspace_commit
            || journal.event_digest != crate::event_digest(&journal)?
        {
            return Err(integrity(
                "retained control has no matching accepted capture",
            ));
        }
        Ok(())
    }

    pub(in super::super) fn capture_control_digest<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        original: &CapturedOriginal,
    ) -> ServiceResult<ContentDigest> {
        let bytes = snapshot
            .get(
                &self.keyspaces.continuous,
                &record_key(original.event.event_id),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("capture control record is missing"))?;
        let record: CaptureRecord = decode(&bytes, "capture control record")?;
        if record.receipt != original.receipt
            || record.producer_sequence != original.event.producer_sequence
            || blake3::Hash::from_hex(&record.producer_key).is_err()
            || blake3::Hash::from_hex(&record.idempotency_digest).is_err()
            || encode(&record)? != bytes
        {
            return Err(integrity(
                "capture control differs from its accepted original",
            ));
        }
        let positioned: ObservationId = read_required(
            snapshot,
            self,
            &position_key(&record.producer_key, record.producer_sequence),
        )?;
        let retry: crate::StoredIdempotency = decode(
            &snapshot
                .get(
                    &self.keyspaces.idempotency,
                    record.idempotency_digest.as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("capture control retry receipt is missing"))?,
            "capture control retry receipt",
        )?;
        if positioned != original.event.event_id
            || retry.operation != "capture"
            || retry.response_bytes != encode(&record.receipt)?
            || retry.response_digest != digest_bytes(&retry.response_bytes)
        {
            return Err(integrity(
                "capture control position or retry binding differs",
            ));
        }
        Ok(control_digest(&bytes))
    }

    pub(in super::super) fn capture_work_for_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &CaptureReceipt,
    ) -> ServiceResult<CaptureWork> {
        let record: CaptureRecord = read_required(snapshot, self, &record_key(receipt.event_id))?;
        if record.receipt != *receipt {
            return Err(integrity("capture journal receipt differs"));
        }
        record.work()
    }

    pub(super) fn enable_capture_recovery<T: WriteTransaction>(
        &self,
        tx: &mut T,
        global: u64,
    ) -> ServiceResult<()> {
        let manifest: Manifest = decode(
            &tx.get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest is absent"))?,
            "native manifest",
        )?;
        let activation: Option<u64> = read_optional(tx, self, ACTIVATED)?;
        if manifest.features.contains(RECOVERY_FEATURE) != activation.is_some()
            || activation.is_some_and(|first| first == 0 || first > global)
        {
            return Err(integrity(
                "capture recovery activation differs from its format",
            ));
        }
        if activation.is_none() {
            self.enable_capture_extension(tx, RECOVERY_FEATURE)?;
            tx.put(
                &self.keyspaces.continuous,
                ACTIVATED.to_vec(),
                encode(&global)?,
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(super) fn validate_capture_recovery<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record: &CaptureRecord,
        event: &EventEnvelope,
        global: u64,
    ) -> ServiceResult<()> {
        self.validate_capture_recovery_with_inputs(snapshot, record, event, global, None)
    }

    pub(super) fn validate_capture_recovery_with_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record: &CaptureRecord,
        event: &EventEnvelope,
        global: u64,
        inputs: Option<crate::custody::Inputs>,
    ) -> ServiceResult<()> {
        let activation: Option<u64> = read_optional(snapshot, self, ACTIVATED)?;
        match (&record.recovery, activation) {
            (Some(recovery), Some(first)) if first != 0 && global >= first => {
                self.verify_recovery_features(snapshot, recovery)?;
                let expected = if let Some(inputs) = inputs {
                    CaptureRecovery::from_event_with_inputs(event, inputs)?
                } else {
                    CaptureRecovery::from_event(event)?
                };
                if *recovery != expected {
                    return Err(integrity(
                        "capture recovery metadata differs from its original",
                    ));
                }
            }
            (None, first) if first.is_none_or(|first| global < first) => (),
            _ => {
                return Err(integrity(
                    "capture recovery metadata or activation is missing",
                ));
            }
        }
        Ok(())
    }

    fn verify_recovery_features<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        recovery: &CaptureRecovery,
    ) -> ServiceResult<()> {
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("capture recovery native manifest is absent"))?,
            "capture recovery native manifest",
        )?;
        recovery.verify_features(&manifest)
    }

    pub(super) fn verify_capture_recovery_format<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<Option<u64>> {
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest is absent"))?,
            "native manifest",
        )?;
        let rows = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"recovery/")
            .map_err(storage_error)?;
        if !manifest.features.contains(RECOVERY_FEATURE) {
            return if rows.is_empty() {
                Ok(None)
            } else {
                Err(integrity("undeclared capture recovery metadata"))
            };
        }
        if rows.len() != 1 || rows[0].key != ACTIVATED {
            return Err(integrity(
                "capture recovery activation is absent or invalid",
            ));
        }
        let first: u64 = decode(&rows[0].value, "capture recovery activation")?;
        if first == 0 || first > self.global_head(snapshot)? {
            return Err(integrity("capture recovery activation is outside history"));
        }
        let journal: crate::StoredEvent = decode(
            &snapshot
                .get(&self.keyspaces.events, &first.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("recovery activation journal is absent"))?,
            "recovery activation journal",
        )?;
        if journal
            .accepted_original
            .as_ref()
            .is_none_or(|original| original.recovery_digest.is_none())
        {
            return Err(integrity(
                "capture recovery activation lacks a bound original",
            ));
        }
        Ok(Some(first))
    }
}

pub(in super::super) struct VerifiedCaptureControl {
    pub(in super::super) receipt: CaptureReceipt,
    pub(in super::super) recovery: CaptureRecovery,
    pub(in super::super) control_digest: ContentDigest,
    pub(in super::super) original: Option<EventEnvelope>,
}

pub(super) fn control_digest(bytes: &[u8]) -> ContentDigest {
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb/native-capture-control/v1\0");
    hash.update(bytes);
    ContentDigest::from_bytes(*hash.finalize().as_bytes())
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn text_digest(value: &str) -> ContentDigest {
    digest(value.as_bytes())
}

#[cfg(test)]
mod tests;
