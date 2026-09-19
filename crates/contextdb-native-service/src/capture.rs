//! Atomic original capture on the existing native publication owner.

use std::collections::BTreeMap;

use contextdb_core::{
    ContentDigest, EventEnvelope, EventPayload, EventProvenance, ObservationId, OriginalPayloadRef,
    RequestPart, ResponseStream, StreamId, Validate,
};
use contextdb_service::{
    AuthenticatedRequestContext, Capability, CaptureAcceptance, CaptureDurability, CaptureGapRange,
    CapturePort, CaptureReceipt, CaptureRequest, CapturedOriginal, ErrorCode,
    NATIVE_CAPTURE_DOMAIN, ProducerCoverage, ReadOriginalRequest, SaveRunCheckpointRequest,
    ServiceError, ServiceResult,
};
use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, StorageError, WriteTransaction,
};
use serde::{Deserialize, Serialize};

use super::{
    META_MANIFEST_KEY, Manifest, NativeService, SCHEMA_VERSION, StoredObservationContent,
    StoredObservationPolicy, canonical_digest, decode, digest_bytes, encode, exhausted, integrity,
    invalid, keyed_token, manifest_checksum, not_found, permission_denied, policy_allows,
    request_context_binding, require_capability, require_sync, storage_error,
    trusted_structured_policy, validate_identifier,
};

pub(super) const CAPTURE_FEATURE: &str = "continuous-capture-v1";
pub(super) const IMPACT_FEATURE: &str = "continuous-capture-impact-v1";
/// Maximum original payload in one synchronized capture transaction.
pub const CAPTURE_MAX_INLINE_BYTES: usize = 256 * 1024;
/// Maximum disjoint producer gaps before strict capture applies backpressure.
pub const CAPTURE_MAX_PRODUCER_GAPS: usize = 128;
const MAX_CAPTURE_RETRIES: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureRecord {
    receipt: CaptureReceipt,
    producer_key: String,
    producer_sequence: u64,
    idempotency_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<CaptureDependency>,
    // Older receipts always affected scopes. A verified host request echo may
    // opt out: recording disclosure is not another semantic observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    affects_scope: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody_version: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CaptureDependency {
    Source { event_id: ObservationId },
    Payload { reference: OriginalPayloadRef },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamHead {
    chunks: u32,
    finished: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureWork {
    pub event_id: ObservationId,
    pub workspace_commit: u64,
    pub event_digest: ContentDigest,
}

impl CapturePort for NativeService {
    fn append_event_with_status(
        &self,
        request: CaptureRequest,
    ) -> ServiceResult<CaptureAcceptance> {
        self.append_owned_capture(request, None)
    }

    fn read_original(&self, request: ReadOriginalRequest) -> ServiceResult<CapturedOriginal> {
        require_capability(&request.context, Capability::ReadEvidence)?;
        require_capability(&request.context, Capability::RawEvidence)?;
        if let Some(receipt) = &request.after_receipt {
            self.resolve_capture_receipt(&request.context, receipt)?;
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let policy =
            self.authorized_capture_policy(&snapshot, &request.context, request.event_id)?;
        self.authorize_capture_dependencies(&snapshot, &request.context, request.event_id)?;
        let original = self.load_captured_original(&snapshot, request.event_id)?;
        if original.event.workspace_id.to_string() != policy.access.workspace_id {
            return Err(integrity("capture workspace differs from its policy"));
        }
        Ok(original)
    }

    fn resolve_capture_receipt(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &CaptureReceipt,
    ) -> ServiceResult<()> {
        require_capability(context, Capability::Recall)?;
        if receipt.domain != NATIVE_CAPTURE_DOMAIN
            || receipt.database_id != self.database_id
            || receipt.workspace_id.to_string() != context.request.workspace_id
        {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "capture receipt belongs to another store or sequence domain",
                false,
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let policy = self.authorized_capture_policy(&snapshot, context, receipt.event_id)?;
        let stored: CaptureRecord = read_required(&snapshot, self, &record_key(receipt.event_id))?;
        let (global, _) = self.select_snapshot(
            &snapshot,
            &context.request.workspace_id,
            Some(receipt.workspace_commit),
        )?;
        if &stored.receipt != receipt || global != policy.accepted_global_commit {
            return Err(invalid(
                "capture receipt does not match its durable publication",
            ));
        }
        Ok(())
    }

    fn producer_coverage(
        &self,
        context: &AuthenticatedRequestContext,
        producer: StreamId,
    ) -> ServiceResult<ProducerCoverage> {
        require_capability(context, Capability::Recall)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let key = format!("producer/{}", producer_key(context, producer)?);
        let coverage = read_optional(&snapshot, self, key.as_bytes())?.unwrap_or_default();
        validate_coverage(&coverage)?;
        Ok(coverage)
    }
}

impl NativeService {
    pub(super) fn captured_receipt_metadata<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<CaptureReceipt> {
        let record: CaptureRecord = read_required(snapshot, self, &record_key(id))?;
        if record.receipt.event_id != id
            || record.receipt.database_id != self.database_id
            || record.receipt.domain != NATIVE_CAPTURE_DOMAIN
        {
            return Err(integrity("capture metadata receipt binding differs"));
        }
        Ok(record.receipt)
    }

    /// Check an already-verified immutable version without decoding its original
    /// body while a dispatch admission holds publication authority.
    pub(super) fn check_captured_payload_version<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
        expected: ContentDigest,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<()> {
        self.authorized_capture_policy(snapshot, context, id)?;
        self.authorize_capture_dependencies(snapshot, context, id)?;
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &record_key(id))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("lease capture receipt missing"))?;
        budget
            .charge(1, bytes.len() as u64)
            .map_err(super::raw_index::budget_error)?;
        let record: CaptureRecord = decode(&bytes, "lease capture version")?;
        if record.receipt.event_id != id
            || record.receipt.database_id != self.database_id
            || record.receipt.workspace_id.to_string() != context.request.workspace_id
            || record.receipt.domain != NATIVE_CAPTURE_DOMAIN
            || record.receipt.payload_digest != Some(expected)
        {
            return Err(integrity(
                "lease source version differs from its native receipt",
            ));
        }
        Ok(())
    }

    // Only OwnedRunPort can bind an operational checkpoint to the run head.
    // Normal capture cannot manufacture this authority through a provenance tag.
    pub(super) fn append_owned_capture(
        &self,
        request: CaptureRequest,
        checkpoint: Option<&SaveRunCheckpointRequest>,
    ) -> ServiceResult<CaptureAcceptance> {
        require_capability(&request.context, Capability::Observe)?;
        if host_request_echo(&request.event)
            || checkpoint.is_some()
            || matches!(
                request.event.provenance,
                Some(EventProvenance::ModelOutput { .. })
            )
        {
            require_capability(&request.context, Capability::Runtime)?;
        }
        match (&request.event.provenance, checkpoint) {
            (
                Some(EventProvenance::OwnedCheckpoint {
                    expected_revision,
                    state_digest,
                }),
                Some(owned),
            ) if *expected_revision == owned.expected_revision
                && *state_digest
                    == owned
                        .checkpoint
                        .digest()
                        .map_err(|_| invalid("invalid checkpoint"))?
                && request.event.event_id == owned.event_id
                && request.idempotency_key == owned.idempotency_key
                && encode(&request.context)? == encode(&owned.context)? => {}
            (Some(EventProvenance::OwnedCheckpoint { .. }), _) | (_, Some(_)) => {
                return Err(invalid(
                    "checkpoint publication requires the owned-run port",
                ));
            }
            _ => {}
        }
        validate_identifier(&request.idempotency_key, "capture idempotency key")?;
        request
            .event
            .validate()
            .map_err(|_| invalid("event envelope is invalid"))?;
        let principal = &request.context.request;
        if principal.workspace_id != request.event.workspace_id.to_string()
            || !request
                .event
                .scope_ids
                .iter()
                .all(|scope| principal.scopes.contains(&scope.to_string()))
        {
            return Err(permission_denied());
        }
        validate_payload(&request.event)?;
        let producer = producer_key(&request.context, request.event.producer_id)?;
        let idempotency =
            canonical_digest(&(NATIVE_CAPTURE_DOMAIN, &producer, &request.idempotency_key))?;
        let request_digest = canonical_digest(&(
            &request.event,
            request_context_binding(principal)?,
            &request.context.actor_id,
            &request.context.agent_id,
        ))?;
        let _guard = self.lock_writes()?;
        for _ in 0..MAX_CAPTURE_RETRIES {
            if let Some(receipt) = self.append_capture_attempt(
                &request,
                &producer,
                &idempotency,
                &request_digest,
                checkpoint,
            )? {
                return Ok(receipt);
            }
        }
        Err(ServiceError::new(
            ErrorCode::Unavailable,
            "capture publication remained contended; retry the same idempotency key",
            true,
        ))
    }

    pub(super) fn capture_affects_scope<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<bool> {
        let record: CaptureRecord = read_required(snapshot, self, &record_key(id))?;
        Ok(record.affects_scope.unwrap_or(true))
    }

    pub(super) fn captured_authority<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
    ) -> ServiceResult<contextdb_core::SourceAuthority> {
        let content: StoredObservationContent = decode(
            &snapshot
                .get(
                    &self.keyspaces.observations_content,
                    digest_bytes(event.event_id.to_string().as_bytes()).as_bytes(),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("source authority is absent"))?,
            "captured authority",
        )?;
        let actor = content
            .metadata
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| integrity("captured actor is absent"))?;
        Ok(contextdb_core::SourceAuthority {
            adapter_id: event.adapter_id.clone(),
            actor_id: actor.into(),
            role: event.role,
        })
    }

    pub(super) fn captured_producer_incomplete<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event_id: ObservationId,
    ) -> ServiceResult<bool> {
        let record: CaptureRecord = read_required(snapshot, self, &record_key(event_id))?;
        let coverage: ProducerCoverage = read_required(
            snapshot,
            self,
            format!("producer/{}", record.producer_key).as_bytes(),
        )?;
        validate_coverage(&coverage)?;
        Ok(!coverage.gaps.is_empty())
    }

    fn append_capture_attempt(
        &self,
        request: &CaptureRequest,
        producer: &str,
        idempotency: &str,
        request_digest: &str,
        checkpoint: Option<&SaveRunCheckpointRequest>,
    ) -> ServiceResult<Option<CaptureAcceptance>> {
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if let Some(receipt) = self.replay::<CaptureReceipt, _>(
            &transaction,
            idempotency.as_bytes(),
            "capture",
            request_digest,
        )? {
            self.authorized_capture_policy(&transaction, &request.context, receipt.event_id)?;
            self.authorize_capture_dependencies(&transaction, &request.context, receipt.event_id)?;
            return Ok(Some(CaptureAcceptance {
                receipt,
                newly_accepted: false,
            }));
        }
        if let Some(checkpoint) = checkpoint {
            self.validate_checkpoint_publication(&transaction, checkpoint)?;
        }
        let event = &request.event;
        let position = position_key(producer, event.producer_sequence);
        let event_digest = digest_bytes(event.event_id.to_string().as_bytes());
        if transaction
            .get(&self.keyspaces.observations_policy, event_digest.as_bytes())
            .map_err(storage_error)?
            .is_some()
            || transaction
                .get(&self.keyspaces.continuous, &position)
                .map_err(storage_error)?
                .is_some()
        {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "event identity or producer position was already accepted; use its original key",
                false,
            ));
        }
        for parent in event
            .parent_event_ids
            .iter()
            .chain(event.supersedes_event_id.iter())
        {
            self.authorized_capture_policy(&transaction, &request.context, *parent)?;
        }
        if let Some(previous) = event.supersedes_event_id {
            let predecessor = self.load_captured_original(&transaction, previous)?;
            if predecessor.event.source_id != event.source_id {
                return Err(invalid("event edit refers to another source"));
            }
        }
        let producer_head_key = format!("producer/{producer}");
        let old =
            read_optional(&transaction, self, producer_head_key.as_bytes())?.unwrap_or_default();
        let coverage = advance_coverage(old, event.producer_sequence)?;
        self.stage_response_stream(&mut transaction, request, producer)?;
        self.validate_capture_sources(&transaction, &request.context, event)?;
        if event.provenance.is_some()
            || matches!(
                event.payload,
                EventPayload::Staged { .. } | EventPayload::Assembly { .. }
            )
        {
            self.enable_source_format(&mut transaction)?;
        }
        self.enable_capture_format(&mut transaction)?;
        if matches!(event.provenance, Some(EventProvenance::ModelOutput { .. })) {
            self.enable_capture_extension(
                &mut transaction,
                super::payload::MODEL_PROTOCOL_FEATURE,
            )?;
        }
        let affects_scope = !host_request_echo(event);
        if !affects_scope {
            self.enable_capture_extension(&mut transaction, IMPACT_FEATURE)?;
        }
        if matches!(&event.payload, EventPayload::Assembly { manifest }
            if manifest.parts.iter().any(|part| matches!(part, RequestPart::JsonStringSource { .. })))
        {
            self.enable_request_transform_format(&mut transaction)?;
        }
        let frame = self.begin_frame(&transaction, &request.context.request.workspace_id, false)?;
        let mut access = trusted_structured_policy(&request.context.request);
        access.scopes = event.scope_ids.iter().map(ToString::to_string).collect();
        let metadata = BTreeMap::from([
            (
                "capture_format".to_owned(),
                serde_json::json!(NATIVE_CAPTURE_DOMAIN),
            ),
            (
                "actor_id".to_owned(),
                serde_json::json!(request.context.actor_id),
            ),
            (
                "agent_id".to_owned(),
                serde_json::json!(request.context.agent_id),
            ),
        ]);
        let content =
            serde_json::to_value(event).map_err(|_| invalid("event cannot be serialized"))?;
        let observation_id = event.event_id.to_string();
        let content_digest = canonical_digest(&(&observation_id, &metadata, &content))?;
        let policy = StoredObservationPolicy {
            schema_version: SCHEMA_VERSION,
            observation_digest: event_digest.clone(),
            accepted_global_commit: frame.global_commit,
            access,
            content_digest: content_digest.clone(),
        };
        transaction
            .put(
                &self.keyspaces.observations_policy,
                event_digest.as_bytes().to_vec(),
                encode(&policy)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.observations_content,
                event_digest.as_bytes().to_vec(),
                encode(&StoredObservationContent {
                    schema_version: SCHEMA_VERSION,
                    observation_id,
                    metadata,
                    content,
                    digest: content_digest,
                })?,
            )
            .map_err(storage_error)?;
        #[cfg(test)]
        capture_fault("after_payload");

        let mut receipt = CaptureReceipt {
            domain: NATIVE_CAPTURE_DOMAIN.into(),
            database_id: self.database_id.clone(),
            workspace_id: event.workspace_id,
            event_id: event.event_id,
            workspace_commit: frame.state.watermarks.journal,
            event_digest: content_digest_of(event)?,
            payload_digest: event.payload.digest(),
            durability: CaptureDurability::Sync,
            token: String::new(),
        };
        receipt.token = keyed_token(
            &self.token_key,
            b"contextdb/capture-receipt/v1\0",
            &encode(&receipt)?,
        );
        let record = CaptureRecord {
            receipt: receipt.clone(),
            producer_key: producer.into(),
            producer_sequence: event.producer_sequence,
            idempotency_digest: idempotency.into(),
            dependencies: capture_dependencies(&event.payload),
            affects_scope: (!affects_scope).then_some(false),
            custody_version: Some(super::custody::CUSTODY_VERSION),
        };
        transaction
            .put(
                &self.keyspaces.continuous,
                record_key(event.event_id),
                encode(&record)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.continuous,
                position,
                encode(&event.event_id)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.continuous,
                producer_head_key.into_bytes(),
                encode(&coverage)?,
            )
            .map_err(storage_error)?;
        self.publish_capture_custody(
            &mut transaction,
            &request.context,
            event,
            receipt.workspace_commit,
        )?;
        transaction
            .put(
                &self.keyspaces.continuous,
                work_key(&frame.workspace_digest, receipt.workspace_commit),
                encode(&CaptureWork {
                    event_id: event.event_id,
                    workspace_commit: receipt.workspace_commit,
                    event_digest: receipt.event_digest,
                })?,
            )
            .map_err(storage_error)?;
        for scope in event.scope_ids.iter().filter(|_| affects_scope) {
            let key = scope_key(&frame.workspace_digest, &scope.to_string());
            transaction
                .put(
                    &self.keyspaces.continuous,
                    key,
                    encode(&receipt.workspace_commit)?,
                )
                .map_err(storage_error)?;
        }
        if let Some(checkpoint) = checkpoint {
            self.publish_checkpoint_head(&mut transaction, checkpoint, &receipt)?;
        }
        self.finish_frame(
            &mut transaction,
            &frame,
            "capture",
            idempotency.as_bytes(),
            request_digest,
            &receipt,
        )?;
        #[cfg(test)]
        capture_fault("before_commit");
        match transaction.commit(Durability::Sync) {
            Ok(committed) => require_sync(committed.durability)?,
            Err(StorageError::WriteConflict { .. }) => return Ok(None),
            Err(error) => return Err(storage_error(error)),
        }
        #[cfg(test)]
        capture_fault("after_commit");
        Ok(Some(CaptureAcceptance {
            receipt,
            newly_accepted: true,
        }))
    }

    pub(super) fn enable_capture_format<T: WriteTransaction>(
        &self,
        transaction: &mut T,
    ) -> ServiceResult<()> {
        let bytes = transaction
            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native manifest is absent"))?;
        let mut manifest: Manifest = decode(&bytes, "native manifest")?;
        super::validate_manifest(&manifest, &self.database_id)?;
        if manifest.features.insert(CAPTURE_FEATURE.to_owned()) {
            manifest.checksum = manifest_checksum(&manifest)?;
            transaction
                .put(
                    &self.keyspaces.meta,
                    META_MANIFEST_KEY.to_vec(),
                    encode(&manifest)?,
                )
                .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(super) fn enable_capture_extension<T: WriteTransaction>(
        &self,
        transaction: &mut T,
        feature: &str,
    ) -> ServiceResult<()> {
        self.enable_capture_format(transaction)?;
        let mut manifest: Manifest = decode(
            &transaction
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if manifest.features.insert(feature.into()) {
            manifest.checksum = manifest_checksum(&manifest)?;
            transaction
                .put(
                    &self.keyspaces.meta,
                    META_MANIFEST_KEY.to_vec(),
                    encode(&manifest)?,
                )
                .map_err(storage_error)?;
        }
        Ok(())
    }

    fn stage_response_stream<T: WriteTransaction>(
        &self,
        transaction: &mut T,
        request: &CaptureRequest,
        producer: &str,
    ) -> ServiceResult<()> {
        let Some(stream) = &request.event.response_stream else {
            return Ok(());
        };
        let response = match stream {
            ResponseStream::Chunk { response_id, .. }
            | ResponseStream::Finished { response_id, .. } => response_id,
        };
        let key = format!("stream/{producer}/{response}");
        let mut head: StreamHead =
            read_optional(transaction, self, key.as_bytes())?.unwrap_or_default();
        advance_stream(&mut head, stream)?;
        transaction
            .put(&self.keyspaces.continuous, key.into_bytes(), encode(&head)?)
            .map_err(storage_error)
    }

    pub(super) fn authorized_capture_policy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        id: ObservationId,
    ) -> ServiceResult<StoredObservationPolicy> {
        let digest = digest_bytes(id.to_string().as_bytes());
        let bytes = snapshot
            .get(&self.keyspaces.observations_policy, digest.as_bytes())
            .map_err(storage_error)?
            .ok_or_else(not_found)?;
        let policy: StoredObservationPolicy = decode(&bytes, "observation policy")?;
        if !policy_allows(&context.request, &policy.access) {
            return Err(permission_denied());
        }
        if policy.schema_version != SCHEMA_VERSION || policy.observation_digest != digest {
            return Err(integrity("capture policy binding is invalid"));
        }
        Ok(policy)
    }

    pub(super) fn load_captured_original<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        id: ObservationId,
    ) -> ServiceResult<CapturedOriginal> {
        let record: CaptureRecord = read_required(snapshot, self, &record_key(id))?;
        let digest = digest_bytes(id.to_string().as_bytes());
        let policy: StoredObservationPolicy = decode(
            &snapshot
                .get(&self.keyspaces.observations_policy, digest.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("capture policy is absent"))?,
            "capture policy",
        )?;
        let content: StoredObservationContent = decode(
            &snapshot
                .get(&self.keyspaces.observations_content, digest.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("capture original is absent"))?,
            "capture original",
        )?;
        if content.digest != policy.content_digest
            || content.digest
                != canonical_digest(&(
                    &content.observation_id,
                    &content.metadata,
                    &content.content,
                ))?
        {
            return Err(integrity("capture payload binding is invalid"));
        }
        let event: EventEnvelope = serde_json::from_value(content.content)
            .map_err(|_| integrity("captured envelope is invalid"))?;
        event
            .validate()
            .map_err(|_| integrity("captured envelope invariant failed"))?;
        validate_payload(&event).map_err(|_| integrity("captured original digest is invalid"))?;
        if record.dependencies != capture_dependencies(&event.payload) {
            return Err(integrity(
                "capture source dependencies differ from its original",
            ));
        }
        if record.affects_scope != host_request_echo(&event).then_some(false) {
            return Err(integrity(
                "a source observation cannot suppress its scope impact",
            ));
        }
        let receipt = record.receipt;
        let (global, _) = self.select_snapshot(
            snapshot,
            &event.workspace_id.to_string(),
            Some(receipt.workspace_commit),
        )?;
        if event.event_id != id
            || receipt.event_id != id
            || receipt.database_id != self.database_id
            || receipt.domain != NATIVE_CAPTURE_DOMAIN
            || receipt.workspace_id != event.workspace_id
            || receipt.event_digest != content_digest_of(&event)?
            || receipt.payload_digest != event.payload.digest()
            || global != policy.accepted_global_commit
            || content.observation_id != id.to_string()
        {
            return Err(integrity("capture receipt and original disagree"));
        }
        Ok(CapturedOriginal { event, receipt })
    }

    pub(super) fn verify_capture_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let entries = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"")
            .map_err(storage_error)?
            .into_iter()
            .filter(|entry| {
                !entry.key.starts_with(b"payload/")
                    && !entry.key.starts_with(b"raw/")
                    && !entry.key.starts_with(b"state/")
                    && !entry.key.starts_with(b"semantic/")
                    && !entry.key.starts_with(b"catalog/")
                    && !entry.key.starts_with(b"custody/")
            })
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Ok(());
        }
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest is absent"))?,
            "native manifest",
        )?;
        if !manifest.features.contains(CAPTURE_FEATURE)
            && !manifest
                .features
                .contains(super::record_journal::RECORD_FEATURE)
        {
            return Err(integrity(
                "continuous data is not declared by the native format",
            ));
        }
        let mut accepted = Vec::new();
        for entry in &entries {
            if entry.key.starts_with(b"receipt/") {
                let record: CaptureRecord = decode(&entry.value, "capture record")?;
                let original = self.load_captured_original(snapshot, record.receipt.event_id)?;
                if let Some(version) = record.custody_version {
                    if version != super::custody::CUSTODY_VERSION
                        || !manifest.features.contains(super::custody::CUSTODY_FEATURE)
                    {
                        return Err(integrity(
                            "capture custody format is absent or incompatible",
                        ));
                    }
                    self.require_capture_custody_metadata(snapshot, &original.event)?;
                }
                if matches!(
                    original.event.provenance,
                    Some(EventProvenance::ModelOutput { .. })
                ) && !manifest
                    .features
                    .contains(super::payload::MODEL_PROTOCOL_FEATURE)
                {
                    return Err(integrity("model protocol format feature is absent"));
                }
                if record.affects_scope.is_some() && !manifest.features.contains(IMPACT_FEATURE) {
                    return Err(integrity("capture scope-impact format feature is absent"));
                }
                if matches!(
                    original.event.provenance,
                    Some(EventProvenance::OwnedCheckpoint { .. })
                ) && !manifest.features.contains(super::owned::OWNED_FEATURE)
                {
                    return Err(integrity("owned checkpoint format feature is absent"));
                }
                if (original.event.provenance.is_some()
                    || matches!(
                        original.event.payload,
                        EventPayload::Staged { .. } | EventPayload::Assembly { .. }
                    ))
                    && !manifest.features.contains(super::payload::SOURCE_FEATURE)
                {
                    return Err(integrity("capture source format feature is absent"));
                }
                self.verify_capture_source_integrity(snapshot, &original.event)
                    .map_err(|_| integrity("captured original source closure is invalid"))?;
                if entry.key != record_key(original.event.event_id)
                    || record.producer_sequence != original.event.producer_sequence
                {
                    return Err(integrity("capture record identity is invalid"));
                }
                let positioned: ObservationId = read_required(
                    snapshot,
                    self,
                    &position_key(&record.producer_key, record.producer_sequence),
                )?;
                if positioned != original.event.event_id {
                    return Err(integrity(
                        "capture producer position differs from its original",
                    ));
                }
                let receipt: super::StoredIdempotency = decode(
                    &snapshot
                        .get(
                            &self.keyspaces.idempotency,
                            record.idempotency_digest.as_bytes(),
                        )
                        .map_err(storage_error)?
                        .ok_or_else(|| integrity("capture retry receipt is absent"))?,
                    "capture retry receipt",
                )?;
                if receipt.response_bytes != encode(&record.receipt)?
                    || receipt.operation != "capture"
                {
                    return Err(integrity("capture retry binding is invalid"));
                }
                accepted.push((record, original.event));
            } else if entry.key.starts_with(b"producer/") {
                validate_coverage(&decode(&entry.value, "producer coverage")?)?;
            } else if entry.key.starts_with(b"position/") {
                let id: ObservationId = decode(&entry.value, "capture position")?;
                let record: CaptureRecord = read_required(snapshot, self, &record_key(id))?;
                if entry.key != position_key(&record.producer_key, record.producer_sequence) {
                    return Err(integrity("capture position reverse binding is invalid"));
                }
            } else if entry.key.starts_with(b"outbox/") {
                let work: CaptureWork = decode(&entry.value, "capture outbox")?;
                let record: CaptureRecord =
                    read_required(snapshot, self, &record_key(work.event_id))?;
                if work.workspace_commit != record.receipt.workspace_commit
                    || work.event_digest != record.receipt.event_digest
                {
                    return Err(integrity("capture outbox binding is invalid"));
                }
            } else if entry.key.starts_with(b"scope/") {
                let _: u64 = decode(&entry.value, "capture scope epoch")?;
            } else if entry.key.starts_with(b"stream/") {
                let _: StreamHead = decode(&entry.value, "capture stream")?;
            } else if entry.key.starts_with(b"runhead/") {
                let _: super::owned::RunHead = decode(&entry.value, "run head")?;
            } else {
                return Err(integrity("unknown continuous capture record family"));
            }
        }
        // Deep verification reconstructs every derived capture row from accepted
        // originals. It is deliberately separate from the bounded append/read path.
        accepted.sort_by_key(|(record, _)| record.receipt.workspace_commit);
        let mut expected = BTreeMap::new();
        let mut producers = BTreeMap::<String, ProducerCoverage>::new();
        let mut streams = BTreeMap::<String, StreamHead>::new();
        let mut scopes = BTreeMap::<Vec<u8>, u64>::new();
        let mut run_heads = BTreeMap::new();
        for (record, event) in accepted {
            self.replay_checkpoint_head(&event, &record.receipt, &mut run_heads)?;
            let workspace = digest_bytes(event.workspace_id.to_string().as_bytes());
            let work = CaptureWork {
                event_id: event.event_id,
                workspace_commit: record.receipt.workspace_commit,
                event_digest: record.receipt.event_digest,
            };
            let (global, _) = self.select_snapshot(
                snapshot,
                &event.workspace_id.to_string(),
                Some(work.workspace_commit),
            )?;
            let journal: super::StoredEvent = decode(
                &snapshot
                    .get(&self.keyspaces.events, &global.to_be_bytes())
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("capture journal event is absent"))?,
                "capture journal event",
            )?;
            if journal.operation != "capture" || journal.accepted_original.as_ref() != Some(&work) {
                return Err(integrity(
                    "capture journal lacks its accepted original reference",
                ));
            }
            expected.insert(record_key(event.event_id), encode(&record)?);
            expected.insert(
                position_key(&record.producer_key, record.producer_sequence),
                encode(&event.event_id)?,
            );
            expected.insert(work_key(&workspace, work.workspace_commit), encode(&work)?);
            let coverage = producers.entry(record.producer_key.clone()).or_default();
            *coverage = advance_coverage(std::mem::take(coverage), record.producer_sequence)?;
            for scope in event
                .scope_ids
                .iter()
                .filter(|_| record.affects_scope.unwrap_or(true))
            {
                scopes.insert(
                    scope_key(&workspace, &scope.to_string()),
                    work.workspace_commit,
                );
            }
            if let Some(stream) = &event.response_stream {
                let response = match stream {
                    ResponseStream::Chunk { response_id, .. }
                    | ResponseStream::Finished { response_id, .. } => response_id,
                };
                let head = streams
                    .entry(format!("stream/{}/{response}", record.producer_key))
                    .or_default();
                advance_stream(head, stream)
                    .map_err(|_| integrity("captured response sequence is invalid"))?;
            }
        }
        for (producer, coverage) in producers {
            expected.insert(
                format!("producer/{producer}").into_bytes(),
                encode(&coverage)?,
            );
        }
        for (stream, head) in streams {
            expected.insert(stream.into_bytes(), encode(&head)?);
        }
        for (key, head) in run_heads {
            expected.insert(key, encode(&head)?);
        }
        for (scope, epoch) in self.raw_revocation_scope_epochs(snapshot)? {
            let current = scopes.entry(scope).or_default();
            *current = (*current).max(epoch);
        }
        for (scope, epoch) in self.assertion_scope_epochs(snapshot)? {
            let current = scopes.entry(scope).or_default();
            *current = (*current).max(epoch);
        }
        for (scope, epoch) in self.record_scope_epochs(snapshot)? {
            let current = scopes.entry(scope).or_default();
            *current = (*current).max(epoch);
        }
        for (scope, epoch) in scopes {
            expected.insert(scope, encode(&epoch)?);
        }
        if entries.len() != expected.len()
            || entries
                .iter()
                .any(|entry| expected.get(&entry.key) != Some(&entry.value))
        {
            return Err(integrity(
                "capture derived rows differ from accepted originals",
            ));
        }
        Ok(())
    }

    pub(super) fn authorize_capture_dependencies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        event_id: ObservationId,
    ) -> ServiceResult<()> {
        self.authorize_derived_custody(snapshot, context, event_id)
    }

    /// Materialized intersection of every input's disclosure restrictions.
    pub(super) fn capture_index_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event_id: ObservationId,
    ) -> ServiceResult<Vec<contextdb_service::AccessPolicy>> {
        self.derived_custody_policies(snapshot, event_id)
    }

    pub(super) fn verify_capture_journal_reference<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &super::StoredEvent,
    ) -> ServiceResult<()> {
        match (&event.accepted_original, event.operation.as_str()) {
            (Some(work), "capture") => {
                let record: CaptureRecord =
                    read_required(snapshot, self, &record_key(work.event_id))
                        .map_err(|_| integrity("journal capture reference is absent"))?;
                if record.receipt.event_digest != work.event_digest
                    || record.receipt.workspace_commit != event.workspace_commit
                    || work.workspace_commit != event.workspace_commit
                {
                    return Err(integrity("journal capture reference differs"));
                }
            }
            (None, operation) if operation != "capture" => {}
            _ => return Err(integrity("journal capture reference kind is invalid")),
        }
        Ok(())
    }
}

fn capture_dependencies(payload: &EventPayload) -> Vec<CaptureDependency> {
    match payload {
        EventPayload::Staged { reference, .. } => vec![CaptureDependency::Payload {
            reference: reference.clone(),
        }],
        EventPayload::Assembly { manifest } => manifest
            .parts
            .iter()
            .filter_map(|part| match part {
                RequestPart::Source { span } | RequestPart::JsonStringSource { span, .. } => {
                    Some(CaptureDependency::Source {
                        event_id: span.event_id,
                    })
                }
                RequestPart::StoredNovel { payload } => Some(CaptureDependency::Payload {
                    reference: payload.clone(),
                }),
                RequestPart::Novel { .. } => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn host_request_echo(event: &EventEnvelope) -> bool {
    event.kind == contextdb_core::EventKind::ModelRequested
        && event.role == contextdb_core::EventRole::Host
        && matches!(event.payload, EventPayload::Assembly { .. })
        && matches!(event.provenance, Some(EventProvenance::ModelRequest { .. }))
}

fn advance_stream(head: &mut StreamHead, stream: &ResponseStream) -> ServiceResult<()> {
    if head.finished {
        return Err(invalid("response stream is already terminal"));
    }
    match stream {
        ResponseStream::Chunk { index, .. } => {
            if *index != head.chunks {
                return Err(invalid("response chunk is not the next contiguous chunk"));
            }
            head.chunks = head
                .chunks
                .checked_add(1)
                .ok_or_else(|| exhausted("response chunk ordinal is exhausted"))?;
        }
        ResponseStream::Finished { chunk_count, .. } => {
            if *chunk_count != head.chunks {
                return Err(invalid("response manifest differs from durable chunks"));
            }
            head.finished = true;
        }
    }
    Ok(())
}

fn validate_payload(event: &EventEnvelope) -> ServiceResult<()> {
    if let Some(bytes) = event.payload.original_bytes() {
        if bytes.len() > CAPTURE_MAX_INLINE_BYTES {
            return Err(exhausted(
                "original exceeds inline capture limit; use bounded chunks",
            ));
        }
        if event.payload.digest()
            != Some(ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()))
        {
            return Err(invalid("original payload digest mismatch"));
        }
    }
    Ok(())
}

pub(super) fn content_digest_of(event: &EventEnvelope) -> ServiceResult<ContentDigest> {
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&encode(event)?).as_bytes(),
    ))
}

pub(super) fn producer_key(
    context: &AuthenticatedRequestContext,
    producer: StreamId,
) -> ServiceResult<String> {
    canonical_digest(&(
        NATIVE_CAPTURE_DOMAIN,
        &context.request.workspace_id,
        &context.request.subject_id,
        &context.actor_id,
        &context.agent_id,
        producer,
    ))
}

fn record_key(id: ObservationId) -> Vec<u8> {
    format!("receipt/{id}").into_bytes()
}
pub(super) fn position_key(producer: &str, sequence: u64) -> Vec<u8> {
    let mut key = format!("position/{producer}/").into_bytes();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}
pub(super) fn work_key(workspace_digest: &str, sequence: u64) -> Vec<u8> {
    let mut key = format!("outbox/{workspace_digest}/").into_bytes();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}
pub(super) fn scope_key(workspace_digest: &str, scope: &str) -> Vec<u8> {
    format!(
        "scope/{workspace_digest}/{}",
        digest_bytes(scope.as_bytes())
    )
    .into_bytes()
}

fn read_optional<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
    snapshot: &S,
    service: &NativeService,
    key: &[u8],
) -> ServiceResult<Option<T>> {
    snapshot
        .get(&service.keyspaces.continuous, key)
        .map_err(storage_error)?
        .map(|bytes| decode(&bytes, "continuous capture record"))
        .transpose()
}
fn read_required<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
    snapshot: &S,
    service: &NativeService,
    key: &[u8],
) -> ServiceResult<T> {
    read_optional(snapshot, service, key)?.ok_or_else(not_found)
}

fn advance_coverage(
    mut coverage: ProducerCoverage,
    sequence: u64,
) -> ServiceResult<ProducerCoverage> {
    validate_coverage(&coverage)?;
    if sequence > coverage.head {
        if sequence - coverage.head > 1 {
            coverage.gaps.push(CaptureGapRange {
                from: coverage.head + 1,
                through: sequence - 1,
            });
        }
        coverage.head = sequence;
    } else {
        let index = coverage
            .gaps
            .iter()
            .position(|gap| gap.from <= sequence && sequence <= gap.through)
            .ok_or_else(|| invalid("producer sequence is already covered"))?;
        let gap = coverage.gaps.remove(index);
        if gap.through > sequence {
            coverage.gaps.insert(
                index,
                CaptureGapRange {
                    from: sequence + 1,
                    through: gap.through,
                },
            );
        }
        if gap.from < sequence {
            coverage.gaps.insert(
                index,
                CaptureGapRange {
                    from: gap.from,
                    through: sequence - 1,
                },
            );
        }
    }
    if coverage.gaps.len() > CAPTURE_MAX_PRODUCER_GAPS {
        return Err(exhausted(
            "producer gap budget exhausted; strict capture is paused",
        ));
    }
    coverage.contiguous_through = coverage
        .gaps
        .first()
        .map_or(coverage.head, |gap| gap.from - 1);
    Ok(coverage)
}

fn validate_coverage(coverage: &ProducerCoverage) -> ServiceResult<()> {
    let mut previous_end = 0;
    for gap in &coverage.gaps {
        if gap.from == 0
            || gap.from > gap.through
            || gap.through >= coverage.head
            || gap.from <= previous_end
        {
            return Err(integrity("producer gap ranges are invalid"));
        }
        previous_end = gap.through;
    }
    if coverage.gaps.len() > CAPTURE_MAX_PRODUCER_GAPS
        || coverage.contiguous_through
            != coverage
                .gaps
                .first()
                .map_or(coverage.head, |gap| gap.from - 1)
    {
        return Err(integrity("producer coverage prefix is invalid"));
    }
    Ok(())
}

#[cfg(test)]
fn capture_fault(stage: &str) {
    if std::env::var("CONTEXTDB_CAPTURE_CRASH").as_deref() == Ok(stage) {
        std::process::exit(86);
    }
}

#[cfg(test)]
pub(crate) mod tests;
